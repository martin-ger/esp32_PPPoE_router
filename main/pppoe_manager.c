/* PPPoE DSL uplink management.
 *
 * Handles PPPoE session lifecycle (connect/disconnect/reconnect),
 * VLAN tagging for outgoing PPPoE frames, and SNTP initialization.
 *
 * Uses the raw lwIP pppapi because ESP-IDF's esp_netif PPP wrapper
 * only supports PPPoS (serial), not PPPoE.
 */

#include <string.h>
#include <time.h>
#include "esp_log.h"
#include "esp_sntp.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "lwip/ip_addr.h"
#include "lwip/dns.h"
#include "lwip/netif.h"
#include "netif/ppp/pppapi.h"
#include "netif/ppp/pppoe.h"
#include "pppoe_config.h"
#include "router_config.h"
#include "wifi_config.h"
#include "vpn_config.h"
#include "portmap.h"
#include "pcap_capture.h"
#include "syslog_client.h"

static const char *TAG = "pppoe_mgr";

/* ---- External references from esp32_nat_router.c ---- */
extern esp_netif_t *wifiAP;
extern EventGroupHandle_t wifi_event_group;
extern const int WIFI_CONNECTED_BIT;

/* ---- Module-private state ---- */
static ppp_pcb *ppp_pcb_handle = NULL;
static struct netif ppp_netif;
static struct netif *eth_netif_cached = NULL;
static bool pppoe_session_active = false;

/* VLAN hook state */
static netif_linkoutput_fn original_eth_linkoutput = NULL;

/* ---- Forward declarations ---- */
static void ppp_link_status_cb(ppp_pcb *pcb, int err_code, void *ctx);
static void pppoe_reconnect_task(void *pvParameters);

/* ------------------------------------------------------------------ */
/*  VLAN tagging hook                                                  */
/* ------------------------------------------------------------------ */

/*
 * Hook installed on the Ethernet netif's linkoutput to inject 802.1Q VLAN
 * tags on outgoing PPPoE frames (ethertypes 0x8863 and 0x8864).
 *
 * Uses pbuf_add_header() to expand into existing headroom (guaranteed by
 * ETHARP_SUPPORT_VLAN=1 which increases PBUF_LINK_HLEN by 4 bytes), then
 * shifts the 12-byte MAC header to make room for the 4-byte VLAN tag.
 * No allocation, no full-frame copy.
 *
 * Incoming VLAN-tagged frames are handled automatically by lwIP's
 * ethernet_input() when ETHARP_SUPPORT_VLAN=1.
 */
static err_t eth_vlan_linkoutput_hook(struct netif *netif, struct pbuf *p)
{
    if (pppoe_vlan > 0 && p != NULL && p->len >= 14) {
        uint8_t *eth = (uint8_t *)p->payload;
        uint16_t ethertype = (eth[12] << 8) | eth[13];

        if (ethertype == 0x8863 || ethertype == 0x8864) {
            if (pbuf_add_header(p, 4) == 0) {
                uint8_t *dst = (uint8_t *)p->payload;
                /* Shift DA+SA (12 bytes) back to make room for VLAN tag */
                memmove(dst, dst + 4, 12);
                /* Insert 802.1Q VLAN tag at bytes 12-15 */
                dst[12] = 0x81; dst[13] = 0x00;                /* TPID */
                dst[14] = (uint8_t)((pppoe_vlan >> 8) & 0x0F); /* PCP=0, DEI=0, VID high */
                dst[15] = (uint8_t)(pppoe_vlan & 0xFF);        /* VID low */
                /* Original ethertype stays at bytes 16-17 */

                err_t ret = original_eth_linkoutput(netif, p);

                /* Restore pbuf to original layout */
                memmove(dst + 4, dst, 12);
                pbuf_remove_header(p, 4);
                return ret;
            }
            /* No headroom — copy frame into new pbuf with VLAN tag inserted */
            {
                struct pbuf *np = pbuf_alloc(PBUF_RAW, p->tot_len + 4, PBUF_RAM);
                if (np != NULL) {
                    ESP_LOGI(TAG, "VLAN: pbuf has no headroom - copying");
                    uint8_t *dst = (uint8_t *)np->payload;
                    pbuf_copy_partial(p, dst, 12, 0);           /* DA + SA */
                    dst[12] = 0x81; dst[13] = 0x00;             /* TPID */
                    dst[14] = (uint8_t)((pppoe_vlan >> 8) & 0x0F);
                    dst[15] = (uint8_t)(pppoe_vlan & 0xFF);
                    pbuf_copy_partial(p, dst + 16, p->tot_len - 12, 12); /* ethertype + payload */
                    err_t ret = original_eth_linkoutput(netif, np);
                    pbuf_free(np);
                    return ret;
                }
            }
            ESP_LOGW(TAG, "VLAN: pbuf alloc failed, sending untagged");
        }
    }
    return original_eth_linkoutput(netif, p);
}

static void install_vlan_hook(struct netif *eth_netif)
{
    if (pppoe_vlan > 0 && original_eth_linkoutput == NULL) {
        original_eth_linkoutput = eth_netif->linkoutput;
        eth_netif->linkoutput = eth_vlan_linkoutput_hook;
        ESP_LOGI(TAG, "VLAN %d tagging enabled for PPPoE frames", (int)pppoe_vlan);
    }
}

static void remove_vlan_hook(struct netif *eth_netif)
{
    if (original_eth_linkoutput != NULL && eth_netif != NULL) {
        eth_netif->linkoutput = original_eth_linkoutput;
        original_eth_linkoutput = NULL;
        ESP_LOGI(TAG, "VLAN hook removed");
    }
}

/* ------------------------------------------------------------------ */
/*  DNS forwarding from PPP to AP                                      */
/* ------------------------------------------------------------------ */

static void copy_dns_to_ap(void)
{
    // VPN DNS (while VPN enabled) or the manual ap_dns override take precedence
    // over the ISP-supplied servers; effective_ap_dns() returns NULL otherwise.
    const char *eff_dns = effective_ap_dns();
    if (eff_dns) {
        esp_netif_dns_info_t dns_info;
        dns_info.ip.type = ESP_IPADDR_TYPE_V4;
        dns_info.ip.u_addr.ip4.addr = esp_ip4addr_aton(eff_dns);
        esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dns_info);
        ESP_LOGI(TAG, "DNS: %s (override)", eff_dns);
        return;
    }
    for (int i = 0; i < 2; i++) {
        const ip_addr_t *dns = dns_getserver(i);
        if (dns != NULL && !ip_addr_isany(dns)) {
            esp_netif_dns_info_t dns_info;
            dns_info.ip = *(const esp_ip_addr_t *)dns;
            esp_netif_dns_type_t type = (i == 0) ? ESP_NETIF_DNS_MAIN : ESP_NETIF_DNS_BACKUP;
            esp_netif_set_dns_info(wifiAP, type, &dns_info);
            ESP_LOGI(TAG, "DNS%d: " IPSTR, i, IP2STR(ip_2_ip4(dns)));
        }
    }
}

/* Revert AP DNS to the router's own IP so the captive-portal DNS task
 * intercepts client queries while there is no upstream connection. */
static void reset_dns_to_captive(void)
{
    esp_netif_dns_info_t dns_info;
    dns_info.ip.type = ESP_IPADDR_TYPE_V4;
    dns_info.ip.u_addr.ip4.addr = my_ap_ip;
    esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dns_info);
    ESP_LOGI(TAG, "DNS reset to captive portal (" IPSTR ")", IP2STR(&dns_info.ip.u_addr.ip4));
}

/* ------------------------------------------------------------------ */
/*  PPP status callback (called from lwIP tcpip thread)                */
/* ------------------------------------------------------------------ */

static void ppp_link_status_cb(ppp_pcb *pcb, int err_code, void *ctx)
{
    switch (err_code) {
    case PPPERR_NONE:
        /* PPPoE session established — IPCP negotiation complete */
        pppoe_ip = ip_2_ip4(&ppp_netif.ip_addr)->addr;
        my_ip = pppoe_ip;
        ap_connect = true;
        pppoe_connected = true;
        if (pppoe_babyjumbo) {
            ap_mss_clamp = 1460;
            ap_pmtu = 1500;
        } else {
            ap_mss_clamp = 1452;
            ap_pmtu = 1492;
        }

        netif_set_default(&ppp_netif);
        /* A fast PPPoE re-establish can leave the VPN tunnel still up while the
         * line above steals the default route from it. If the VPN is connected
         * in route-all mode, restore the WG tunnel as the default route at once
         * (no-op on first connect — vpn_monitor_task brings the VPN up after). */
        vpn_reassert_default_route();
        delete_portmap_tab();
        apply_portmap_tab();
        copy_dns_to_ap();
        pcap_set_link_type(101);  /* DLT_RAW: PPP delivers raw IP, no Ethernet header */
        init_byte_counter();
        init_sntp_if_needed();
        syslog_notify_connected();
#if defined(CONFIG_DDNS_ENABLED) && CONFIG_DDNS_ENABLED
        extern void ddns_update_wan_ip(uint32_t wan_ip);
        ddns_update_wan_ip(pppoe_ip);
#endif
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);

        ESP_LOGI(TAG, "PPPoE connected%s, IP: " IPSTR ", MSS=%u PMTU=%u",
                 pppoe_babyjumbo ? " (baby-jumbo)" : "",
                 IP2STR(ip_2_ip4(&ppp_netif.ip_addr)),
                 ap_mss_clamp, ap_pmtu);
        break;

    case PPPERR_CONNECT:
        ESP_LOGW(TAG, "PPPoE connection lost");
        goto handle_disconnect;

    case PPPERR_PEERDEAD:
        ESP_LOGW(TAG, "PPPoE peer dead (LCP timeout)");
        goto handle_disconnect;

    handle_disconnect:
        pppoe_connected = false;
        ap_connect = false;
        pppoe_ip = 0;
        my_ip = 0;
        ap_mss_clamp = 0;
        ap_pmtu = 0;
        netif_set_default(NULL);
        deinit_byte_counter_ppp();
        reset_dns_to_captive();
        xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        /* Schedule reconnect in a separate task (can't block tcpip thread) */
        xTaskCreate(pppoe_reconnect_task, "pppoe_reconn", 4096, NULL, 5, NULL);
        break;

    case PPPERR_AUTHFAIL:
        ESP_LOGE(TAG, "PPPoE authentication failed — check username/password");
        pppoe_connected = false;
        ap_connect = false;
        pppoe_ip = 0;
        my_ip = 0;
        /* Do NOT auto-reconnect on auth failure */
        break;

    case PPPERR_USER:
        /* Normal shutdown (we called pppapi_close).  Phase is now DEAD so
         * pppapi_free is safe to call — it will remove the netif from the
         * lwIP list.  This must happen here rather than in pppoe_stop()
         * because ppp_free() returns ERR_CONN if phase != PPP_PHASE_DEAD,
         * which means the netif would stay in the list and cause a
         * "netif already added" panic on the next pppoe_start(). */
        ESP_LOGI(TAG, "PPPoE session closed by user");
        deinit_byte_counter_ppp();
        if (ppp_pcb_handle != NULL) {
            /* pppapi_free() uses tcpip_api_call() which deadlocks when called
             * from within the tcpip thread (no re-entrancy without core locking).
             * Call ppp_free() directly — we are already in the tcpip thread
             * and phase is PPP_PHASE_DEAD, so the direct call is safe. */
            ppp_free(ppp_pcb_handle);
            ppp_pcb_handle = NULL;
        }
        pppoe_session_active = false;
        break;

    default:
        ESP_LOGW(TAG, "PPPoE error: %d — treating as disconnect, will retry", err_code);
        goto handle_disconnect;
    }
}

/* ------------------------------------------------------------------ */
/*  Reconnect task                                                     */
/* ------------------------------------------------------------------ */

static void pppoe_reconnect_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Reconnecting PPPoE in 2 seconds...");
    vTaskDelay(pdMS_TO_TICKS(2000));

    /* Clean up old session.
     * Save and clear ppp_pcb_handle BEFORE calling pppapi_close so that the
     * PPPERR_USER callback (which fires synchronously inside pppapi_close)
     * sees ppp_pcb_handle == NULL and skips ppp_free.  We then call
     * pppapi_free on the saved copy ourselves.  Without this, pppapi_close
     * triggers PPPERR_USER → ppp_free(handle) + ppp_pcb_handle = NULL, and
     * the subsequent pppapi_free(NULL) crashes in ppp_free. */
    ppp_pcb *pcb = ppp_pcb_handle;
    ppp_pcb_handle = NULL;
    pppoe_session_active = false;
    if (pcb != NULL) {
        pppapi_close(pcb, 1); /* nocarrier=1: forces immediate teardown */
        pppapi_free(pcb);     /* phase is DEAD after close; removes netif from lwIP list */
    }

    /* Only retry if Ethernet link is still up — if it's down the
     * ETHERNET_EVENT_CONNECTED handler will start a new session when
     * the physical link recovers. */
    if (eth_netif_cached != NULL &&
        (eth_netif_cached->flags & NETIF_FLAG_LINK_UP)) {
        ESP_LOGI(TAG, "Re-initiating PPPoE session");
        pppoe_start(eth_netif_cached);
    } else {
        ESP_LOGI(TAG, "Ethernet link is down, waiting for link-up event");
    }
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

esp_err_t pppoe_start(struct netif *eth_netif)
{
    if (!pppoe_enabled) {
        ESP_LOGI(TAG, "PPPoE not enabled");
        return ESP_ERR_INVALID_STATE;
    }
    if (pppoe_session_active) {
        ESP_LOGW(TAG, "PPPoE session already active, ignoring start");
        return ESP_ERR_INVALID_STATE;
    }
    if (pppoe_user == NULL || strlen(pppoe_user) == 0) {
        ESP_LOGE(TAG, "PPPoE username not configured");
        return ESP_ERR_INVALID_ARG;
    }
    if (eth_netif == NULL) {
        ESP_LOGE(TAG, "Ethernet netif is NULL");
        return ESP_ERR_INVALID_ARG;
    }

    eth_netif_cached = eth_netif;

    /* Install VLAN hook on the Ethernet interface if needed */
    install_vlan_hook(eth_netif);

    /* Zero the netif struct so lwIP's netif_add assertion (next==NULL) passes
     * cleanly on reconnect — pppapi_pppoe_create will fully initialise it. */
    memset(&ppp_netif, 0, sizeof(ppp_netif));

    /* Create PPPoE session on top of the Ethernet interface */
    const char *svc = (pppoe_service && strlen(pppoe_service) > 0) ? pppoe_service : NULL;
    ppp_pcb_handle = pppapi_pppoe_create(&ppp_netif, eth_netif,
                                          svc, NULL,
                                          ppp_link_status_cb, NULL);
    if (ppp_pcb_handle == NULL) {
        ESP_LOGE(TAG, "pppapi_pppoe_create failed");
        return ESP_FAIL;
    }

    /* Set authentication */
    u8_t auth_type;
    switch (pppoe_auth) {
    case 1:  auth_type = PPPAUTHTYPE_PAP;  break;
    case 2:  auth_type = PPPAUTHTYPE_CHAP; break;
    default: auth_type = PPPAUTHTYPE_ANY;  break;
    }
    ppp_set_auth(ppp_pcb_handle, auth_type,
                 pppoe_user,
                 (pppoe_pass && strlen(pppoe_pass) > 0) ? pppoe_pass : "");

    /* Request DNS servers from the peer via IPCP options 129/131 */
    ppp_set_usepeerdns(ppp_pcb_handle, 1);

    /* Initiate PPPoE discovery + LCP + IPCP */
    esp_err_t err = pppapi_connect(ppp_pcb_handle, 0);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "pppapi_connect failed: %d", err);
        pppapi_free(ppp_pcb_handle);
        ppp_pcb_handle = NULL;
        return ESP_FAIL;
    }

    pppoe_session_active = true;
    ESP_LOGI(TAG, "PPPoE discovery started (user=%s, service=%s, VLAN=%d)",
             pppoe_user, svc ? svc : "any", (int)pppoe_vlan);
    return ESP_OK;
}

void pppoe_stop(void)
{
    /* Set state flags first (race prevention with hot-path checks) */
    pppoe_connected = false;
    pppoe_ip = 0;
    my_ip = 0;
    ap_mss_clamp = 0;
    ap_pmtu = 0;

    delete_portmap_tab();
    apply_portmap_tab();

    if (pppoe_session_active && ppp_pcb_handle != NULL) {
        /* nocarrier=1: carrier is physically gone, forces immediate teardown.
         * With phase==PPP_PHASE_RUNNING this calls link_terminated() which
         * sets phase=DEAD and fires PPPERR_USER synchronously before
         * pppapi_close() returns.  pppapi_free() is called from the
         * PPPERR_USER branch of ppp_link_status_cb() once phase is DEAD. */
        pppapi_close(ppp_pcb_handle, 1);
        /* ppp_pcb_handle and pppoe_session_active are cleared in PPPERR_USER */
    } else {
        pppoe_session_active = false;
    }

    /* Remove VLAN hook */
    if (eth_netif_cached != NULL) {
        remove_vlan_hook(eth_netif_cached);
    }

    ESP_LOGI(TAG, "PPPoE session stopped");
}

IRAM_ATTR bool pppoe_is_connected(void)
{
    return pppoe_session_active && pppoe_connected && ppp_pcb_handle != NULL;
}

struct netif *pppoe_get_netif(void)
{
    return &ppp_netif;
}

/* ------------------------------------------------------------------ */
/*  SNTP (useful for syslog timestamps)                               */
/* ------------------------------------------------------------------ */

static void sntp_init_task(void *pvParameters)
{
    /* esp_sntp_setservername() calls tcpip_api_call() which blocks until the
     * tcpip thread processes the message.  This function MUST NOT be called
     * from within the tcpip thread (e.g. from ppp_link_status_cb) or it will
     * deadlock: the tcpip thread posts to its own mailbox and then waits on a
     * semaphore that can never be signalled because it is the only consumer.
     *
     * Running in a separate task avoids this: tcpip_api_call() posts normally
     * and the tcpip thread handles the message while this task waits. */
    ESP_LOGI(TAG, "Initializing SNTP");
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_setservername(1, "time.nist.gov");
    esp_sntp_setservername(2, "time.google.com");
    esp_sntp_init();
    vTaskDelete(NULL);
}

void init_sntp_if_needed(void)
{
    if (!esp_sntp_enabled()) {
        /* xTaskCreate is safe to call from the tcpip thread */
        xTaskCreate(sntp_init_task, "sntp_init", 4192, NULL, 5, NULL);
    }
}
