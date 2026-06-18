/* WireGuard VPN management.
 *
 * Handles VPN connection/disconnection via a long-running monitor task that
 * reacts to the WIFI_CONNECTED_BIT event group (set/cleared by pppoe_manager.c
 * on PPPoE connect/disconnect).  All WireGuard calls run in the monitor task's
 * context — never from the lwIP tcpip thread — to avoid tcpip_api_call deadlocks.
 *
 * MTU chain (WireGuard overhead = 60 bytes: 20 IP + 8 UDP + 16 WG hdr + 16 tag):
 *   Standard PPPoE  (outer IP MTU 1492): inner IP MTU 1432, TCP MSS 1352
 *   Baby-jumbo PPPoE (outer IP MTU 1500): inner IP MTU 1440, TCP MSS 1380
 */

#include <string.h>
#include <time.h>
#include "esp_log.h"
#include "esp_wireguard.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "lwip/ip_addr.h"
#include "vpn_config.h"
#include "pppoe_config.h"
#include "router_config.h"
#include "portmap.h"

static const char *TAG = "vpn_mgr";

// Cached VPN subnet for kill switch (network byte order)
static uint32_t vpn_subnet_ip = 0;
static uint32_t vpn_subnet_mask = 0;

// WireGuard context (module-private)
static wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();
static wireguard_ctx_t wg_ctx = {0};
static bool wg_initialized = false;

void vpn_set_subnet(uint32_t ip, uint32_t mask) {
    vpn_subnet_ip = ip;
    vpn_subnet_mask = mask;
}

IRAM_ATTR bool vpn_in_subnet(uint32_t ip) {
    if (vpn_subnet_mask == 0) return false;
    return (ip & vpn_subnet_mask) == vpn_subnet_ip;
}

esp_err_t vpn_connect(void)
{
    if (!vpn_enabled) {
        ESP_LOGI(TAG, "VPN not enabled");
        return ESP_ERR_INVALID_STATE;
    }
    if (vpn_private_key == NULL || strlen(vpn_private_key) == 0 ||
        vpn_public_key == NULL || strlen(vpn_public_key) == 0 ||
        vpn_endpoint == NULL || strlen(vpn_endpoint) == 0 ||
        vpn_address == NULL || strlen(vpn_address) == 0) {
        ESP_LOGE(TAG, "VPN missing required config (privkey, pubkey, endpoint, address)");
        return ESP_ERR_INVALID_ARG;
    }

    wg_config.private_key = vpn_private_key;
    wg_config.public_key = vpn_public_key;
    wg_config.preshared_key = (vpn_preshared_key && strlen(vpn_preshared_key) > 0) ? vpn_preshared_key : NULL;
    wg_config.allowed_ip = vpn_address;
    wg_config.allowed_ip_mask = (vpn_netmask && strlen(vpn_netmask) > 0) ? vpn_netmask : "255.255.255.0";
    wg_config.endpoint = vpn_endpoint;
    wg_config.port = vpn_port;
    wg_config.persistent_keepalive = vpn_keepalive;
    /* netif_key intentionally left NULL: WireGuard will use the current default
     * route (PPP netif, set by pppoe_manager on connect) for the endpoint host
     * route.  esp_wireguard_set_default() then replaces the default with the
     * WireGuard netif so all forwarded AP traffic goes through the tunnel. */

    esp_err_t err;
    if (!wg_initialized) {
        err = esp_wireguard_init(&wg_config, &wg_ctx);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "WireGuard init failed: %s", esp_err_to_name(err));
            return err;
        }
        wg_initialized = true;
    }

    err = esp_wireguard_connect(&wg_ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WireGuard connect failed: %s", esp_err_to_name(err));
        // Reset so next attempt does a clean init (avoids leaked netif/timers)
        wg_initialized = false;
        memset(&wg_ctx, 0, sizeof(wg_ctx));
        return err;
    }

    if (vpn_route_all) {
        err = esp_wireguard_set_default(&wg_ctx);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "WireGuard set_default failed: %s", esp_err_to_name(err));
        }
    }

    /* MTU/MSS: WireGuard adds 60 bytes of overhead on top of the PPPoE IP MTU.
     * Baby-jumbo mode gives PPPoE outer IP MTU 1500; standard gives 1492. */
    if (pppoe_babyjumbo) {
        ap_mss_clamp = 1380;   /* 1440 inner IP MTU - 40 TCP+IP - 20 safety */
        ap_pmtu = 1440;
    } else {
        ap_mss_clamp = 1352;   /* 1432 inner IP MTU - 40 TCP+IP - 40 safety */
        ap_pmtu = 1432;
    }

    vpn_connected = true;

    /* Cache VPN tunnel IP and activate VPN-bound port mappings */
    if (wg_ctx.netif) {
        vpn_tunnel_ip = ip_2_ip4(&wg_ctx.netif->ip_addr)->addr;
    }
    delete_portmap_tab();
    apply_portmap_tab();

    ESP_LOGI(TAG, "WireGuard VPN connected%s, MSS=%u PMTU=%u",
             vpn_route_all ? "" : " (split tunnel)", ap_mss_clamp, ap_pmtu);
    return ESP_OK;
}

void vpn_reassert_default_route(void)
{
    /* ESP-IDF's esp_netif owns lwIP's netif_default and re-asserts it (for PPP,
     * via esp_netif_ppp_set_default_netif) whenever the PPPoE link comes up.
     * esp_wireguard_set_default() uses raw netif_set_default(), which esp_netif
     * does not track, so on every PPPoE (re)connect the WG tunnel silently loses
     * the default route to the PPP netif and route-all traffic leaks straight
     * out the uplink. Re-assert the tunnel as default after the PPP GOT_IP event
     * while the VPN is up in route-all mode.
     *
     * Safe to call from event-handler context: WireGuard's own encrypted packets
     * are sent via udp_sendto_if(underlying_netif) and never use the default
     * route, so this only redirects the forwarded inner traffic. */
    if (vpn_enabled && vpn_route_all && wg_initialized && wg_ctx.netif && vpn_connected) {
        esp_wireguard_set_default(&wg_ctx);
    }
}

void vpn_disconnect(void)
{
    // Set vpn_connected false FIRST to prevent race with vpn_is_connected()
    // (called from netif hooks and HTTP handlers in other tasks)
    vpn_connected = false;
    vpn_tunnel_ip = 0;

    /* Restore PPPoE baseline MSS/PMTU (don't zero — PPPoE still needs clamping).
     * If PPPoE is also down, set to 0 (pppoe_manager will re-set on reconnect). */
    if (pppoe_connected) {
        ap_mss_clamp = pppoe_babyjumbo ? 1460 : 1452;
        ap_pmtu      = pppoe_babyjumbo ? 1500 : 1492;
    } else {
        ap_mss_clamp = 0;
        ap_pmtu = 0;
    }

    /* Deactivate VPN portmaps, keep regular ones */
    delete_portmap_tab();
    apply_portmap_tab();

    if (wg_initialized) {
        esp_wireguard_disconnect(&wg_ctx);
        wg_initialized = false;
    }
    ESP_LOGI(TAG, "WireGuard VPN disconnected");
}

IRAM_ATTR bool vpn_is_connected(void)
{
    if (!wg_initialized || !vpn_connected || !wg_ctx.netif) {
        return false;
    }
    return esp_wireguardif_peer_is_up(&wg_ctx) == ESP_OK;
}


/* Wait up to 30 s for SNTP time sync (WireGuard needs valid wall clock for
 * TAI64N timestamps).  Returns when time is valid or timeout expires. */
static void wait_for_sntp(void)
{
    int retry = 0;
    const int max_retry = 60;  /* 60 × 500 ms = 30 s */
    time_t now = 0;
    while (retry < max_retry) {
        time(&now);
        if (now > 1577836800) {  /* Valid if after 2020-01-01 */
            break;
        }
        if (retry % 4 == 0) {
            ESP_LOGI(TAG, "Waiting for SNTP time sync... (%d/%ds)", retry / 2, max_retry / 2);
        }
        vTaskDelay(pdMS_TO_TICKS(500));
        retry++;
    }
    if (now > 1577836800) {
        struct tm timeinfo;
        localtime_r(&now, &timeinfo);
        ESP_LOGI(TAG, "Time synchronized: %04d-%02d-%02d %02d:%02d:%02d",
                 timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                 timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
    } else {
        ESP_LOGW(TAG, "SNTP sync timeout after %ds, proceeding with VPN anyway", max_retry / 2);
    }
}

/* Long-running VPN lifecycle task.
 *
 * Waits for PPPoE to establish (WIFI_CONNECTED_BIT), syncs SNTP, connects
 * WireGuard, then monitors health every 15 seconds.  When PPPoE drops the bit
 * is cleared — VPN is torn down and the task loops back to wait.
 *
 * All WireGuard API calls happen here (not in the lwIP tcpip thread) to avoid
 * potential tcpip_api_call deadlocks.
 */
void vpn_monitor_task(void *pvParameters)
{
    extern EventGroupHandle_t wifi_event_group;
    extern const int WIFI_CONNECTED_BIT;

    while (1) {
        /* Block until PPPoE is up.  pppoe_manager sets this bit after
         * netif_set_default(&ppp_netif), so the PPP netif IS the default
         * route when we call vpn_connect() — required for endpoint host route. */
        xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT,
                            pdFALSE, pdTRUE, portMAX_DELAY);

        ESP_LOGI(TAG, "PPPoE up, starting VPN connection");

        /* SNTP is already started by pppoe_manager; wait for it to sync */
        init_sntp_if_needed();
        wait_for_sntp();

        vpn_connect();

        /* Health-check loop while PPPoE is up */
        while (1) {
            vTaskDelay(pdMS_TO_TICKS(15000));

            EventBits_t bits = xEventGroupGetBits(wifi_event_group);
            if (!(bits & WIFI_CONNECTED_BIT)) {
                /* PPPoE went down — tear down VPN and go back to waiting */
                ESP_LOGI(TAG, "PPPoE down, disconnecting VPN");
                vpn_disconnect();
                break;
            }

            /* PPPoE is up — check VPN tunnel health */
            if (!vpn_is_connected()) {
                ESP_LOGW(TAG, "VPN health check failed, reconnecting");
                vpn_disconnect();
                vTaskDelay(pdMS_TO_TICKS(2000));
                vpn_connect();
            } else {
                /* Tunnel healthy. A PPPoE re-establish within this interval may
                 * have run netif_set_default(&ppp_netif) and stolen the default
                 * route from the WG tunnel without the health check noticing
                 * (the peer stays up across a brief link bounce). Re-assert the
                 * tunnel as default so route-all traffic stays in the tunnel. */
                vpn_reassert_default_route();
            }
        }
    }
}
