/* Port mapping (NAPT) table management with NVS persistence.
 *
 * Manages the portmap_tab[] array, persists it to NVS, and applies
 * entries to the lwIP NAT engine via ip_portmap_add/remove.
 */

#include <string.h>
#include "esp_log.h"
#include "nvs.h"
#include "lwip/lwip_napt.h"
#include "lwip/ip4_addr.h"
#include "esp_netif.h"
#include "router_config.h"
#include "portmap.h"
#include "pppoe_config.h"
#include "dhcp_reservations.h"
#include "wifi_config.h"

#define PORTMAP_TAB_SIZE (sizeof(struct portmap_table_entry) * IP_PORTMAP_MAX)

static const char *TAG = "portmap";

esp_err_t apply_portmap_tab() {
    uint32_t bind_ip = pppoe_enabled ? pppoe_ip : my_ip;
    if (bind_ip == 0) return ESP_OK;  // Uplink not yet connected
    for (int i = 0; i<IP_PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid) {
            ip_portmap_add(portmap_tab[i].proto, bind_ip, portmap_tab[i].mport, portmap_tab[i].daddr, portmap_tab[i].dport);
        }
    }
    return ESP_OK;
}

esp_err_t delete_portmap_tab() {
    for (int i = 0; i<IP_PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid) {
            ip_portmap_remove(portmap_tab[i].proto, portmap_tab[i].mport);
        }
    }
    return ESP_OK;
}

void print_portmap_tab() {
    for (int i = 0; i<IP_PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid) {
            printf ("%s ", portmap_tab[i].proto == PROTO_TCP?"TCP":"UDP");
            ip4_addr_t addr;
            addr.addr = pppoe_enabled ? pppoe_ip : my_ip;
            printf (IPSTR":%d -> ", IP2STR(&addr), portmap_tab[i].mport);

            /* Try to look up device name for destination IP */
            const char *name = lookup_device_name_by_ip(portmap_tab[i].daddr);
            if (name) {
                printf ("%s:%d\n", name, portmap_tab[i].dport);
            } else {
                addr.addr = portmap_tab[i].daddr;
                printf (IPSTR":%d\n", IP2STR(&addr), portmap_tab[i].dport);
            }
        }
    }
}

esp_err_t get_portmap_tab() {
    esp_err_t err;
    nvs_handle_t nvs;
    size_t len;

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_get_blob(nvs, "portmap_tab", NULL, &len);
    if (err == ESP_OK) {
        if (len != PORTMAP_TAB_SIZE) {
            err = ESP_ERR_NVS_INVALID_LENGTH;
        } else {
            err = nvs_get_blob(nvs, "portmap_tab", portmap_tab, &len);
            if (err != ESP_OK) {
                memset(portmap_tab, 0, PORTMAP_TAB_SIZE);
            }
        }
    }
    nvs_close(nvs);

    return err;
}

esp_err_t add_portmap(u8_t proto, u16_t mport, u32_t daddr, u16_t dport) {
    for (int i = 0; i<IP_PORTMAP_MAX; i++) {
        if (!portmap_tab[i].valid) {
            portmap_tab[i].proto = proto;
            portmap_tab[i].mport = mport;
            portmap_tab[i].daddr = daddr;
            portmap_tab[i].dport = dport;
            portmap_tab[i].valid = 1;
            portmap_tab[i].iface = 0;

            esp_err_t err = set_config_param_blob("portmap_tab", portmap_tab, PORTMAP_TAB_SIZE);
            if (err == ESP_OK) {
                ESP_LOGI(TAG, "New portmap table stored.");
            }

            uint32_t bind_ip = pppoe_enabled ? pppoe_ip : my_ip;
            if (bind_ip != 0) {
                ip_portmap_add(proto, bind_ip, mport, daddr, dport);
            }

            return err;
        }
    }
    return ESP_ERR_NO_MEM;
}

esp_err_t del_portmap(u8_t proto, u16_t mport) {
    for (int i = 0; i<IP_PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid && portmap_tab[i].mport == mport && portmap_tab[i].proto == proto) {
            portmap_tab[i].valid = 0;

            esp_err_t err = set_config_param_blob("portmap_tab", portmap_tab, PORTMAP_TAB_SIZE);
            if (err == ESP_OK) {
                ESP_LOGI(TAG, "New portmap table stored.");
            }

            ip_portmap_remove(proto, mport);
            return err;
        }
    }
    return ESP_OK;
}

esp_err_t clear_all_portmaps() {
    // Clear all portmap entries from NAPT
    for (int i = 0; i < IP_PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid) {
            ip_portmap_remove(portmap_tab[i].proto, portmap_tab[i].mport);
            portmap_tab[i].valid = 0;
        }
    }

    // Save cleared table to NVS
    esp_err_t err = set_config_param_blob("portmap_tab", portmap_tab, PORTMAP_TAB_SIZE);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "All port mappings cleared.");
    }
    return err;
}
