/* ESP32 NAT Router - Main application
 *
 * Entry point, global variable definitions, WiFi/Ethernet initialization,
 * event handlers, LED status thread, and console REPL.
 *
 * Modular source files:
 *   portmap.c       - Port mapping (NAPT) table management
 *   dhcp_manager.c  - DHCP reservation management
 *   acl_nvs.c       - ACL firewall rule persistence
 *   pppoe_manager.c  - PPPoE DSL uplink management
 *   netif_hooks.c   - Network interface hooks (byte counting, ACL, PCAP, MSS/PMTU)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_console.h"
#include "esp_vfs_dev.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "driver/uart_vfs.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "linenoise/linenoise.h"
#include "argtable3/argtable3.h"
#include "esp_vfs_fat.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_ota_ops.h"

#include "freertos/event_groups.h"
#include "esp_wifi.h"
#if !CONFIG_ETH_UPLINK
#include "esp_eap_client.h"
#endif
#if CONFIG_ETH_UPLINK
#include "esp_eth.h"
#include "esp_mac.h"
#if defined(CONFIG_ETH_DRIVER_W5500)
#include "driver/spi_master.h"
#include "esp_eth_mac_spi.h"
#include "w5500_spi_driver.h"
#include "esp_heap_caps.h"
#else
/* ESP32 internal EMAC API (eth_esp32_emac_config_t, esp_eth_mac_new_esp32).
 * Since ESP-IDF v5.4 the chip-specific MAC types moved out of esp_eth.h into
 * their own header; its contents are guarded by CONFIG_ETH_USE_ESP32_EMAC so
 * it is harmless to include on targets without an internal EMAC. */
#include "esp_eth_mac_esp.h"
#endif
#endif

#include "lwip/opt.h"
#include "lwip/err.h"
#include "lwip/sys.h"

#include "dhcpserver/dhcpserver.h"
#include "dhcpserver/dhcpserver_options.h"

#include "cmd_system.h"
#include "cmd_router.h"
#include <esp_http_server.h>

#if !IP_NAPT
#error "IP_NAPT must be defined"
#endif
#include "lwip/lwip_napt.h"

#include "router_globals.h"
#include "lwip/ip_addr.h"
#include "esp_netif.h"
#include "client_stats.h"
#include "pcap_capture.h"
#include "remote_console.h"
#include "syslog_client.h"
#include "vpn_config.h"
#include "mdns.h"
#if CONFIG_MQTT_HOMEASSISTANT
#include "mqtt_ha.h"
#endif
#include "ddns.h"

// Byte counting variables
uint64_t sta_bytes_sent = 0;
uint64_t sta_bytes_received = 0;

// TTL override for STA upstream (0 = disabled/no change)
uint8_t sta_ttl_override = 0;

// MSS clamp for AP interface (0 = disabled, otherwise max MSS in bytes)
uint16_t ap_mss_clamp = 0;

// Path MTU for AP clients: send ICMP Fragmentation Needed when a DF-flagged packet
// from a client exceeds this size (0 = disabled).
uint16_t ap_pmtu = 0;

// AP SSID hidden (0 = visible, 1 = hidden)
uint8_t ap_ssid_hidden = 0;

// AP auth mode (0 = WPA2/WPA3, 1 = WPA2 only, 2 = WPA3 only)
uint8_t ap_authmode = 0;

// WiFi regulatory country code ("01" = world-safe default)
char wifi_country_code[3] = "01";

#if CONFIG_ETH_UPLINK
// AP WiFi channel (0 = auto, 1-13 = fixed channel; ETH_UPLINK only)
uint8_t ap_channel = 0;
#endif

#if !CONFIG_ETH_UPLINK
// WPA2-Enterprise settings
int32_t eap_method = 0;          // 0=Auto, 1=PEAP, 2=TTLS, 3=TLS
int32_t ttls_phase2 = 0;         // 0=MSCHAPv2, 1=MSCHAP, 2=PAP, 3=CHAP
int32_t use_cert_bundle = 0;     // 0=off, 1=on
int32_t disable_time_check = 0;  // 0=off, 1=on
#endif

#if WIFI_HAS_5GHZ
// STA band preference (0=auto, 1=2.4GHz, 2=5GHz)
uint8_t sta_band = STA_BAND_AUTO;
#endif

// WireGuard VPN settings
int32_t vpn_enabled = 0;
int32_t vpn_port = 51820;
int32_t vpn_keepalive = 0;
char* vpn_private_key = NULL;
char* vpn_public_key = NULL;
char* vpn_preshared_key = NULL;
char* vpn_endpoint = NULL;
char* vpn_address = NULL;
char* vpn_netmask = NULL;
char* vpn_dns = NULL;
bool vpn_connected = false;
uint32_t vpn_tunnel_ip = 0;
int32_t vpn_killswitch = 1;
int32_t vpn_route_all = 1;

// PPPoE DSL uplink settings
int32_t pppoe_enabled = 0;
char* pppoe_user = NULL;
char* pppoe_pass = NULL;
char* pppoe_service = NULL;
int32_t pppoe_auth = 0;
int32_t pppoe_vlan = 0;
bool pppoe_babyjumbo = true;
bool pppoe_connected = false;
uint32_t pppoe_ip = 0;

/* FreeRTOS event group to signal when we are connected*/
EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about one event
 * - are we connected to the AP with an IP? */
const int WIFI_CONNECTED_BIT = BIT0;

/* Effective DNS for AP clients: VPN DNS (while VPN enabled) overrides the
 * manual ap_dns override, which in turn overrides the upstream-supplied DNS.
 * Returns NULL when neither override is set so callers fall back to upstream. */
const char* effective_ap_dns(void)
{
    if (vpn_enabled && vpn_dns && vpn_dns[0]) return vpn_dns;
    if (ap_dns && ap_dns[0]) return ap_dns;
    return NULL;
}

#if !CONFIG_ETH_UPLINK
/* STA reconnect backoff */
#define STA_RECONNECT_INITIAL_MS  250
#define STA_RECONNECT_MAX_MS     16000
static esp_timer_handle_t sta_reconnect_timer;
static uint32_t sta_reconnect_delay_ms = STA_RECONNECT_INITIAL_MS;
#endif

/* Global vars */
uint16_t connect_count = 0;
bool ap_connect = false;
bool wifi_scan_active = false;
#if CONFIG_ETH_UPLINK
bool eth_link_up = false;
#endif
bool has_static_ip = false;
int led_gpio = -1;  // -1 means LED disabled (none)
uint8_t led_lowactive = 0;  // 0 = active-high (default), 1 = active-low (inverted)
uint8_t led_toggle = 0;  // Shared toggle state for packet-driven LED flicker

uint32_t my_ip;
uint32_t my_ap_ip;

struct portmap_table_entry portmap_tab[IP_PORTMAP_MAX];
struct dhcp_reservation_entry dhcp_reservations[MAX_DHCP_RESERVATIONS];

esp_netif_t* wifiAP;
bool ap_disabled = false;
uint8_t ap_nat_enabled = 1;
#if CONFIG_ETH_UPLINK
esp_netif_t* ethNetif = NULL;
esp_eth_handle_t eth_handle = NULL;
#else
esp_netif_t* wifiSTA;
#endif

#include "http_server.h"

static const char *TAG = "ESP32 NAT router";

/* Console command history can be stored to and loaded from a file.
 * The easiest way to do this is to use FATFS filesystem on top of
 * wear_levelling library.
 */
#if CONFIG_STORE_HISTORY

#define MOUNT_PATH "/data"
#define HISTORY_PATH MOUNT_PATH "/history.txt"

static void initialize_filesystem(void)
{
    static wl_handle_t wl_handle;
    const esp_vfs_fat_mount_config_t mount_config = {
            .max_files = 4,
            .format_if_mount_failed = true
    };
    esp_err_t err = esp_vfs_fat_spiflash_mount_rw_wl(MOUNT_PATH, "storage", &mount_config, &wl_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount FATFS (%s)", esp_err_to_name(err));
        return;
    }
}
#endif // CONFIG_STORE_HISTORY

static void initialize_nvs(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK( nvs_flash_erase() );
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
}

static void initialize_console(void)
{
    /* Disable buffering on stdin */
    setvbuf(stdin, NULL, _IONBF, 0);

#if CONFIG_ESP_CONSOLE_UART_DEFAULT || CONFIG_ESP_CONSOLE_UART_CUSTOM
    /* Drain stdout before reconfiguring it */
    fflush(stdout);
    fsync(fileno(stdout));

    /* Minicom, screen, idf_monitor send CR when ENTER key is pressed */
    uart_vfs_dev_port_set_rx_line_endings(0, ESP_LINE_ENDINGS_CR);
    /* Move the caret to the beginning of the next line on '\n' */
    uart_vfs_dev_port_set_tx_line_endings(0, ESP_LINE_ENDINGS_CRLF);

    /* Configure UART. Note that REF_TICK is used so that the baud rate remains
     * correct while APB frequency is changing in light sleep mode.
     */
    const uart_config_t uart_config = {
            .baud_rate = CONFIG_ESP_CONSOLE_UART_BAUDRATE,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .source_clk = UART_SCLK_DEFAULT,
    };
    /* Install UART driver for interrupt-driven reads and writes */
    ESP_ERROR_CHECK( uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM,
            256, 0, 0, NULL, 0) );
    ESP_ERROR_CHECK( uart_param_config(CONFIG_ESP_CONSOLE_UART_NUM, &uart_config) );

    /* Tell VFS to use UART driver */
    uart_vfs_dev_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);
#endif

#if CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
    /* Enable non-blocking mode on stdin and stdout */
    fcntl(fileno(stdout), F_SETFL, O_NONBLOCK);
    fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);

    /* Minicom, screen, idf_monitor send CR when ENTER key is pressed */
    usb_serial_jtag_vfs_set_rx_line_endings(ESP_LINE_ENDINGS_CR);

    /* Move the caret to the beginning of the next line on '\n' */
    usb_serial_jtag_vfs_set_tx_line_endings(ESP_LINE_ENDINGS_CRLF);
    usb_serial_jtag_driver_config_t usb_serial_jtag_config = {
        .tx_buffer_size = 256,
        .rx_buffer_size = 256,
    };

    /* Install USB-SERIAL-JTAG driver for interrupt-driven reads and writes */
    usb_serial_jtag_driver_install(&usb_serial_jtag_config);

    /* Tell vfs to use usb-serial-jtag driver */
    usb_serial_jtag_vfs_use_driver();
#endif

    /* Initialize the console */
    esp_console_config_t console_config = {
            .max_cmdline_args = 12,
            .max_cmdline_length = 256,
#if CONFIG_LOG_COLORS
            .hint_color = atoi(LOG_COLOR_CYAN)
#endif
    };
    ESP_ERROR_CHECK( esp_console_init(&console_config) );

    /* Configure linenoise line completion library */
    /* Enable multiline editing. If not set, long commands will scroll within
     * single line.
     */
    linenoiseSetMultiLine(1);

    /* Tell linenoise where to get command completions and hints */
    linenoiseSetCompletionCallback(&esp_console_get_completion);
    linenoiseSetHintsCallback((linenoiseHintsCallback*) &esp_console_get_hint);

    /* Set command history size */
    linenoiseHistorySetMaxLen(100);

#if CONFIG_STORE_HISTORY
    /* Load command history from filesystem */
    linenoiseHistoryLoad(HISTORY_PATH);
#endif
}

// BOOT button GPIO: GPIO28 on ESP32-C5 board, GPIO9 on C3/C2/C6, GPIO0 on ESP32/S2/S3
#if defined(CONFIG_IDF_TARGET_ESP32C5)
#define BOOT_BUTTON_GPIO      28
#elif defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C2) || defined(CONFIG_IDF_TARGET_ESP32C6)
#define BOOT_BUTTON_GPIO      9
#else
#define BOOT_BUTTON_GPIO      0
#endif
#define FACTORY_RESET_HOLD_MS 5000
#define POLL_INTERVAL_MS      50

void * led_status_thread(void * p)
{
#if !CONFIG_ETH_UPLINK
    // Init boot button for factory reset detection (GPIO0 used by ETH clock on WT32-ETH01)
    gpio_reset_pin(BOOT_BUTTON_GPIO);
    gpio_set_direction(BOOT_BUTTON_GPIO, GPIO_MODE_INPUT);
    gpio_set_pull_mode(BOOT_BUTTON_GPIO, GPIO_PULLUP_ONLY);
#endif

    bool led_enabled = (led_gpio >= 0);
    if (led_enabled) {
        ESP_LOGI(TAG, "LED status on GPIO %d%s", led_gpio, led_lowactive ? " (low-active)" : "");
        gpio_reset_pin(led_gpio);
        gpio_set_direction(led_gpio, GPIO_MODE_OUTPUT);
    } else {
        ESP_LOGI(TAG, "LED status disabled (no GPIO configured)");
    }

    int held_ms = 0;

    while (true)
    {
        // --- LED status: OFF=disconnected, ON=connected (packet hooks flicker it off) ---
        if (led_enabled && held_ms == 0) {
            gpio_set_level(led_gpio, ap_connect ^ led_lowactive);
        }

        // --- Poll interval with button polling ---
        for (int t = 0; t < 1000 / POLL_INTERVAL_MS; t++) {
            vTaskDelay(pdMS_TO_TICKS(POLL_INTERVAL_MS));

#if !CONFIG_ETH_UPLINK
            if (gpio_get_level(BOOT_BUTTON_GPIO) == 0) {
                held_ms += POLL_INTERVAL_MS;
                // Rapid LED toggle for visual feedback during hold
                if (led_enabled) {
                    gpio_set_level(led_gpio, ((held_ms / POLL_INTERVAL_MS) % 2) ^ led_lowactive);
                }
                if (held_ms >= FACTORY_RESET_HOLD_MS) {
                    ESP_LOGW(TAG, "BOOT button held %d ms - factory reset!", held_ms);
                    nvs_handle_t nvs;
                    if (nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK) {
                        nvs_erase_all(nvs);
                        nvs_commit(nvs);
                        nvs_close(nvs);
                    }
                    esp_wifi_restore();
                    esp_restart();
                }
            } else {
                held_ms = 0;
            }
#endif
        }
    }
}

/* Event handlers */

#if CONFIG_ETH_UPLINK
static void eth_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    if (event_base == ETH_EVENT) {
        if (event_id == ETHERNET_EVENT_CONNECTED) {
            ESP_LOGI(TAG, "Ethernet link up");
            eth_link_up = true;
            if (pppoe_enabled) {
                extern struct netif *esp_netif_get_netif_impl(esp_netif_t *esp_netif);
                struct netif *lwip_nif = esp_netif_get_netif_impl(ethNetif);
                if (lwip_nif) {
                    pppoe_start(lwip_nif);
                } else {
                    ESP_LOGE(TAG, "Ethernet link up but lwip netif is NULL — PPPoE not started");
                }
            }
        } else if (event_id == ETHERNET_EVENT_DISCONNECTED) {
            ESP_LOGI(TAG, "Ethernet link down");
            eth_link_up = false;
            if (pppoe_enabled) {
                pppoe_stop();
            }
            ap_connect = false;
            xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        } else if (event_id == ETHERNET_EVENT_START) {
            ESP_LOGI(TAG, "Ethernet started");
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_ETH_GOT_IP) {
        /* When PPPoE is active, IP comes via IPCP (handled in ppp_link_status_cb),
         * not via this event. Skip to avoid duplicate init. */
        if (!pppoe_enabled) {
            ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
            ESP_LOGI(TAG, "ETH got ip:" IPSTR, IP2STR(&event->ip_info.ip));
            ap_connect = true;
            my_ip = event->ip_info.ip.addr;
            delete_portmap_tab();
            apply_portmap_tab();

            // Copy DNS from ETH to AP (or use the effective override: VPN DNS / ap_dns)
            esp_netif_dns_info_t dns;
            const char *eff_dns = effective_ap_dns();
            if (eff_dns) {
                dns.ip.u_addr.ip4.addr = esp_ip4addr_aton(eff_dns);
                dns.ip.type = ESP_IPADDR_TYPE_V4;
                esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dns);
                ESP_LOGI(TAG, "AP DNS set to %s", eff_dns);
            } else if (esp_netif_get_dns_info(ethNetif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK) {
                esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dns);
                ESP_LOGI(TAG, "set dns to:" IPSTR, IP2STR(&(dns.ip.u_addr.ip4)));
            }

            init_byte_counter();
            init_sntp_if_needed();
            syslog_notify_connected();
#if defined(CONFIG_DDNS_ENABLED) && CONFIG_DDNS_ENABLED
            {
                extern void ddns_update_wan_ip(uint32_t wan_ip);
                ddns_update_wan_ip(event->ip_info.ip.addr);
            }
#endif
            xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        }
    }
}

static void wifi_ap_event_handler(void* arg, esp_event_base_t event_base,
                                   int32_t event_id, void* event_data)
{
    if (event_id == WIFI_EVENT_AP_START) {
        ESP_LOGI(TAG, "AP started");
        init_ap_netif_hooks();
    } else if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;

        /* Check if this MAC is blacklisted (reservation with IP 0.0.0.0) */
        if (is_mac_blocked(event->mac)) {
            const char* name = lookup_device_name_by_mac(event->mac);
            ESP_LOGW(TAG, "Blocked client: %02X:%02X:%02X:%02X:%02X:%02X%s%s",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     name ? " (" : "", name ? name : "");
            esp_wifi_deauth_sta(event->aid);
            return;
        }

        connect_count++;
        client_stats_on_connect(event->mac);
        const char* name = lookup_device_name_by_mac(event->mac);
        if (name) {
            ESP_LOGI(TAG, "Client connected: %02X:%02X:%02X:%02X:%02X:%02X (%s) - %d total",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     name, connect_count);
        } else {
            ESP_LOGI(TAG, "Client connected: %02X:%02X:%02X:%02X:%02X:%02X - %d total",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     connect_count);
        }
    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        connect_count--;
        client_stats_on_disconnect(event->mac);
        const char* name = lookup_device_name_by_mac(event->mac);
        if (name) {
            ESP_LOGI(TAG, "Client disconnected: %02X:%02X:%02X:%02X:%02X:%02X (%s) - %d remain",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     name, connect_count);
        } else {
            ESP_LOGI(TAG, "Client disconnected: %02X:%02X:%02X:%02X:%02X:%02X - %d remain",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     connect_count);
        }
    }
}
#else

#if WIFI_HAS_5GHZ
/**
 * Band-aware STA connection helper.
 *
 * When a band preference is configured (sta_band == STA_BAND_2G or STA_BAND_5G),
 * this function scans for the configured SSID, selects the best BSSID on the
 * preferred band, and sets it in the STA config before connecting.
 * Falls back to the other band if the preferred one is unavailable.
 *
 * When sta_band == STA_BAND_AUTO (or on non-5GHz chips) this just calls
 * esp_wifi_connect() directly.
 */
static void wifi_connect_band_aware(void)
{
    if (sta_band == STA_BAND_AUTO || ssid == NULL || ssid[0] == '\0') {
        esp_wifi_connect();
        return;
    }

    /* Targeted scan for our SSID only */
    wifi_scan_config_t scan_cfg = {
        .ssid = (uint8_t *)ssid,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
    };

    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true);  /* blocking */
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Band-aware scan failed (%s), falling back", esp_err_to_name(err));
        esp_wifi_connect();
        return;
    }

    uint16_t ap_count = 0;
    esp_wifi_scan_get_ap_num(&ap_count);
    if (ap_count == 0) {
        ESP_LOGI(TAG, "No APs found for SSID '%s', connecting normally", ssid);
        esp_wifi_connect();
        return;
    }

    wifi_ap_record_t *ap_list = malloc(sizeof(wifi_ap_record_t) * ap_count);
    if (ap_list == NULL) {
        esp_wifi_connect();
        return;
    }
    esp_wifi_scan_get_ap_records(&ap_count, ap_list);

    /* Find best BSSID on preferred band, and best on any band as fallback */
    int best_preferred = -1;
    int best_fallback = -1;
    for (int i = 0; i < ap_count; i++) {
        bool is_5g = (ap_list[i].primary > 14);
        bool matches_pref = (sta_band == STA_BAND_5G) ? is_5g : !is_5g;

        if (matches_pref) {
            if (best_preferred < 0 || ap_list[i].rssi > ap_list[best_preferred].rssi)
                best_preferred = i;
        } else {
            if (best_fallback < 0 || ap_list[i].rssi > ap_list[best_fallback].rssi)
                best_fallback = i;
        }
    }

    int chosen = (best_preferred >= 0) ? best_preferred : best_fallback;
    if (chosen < 0) {
        free(ap_list);
        esp_wifi_connect();
        return;
    }

    if (best_preferred < 0) {
        ESP_LOGW(TAG, "Preferred band (%s) unavailable, falling back to %s",
                 (sta_band == STA_BAND_5G) ? "5 GHz" : "2.4 GHz",
                 (sta_band == STA_BAND_5G) ? "2.4 GHz" : "5 GHz");
    }

    ESP_LOGI(TAG, "Connecting to BSSID %02X:%02X:%02X:%02X:%02X:%02X (ch %d, %s, %d dBm)",
             ap_list[chosen].bssid[0], ap_list[chosen].bssid[1],
             ap_list[chosen].bssid[2], ap_list[chosen].bssid[3],
             ap_list[chosen].bssid[4], ap_list[chosen].bssid[5],
             ap_list[chosen].primary,
             ap_list[chosen].primary > 14 ? "5 GHz" : "2.4 GHz",
             ap_list[chosen].rssi);

    /* Update STA config with the chosen BSSID */
    wifi_config_t sta_cfg;
    esp_wifi_get_config(WIFI_IF_STA, &sta_cfg);
    memcpy(sta_cfg.sta.bssid, ap_list[chosen].bssid, 6);
    sta_cfg.sta.bssid_set = true;
    sta_cfg.sta.channel = ap_list[chosen].primary;
    esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);

    free(ap_list);
    esp_wifi_connect();
}
#endif /* WIFI_HAS_5GHZ */

static inline void sta_connect(void)
{
#if WIFI_HAS_5GHZ
    wifi_connect_band_aware();
#else
    esp_wifi_connect();
#endif
}

static void sta_reconnect_timer_cb(void* arg)
{
    ESP_LOGI(TAG, "reconnect backoff expired (%"PRIu32" ms), attempting STA connect", sta_reconnect_delay_ms);
    sta_connect();
    /* Double the delay for next time, capped at max */
    if (sta_reconnect_delay_ms < STA_RECONNECT_MAX_MS) {
        sta_reconnect_delay_ms *= 2;
        if (sta_reconnect_delay_ms > STA_RECONNECT_MAX_MS) {
            sta_reconnect_delay_ms = STA_RECONNECT_MAX_MS;
        }
    }
}

static void sta_schedule_reconnect(void)
{
    /* Stop any pending reconnect timer before starting a new one */
    esp_timer_stop(sta_reconnect_timer);
    ESP_LOGI(TAG, "scheduling STA reconnect in %"PRIu32" ms", sta_reconnect_delay_ms);
    esp_timer_start_once(sta_reconnect_timer, (uint64_t)sta_reconnect_delay_ms * 1000);
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    esp_netif_dns_info_t dns;

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        sta_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        ESP_LOGI(TAG,"disconnected - retry to connect to the AP");
        ap_connect = false;
        if (wifi_scan_active) {
            ESP_LOGI(TAG, "scan in progress - deferring reconnect");
        } else {
            sta_schedule_reconnect();
        }
        xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_SCAN_DONE)
    {
        if (wifi_scan_active) {
            /* Just clear the flag — don't reconnect here.
             * Reconnection is handled by the caller (CLI after reading results,
             * or the disconnect handler once wifi_scan_active is cleared). */
            wifi_scan_active = false;
            ESP_LOGI(TAG, "scan complete");
        }
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        /* Reset backoff on successful connection */
        sta_reconnect_delay_ms = STA_RECONNECT_INITIAL_MS;
        esp_timer_stop(sta_reconnect_timer);
        ap_connect = true;
        my_ip = event->ip_info.ip.addr;
        delete_portmap_tab();
        apply_portmap_tab();
        const char *eff_dns = effective_ap_dns();
        if (eff_dns) {
            dns.ip.u_addr.ip4.addr = esp_ip4addr_aton(eff_dns);
            dns.ip.type = ESP_IPADDR_TYPE_V4;
            esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dns);
            ESP_LOGI(TAG, "AP DNS set to %s", eff_dns);
        } else if (esp_netif_get_dns_info(wifiSTA, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK) {
            esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dns);
            ESP_LOGI(TAG, "set dns to:" IPSTR, IP2STR(&(dns.ip.u_addr.ip4)));
        }

        // Initialize byte counter after getting IP (interface is ready)
        init_byte_counter();

        // Start SNTP time synchronization
        init_sntp_if_needed();

        // Re-resolve syslog server now that network is up
        syslog_notify_connected();
#if defined(CONFIG_DDNS_ENABLED) && CONFIG_DDNS_ENABLED
        {
            extern void ddns_update_wan_ip(uint32_t wan_ip);
            ddns_update_wan_ip(event->ip_info.ip.addr);
        }
#endif
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_START)
    {
        ESP_LOGI(TAG, "AP started");
        // Initialize AP netif hooks now that interface is ready
        init_ap_netif_hooks();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED)
    {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;

        /* Check if this MAC is blacklisted (reservation with IP 0.0.0.0) */
        if (is_mac_blocked(event->mac)) {
            const char* name = lookup_device_name_by_mac(event->mac);
            ESP_LOGW(TAG, "Blocked client: %02X:%02X:%02X:%02X:%02X:%02X%s%s",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     name ? " (" : "", name ? name : "");
            esp_wifi_deauth_sta(event->aid);
            return;
        }

        connect_count++;
        client_stats_on_connect(event->mac);

        /* Look up device name from DHCP reservations */
        const char* name = lookup_device_name_by_mac(event->mac);
        if (name) {
            ESP_LOGI(TAG, "Client connected: %02X:%02X:%02X:%02X:%02X:%02X (%s) - %d total",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     name, connect_count);
        } else {
            ESP_LOGI(TAG, "Client connected: %02X:%02X:%02X:%02X:%02X:%02X - %d total",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     connect_count);
        }
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED)
    {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        connect_count--;
        client_stats_on_disconnect(event->mac);

        /* Look up device name from DHCP reservations */
        const char* name = lookup_device_name_by_mac(event->mac);
        if (name) {
            ESP_LOGI(TAG, "Client disconnected: %02X:%02X:%02X:%02X:%02X:%02X (%s) - %d remain",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     name, connect_count);
        } else {
            ESP_LOGI(TAG, "Client disconnected: %02X:%02X:%02X:%02X:%02X:%02X - %d remain",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     connect_count);
        }
    }
}
#endif

const int CONNECTED_BIT = BIT0;
#define JOIN_TIMEOUT_MS (2000)

void ap_set_enabled(bool enabled)
{
#if CONFIG_ETH_UPLINK
    if (enabled) {
        esp_wifi_start();
        if (ap_nat_enabled) ip_napt_enable(my_ap_ip, 1);
    } else {
        connect_count = 0;
        esp_wifi_stop();
    }
#else
    if (enabled) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        if (ap_nat_enabled) ip_napt_enable(my_ap_ip, 1);
    } else {
        connect_count = 0;
        esp_wifi_set_mode(WIFI_MODE_STA);
    }
#endif
    ap_disabled = !enabled;
    set_config_param_int("ap_disabled", ap_disabled ? 1 : 0);
    ESP_LOGI(TAG, "AP interface %s", enabled ? "enabled" : "disabled");
}

static wifi_auth_mode_t get_ap_authmode(void)
{
    switch (ap_authmode) {
        case 1: return WIFI_AUTH_WPA2_PSK;
        case 2: return WIFI_AUTH_WPA3_PSK;
        default: return WIFI_AUTH_WPA2_WPA3_PSK;
    }
}

#if CONFIG_ETH_UPLINK
void eth_init(const char* static_ip, const char* subnet_mask, const char* gateway_addr,
              const uint8_t* ap_mac, const char* ap_ssid, const char* ap_passwd, const char* ap_ip)
{
    esp_netif_dns_info_t dnsserver;

    wifi_event_group = xEventGroupCreate();

    esp_netif_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // --- Ethernet uplink ---
#if defined(CONFIG_ETH_DRIVER_W5500)
    // W5500 SPI Ethernet (ESP32-C3 SuperMini)
    // GPIO ISR service required by the W5500 INT pin handler
    gpio_install_isr_service(0);

    spi_bus_config_t buscfg = {
        .miso_io_num   = CONFIG_ETH_SPI_MISO_GPIO,
        .mosi_io_num   = CONFIG_ETH_SPI_MOSI_GPIO,
        .sclk_io_num   = CONFIG_ETH_SPI_SCLK_GPIO,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(CONFIG_ETH_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO));

    spi_device_interface_config_t devcfg = {
        .command_bits  = 16,  // W5500 SPI frame: 16-bit offset address
        .address_bits  = 8,   // W5500 SPI frame: 8-bit control byte
        .mode          = 0,
        .spics_io_num  = CONFIG_ETH_SPI_CS_GPIO,
        .queue_size    = 4,
    };

    int spi_mhz = CONFIG_ETH_SPI_CLOCK_MHZ;
    get_config_param_int("spi_clk_mhz", &spi_mhz);
    if (spi_mhz < 1 || spi_mhz > 80) spi_mhz = CONFIG_ETH_SPI_CLOCK_MHZ;
    devcfg.clock_speed_hz = spi_mhz * 1000 * 1000;

    ESP_LOGI(TAG, "Initializing W5500 SPI driver with %d MHz.", spi_mhz);

    eth_w5500_config_t w5500_config = ETH_W5500_DEFAULT_CONFIG(CONFIG_ETH_SPI_HOST, &devcfg);
    w5500_config.int_gpio_num = CONFIG_ETH_SPI_INT_GPIO;
    w5500_spi_driver_config(&w5500_config.custom_spi_driver, &w5500_config);

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    mac_config.rx_task_prio = 19;
    esp_eth_mac_t *mac = esp_eth_mac_new_w5500(&w5500_config, &mac_config);

    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.reset_gpio_num = CONFIG_ETH_SPI_RST_GPIO;
    esp_eth_phy_t *phy = esp_eth_phy_new_w5500(&phy_config);

#else
    // Power on LAN8720 PHY via GPIO16 before EMAC init (WT32-ETH01)
#if CONFIG_ETH_PHY_POWER_GPIO >= 0
    gpio_config_t phy_power_cfg = {
        .pin_bit_mask = (1ULL << CONFIG_ETH_PHY_POWER_GPIO),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&phy_power_cfg);
    gpio_set_level(CONFIG_ETH_PHY_POWER_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(20));  // Let PHY power stabilize
#endif

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t emac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    emac_config.smi_gpio.mdc_num = CONFIG_ETH_MDC_GPIO;
    emac_config.smi_gpio.mdio_num = CONFIG_ETH_MDIO_GPIO;
    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&emac_config, &mac_config);

    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = CONFIG_ETH_PHY_ADDR;
    // phy_config.reset_gpio_num = CONFIG_ETH_PHY_POWER_GPIO;
    phy_config.reset_gpio_num = -1;  // Don't use PHY reset - we handle power via GPIO above
    esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_config);
#endif  // CONFIG_ETH_DRIVER_W5500

    esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_ERROR_CHECK(esp_eth_driver_install(&config, &eth_handle));

#if defined(CONFIG_ETH_DRIVER_W5500)
    // W5500 modules often lack a factory MAC — derive one from the chip's base MAC
    {
        uint8_t eth_mac_addr[6];
        ESP_ERROR_CHECK(esp_read_mac(eth_mac_addr, ESP_MAC_ETH));
        ESP_ERROR_CHECK(esp_eth_ioctl(eth_handle, ETH_CMD_S_MAC_ADDR, eth_mac_addr));
    }
#endif

    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    ethNetif = esp_netif_new(&netif_cfg);
    esp_netif_attach(ethNetif, esp_eth_new_netif_glue(eth_handle));

    // Set DHCP client hostname (Option 12)
    esp_netif_set_hostname(ethNetif, hostname);

    // PPPoE mode: Ethernet is a frame transport only — no DHCP, no static IP.
    // A non-zero placeholder IP is required to suppress esp_netif's
    // "invalid static ip" error when the link comes up with DHCP stopped
    // and ip==0.0.0.0.  The PPP netif becomes the default route anyway.
    if (pppoe_enabled) {
        esp_netif_dhcpc_stop(ethNetif);
        esp_netif_ip_info_t placeholder = {};
        placeholder.ip.addr      = esp_ip4addr_aton("169.254.0.1");
        placeholder.netmask.addr = esp_ip4addr_aton("255.255.255.255");
        esp_netif_set_ip_info(ethNetif, &placeholder);
        ESP_LOGI(TAG, "PPPoE mode: DHCP disabled on Ethernet interface");
    }

    // Static IP on ETH if configured (skip when PPPoE is active)
    if (!pppoe_enabled && strlen(static_ip) > 0 && strlen(subnet_mask) > 0 && strlen(gateway_addr) > 0) {
        has_static_ip = true;
        esp_netif_ip_info_t ipInfo;
        ipInfo.ip.addr = esp_ip4addr_aton(static_ip);
        ipInfo.gw.addr = esp_ip4addr_aton(gateway_addr);
        ipInfo.netmask.addr = esp_ip4addr_aton(subnet_mask);
        esp_netif_dhcpc_stop(ethNetif);
        esp_netif_set_ip_info(ethNetif, &ipInfo);
        apply_portmap_tab();
    }

    // Register ETH events
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &eth_event_handler, NULL));

    // --- WiFi AP only ---
    wifiAP = esp_netif_create_default_wifi_ap();

    my_ap_ip = esp_ip4addr_aton(ap_ip);
    esp_netif_ip_info_t ipInfo_ap;
    ipInfo_ap.ip.addr = my_ap_ip;
    ipInfo_ap.gw.addr = my_ap_ip;
    esp_netif_set_ip4_addr(&ipInfo_ap.netmask, 255,255,255,0);
    esp_netif_dhcps_stop(wifiAP);
    esp_netif_set_ip_info(wifiAP, &ipInfo_ap);
    esp_netif_dhcps_start(wifiAP);

    // WiFi AP-only event handler
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_ap_event_handler, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t ap_config = {
        .ap = {
            .channel = ap_channel,
            .authmode = get_ap_authmode(),
            .ssid_hidden = ap_ssid_hidden,
            .max_connection = AP_MAX_CONNECTIONS,
            .beacon_interval = 100,
        }
    };
    strlcpy((char*)ap_config.ap.ssid, ap_ssid, sizeof(ap_config.ap.ssid));
    if (strlen(ap_passwd) < 8) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    } else {
        strlcpy((char*)ap_config.ap.password, ap_passwd, sizeof(ap_config.ap.password));
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &ap_config));
    if (ap_mac != NULL) {
        ESP_ERROR_CHECK(esp_wifi_set_mac(ESP_IF_WIFI_AP, ap_mac));
    }

    // Enable DNS (offer) for dhcp server
    dhcps_offer_t dhcps_dns_value = OFFER_DNS;
    esp_netif_dhcps_option(wifiAP, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &dhcps_dns_value, sizeof(dhcps_dns_value));

    // DNS server for DHCP clients.
    // Before PPPoE connects there is no upstream DNS, so point clients at the
    // router itself so the captive-portal DNS task can intercept all queries.
    // copy_dns_to_ap() will overwrite this with the ISP's DNS once PPPoE is up.
    const char *eff_dns = effective_ap_dns();
    const char *dns_src = eff_dns ? eff_dns : ap_ip;
    dnsserver.ip.u_addr.ip4.addr = esp_ip4addr_aton(dns_src);
    dnsserver.ip.type = ESP_IPADDR_TYPE_V4;
    esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dnsserver);

    if (!ap_disabled) {
#if defined(CONFIG_ETH_DRIVER_W5500)
        // Single-core C3: disable WiFi power saving to reduce TX latency
        esp_wifi_set_ps(WIFI_PS_NONE);
#endif
        ESP_ERROR_CHECK(esp_wifi_start());
    } else {
        ESP_LOGI(TAG, "AP interface disabled at boot");
    }
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));

    ESP_LOGI(TAG, "Ethernet-to-WiFi PPPoE Router initialized");
}
#else
void wifi_init(const uint8_t* mac, const char* ssid, const char* ent_username, const char* ent_identity, const char* passwd, const char* static_ip, const char* subnet_mask, const char* gateway_addr, const uint8_t* ap_mac, const char* ap_ssid, const char* ap_passwd, const char* ap_ip)
{
    esp_netif_dns_info_t dnsserver;
    // esp_netif_dns_info_t dnsinfo;

    wifi_event_group = xEventGroupCreate();

    esp_netif_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifiAP = esp_netif_create_default_wifi_ap();
    wifiSTA = esp_netif_create_default_wifi_sta();

    // Set DHCP client hostname (Option 12)
    esp_netif_set_hostname(wifiSTA, hostname);

    esp_netif_ip_info_t ipInfo_sta;
    if ((strlen(ssid) > 0) && (strlen(static_ip) > 0) && (strlen(subnet_mask) > 0) && (strlen(gateway_addr) > 0)) {
        has_static_ip = true;
        ipInfo_sta.ip.addr = esp_ip4addr_aton(static_ip);
        ipInfo_sta.gw.addr = esp_ip4addr_aton(gateway_addr);
        ipInfo_sta.netmask.addr = esp_ip4addr_aton(subnet_mask);
        esp_netif_dhcpc_stop(wifiSTA); // Don't run a DHCP client
        esp_netif_set_ip_info(wifiSTA, &ipInfo_sta);
        apply_portmap_tab();
    }

    my_ap_ip = esp_ip4addr_aton(ap_ip);

    esp_netif_ip_info_t ipInfo_ap;
    ipInfo_ap.ip.addr = my_ap_ip;
    ipInfo_ap.gw.addr = my_ap_ip;
    esp_netif_set_ip4_addr(&ipInfo_ap.netmask, 255,255,255,0);
    esp_netif_dhcps_stop(wifiAP); // stop before setting ip WifiAP
    esp_netif_set_ip_info(wifiAP, &ipInfo_ap);
    esp_netif_dhcps_start(wifiAP);

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    /* ESP WIFI CONFIG */
    wifi_config_t wifi_config = { 0 };
        wifi_config_t ap_config = {
        .ap = {
            .channel = 0,
            .authmode = get_ap_authmode(),
            .ssid_hidden = ap_ssid_hidden,
            .max_connection = AP_MAX_CONNECTIONS,
            .beacon_interval = 100,
        }
    };

    strlcpy((char*)ap_config.sta.ssid, ap_ssid, sizeof(ap_config.sta.ssid));
    if (strlen(ap_passwd) < 8) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    } else {
	    strlcpy((char*)ap_config.sta.password, ap_passwd, sizeof(ap_config.sta.password));
    }

    // Always use APSTA mode so WiFi scanning works even without an uplink configured
    ESP_ERROR_CHECK(esp_wifi_set_mode(ap_disabled ? WIFI_MODE_STA : WIFI_MODE_APSTA));

    if (strlen(ssid) > 0) {
        //Set SSID
        strlcpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
        //Set password
        if(strlen(ent_username) == 0) {
            ESP_LOGI(TAG, "STA regular connection");
            strlcpy((char*)wifi_config.sta.password, passwd, sizeof(wifi_config.sta.password));
        }
        ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
        if(strlen(ent_username) != 0) {
            ESP_LOGI(TAG, "STA enterprise connection");
            if(strlen(ent_identity) != 0) {
                esp_eap_client_set_identity((uint8_t *)ent_identity, strlen(ent_identity));
            } else {
                esp_eap_client_set_identity((uint8_t *)ent_username, strlen(ent_username));
            }
            esp_eap_client_set_username((uint8_t *)ent_username, strlen(ent_username));
            esp_eap_client_set_password((uint8_t *)passwd, strlen(passwd));

            // Set TTLS phase 2 method
            if (ttls_phase2 >= 0 && ttls_phase2 <= 3) {
                esp_eap_client_set_ttls_phase2_method(ttls_phase2);
            }

            // Use CA certificate bundle for server validation
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
            if (use_cert_bundle) {
                esp_eap_client_use_default_cert_bundle(true);
            }
#endif

            // Disable certificate time check
            if (disable_time_check) {
                esp_eap_client_set_disable_time_check(true);
            }

            esp_wifi_sta_enterprise_enable();
        }

        if (mac != NULL) {
            ESP_ERROR_CHECK(esp_wifi_set_mac(ESP_IF_WIFI_STA, mac));
        }
    }

    if (!ap_disabled) {
        ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &ap_config));
        if (ap_mac != NULL) {
            ESP_ERROR_CHECK(esp_wifi_set_mac(ESP_IF_WIFI_AP, ap_mac));
        }
    }


    // Enable DNS (offer) for dhcp server
    dhcps_offer_t dhcps_dns_value = OFFER_DNS;
    esp_netif_dhcps_option(wifiAP,ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &dhcps_dns_value, sizeof(dhcps_dns_value));

    // Set DNS server address for DHCP clients.
    // When no STA is configured, point clients at the AP itself so the
    // captive-portal DNS server can intercept all queries.
    if (strlen(ssid) > 0) {
        const char *eff_dns = effective_ap_dns();
        const char *dns_src = eff_dns ? eff_dns : "1.1.1.1";
        dnsserver.ip.u_addr.ip4.addr = esp_ip4addr_aton(dns_src);
    } else {
        dnsserver.ip.u_addr.ip4.addr = my_ap_ip;
    }
    dnsserver.ip.type = ESP_IPADDR_TYPE_V4;
    esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dnsserver);

    // esp_netif_get_dns_info(ESP_IF_WIFI_AP, ESP_NETIF_DNS_MAIN, &dnsinfo);
    // ESP_LOGI(TAG, "DNS IP:" IPSTR, IP2STR(&dnsinfo.ip.u_addr.ip4));

    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
        pdFALSE, pdTRUE, pdMS_TO_TICKS(JOIN_TIMEOUT_MS));
    ESP_ERROR_CHECK(esp_wifi_start());

    if (strlen(ssid) > 0) {
        ESP_LOGI(TAG, "wifi_init_apsta finished.");
        ESP_LOGI(TAG, "connect to ap SSID: %s ", ssid);
    } else {
        ESP_LOGI(TAG, "wifi_init_ap with default finished.");
    }
}
#endif

#if !CONFIG_ETH_UPLINK
uint8_t* mac = NULL;
char* ssid = NULL;
char* ent_username = NULL;
char* ent_identity = NULL;
char* passwd = NULL;
#endif
char* static_ip = NULL;
char* subnet_mask = NULL;
char* gateway_addr = NULL;
uint8_t* ap_mac = NULL;
char* ap_ssid = NULL;
char* ap_passwd = NULL;
char* ap_ip = NULL;
char* ap_dns = NULL;
char* hostname = NULL;

char* param_set_default(const char* def_val) {
    char * retval = malloc(strlen(def_val)+1);
    if (retval == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for default parameter");
        return NULL;
    }
    strcpy(retval, def_val);
    return retval;
}

void app_main(void)
{
    initialize_nvs();
    load_log_level();  // Apply saved log level early

    /* Restore timezone from NVS */
    {
        char *tz = NULL;
        if (get_config_param_str("tz", &tz) == ESP_OK && tz[0] != '\0') {
            setenv("TZ", tz, 1);
            tzset();
            ESP_LOGI(TAG, "Timezone set to: %s", tz);
        }
        free(tz);
    }

    /* OTA rollback support: confirm the running firmware is valid */
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            ESP_LOGI(TAG, "OTA: confirming new firmware on partition '%s'", running->label);
            esp_ota_mark_app_valid_cancel_rollback();
        }
    }

#if CONFIG_STORE_HISTORY
    initialize_filesystem();
    ESP_LOGI(TAG, "Command history enabled");
#else
    ESP_LOGI(TAG, "Command history disabled");
#endif

#if !CONFIG_ETH_UPLINK
    get_config_param_blob("mac", &mac, 6);
    get_config_param_str("ssid", &ssid);
    if (ssid == NULL) {
        ssid = param_set_default("");
    }
    get_config_param_str("ent_username", &ent_username);
    if (ent_username == NULL) {
        ent_username = param_set_default("");
    }
    get_config_param_str("ent_identity", &ent_identity);
    if (ent_identity == NULL) {
        ent_identity = param_set_default("");
    }
    get_config_param_str("passwd", &passwd);
    if (passwd == NULL) {
        passwd = param_set_default("");
    }
#endif
    get_config_param_str("static_ip", &static_ip);
    if (static_ip == NULL) {
        static_ip = param_set_default("");
    }
    get_config_param_str("subnet_mask", &subnet_mask);
    if (subnet_mask == NULL) {
        subnet_mask = param_set_default("");
    }
    get_config_param_str("gateway_addr", &gateway_addr);
    if (gateway_addr == NULL) {
        gateway_addr = param_set_default("");
    }
    get_config_param_blob("ap_mac", &ap_mac, 6);
    get_config_param_str("ap_ssid", &ap_ssid);
    if (ap_ssid == NULL) {
        ap_ssid = param_set_default(DEFAULT_AP_SSID);
    }
    get_config_param_str("ap_passwd", &ap_passwd);
    if (ap_passwd == NULL) {
        ap_passwd = param_set_default("");
    }
    get_config_param_str("ap_ip", &ap_ip);
    if (ap_ip == NULL) {
        ap_ip = param_set_default(DEFAULT_AP_IP);
    }
    get_config_param_str("ap_dns", &ap_dns);
    if (ap_dns == NULL) {
        ap_dns = param_set_default("");
    }
    get_config_param_str("hostname", &hostname);
    if (hostname == NULL || hostname[0] == '\0') {            
        free(hostname);                                       
        hostname = param_set_default(DEFAULT_HOSTNAME);
    }

    get_portmap_tab();
    get_dhcp_reservations();
    load_acl_rules();

    // Load LED GPIO setting from NVS (default -1 = disabled)
    int led_gpio_setting = -1;
    if (get_config_param_int("led_gpio", &led_gpio_setting) == ESP_OK) {
        led_gpio = led_gpio_setting;
    }
    // led_gpio remains -1 (disabled) if not set in NVS

    // Load LED low-active setting from NVS (default 0 = active-high)
    int led_lowactive_setting = 0;
    if (get_config_param_int("led_low", &led_lowactive_setting) == ESP_OK) {
        led_lowactive = (led_lowactive_setting != 0) ? 1 : 0;
    }
    if (led_lowactive) {
        ESP_LOGI(TAG, "LED low-active mode enabled");
    }


#if defined(CONFIG_IDF_TARGET_ESP32C6)
    // XIAO ESP32-C6 RF switch: GPIO3 enables switch, GPIO14 selects antenna
    int rf_switch_setting = 0;
    get_config_param_int("rf_switch", &rf_switch_setting);
    if (rf_switch_setting) {
        gpio_reset_pin(GPIO_NUM_3);
        gpio_set_direction(GPIO_NUM_3, GPIO_MODE_OUTPUT);
        gpio_set_level(GPIO_NUM_3, 0);  // Activate RF switch control
        vTaskDelay(pdMS_TO_TICKS(10));
        gpio_reset_pin(GPIO_NUM_14);
        gpio_set_direction(GPIO_NUM_14, GPIO_MODE_OUTPUT);
        gpio_set_level(GPIO_NUM_14, 1); // Select external antenna
        ESP_LOGI(TAG, "XIAO ESP32-C6 RF switch: external antenna enabled");
    }
#endif

    // Load per-client stats enabled flag from NVS (default 0 = disabled)
    int cstats_setting = 0;
    if (get_config_param_int("cstats_en", &cstats_setting) == ESP_OK) {
        client_stats_enabled = (cstats_setting != 0);
    }
    if (client_stats_enabled) {
        ESP_LOGI(TAG, "Per-client stats enabled");
    }

    // Load TTL override setting from NVS (default 0 = disabled)
    int ttl_setting = 0;
    if (get_config_param_int("sta_ttl", &ttl_setting) == ESP_OK) {
        if (ttl_setting >= 0 && ttl_setting <= 255) {
            sta_ttl_override = (uint8_t)ttl_setting;
        }
    }
    if (sta_ttl_override > 0) {
        ESP_LOGI(TAG, "TTL override enabled: %d", sta_ttl_override);
    }

    // Load AP disabled setting from NVS (default 0 = enabled)
    int ap_disabled_setting = 0;
    if (get_config_param_int("ap_disabled", &ap_disabled_setting) == ESP_OK) {
        ap_disabled = (ap_disabled_setting != 0);
    }
    if (ap_disabled) {
        ESP_LOGI(TAG, "AP interface disabled (NVS)");
    }

    // Load AP NAT setting from NVS (default 1 = NAT enabled)
    int ap_nat_setting = 1;
    if (get_config_param_int("ap_nat", &ap_nat_setting) == ESP_OK) {
        ap_nat_enabled = (ap_nat_setting != 0) ? 1 : 0;
    }
    if (!ap_nat_enabled) {
        ESP_LOGI(TAG, "AP NAT disabled (routed mode)");
    }

    // Load AP SSID hidden setting from NVS (default 0 = visible)
    int hidden_setting = 0;
    if (get_config_param_int("ap_hidden", &hidden_setting) == ESP_OK) {
        ap_ssid_hidden = (hidden_setting != 0) ? 1 : 0;
    }
    if (ap_ssid_hidden) {
        ESP_LOGI(TAG, "AP SSID hidden enabled");
    }

    // Load AP auth mode from NVS (default 0 = WPA2/WPA3)
    int authmode_setting = 0;
    if (get_config_param_int("ap_authmode", &authmode_setting) == ESP_OK) {
        if (authmode_setting >= 0 && authmode_setting <= 2) {
            ap_authmode = (uint8_t)authmode_setting;
        }
    }
    if (ap_authmode > 0) {
        ESP_LOGI(TAG, "AP auth mode: %s", ap_authmode == 1 ? "WPA2" : "WPA3");
    }

    // Load WiFi country code from NVS (default "01" = world-safe)
    char *saved_cc = NULL;
    if (get_config_param_str("wifi_cc", &saved_cc) == ESP_OK && saved_cc != NULL) {
        if (strlen(saved_cc) == 2) {
            wifi_country_code[0] = saved_cc[0];
            wifi_country_code[1] = saved_cc[1];
            wifi_country_code[2] = '\0';
        }
        free(saved_cc);
    }
    ESP_LOGI(TAG, "WiFi country code: %s", wifi_country_code);

#if CONFIG_ETH_UPLINK
    // Load AP channel setting from NVS (default 0 = auto)
    int channel_setting = 0;
    if (get_config_param_int("ap_channel", &channel_setting) == ESP_OK) {
        if (channel_setting >= 1 && channel_setting <= 13) ap_channel = (uint8_t)channel_setting;
    }
    if (ap_channel > 0) {
        ESP_LOGI(TAG, "AP WiFi channel: %d", ap_channel);
    }
#endif

#if WIFI_HAS_5GHZ
    // Load STA band preference from NVS (default 0 = auto)
    int sta_band_setting = STA_BAND_AUTO;
    if (get_config_param_int("sta_band", &sta_band_setting) == ESP_OK) {
        if (sta_band_setting >= STA_BAND_AUTO && sta_band_setting <= STA_BAND_5G) {
            sta_band = (uint8_t)sta_band_setting;
        }
    }
    if (sta_band != STA_BAND_AUTO) {
        ESP_LOGI(TAG, "STA band preference: %s", sta_band == STA_BAND_2G ? "2.4 GHz" : "5 GHz");
    }
#endif

#if !CONFIG_ETH_UPLINK
    // Load WPA2-Enterprise settings from NVS (defaults: 0)
    int eap_setting = 0;
    if (get_config_param_int("eap_method", &eap_setting) == ESP_OK) {
        eap_method = (int32_t)eap_setting;
    }
    int phase2_setting = 0;
    if (get_config_param_int("ttls_phase2", &phase2_setting) == ESP_OK) {
        ttls_phase2 = (int32_t)phase2_setting;
    }
    int cert_bundle_setting = 0;
    if (get_config_param_int("cert_bundle", &cert_bundle_setting) == ESP_OK) {
        use_cert_bundle = (int32_t)cert_bundle_setting;
    }
    int time_check_setting = 0;
    if (get_config_param_int("no_time_chk", &time_check_setting) == ESP_OK) {
        disable_time_check = (int32_t)time_check_setting;
    }
#endif

    // Load PPPoE settings from NVS
    int pppoe_setting = 0;
    if (get_config_param_int("pppoe_en", &pppoe_setting) == ESP_OK) {
        pppoe_enabled = (int32_t)pppoe_setting;
    }
    get_config_param_str("pppoe_user", &pppoe_user);
    if (pppoe_user == NULL) pppoe_user = param_set_default("");
    get_config_param_str("pppoe_pass", &pppoe_pass);
    if (pppoe_pass == NULL) pppoe_pass = param_set_default("");
    get_config_param_str("pppoe_svc", &pppoe_service);
    if (pppoe_service == NULL) pppoe_service = param_set_default("");
    int pppoe_auth_setting = 0;
    if (get_config_param_int("pppoe_auth", &pppoe_auth_setting) == ESP_OK) {
        pppoe_auth = (int32_t)pppoe_auth_setting;
    }
    int pppoe_vlan_setting = 0;
    if (get_config_param_int("pppoe_vlan", &pppoe_vlan_setting) == ESP_OK) {
        pppoe_vlan = (int32_t)pppoe_vlan_setting;
    }
    int pppoe_bj_setting = 1;
    if (get_config_param_int("pppoe_bj", &pppoe_bj_setting) == ESP_OK) {
        pppoe_babyjumbo = (pppoe_bj_setting != 0);
    }
    // Pre-set MSS/PMTU when PPPoE is enabled (before Ethernet connects)
    if (pppoe_enabled) {
        if (pppoe_babyjumbo) {
            ap_mss_clamp = 1460;
            ap_pmtu = 1500;
            ESP_LOGI(TAG, "PPPoE enabled (baby-jumbo), MSS=1460 PMTU=1500 pre-set");
        } else {
            ap_mss_clamp = 1452;
            ap_pmtu = 1492;
            ESP_LOGI(TAG, "PPPoE enabled, MSS=1452 PMTU=1492 pre-set");
        }
    }

    // Load WireGuard VPN settings from NVS
    int vpn_setting = 0;
    if (get_config_param_int("vpn_enabled", &vpn_setting) == ESP_OK) {
        vpn_enabled = (int32_t)vpn_setting;
    }
    get_config_param_str("vpn_privkey", &vpn_private_key);
    if (vpn_private_key == NULL) vpn_private_key = param_set_default("");
    get_config_param_str("vpn_pubkey", &vpn_public_key);
    if (vpn_public_key == NULL) vpn_public_key = param_set_default("");
    get_config_param_str("vpn_psk", &vpn_preshared_key);
    if (vpn_preshared_key == NULL) vpn_preshared_key = param_set_default("");
    get_config_param_str("vpn_endpoint", &vpn_endpoint);
    if (vpn_endpoint == NULL) vpn_endpoint = param_set_default("");
    int vpn_port_setting = 51820;
    if (get_config_param_int("vpn_port", &vpn_port_setting) == ESP_OK) {
        vpn_port = (int32_t)vpn_port_setting;
    }
    get_config_param_str("vpn_ip", &vpn_address);
    if (vpn_address == NULL) vpn_address = param_set_default("");
    get_config_param_str("vpn_mask", &vpn_netmask);
    if (vpn_netmask == NULL) vpn_netmask = param_set_default("255.255.255.0");
    get_config_param_str("vpn_dns", &vpn_dns);
    if (vpn_dns == NULL) vpn_dns = param_set_default("");
    int vpn_ka_setting = 0;
    if (get_config_param_int("vpn_ka", &vpn_ka_setting) == ESP_OK) {
        vpn_keepalive = (int32_t)vpn_ka_setting;
    }
    int vpn_ks_setting = 1;
    if (get_config_param_int("vpn_ks", &vpn_ks_setting) == ESP_OK) {
        vpn_killswitch = (int32_t)vpn_ks_setting;
    }
    int vpn_rall_setting = 1;
    if (get_config_param_int("vpn_rall", &vpn_rall_setting) == ESP_OK) {
        vpn_route_all = (int32_t)vpn_rall_setting;
    }
    // Cache VPN subnet for kill switch packet filtering
    if (vpn_address && vpn_address[0]) {
        ip_addr_t addr, mask;
        if (ipaddr_aton(vpn_address, &addr) && ipaddr_aton(
                (vpn_netmask && vpn_netmask[0]) ? vpn_netmask : "255.255.255.0", &mask)) {
            vpn_set_subnet(ip_2_ip4(&addr)->addr & ip_2_ip4(&mask)->addr,
                           ip_2_ip4(&mask)->addr);
        }
    }
    // Pre-set MSS/PMTU when VPN is enabled (before PPPoE connects)
    if (vpn_enabled && pppoe_enabled) {
        if (pppoe_babyjumbo) {
            ap_mss_clamp = 1380;
            ap_pmtu = 1440;
            ESP_LOGI(TAG, "VPN+PPPoE baby-jumbo enabled, MSS=1380 PMTU=1440 pre-set");
        } else {
            ap_mss_clamp = 1352;
            ap_pmtu = 1432;
            ESP_LOGI(TAG, "VPN+PPPoE enabled, MSS=1352 PMTU=1432 pre-set");
        }
    }

#if !CONFIG_ETH_UPLINK
    /* Create one-shot timer for STA reconnect backoff */
    const esp_timer_create_args_t reconnect_timer_args = {
        .callback = sta_reconnect_timer_cb,
        .name = "sta_reconnect",
    };
    ESP_ERROR_CHECK(esp_timer_create(&reconnect_timer_args, &sta_reconnect_timer));
#endif

#if CONFIG_ETH_UPLINK
    eth_init(static_ip, subnet_mask, gateway_addr, ap_mac, ap_ssid, ap_passwd, ap_ip);
#else
    wifi_init(mac, ssid, ent_username, ent_identity, passwd, static_ip, subnet_mask, gateway_addr, ap_mac, ap_ssid, ap_passwd, ap_ip);
#endif


    // Apply WiFi country code (must be after esp_wifi_start)
    {
        esp_err_t ret = esp_wifi_set_country_code(wifi_country_code, true);
        if (ret == ESP_OK) {
            ESP_LOGI(TAG, "WiFi country code applied: %s", wifi_country_code);
        } else {
            ESP_LOGW(TAG, "Failed to apply WiFi country code %s: %s", wifi_country_code, esp_err_to_name(ret));
        }
    }

    // Apply TX power setting from NVS (must be after esp_wifi_start)
    int tx_power_dbm = 0;
    if (get_config_param_int("tx_power", &tx_power_dbm) == ESP_OK && tx_power_dbm >= 2 && tx_power_dbm <= 20) {
        int8_t power_qdbm = (int8_t)(tx_power_dbm * 4);
        esp_err_t ret = esp_wifi_set_max_tx_power(power_qdbm);
        if (ret == ESP_OK) {
            int8_t actual = 0;
            esp_wifi_get_max_tx_power(&actual);
            ESP_LOGI(TAG, "TX power set to %.1f dBm", actual * 0.25);
        } else {
            ESP_LOGW(TAG, "Failed to set TX power: %s", esp_err_to_name(ret));
        }
    }

    // Start VPN monitor task (waits for PPPoE to come up before connecting)
    if (vpn_enabled) {
        xTaskCreate(vpn_monitor_task, "vpn_monitor", 4096, NULL, 5, NULL);
        ESP_LOGI(TAG, "VPN monitor task started");
    }

    pthread_t t1;
    pthread_create(&t1, NULL, led_status_thread, NULL);

    if (!ap_disabled) {
        if (ap_nat_enabled) {
            ip_napt_enable(my_ap_ip, 1);
            ESP_LOGI(TAG, "NAT is enabled");
        } else {
            ESP_LOGI(TAG, "NAT is disabled (routed mode)");
        }
    }

    char* web_disabled = NULL;
    get_config_param_str("web_disabled", &web_disabled);
    if (web_disabled == NULL) {
        web_disabled = param_set_default("0");
    }
    int web_port_setting = 80;
    if (strcmp(web_disabled, "0") ==0) {
        get_config_param_int("web_port", &web_port_setting);
        ESP_LOGI(TAG,"Starting web server on port %d", web_port_setting);
        start_webserver((uint16_t)web_port_setting);
        int wa = 0;
        get_config_param_int("wan_access", &wa);
        update_web_wan_acl(wa);
    }

    // Initialize mDNS responder — answers <hostname>.local on all interfaces.
    if (hostname && hostname[0]) {
        esp_err_t merr = mdns_init();
        if (merr == ESP_OK) {
            mdns_hostname_set(hostname);
            mdns_instance_name_set(hostname);
            if (strcmp(web_disabled, "0") == 0) {
                mdns_service_add(NULL, "_http", "_tcp",
                                 (uint16_t)web_port_setting, NULL, 0);
            }
            ESP_LOGI(TAG, "mDNS responder up: %s.local", hostname);
        } else {
            ESP_LOGW(TAG, "mdns_init failed: %s", esp_err_to_name(merr));
        }
    }

    free(web_disabled);

#if CONFIG_PCAP_CAPTURE
    // Initialize PCAP capture (TCP server on port 19000)
    pcap_init();
#endif

    // Initialize remote console (TCP server on port 2323, disabled by default)
    remote_console_init();

    // Initialize syslog client (UDP forwarding, disabled by default)
    syslog_init();

    initialize_console();

    /* Register commands */
    esp_console_register_help_command();
    register_system();
    register_router();

#if CONFIG_MQTT_HOMEASSISTANT
    mqtt_ha_init();
#endif

#if defined(CONFIG_DDNS_ENABLED) && CONFIG_DDNS_ENABLED
    ddns_init();
#endif

    /* Prompt to be printed before each line.
     * This can be customized, made dynamic, etc.
     */
    const char* prompt = LOG_COLOR_I "esp32> " LOG_RESET_COLOR;

    printf("\n"
           "ESP32 PPPoE ROUTER\n"
           "Type 'help' to get the list of commands.\n"
           "Use UP/DOWN arrows to navigate through command history.\n"
           "Press TAB when typing command name to auto-complete.\n");

#if !CONFIG_ETH_UPLINK
    if (strlen(ssid) == 0) {
         printf("\n"
               "Unconfigured WiFi\n"
               "Configure using 'set_sta' and 'set_ap' and restart.\n");
    }
#endif

    /* Figure out if the terminal supports escape sequences */
    int probe_status = linenoiseProbe();
    if (probe_status) { /* zero indicates success */
        printf("\n"
               "Your terminal application does not support escape sequences.\n"
               "Line editing and history features are disabled.\n"
               "On Windows, try using Putty instead.\n");
        linenoiseSetDumbMode(1);
#if CONFIG_LOG_COLORS
        /* Since the terminal doesn't support escape sequences,
         * don't use color codes in the prompt.
         */
        prompt = "esp32> ";
#endif //CONFIG_LOG_COLORS
    }

    /* Main loop */
    while(true) {
        /* Get a line using linenoise.
         * The line is returned when ENTER is pressed.
         */
        char* line = linenoise(prompt);
        if (line == NULL) { /* Ignore empty lines */
            continue;
        }
        /* Add the command to the history */
        linenoiseHistoryAdd(line);
#if CONFIG_STORE_HISTORY
        /* Save command history to filesystem */
        linenoiseHistorySave(HISTORY_PATH);
#endif

        /* Try to run the command */
        int ret;
        esp_err_t err = esp_console_run(line, &ret);
        if (err == ESP_ERR_NOT_FOUND) {
            printf("Unrecognized command\n");
        } else if (err == ESP_ERR_INVALID_ARG) {
            // command was empty
        } else if (err == ESP_OK && ret != ESP_OK) {
            printf("Command returned non-zero error code: 0x%x (%s)\n", ret, esp_err_to_name(ret));
        } else if (err != ESP_OK) {
            printf("Internal error: %s\n", esp_err_to_name(err));
        }
        /* linenoise allocates line buffer on the heap, so need to free it */
        linenoiseFree(line);
    }
}
