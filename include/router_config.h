/* Core router configuration constants, byte counters, LED state,
 * TTL/MSS/PMTU tuning, uptime, and netif hooks.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PARAM_NAMESPACE "esp32_nat"

#define DEFAULT_HOSTNAME "esp32-pppoe-router"
#define DEFAULT_AP_SSID "ESP32_PPPoE_Router"
#define DEFAULT_AP_IP "192.168.4.1"
#define DEFAULT_DNS "1.1.1.1"

#define PROTO_TCP 6
#define PROTO_UDP 17

// One active connection uses about 5kB RAM
#if CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32C5
// Unified SRAM: IRAM and heap share the same pool, leaving ~135 KB free
#define AP_MAX_CONNECTIONS 5
#else
#define AP_MAX_CONNECTIONS 8
#endif

// Byte counting variables for STA interface
extern uint64_t sta_bytes_sent;
extern uint64_t sta_bytes_received;

// LED GPIO configuration (-1 means disabled/none)
extern int led_gpio;

// LED low-active mode (0 = active-high, 1 = active-low/inverted)
extern uint8_t led_lowactive;

// Shared LED toggle state (packet-driven flicker)
extern uint8_t led_toggle;

// TTL override for STA upstream (0 = disabled/no change, 1-255 = fixed TTL)
extern uint8_t sta_ttl_override;

// MSS clamp for AP interface (0 = disabled, otherwise max MSS in bytes)
extern uint16_t ap_mss_clamp;

// Path MTU for AP clients (0 = disabled, otherwise send ICMP Frag Needed when DF packets exceed this)
extern uint16_t ap_pmtu;

// Byte counting functions
void init_byte_counter(void);
void deinit_byte_counter_ppp(void);  /* PPPoE only: reset hook state before session is freed */
uint64_t get_sta_bytes_sent(void);
uint64_t get_sta_bytes_received(void);
void reset_sta_byte_counts(void);
void resync_connect_count(void);

// Uptime functions
uint32_t get_uptime_seconds(void);
void format_uptime(uint32_t seconds, char *buf, size_t buf_len);
void format_boot_time(char *buf, size_t buf_len);

// AP netif hook functions (for future use)
void init_ap_netif_hooks(void);

// NAPT table stats
typedef struct {
    uint32_t tcp;
    uint32_t udp;
    uint32_t icmp;
    uint32_t total;
    uint32_t max;
} napt_stats_t;

void get_napt_stats(napt_stats_t *out);

#ifdef __cplusplus
}
#endif
