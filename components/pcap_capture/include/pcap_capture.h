/* PCAP Capture - Capture AP interface traffic and stream via TCP

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#pragma once

#include "sdkconfig.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "lwip/pbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PCAP_TCP_PORT           19000

/**
 * @brief Capture mode enumeration
 */
typedef enum {
    PCAP_MODE_OFF = 0,        /**< Capture disabled - no packets recorded */
    PCAP_MODE_ACL_MONITOR,    /**< Only capture packets with ACL_MONITOR flag */
    PCAP_MODE_PROMISCUOUS     /**< Capture all traffic on hooked interfaces */
} pcap_capture_mode_t;

#if CONFIG_PCAP_CAPTURE

/**
 * @brief Initialize PCAP capture system and start TCP server task
 *
 * Creates ring buffer, starts TCP server listening on port 19000.
 * Capture mode is OFF by default.
 */
void pcap_init(void);

/**
 * @brief Check if a packet should be captured based on current mode and state
 *
 * This is the main decision function for capturing. It considers:
 * - Current capture mode (OFF, ACL_MONITOR, or PROMISCUOUS)
 * - Whether a Wireshark client is connected
 * - Whether packet has ACL_MONITOR flag (for ACL_MONITOR mode)
 * - Interface type (promiscuous mode only captures Ethernet/upstream interface)
 *
 * @param is_acl_monitored true if packet matched ACL rule with MONITOR flag
 * @param is_ap_interface true if packet is from AP interface (client traffic)
 * @return true if packet should be captured
 */
bool pcap_should_capture(bool is_acl_monitored, bool is_ap_interface);

/**
 * @brief Capture a packet into the ring buffer
 *
 * Called from netif hooks after pcap_should_capture() returns true.
 * Non-blocking - if buffer is full, packet is dropped and counter incremented.
 *
 * @param p Packet buffer to capture
 */
void pcap_capture_packet(struct pbuf *p);

/**
 * @brief Set capture mode
 * @param mode The capture mode to set
 */
void pcap_set_mode(pcap_capture_mode_t mode);

/**
 * @brief Get current capture mode
 * @return Current capture mode
 */
pcap_capture_mode_t pcap_get_mode(void);

/**
 * @brief Get capture mode name as string
 * @param mode The capture mode
 * @return String representation of mode
 */
const char* pcap_mode_to_string(pcap_capture_mode_t mode);

/**
 * @brief Enable packet capture (legacy - sets PROMISCUOUS mode)
 * @deprecated Use pcap_set_mode() instead
 */
void pcap_capture_start(void);

/**
 * @brief Disable packet capture (legacy - sets OFF mode)
 * @deprecated Use pcap_set_mode() instead
 */
void pcap_capture_stop(void);

/**
 * @brief Check if capture is enabled (legacy)
 * @return true if mode is not OFF
 * @deprecated Use pcap_get_mode() instead
 */
bool pcap_capture_enabled(void);

/**
 * @brief Check if a client is connected to the TCP server
 * @return true if client is connected
 */
bool pcap_client_connected(void);

/**
 * @brief Get count of captured packets
 * @return Number of packets captured since last start
 */
uint32_t pcap_get_captured_count(void);

/**
 * @brief Get count of dropped packets (buffer overflow)
 * @return Number of packets dropped since last reset
 */
uint32_t pcap_get_dropped_count(void);

/**
 * @brief Get current ring buffer usage
 * @param used Returns bytes currently in buffer
 * @param total Returns total buffer size
 */
void pcap_get_buffer_usage(size_t *used, size_t *total);

/**
 * @brief Get current snaplen (max captured bytes per packet)
 * @return Current snaplen value
 */
uint16_t pcap_get_snaplen(void);

/**
 * @brief Set snaplen (max captured bytes per packet)
 * @param snaplen Value between 64 and 1600
 * @return true on success, false if value out of range
 */
bool pcap_set_snaplen(uint16_t snaplen);

/**
 * @brief Set PCAP link-layer header type
 * @param dlt Data Link Type (1=DLT_EN10MB for Ethernet, 101=DLT_RAW for raw IP)
 */
void pcap_set_link_type(uint32_t dlt);

/**
 * @brief Get current PCAP link-layer header type
 * @return Current DLT value
 */
uint32_t pcap_get_link_type(void);

#else /* !CONFIG_PCAP_CAPTURE — no-op stubs */

static inline void pcap_init(void) {}
static inline bool pcap_should_capture(bool a, bool b) { (void)a; (void)b; return false; }
static inline void pcap_capture_packet(struct pbuf *p) { (void)p; }
static inline void pcap_set_mode(pcap_capture_mode_t m) { (void)m; }
static inline pcap_capture_mode_t pcap_get_mode(void) { return PCAP_MODE_OFF; }
static inline const char* pcap_mode_to_string(pcap_capture_mode_t m) { (void)m; return "off"; }
static inline void pcap_capture_start(void) {}
static inline void pcap_capture_stop(void) {}
static inline bool pcap_capture_enabled(void) { return false; }
static inline bool pcap_client_connected(void) { return false; }
static inline uint32_t pcap_get_captured_count(void) { return 0; }
static inline uint32_t pcap_get_dropped_count(void) { return 0; }
static inline void pcap_get_buffer_usage(size_t *used, size_t *total) { if (used) *used = 0; if (total) *total = 0; }
static inline uint16_t pcap_get_snaplen(void) { return 64; }
static inline bool pcap_set_snaplen(uint16_t s) { (void)s; return false; }
static inline void pcap_set_link_type(uint32_t d) { (void)d; }
static inline uint32_t pcap_get_link_type(void) { return 1; }

#endif /* CONFIG_PCAP_CAPTURE */

#ifdef __cplusplus
}
#endif
