/* PPPoE DSL uplink settings and runtime state.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

struct netif; /* lwIP forward declaration */

/* NVS-backed PPPoE settings */
extern int32_t pppoe_enabled;       /* 0=Ethernet DHCP, 1=PPPoE uplink */
extern char* pppoe_user;            /* ISP username */
extern char* pppoe_pass;            /* ISP password */
extern char* pppoe_service;         /* PPPoE service name (optional, NULL/"" = any) */
extern int32_t pppoe_auth;          /* Auth type: 0=auto, 1=PAP, 2=CHAP */
extern int32_t pppoe_vlan;          /* 802.1Q VLAN ID for PPPoE frames (0=disabled) */
extern bool pppoe_babyjumbo;        /* 1=1508-byte Ethernet payload (MSS=1460, PMTU=1500), 0=standard (MSS=1452, PMTU=1492) */

/* Runtime state */
extern bool pppoe_connected;        /* PPPoE session is up */
extern uint32_t pppoe_ip;           /* IPCP-assigned IP (network byte order, 0 if not connected) */

/* PPPoE lifecycle */
esp_err_t pppoe_start(struct netif *eth_lwip_netif);
void pppoe_stop(void);
bool pppoe_is_connected(void);      /* IRAM_ATTR — safe for hot-path packet filtering */
struct netif *pppoe_get_netif(void); /* Returns PPP netif for hook attachment */

/* SNTP (useful for syslog timestamps) */
void init_sntp_if_needed(void);

#ifdef __cplusplus
}
#endif
