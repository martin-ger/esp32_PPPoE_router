/* ddns.h — Dynamic DNS client types and public API.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include "sdkconfig.h"
#ifdef CONFIG_DDNS_ENABLED

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "esp_err.h"

/* ---- Provider IDs ---- */
#define DDNS_PROVIDER_NOIP      0
#define DDNS_PROVIDER_DUCKDNS   1
#define DDNS_PROVIDER_SELFSOFT  2

#define DDNS_MAX_HOSTNAME 128
#define DDNS_MAX_TOKEN    128
#define DDNS_MAX_PASS     64

/* ---- Config struct (loaded from / saved to NVS) ---- */
typedef struct {
    uint8_t  provider;     /* DDNS_PROVIDER_* */
    char     hostname[DDNS_MAX_HOSTNAME];
    char     token[DDNS_MAX_TOKEN];     /* token (DuckDNS/Selfhost) or NoIP hostname */
    char     password[DDNS_MAX_PASS];
    uint32_t poll_interval;             /* seconds */
    uint32_t saved_ip;                  /* last IP sent (network byte order) */
    time_t   last_update;               /* last successful update timestamp */
    bool     enabled;
    char     provider_name[16];         /* display name */
} ddns_config_t;

/* ---- Public API ---- */

/** Called from app_main during boot. Loads config, starts timer if enabled. */
esp_err_t ddns_init(void);

/** Reload config from NVS and restart the poll timer. Call after web/CLI save. */
esp_err_t ddns_reload_config(void);

/** Load DDNS config from NVS. */
esp_err_t ddns_load_config(void);

/** Save DDNS config to NVS. */
esp_err_t ddns_save_config(void);

/** Update DDNS with the current WAN IP. Call from PPPoE connect callback. */
esp_err_t ddns_trigger_update(void);

/** Called periodically to compare WAN IP and update if changed. */
void ddns_tick(void);

/** Set the WAN IP from PPPoE callback. */
void ddns_update_wan_ip(uint32_t wan_ip);

/** Get provider count. */
int ddns_get_provider_count(void);

/** Get provider index given a name string. Returns -1 if not found. */
int ddns_get_provider_index(const char *name);

/** Get provider names (for UI/CLI). */
const char *ddns_get_provider_name(int index);

/** Build status string formatted for CLI display. */
void ddns_get_status(char *buf, size_t len);

/** Build status as HTML table rows for the web UI. */
void ddns_get_status_html(char *buf, size_t len);

/** Build full FQDN for the current config. */
void ddns_get_fqdn(char *fqdn, size_t fqdn_len);

/** Return true if DDNS is enabled. */
bool ddns_is_enabled(void);

/** Return the current provider index (DDNS_PROVIDER_*). */
int ddns_get_current_provider(void);

#endif /* CONFIG_DDNS_ENABLED */
