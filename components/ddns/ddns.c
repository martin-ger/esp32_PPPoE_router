/* ddns.c — Dynamic DNS core task and NVS persistence.
 *
 * Periodically checks WAN IP against last-reported value via esp_http_client
 * and updates the Dynamic DNS record through the selected provider.
 * Triggered immediately on PPPoE connect, then periodically thereafter.
 *
 * SPDX-License-Identifier: MIT
 */

#include "sdkconfig.h"
#ifdef CONFIG_DDNS_ENABLED

#include "ddns.h"
#include "ddns_providers.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "router_config.h"
#include "router_globals.h"
#include "pppoe_config.h"

static const char *TAG = "ddns";

/* ---- NVS keys ---- */
#define DDNS_NVS_NS         PARAM_NAMESPACE
#define DDNS_NVS_KEY_EN     "ddns_en"
#define DDNS_NVS_KEY_PROV   "ddns_prov"
#define DDNS_NVS_KEY_HOST   "ddns_host"
#define DDNS_NVS_KEY_TOKEN  "ddns_token"
#define DDNS_NVS_KEY_PASS   "ddns_pass"
#define DDNS_NVS_KEY_POLL   "ddns_poll"
#define DDNS_NVS_KEY_SAVED_IP  "ddns_saved_ip"
#define DDNS_NVS_KEY_LAST_UPD  "ddns_last_upd"

/* ---- Provider names ---- */
static const char *s_provider_names[] = { "NoIP", "DuckDNS", "Selfhost.de" };
#define DDNS_PROVIDER_COUNT (sizeof(s_provider_names) / sizeof(s_provider_names[0]))

/* ---- Internal state ---- */
static ddns_config_t      g_ddns;
static uint32_t           g_wan_ip        = 0;
static bool               g_wan_changed   = false;
static esp_timer_handle_t g_poll_timer    = NULL;
static bool               g_timer_running = false;
static volatile bool      g_update_running = false;

/* ---- Helpers ---- */

static void clear_config(void)
{
    g_ddns.enabled      = false;
    g_ddns.provider     = 0;
    memset(g_ddns.hostname, 0, sizeof(g_ddns.hostname));
    memset(g_ddns.token,    0, sizeof(g_ddns.token));
    memset(g_ddns.password, 0, sizeof(g_ddns.password));
    g_ddns.poll_interval = (uint32_t)CONFIG_DDNS_POLL_INTERVAL;
    g_ddns.saved_ip     = 0;
    g_ddns.last_update  = 0;
    strncpy(g_ddns.provider_name, "NoIP", sizeof(g_ddns.provider_name) - 1);
}

/**
 * Get the full FQDN for the current provider.
 * - NoIP:    hostname field is already FQDN
 * - DuckDNS: hostname is subdomain -> "subdomain.duckdns.org"
 * - Selfhost: hostname field is FQDN
 */
void ddns_get_fqdn(char *fqdn, size_t fqdn_len)
{
    if (!fqdn || !fqdn_len) return;
    memset(fqdn, 0, fqdn_len);

    switch (g_ddns.provider) {
    case DDNS_PROVIDER_DUCKDNS:
        if (g_ddns.hostname[0]) {
            snprintf(fqdn, fqdn_len, "%s.duckdns.org", g_ddns.hostname);
        }
        break;
    default:
        strncpy(fqdn, g_ddns.hostname, fqdn_len - 1);
        break;
    }
}

/* ---- NVS persistence ---- */

esp_err_t ddns_save_config(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(DDNS_NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS open for write failed: %s", esp_err_to_name(err));
        return err;
    }

    nvs_set_i32(h, DDNS_NVS_KEY_EN,   g_ddns.enabled ? 1 : 0);
    nvs_set_u8 (h, DDNS_NVS_KEY_PROV, (uint8_t)g_ddns.provider);
    nvs_set_str(h, DDNS_NVS_KEY_HOST,  g_ddns.hostname);
    nvs_set_str(h, DDNS_NVS_KEY_TOKEN, g_ddns.token);
    nvs_set_str(h, DDNS_NVS_KEY_PASS,  g_ddns.password);
    nvs_set_i32(h, DDNS_NVS_KEY_POLL,  (int32_t)g_ddns.poll_interval);
    nvs_set_u32(h, DDNS_NVS_KEY_SAVED_IP, g_ddns.saved_ip);
    nvs_set_i64(h, DDNS_NVS_KEY_LAST_UPD, (int64_t)g_ddns.last_update);
    nvs_commit(h);
    nvs_close(h);
    return ESP_OK;
}

esp_err_t ddns_load_config(void)
{
    clear_config();

    nvs_handle_t h;
    esp_err_t err = nvs_open(DDNS_NVS_NS, NVS_READONLY, &h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "NVS open for read failed: %s", esp_err_to_name(err));
        return err;
    }

    int32_t en = 0;
    if (nvs_get_i32(h, DDNS_NVS_KEY_EN, &en) == ESP_OK) {
        g_ddns.enabled = (en != 0);
    }

    uint8_t prov = 0;
    if (nvs_get_u8(h, DDNS_NVS_KEY_PROV, &prov) == ESP_OK) {
        g_ddns.provider = prov;
    }

    size_t len = DDNS_MAX_HOSTNAME;
    if (nvs_get_str(h, DDNS_NVS_KEY_HOST, g_ddns.hostname, &len) != ESP_OK) {
        g_ddns.hostname[0] = '\0';
    }
    len = DDNS_MAX_TOKEN;
    if (nvs_get_str(h, DDNS_NVS_KEY_TOKEN, g_ddns.token, &len) != ESP_OK) {
        g_ddns.token[0] = '\0';
    }
    len = DDNS_MAX_PASS;
    if (nvs_get_str(h, DDNS_NVS_KEY_PASS, g_ddns.password, &len) != ESP_OK) {
        g_ddns.password[0] = '\0';
    }

    int32_t poll = (int32_t)CONFIG_DDNS_POLL_INTERVAL;
    if (nvs_get_i32(h, DDNS_NVS_KEY_POLL, &poll) == ESP_OK && poll > 0) {
        g_ddns.poll_interval = (uint32_t)poll;
    }

    uint32_t saved_ip = 0;
    if (nvs_get_u32(h, DDNS_NVS_KEY_SAVED_IP, &saved_ip) == ESP_OK) {
        g_ddns.saved_ip = saved_ip;
    }

    int64_t last_upd = 0;
    if (nvs_get_i64(h, DDNS_NVS_KEY_LAST_UPD, &last_upd) == ESP_OK) {
        g_ddns.last_update = (time_t)last_upd;
    }

    nvs_close(h);

    strncpy(g_ddns.provider_name, s_provider_names[g_ddns.provider],
            sizeof(g_ddns.provider_name) - 1);

    ESP_LOGI(TAG, "Config loaded: enabled=%d prov=%s host=%s",
             g_ddns.enabled, g_ddns.provider_name,
             g_ddns.hostname[0] ? g_ddns.hostname : "(none)");

    return ESP_OK;
}

/* ---- Provider dispatch ---- */

static esp_err_t ddns_update(uint32_t wan_ip, char *resp, size_t resp_len)
{
    char ip_str[16];
    esp_ip4addr_ntoa((esp_ip4_addr_t *)&wan_ip, ip_str, sizeof(ip_str));

    char fqdn[128];
    ddns_get_fqdn(fqdn, sizeof(fqdn));

    switch (g_ddns.provider) {
    case DDNS_PROVIDER_NOIP:
        if (fqdn[0] == '\0') {
            ESP_LOGW(TAG, "NoIP: no hostname configured");
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "Updating NoIP: host=%s ip=%s", fqdn, ip_str);
        return noip_update(wan_ip, fqdn, g_ddns.token, g_ddns.password, resp, resp_len);

    case DDNS_PROVIDER_DUCKDNS:
        if (fqdn[0] == '\0') {
            ESP_LOGW(TAG, "DuckDNS: no subdomain configured");
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "Updating DuckDNS: subdomain=%s ip=%s", g_ddns.hostname, ip_str);
        return duckdns_update(wan_ip, g_ddns.hostname, g_ddns.token, resp, resp_len);

    case DDNS_PROVIDER_SELFSOFT:
        if (fqdn[0] == '\0') {
            ESP_LOGW(TAG, "Selfhost: no hostname configured");
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "Updating Selfhost: host=%s ip=%s", fqdn, ip_str);
        return selfhost_update(wan_ip, fqdn, g_ddns.token, resp, resp_len);

    default:
        ESP_LOGW(TAG, "Unknown provider %d", g_ddns.provider);
        return ESP_FAIL;
    }
}

/* ---- Update task (runs HTTP I/O off the tcpip/timer thread) ---- */

static void ddns_update_task(void *arg)
{
    char resp[128];
    memset(resp, 0, sizeof(resp));

    uint32_t ip = g_wan_ip;
    esp_err_t err = ddns_update(ip, resp, sizeof(resp));
    if (err == ESP_OK && resp[0] != '\0') {
        g_ddns.last_update = time(NULL);
        g_ddns.saved_ip    = ip;
        ddns_save_config();
        ESP_LOGI(TAG, "DDNS update successful: %s", resp);
    } else {
        ESP_LOGE(TAG, "DDNS update failed: error=%s response=%s",
                 esp_err_to_name(err), resp[0] ? resp : "(empty)");
    }

    g_wan_changed    = false;
    g_update_running = false;
    vTaskDelete(NULL);
}

/* ---- Timer callback ---- */

static void ddns_timer_cb(void *arg)
{
    if (!g_ddns.enabled || g_wan_ip == 0 || !g_wan_changed) {
        ESP_LOGD(TAG, "Timer: skipping (en=%d ip=%lu changed=%d)",
                 g_ddns.enabled, (unsigned long)g_wan_ip, g_wan_changed);
        return;
    }
    ddns_trigger_update();
}

/* ---- Public API ---- */

esp_err_t ddns_reload_config(void)
{
    if (g_poll_timer) {
        if (g_timer_running) {
            esp_timer_stop(g_poll_timer);
            g_timer_running = false;
        }
        esp_timer_delete(g_poll_timer);
        g_poll_timer = NULL;
    }

    esp_err_t err = ddns_load_config();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "DDNS reload: NVS read failed");
        return err;
    }

    if (g_ddns.enabled && g_ddns.poll_interval > 0) {
        esp_timer_create_args_t cfg = {
            .callback              = ddns_timer_cb,
            .arg                   = NULL,
            .dispatch_method       = ESP_TIMER_TASK,
            .name                  = "ddns_poll",
            .skip_unhandled_events = false,
        };
        if (esp_timer_create(&cfg, &g_poll_timer) == ESP_OK) {
            err = esp_timer_start_periodic(g_poll_timer,
                (int64_t)g_ddns.poll_interval * 1000000LL);
            if (err == ESP_OK) {
                g_timer_running = true;
                ESP_LOGI(TAG, "DDNS timer restarted: %lu s",
                         (unsigned long)g_ddns.poll_interval);
            }
        }
    }
    ESP_LOGI(TAG, "DDNS config reloaded (enabled=%d prov=%s)",
             g_ddns.enabled, g_ddns.provider_name);
    return ESP_OK;
}

esp_err_t ddns_init(void)
{
    esp_err_t err = ddns_load_config();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to load DDNS config from NVS");
        clear_config();
    }

    if (g_ddns.enabled && g_ddns.poll_interval > 0) {
        esp_timer_create_args_t timer_cfg = {
            .callback             = ddns_timer_cb,
            .arg                  = NULL,
            .dispatch_method      = ESP_TIMER_TASK,
            .name                 = "ddns_poll",
            .skip_unhandled_events = false,
        };
        if (esp_timer_create(&timer_cfg, &g_poll_timer) == ESP_OK) {
            err = esp_timer_start_periodic(g_poll_timer,
                (int64_t)g_ddns.poll_interval * 1000000LL);
            if (err == ESP_OK) {
                g_timer_running = true;
                ESP_LOGI(TAG, "DDNS poll timer started: %d s", g_ddns.poll_interval);
            } else {
                ESP_LOGE(TAG, "Failed to start DDNS timer: %s", esp_err_to_name(err));
            }
        }
    }

    ESP_LOGI(TAG, "DDNS initialized (enabled=%d prov=%s)",
             g_ddns.enabled, g_ddns.provider_name);
    return ESP_OK;
}

void ddns_tick(void)
{
    ESP_LOGD(TAG, "tick called (timer-driven)");
}

esp_err_t ddns_trigger_update(void)
{
    g_wan_changed = true;

    if (!g_ddns.enabled || g_wan_ip == 0) return ESP_OK;

    if (g_update_running) {
        ESP_LOGD(TAG, "Update already in progress, skipping");
        return ESP_OK;
    }

    g_update_running = true;
    BaseType_t rc = xTaskCreate(ddns_update_task, "ddns_upd", 4096, NULL, 5, NULL);
    if (rc != pdPASS) {
        g_update_running = false;
        ESP_LOGE(TAG, "Failed to create DDNS update task");
        return ESP_FAIL;
    }
    return ESP_OK;
}

void ddns_update_wan_ip(uint32_t wan_ip)
{
    if (g_wan_ip != wan_ip) {
        g_wan_ip      = wan_ip;
        g_wan_changed = true;
        ESP_LOGI(TAG, "WAN IP changed: " IPSTR, IP2STR((esp_ip4_addr_t *)&wan_ip));
    }

    if (g_ddns.enabled && g_wan_ip != 0) {
        ddns_trigger_update();
    }
}

/* ---- Status helpers ---- */

void ddns_get_status(char *buf, size_t len)
{
    if (!buf || len == 0) return;
    memset(buf, 0, len);

    char ip_str[16];
    char time_str[64];

    if (g_ddns.last_update) {
        struct tm *tm_info = gmtime(&g_ddns.last_update);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M UTC", tm_info);
    } else {
        strcpy(time_str, "Never");
    }

    if (g_wan_ip) {
        esp_ip4addr_ntoa((esp_ip4_addr_t *)&g_wan_ip, ip_str, sizeof(ip_str));
    } else {
        strcpy(ip_str, "0.0.0.0");
    }

    char saved_ip_str[16];
    if (g_ddns.saved_ip) {
        esp_ip4addr_ntoa((esp_ip4_addr_t *)&g_ddns.saved_ip, saved_ip_str, sizeof(saved_ip_str));
    } else {
        strcpy(saved_ip_str, "0.0.0.0");
    }

    snprintf(buf, len,
             "DDNS: %s [%s]\n"
             "  Provider:    %s\n"
             "  Hostname:    %s\n"
             "  WAN IP:      %s\n"
             "  Last update: %s\n"
             "  Saved IP:    %s\n"
             "  Poll:        %lu s",
             g_ddns.enabled ? "enabled" : "disabled",
             g_timer_running ? "timer-running" : "stopped",
             g_ddns.enabled ? g_ddns.provider_name : "N/A",
             g_ddns.hostname[0] ? g_ddns.hostname : "(none)",
             ip_str,
             time_str,
             saved_ip_str,
             (unsigned long)g_ddns.poll_interval);
}

void ddns_get_status_html(char *buf, size_t len)
{
    if (!buf || len == 0) return;

    char ip_str[16];
    char time_str[64];

    if (g_ddns.last_update) {
        struct tm *tm_info = gmtime(&g_ddns.last_update);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M UTC", tm_info);
    } else {
        strcpy(time_str, "Never");
    }

    if (g_wan_ip) {
        esp_ip4addr_ntoa((esp_ip4_addr_t *)&g_wan_ip, ip_str, sizeof(ip_str));
    } else {
        strcpy(ip_str, "0.0.0.0");
    }

    char saved_ip_str[16];
    if (g_ddns.saved_ip) {
        esp_ip4addr_ntoa((esp_ip4_addr_t *)&g_ddns.saved_ip, saved_ip_str, sizeof(saved_ip_str));
    } else {
        strcpy(saved_ip_str, "0.0.0.0");
    }

    snprintf(buf, len,
             "<tr><td>State</td><td>%s [%s]</td></tr>"
             "<tr><td>Provider</td><td>%s</td></tr>"
             "<tr><td>WAN IP</td><td>%s</td></tr>"
             "<tr><td>Last Update</td><td>%s</td></tr>"
             "<tr><td>Saved IP</td><td>%s</td></tr>"
             "<tr><td>Poll</td><td>%lu s</td></tr>",
             g_ddns.enabled ? "enabled" : "disabled",
             g_timer_running ? "running" : "stopped",
             g_ddns.enabled ? g_ddns.provider_name : "N/A",
             ip_str,
             time_str,
             saved_ip_str,
             (unsigned long)g_ddns.poll_interval);
}

bool ddns_is_enabled(void)
{
    return g_ddns.enabled;
}

int ddns_get_current_provider(void)
{
    return (int)g_ddns.provider;
}

int ddns_get_provider_count(void)
{
    return DDNS_PROVIDER_COUNT;
}

int ddns_get_provider_index(const char *name)
{
    const char *known[] = { "NoIP", "DuckDNS", "Selfhost.de" };
    for (int i = 0; i < 3; i++) {
        if (strcmp(name, known[i]) == 0) return i;
    }
    return -1;
}

const char *ddns_get_provider_name(int index)
{
    if (index < 0 || index >= 3) return "Unknown";
    return s_provider_names[index];
}

#endif /* CONFIG_DDNS_ENABLED */
