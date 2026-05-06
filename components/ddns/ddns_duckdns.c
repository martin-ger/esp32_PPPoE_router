/* ddns_duckdns.c — DuckDNS provider adapter.
 *
 * SPDX-License-Identifier: MIT
 */

#include "sdkconfig.h"
#ifdef CONFIG_DDNS_ENABLED

#include "ddns.h"
#include "ddns_providers.h"

#include <stdio.h>
#include <string.h>
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"

static const char *TAG = "ddns_duckdns";

#define DUCKDNS_API_HOST "www.duckdns.org"

esp_err_t duckdns_update(uint32_t wan_ip, const char *subdomain,
                         const char *token, char *resp, size_t resp_len)
{
    if (!subdomain || !token) {
        ESP_LOGE(TAG, "DuckDNS: missing subdomain or token");
        return ESP_ERR_INVALID_ARG;
    }

    char ip_str[16];
    esp_ip4addr_ntoa((esp_ip4_addr_t *)&wan_ip, ip_str, sizeof(ip_str));

    /* URL-encode subdomain and token to prevent query-param injection */
    char enc_sub[256];
    char enc_tok[256];
    url_encode(subdomain, enc_sub, sizeof(enc_sub));
    url_encode(token,     enc_tok, sizeof(enc_tok));

    char url[640];
    snprintf(url, sizeof(url),
             "https://" DUCKDNS_API_HOST "/update?domains=%s&token=%s&ip=%s",
             enc_sub, enc_tok, ip_str);

    ESP_LOGI(TAG, "Updating DuckDNS: subdomain=%s ip=%s", subdomain, ip_str);

    esp_http_client_config_t config = {
        .url                     = url,
        .method                  = HTTP_METHOD_GET,
        .crt_bundle_attach       = esp_crt_bundle_attach,
        .skip_cert_common_name_check = 0,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "DuckDNS: HTTP client init failed");
        return ESP_FAIL;
    }

    esp_http_client_set_header(client, "User-Agent", "ESP32-DDNS/1.0");
    esp_http_client_set_header(client, "Accept", "text/plain");

    esp_err_t err = esp_http_client_perform(client);
    int status = err == ESP_OK ? esp_http_client_get_status_code(client) : 0;

    if (err == ESP_OK && status == 200) {
        int body_len = esp_http_client_read_response(client, resp, resp_len - 1);
        if (body_len > 0) {
            resp[body_len] = '\0';
            /* strip trailing whitespace (DuckDNS appends '\n') */
            char *end = resp + body_len - 1;
            while (end >= resp && (*end == '\n' || *end == '\r' || *end == ' '))
                *end-- = '\0';
        }

        if (strcasecmp(resp, "OK") == 0) {
            ESP_LOGI(TAG, "DuckDNS: update successful");
            err = ESP_OK;
        } else if (strcasecmp(resp, "KO") == 0) {
            ESP_LOGE(TAG, "DuckDNS: rejected (KO) — check token and subdomain");
            err = ESP_FAIL;
        } else {
            ESP_LOGW(TAG, "DuckDNS: unexpected response — %s", resp);
            err = ESP_FAIL;
        }
    } else if (err == ESP_OK) {
        ESP_LOGE(TAG, "DuckDNS: HTTP error %d", status);
        err = ESP_FAIL;
    } else {
        ESP_LOGE(TAG, "DuckDNS: request failed — %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    return err;
}

#endif /* CONFIG_DDNS_ENABLED */
