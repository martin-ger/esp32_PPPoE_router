/* ddns_selfhost.c — Selfhost.de provider adapter.
 *
 * SPDX-License-Identifier: MIT
 */

#include "sdkconfig.h"
#ifdef CONFIG_DDNS_ENABLED

#include "ddns.h"
#include "ddns_providers.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"

static const char *TAG = "ddns_selfhost";

#define SELFHOST_API_HOST "carol.selfhost.de"

static void str_lower(char *s)
{
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

esp_err_t selfhost_update(uint32_t wan_ip, const char *hostname,
                          const char *user, const char *pass,
                          char *resp, size_t resp_len)
{
    if (!user || !pass) {
        ESP_LOGE(TAG, "Selfhost: missing username or password");
        return ESP_ERR_INVALID_ARG;
    }

    char ip_str[16];
    esp_ip4addr_ntoa((esp_ip4_addr_t *)&wan_ip, ip_str, sizeof(ip_str));

    /* URL-encode credentials to prevent query-param injection */
    char enc_user[256];
    char enc_pass[256];
    url_encode(user, enc_user, sizeof(enc_user));
    url_encode(pass, enc_pass, sizeof(enc_pass));

    /* hostname=1 requests dyndns.org-compatible response ("good"/"nochg") */
    char url[640];
    snprintf(url, sizeof(url),
             "https://" SELFHOST_API_HOST "/update?username=%s&password=%s&myip=%s&hostname=1",
             enc_user, enc_pass, ip_str);

    ESP_LOGI(TAG, "Updating Selfhost.de: user=%s ip=%s", user, ip_str);

    esp_http_client_config_t config = {
        .url                     = url,
        .method                  = HTTP_METHOD_GET,
        .crt_bundle_attach       = esp_crt_bundle_attach,
        .skip_cert_common_name_check = 0,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "Selfhost: HTTP client init failed");
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
        }

        char resp_lower[128];
        snprintf(resp_lower, sizeof(resp_lower), "%s", resp);
        str_lower(resp_lower);

        if (strstr(resp_lower, "good") != NULL) {
            ESP_LOGI(TAG, "Selfhost: update successful — %s", resp);
            err = ESP_OK;
        } else if (strstr(resp_lower, "nochg") != NULL) {
            ESP_LOGI(TAG, "Selfhost: no change needed — %s", resp);
            err = ESP_OK;
        } else {
            ESP_LOGW(TAG, "Selfhost: unexpected response — %s", resp);
            err = ESP_FAIL;
        }
    } else if (err == ESP_OK && status == 401) {
        ESP_LOGE(TAG, "Selfhost: authentication failed (401) — check username and password");
        err = ESP_FAIL;
    } else if (err == ESP_OK && status == 403) {
        ESP_LOGE(TAG, "Selfhost: account blocked (403)");
        err = ESP_FAIL;
    } else if (err == ESP_OK) {
        ESP_LOGE(TAG, "Selfhost: HTTP error %d", status);
        err = ESP_FAIL;
    } else {
        ESP_LOGE(TAG, "Selfhost: request failed — %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    return err;
}

#endif /* CONFIG_DDNS_ENABLED */
