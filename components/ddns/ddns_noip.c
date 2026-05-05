/* ddns_noip.c — NoIP dynamic DNS provider adapter.
 *
 * SPDX-License-Identifier: MIT
 */

#include "sdkconfig.h"
#ifdef CONFIG_DDNS_ENABLED

#include "ddns.h"
#include "ddns_providers.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "mbedtls/base64.h"

static const char *TAG = "ddns_noip";

#define NOIP_API_HOST "dyn.update.no-ip.com"

/*
 * Build a "Basic <base64>" Authorization header value.
 *
 * Worst-case input: DDNS_MAX_TOKEN-1 (127) + ':' + DDNS_MAX_PASS-1 (63) = 191 bytes.
 * base64(191) = ceil(191/3)*4 = 256 bytes (no null from mbedtls).
 * out must be at least 264 bytes ("Basic " + 256 + '\0').
 * Returns 0 on success, -1 on mbedtls error.
 */
static int noip_build_auth(char *out, size_t out_len,
                            const char *user, const char *pass)
{
    /* raw = "user:pass" — max 191 bytes, fits in 256 */
    uint8_t raw[256];
    int raw_len = snprintf((char *)raw, sizeof(raw), "%s:%s", user, pass);
    if (raw_len < 0 || raw_len >= (int)sizeof(raw)) {
        raw_len = (int)sizeof(raw) - 1;
    }

    /*
     * b64 buffer: ceil(191/3)*4 = 256 encoded bytes + 1 null = 257.
     * Use 260 for a comfortable margin.
     */
    uint8_t b64[260];
    size_t b64_len = 0;
    int rc = mbedtls_base64_encode(b64, sizeof(b64) - 1, &b64_len,
                                   raw, (size_t)raw_len);
    if (rc != 0) {
        ESP_LOGE(TAG, "base64 encode failed: %d (credentials too long?)", rc);
        return -1;
    }
    b64[b64_len] = '\0';

    snprintf(out, out_len, "Basic %s", (char *)b64);
    return 0;
}

esp_err_t noip_update(uint32_t wan_ip, const char *hostname,
                      const char *user, const char *pass,
                      char *resp, size_t resp_len)
{
    if (!hostname || !user) {
        ESP_LOGE(TAG, "NoIP: missing hostname or user");
        return ESP_ERR_INVALID_ARG;
    }

    char ip_str[16];
    esp_ip4addr_ntoa((esp_ip4_addr_t *)&wan_ip, ip_str, sizeof(ip_str));

    /* URL-encode hostname to prevent query-param injection */
    char enc_host[256];
    url_encode(hostname, enc_host, sizeof(enc_host));

    char url[320];
    snprintf(url, sizeof(url),
             "https://" NOIP_API_HOST "/nic/update?hostname=%s&myip=%s",
             enc_host, ip_str);

    /* "Basic " (6) + base64(191 bytes) (256) + '\0' = 263 bytes needed */
    char auth[270];
    if (noip_build_auth(auth, sizeof(auth), user, pass) != 0) {
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Updating NoIP: host=%s ip=%s", hostname, ip_str);

    esp_http_client_config_t config = {
        .url                     = url,
        .method                  = HTTP_METHOD_GET,
        .crt_bundle_attach       = esp_crt_bundle_attach,
        .skip_cert_common_name_check = 0,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "NoIP: HTTP client init failed");
        return ESP_FAIL;
    }

    esp_http_client_set_header(client, "Authorization", auth);
    esp_http_client_set_header(client, "User-Agent", "ESP32-DDNS/1.0");
    esp_http_client_set_header(client, "Accept", "text/plain");

    esp_err_t err = esp_http_client_perform(client);
    int status = err == ESP_OK ? esp_http_client_get_status_code(client) : 0;

    if (err == ESP_OK && status == 200) {
        int body_len = (int)esp_http_client_read_response(client, resp, resp_len - 1);
        if (body_len > 0) {
            resp[body_len] = '\0';
        }

        if (strstr(resp, "good") != NULL) {
            ESP_LOGI(TAG, "NoIP: update successful — %s", resp);
            err = ESP_OK;
        } else if (strstr(resp, "nochg") != NULL) {
            ESP_LOGI(TAG, "NoIP: no change needed — %s", resp);
            err = ESP_OK;
        } else {
            ESP_LOGW(TAG, "NoIP: unexpected response — %s", resp);
            err = ESP_FAIL;
        }
    } else if (err == ESP_OK) {
        ESP_LOGE(TAG, "NoIP: HTTP error %d", status);
        err = ESP_FAIL;
    } else {
        ESP_LOGE(TAG, "NoIP: request failed — %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    return err;
}

#endif /* CONFIG_DDNS_ENABLED */
