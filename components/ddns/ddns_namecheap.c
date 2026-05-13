/* ddns_namecheap.c — Namecheap FreeDNS provider adapter.
 *
 * Namecheap offers free DDNS for domains hosted on their BasicDNS or FreeDNS
 * nameservers. Uses the DynDNS-compatible GET endpoint at dynamicdns.park-your-domain.com.
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

static const char *TAG = "ddns_namecheap";

#define NAMECHEAP_API_HOST "dynamicdns.park-your-domain.com"

/*
 * Split a Namecheap FQDN (host.domain.tld) into host and domain parts.
 * Writes to out_host and out_domain (caller-allocated, max DDNS_MAX_HOSTNAME each).
 * Returns ESP_OK on success, ESP_FAIL otherwise.
 */
static esp_err_t namecheap_fqdn_split(const char *fqdn,
                                       char *out_host, size_t host_len,
                                       char *out_domain, size_t domain_len)
{
    if (!fqdn || !out_host || !out_domain) return ESP_ERR_INVALID_ARG;

    /* Split on first dot: host.domain.tld -> host="host", domain="domain.tld" */
    const char *first_dot = strchr(fqdn, '.');
    if (!first_dot || first_dot == fqdn) {
        ESP_LOGE(TAG, "Namecheap: invalid FQDN (need host.domain.tld): %s", fqdn);
        return ESP_FAIL;
    }

    size_t host_len_req = (size_t)(first_dot - fqdn);
    if (host_len_req >= host_len) {
        ESP_LOGE(TAG, "Namecheap: host name too long");
        return ESP_FAIL;
    }
    memcpy(out_host, fqdn, host_len_req);
    out_host[host_len_req] = '\0';

    snprintf(out_domain, domain_len, "%s", first_dot + 1);

    return ESP_OK;
}

esp_err_t namecheap_update(uint32_t wan_ip, const char *fqdn,
                            const char *pass,
                            char *resp, size_t resp_len)
{
    if (!fqdn) {
        ESP_LOGE(TAG, "Namecheap: missing FQDN");
        return ESP_ERR_INVALID_ARG;
    }

    char ip_str[16];
    esp_ip4addr_ntoa((esp_ip4_addr_t *)&wan_ip, ip_str, sizeof(ip_str));

    /* Split fqdn into host and domain parts */
    char host[128];
    char domain[128];
    if (namecheap_fqdn_split(fqdn, host, sizeof(host), domain, sizeof(domain)) != ESP_OK) {
        ESP_LOGE(TAG, "Namecheap: cannot parse FQDN %s", fqdn);
        return ESP_FAIL;
    }

    /* URL-encode host, domain, and password to prevent query-param injection */
    char enc_host[256];
    char enc_domain[256];
    char enc_pass[192];
    url_encode(host, enc_host, sizeof(enc_host));
    url_encode(domain, enc_domain, sizeof(enc_domain));
    url_encode(pass, enc_pass, sizeof(enc_pass));

    char url[768];
    snprintf(url, sizeof(url),
             "https://" NAMECHEAP_API_HOST "/update?host=%s&domain=%s&password=%s&ip=%s",
             enc_host, enc_domain, enc_pass, ip_str);

    ESP_LOGI(TAG, "Updating Namecheap: host=%s domain=%s ip=%s", host, domain, ip_str);

    esp_http_client_config_t config = {
        .url                       = url,
        .method                    = HTTP_METHOD_GET,
        .crt_bundle_attach         = esp_crt_bundle_attach,
        .skip_cert_common_name_check = 0,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "Namecheap: HTTP client init failed");
        return ESP_FAIL;
    }

    esp_http_client_set_header(client, "User-Agent", "ESP32-DDNS/1.0");
    esp_http_client_set_header(client, "Accept", "text/plain");

    esp_err_t err = esp_http_client_perform(client);
    int status = err == ESP_OK ? esp_http_client_get_status_code(client) : 0;

    if (err == ESP_OK && status == 200) {
        int body_len = (int)esp_http_client_read_response(client, resp, resp_len - 1);
        if (body_len > 0) {
            resp[body_len] = '\0';
        }

        char resp_upper[128];
        snprintf(resp_upper, sizeof(resp_upper), "%s", resp);
        for (char *p = resp_upper; *p; p++) *p = (char)toupper((unsigned char)*p);

        if (strstr(resp_upper, "SUCCESS") != NULL) {
            ESP_LOGI(TAG, "Namecheap: update successful — %s", resp);
            err = ESP_OK;
        } else if (strstr(resp_upper, "FAILURE") != NULL) {
            ESP_LOGE(TAG, "Namecheap: update failed — %s", resp);
            err = ESP_FAIL;
        } else {
            ESP_LOGW(TAG, "Namecheap: unexpected response — %s", resp);
            err = ESP_FAIL;
        }
    } else if (err == ESP_OK && status == 401) {
        ESP_LOGE(TAG, "Namecheap: authentication failed (401) — check credentials");
        err = ESP_FAIL;
    } else if (err == ESP_OK && status == 500) {
        ESP_LOGE(TAG, "Namecheap: domain not hosted on Namecheap nameservers (500)");
        err = ESP_FAIL;
    } else if (err == ESP_OK) {
        ESP_LOGE(TAG, "Namecheap: HTTP error %d", status);
        err = ESP_FAIL;
    } else {
        ESP_LOGE(TAG, "Namecheap: request failed — %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    return err;
}

#endif /* CONFIG_DDNS_ENABLED */
