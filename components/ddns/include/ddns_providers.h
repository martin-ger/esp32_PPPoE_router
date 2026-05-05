/* ddns_providers.h — Common interface for DDNS provider adapters.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stddef.h>
#include <ctype.h>
#include <stdio.h>
#include "esp_err.h"

/* Percent-encode a string for safe inclusion in a URL query parameter. */
static inline void url_encode(const char *in, char *out, size_t out_len)
{
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 4 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out[j++] = (char)c;
        } else {
            snprintf(out + j, out_len - j, "%%%02X", c);
            j += 3;
        }
    }
    out[j] = '\0';
}

/* NoIP — hostname (FQDN), user (in token), password */
esp_err_t noip_update(uint32_t wan_ip, const char *hostname,
                      const char *user, const char *pass,
                      char *resp, size_t resp_len);

/* DuckDNS — subdomain (in hostname), token (in token) */
esp_err_t duckdns_update(uint32_t wan_ip, const char *subdomain,
                         const char *token, char *resp, size_t resp_len);

/* Selfhost.de — hostname (FQDN), token */
esp_err_t selfhost_update(uint32_t wan_ip, const char *hostname,
                          const char *token, char *resp, size_t resp_len);
