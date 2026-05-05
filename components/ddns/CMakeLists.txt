idf_component_register(
    SRCS "ddns_noip.c" "ddns_duckdns.c" "ddns_selfhost.c" "ddns.c"
    INCLUDE_DIRS "include" "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/components/acl/include"
    PRIV_REQUIRES esp_http_client esp_timer nvs_flash esp_wifi mbedtls
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-format-truncation)
target_compile_options(${COMPONENT_LIB} PRIVATE -Os)
