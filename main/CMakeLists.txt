set(main_priv_requires
    pcap_capture esp_wifi esp_netif console nvs_flash driver esp_http_server
    fatfs cmd_router dhcpserver wpa_supplicant cmd_system acl remote_console
    syslog json esp_eth http_server mqtt_ha app_update esp_wireguard ddns)
list(APPEND main_priv_requires espressif__mdns)

idf_component_register(SRCS "esp32_nat_router.c"
                            "portmap.c"
                            "dhcp_manager.c"
                            "pppoe_manager.c"
                            "netif_hooks.c"
                            "vpn_manager.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES ${main_priv_requires})

# PPPoE support: enable lwIP PPPOE and VLAN tag stripping.
# These defines propagate to all components that depend on main (including lwip)
# via the PUBLIC keyword. Both use #ifndef guards in lwIP headers.
target_compile_definitions(${COMPONENT_LIB} PUBLIC PPPOE_SUPPORT=1 ETHARP_SUPPORT_VLAN=1 PBUF_LINK_HLEN=18)

# Wrap ip4_input so the PPP netif receive path (which calls ip4_input directly,
# bypassing netif->input) can be intercepted for byte counting and ACL.
target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=ip4_input")

# Place PPPoE framing and NAPT table functions in IRAM (hot path, every packet).
# CONFIG_LWIP_IRAM_OPTIMIZATION already covers ip4_input/output, ethernet I/O,
# pbuf ops and UDP; pppoe.c and ip4_napt.c are not included in that list.
idf_build_set_property(LDFRAGMENTS "${CMAKE_CURRENT_LIST_DIR}/pppoe_napt_iram.lf" APPEND)

target_compile_options(__idf_main PRIVATE -O2)
