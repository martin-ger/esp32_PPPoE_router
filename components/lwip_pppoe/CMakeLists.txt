# Thin component to inject PPPOE_SUPPORT and ETHARP_SUPPORT_VLAN into lwIP.
#
# ESP-IDF's lwIP Kconfig doesn't expose these options. Both use #ifndef guards
# in ppp_opts.h / opt.h, so -D flags take precedence.
#
# We add the defines to the lwip component target directly so they apply
# when lwIP source files (pppoe.c, pppapi.c, etc.) are compiled.

idf_component_register()

# Inject into lwIP's own compilation units
idf_build_get_property(build_components BUILD_COMPONENTS)
if("lwip" IN_LIST build_components)
    target_compile_definitions(__idf_lwip PUBLIC PPPOE_SUPPORT=1 ETHARP_SUPPORT_VLAN=1 PBUF_LINK_HLEN=18)
endif()
