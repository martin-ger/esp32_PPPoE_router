# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

set(PROJECT_VER "2.4.7")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32_pppoe_router)

# Force esp_app_desc.c to recompile on every build so that
# __DATE__/__TIME__ in the app descriptor stay current.
set(APP_DESC_OBJ "${CMAKE_BINARY_DIR}/esp-idf/esp_app_format/CMakeFiles/__idf_esp_app_format.dir/esp_app_desc.c.obj")
add_custom_target(force_app_desc_rebuild ALL
    COMMAND ${CMAKE_COMMAND} -E remove -f "${APP_DESC_OBJ}"
    COMMENT "Ensuring app descriptor timestamp is current"
)
add_dependencies(${PROJECT_NAME}.elf force_app_desc_rebuild)

# NAPT table tuning: the default TCP timeout is 30 minutes, which causes the
# 512-entry table to fill up under normal use (ping keeps working because ICMP
# entries expire in 2 s).  Reduce TCP timeout to 5 minutes and double the table.
idf_component_get_property(lwip lwip COMPONENT_LIB)
target_compile_definitions(${lwip} PUBLIC
    IP_NAPT_MAX=1024
    IP_NAPT_TIMEOUT_MS_TCP=300000
)
# ethernet.c calls pppoe_disc_input/pppoe_data_input without a visible declaration;
# the compiler treats -Wimplicit-function-declaration as error in this toolchain version.
target_compile_options(${lwip} PRIVATE -Wno-implicit-function-declaration)
