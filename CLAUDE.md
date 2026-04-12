# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Code Exploration Policy
Always use jCodemunch-MCP tools — never fall back to Read, Grep, Glob, or Bash for code exploration.
- Before reading a file: use get_file_outline or get_file_content
- Before searching: use search_symbols or search_text
- Before exploring structure: use get_file_tree or get_repo_outline
- Call resolve_repo with the current directory first; if not indexed, call index_folder.

---

## Project Overview

ESP32 PPPoE/NAT router firmware for the **WT32-ETH01** board (ESP32 + LAN8720A Ethernet PHY). Clients connect via WiFi softAP. Key capabilities: PPPoE uplink, stateless firewall (ACL), DHCP with reservations, port forwarding, WireGuard VPN, optional PCAP capture, remote console, and MQTT/Home Assistant telemetry.

Build system: **ESP-IDF v5.5**, target `esp32`. Commands: `idf.py build`, `idf.py menuconfig`, `idf.py -p /dev/ttyUSBx flash monitor`.

---

## Directory Layout

```
main/
  esp32_nat_router.c   — app_main, init sequence, NVS load, event loop
  netif_hooks.c        — lwIP netif input/linkoutput hooks: ACL, PCAP, TTL, MSS, byte counting
  pppoe_manager.c      — PPPoE connect/disconnect lifecycle
  vpn_manager.c        — WireGuard VPN connect/disconnect, kill switch, subnet cache
  dhcp_manager.c       — DHCP reservation and client-block management
  portmap.c            — Port-forwarding table (TCP/UDP NAPT extension)
  Kconfig.projbuild    — Project-level Kconfig (uplink type, MQTT)

components/
  pcap_capture/        — PCAP ring buffer + TCP server (port 19000)
  cmd_router/          — All CLI commands (argtable2-based)
  http_server/         — Web interface (chunked HTTP, pages as C header macros)
    pages/             — Per-page HTML template macros (page_*.h)
  acl/                 — Firewall ACL engine + NVS persistence
  dhcpserver/          — Modified lwIP DHCP server
  remote_console/      — TCP CLI console (port 2323)
  syslog/              — UDP syslog client (RFC 3164)
  mqtt_ha/             — MQTT Home Assistant integration
  lwip_pppoe/          — PPPoE patches / lwIP config
```

---

## Conditional Compile Flags

| Symbol | Default | Effect |
|--------|---------|--------|
| `CONFIG_PCAP_CAPTURE` | **n** | PCAP TCP server, `pcap` CLI command, PCAP config-page section, `allow_monitor`/`deny_monitor` ACL actions. Kconfig in `components/pcap_capture/Kconfig`. |
| `CONFIG_MQTT_HOMEASSISTANT` | y | MQTT broker integration and Home Assistant discovery. |
| `CONFIG_ETH_UPLINK` | y (WT32) | Ethernet uplink (LAN8720A). When off, WiFi STA uplink is used instead. |

When adding features that consume significant RAM or flash, consider wrapping them in a Kconfig option following the `CONFIG_PCAP_CAPTURE` pattern: guard the `.c` files at the top with `#if CONFIG_FOO`, provide `static inline` no-op stubs in the header's `#else` block, and wrap all UI/CLI references explicitly.

---

## Key Architecture Patterns

### Packet Path (netif_hooks.c)
lwIP `netif->input` and `netif->linkoutput` are replaced with hook functions at runtime. The hooks run on every packet in the data path and are placed in IRAM (`IRAM_ATTR`). Order per hook: ACL check → optional PCAP capture → byte counting → call original function.

For PPPoE/PPP, `ip4_input` is intercepted via `--wrap=ip4_input` (linker flag in `main/CMakeLists.txt`) because the PPP netif calls `ip4_input` directly, bypassing `netif->input`.

### NVS Storage
All persistent config lives in the `nvs` NVS namespace. Load at boot in `esp32_nat_router.c`. Write immediately on change (no deferred save). Keys are short strings (max 15 chars).

### Web Interface
Pages are rendered as chunked HTTP responses. HTML is defined as C preprocessor macros in `components/http_server/pages/page_*.h`. `snprintf` fills `%s`/`%d` placeholders into a stack/heap buffer, then `httpd_resp_send_chunk` streams it. No templating engine.

### ACL Monitor Flag
`ACL_MONITOR` (0x02) is a flag bit OR'd with the allow/deny action byte in `acl_entry_t.allow`. It is stored in NVS and persists across reboots. When `CONFIG_PCAP_CAPTURE` is disabled, the flag may still exist in saved rules but is silently ignored — no CLI actions produce it and no capture occurs.

### WireGuard VPN
Uses `esp_wireguard` component. In route-all mode, `esp_wireguard_set_default()` replaces the default route with the WireGuard netif after connect. Kill switch is enforced in `ap_netif_input_hook` by dropping non-local packets when `vpn_enabled && vpn_killswitch && !vpn_is_connected()`. MTU/MSS are recalculated on every connect/disconnect.

---

## Build Notes

- IRAM placement: hot-path functions in `netif_hooks.c`, `acl.c`, `pcap_capture.c`, and PPPoE/NAPT framing are placed in IRAM via `IRAM_ATTR` or the linker fragment `pppoe_napt_iram.lf`.
- `PPPOE_SUPPORT=1`, `ETHARP_SUPPORT_VLAN=1`, and `PBUF_LINK_HLEN=18` are injected as PUBLIC compile definitions from `main/CMakeLists.txt` so all components see consistent lwIP settings.
- The project uses `partitions_example.csv` for the partition table (4 MB flash, OTA-capable).
