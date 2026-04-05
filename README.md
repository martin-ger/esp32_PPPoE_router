# ESP32 PPPoE Router

An ESP32-based NAT WAN router for the **[WT32-ETH01](https://github.com/egnor/wt32-eth01)** board with a wired uplink. It can speak PPPoE directly to a WAN/DSL/cable modem, but it also supports DHCP for pure Ethernet uplink. Clients connect via WiFi (softAP). Includes a full web interface, firewall, DHCP reservations, port forwarding, and PCAP capture.

---

## Use Cases

- PPPoE DSL / cable-modem termination without a separate modem-router
- WiFi access point with wired uplink for reliable throughput
- Lightweight travel or lab router with per-client traffic monitoring and firewall

---

## Features

- PPPoE uplink over 802.3 Ethernet (PAP / CHAP / auto, optional VLAN tag)
- Stateless packet firewall with four ACL lists and hit counters
- DHCP server with IP reservations, client blocking, and static pool
- Port forwarding (TCP / UDP) with device-name resolution
- PCAP packet capture streamed to Wireshark over TCP (port 19000)
- Remote CLI console over TCP (password-protected)
- Remote syslog forwarding (UDP, RFC 3164)
- OTA firmware update via web interface
- Configuration import / export via web interface
- Optional per-client traffic statistics
- TTL override and TCP MSS clamping

---

## Hardware — WT32-ETH01

The WT32-ETH01 is a compact ESP32 module with an integrated LAN8720A Ethernet PHY, making it ideal as a wired-uplink router without an external MAC chip.

| Parameter | Value |
|-----------|-------|
| MCU | ESP32 (240 MHz dual-core) |
| Flash | 4 MB |
| Ethernet PHY | LAN8720A (RMII) |
| WiFi | 802.11 b/g/n 2.4 GHz |
| MDC GPIO | 23 |
| MDIO GPIO | 18 |
| PHY address | 1 |
| PHY power GPIO | 16 |

---

## Web Interface

Accessible at `http://192.168.4.1` (or the configured AP IP) from any device connected to the router's WiFi network. Port is configurable; default is 80.

### Pages

**/ — Status**

Live dashboard showing uplink state, uplink IP, byte counters, NAPT table usage, connected client list (with MAC, IP, device name, and optional per-client TX/RX), free heap, and uptime. Also contains the login form and password management.

**Configuration**

Full router configuration, split into sections:

- AP settings (SSID, password, channel, auth mode, hidden SSID, IP range, MAC)
- STA / uplink mode and settings (static IP)
- Remote console settings (port, timeout)
- Pcap monitoring settings (mode, snaplen)
- System settings (OTA update, save/restore settings)

**PPPoE**

PPPoE settings (username, password, service name, auth mode, VLAN, baby-jumbo)

**Mappings**

DHCP lease and reservation management, and port-forwarding rules:

- DHCP pool overview with active leases
- Add / delete IP reservations by MAC and device name
- Block a device from receiving an IP
- Add / delete TCP and UDP port-forwarding rules

**Firewall**

ACL rule management across all four packet-flow lists (`to_esp`, `from_esp`, `to_ap`, `from_ap`). Add rules with protocol, source/destination CIDR, ports, and allow/deny/monitor action. View per-rule hit counters and clear statistics.


### Password Protection

An optional password protects all pages except the status dashboard. Set via the web interface or `set_router_password`. Authentication uses SHA-256 with a 16-byte random salt. Sessions are cookie-based with a 30-minute idle timeout. Clearing the password opens all pages without authentication.

---

## WiFi and Network

### Uplink (Ethernet + PPPoE)

The Ethernet interface connects to a DSL or cable modem. PPPoE is negotiated on top of the Ethernet link. Configure credentials via the web interface or CLI:

```bash
set_pppoe -u <username> -p <password>          # ISP credentials
set_pppoe -a <0|1|2>                           # Auth: 0=auto, 1=PAP, 2=CHAP
set_pppoe -s <service>                         # Service name (optional)
set_pppoe -v <vlan_id>                         # 802.1Q VLAN tag (0=off)
set_pppoe -j <0|1>                             # Baby-jumbo frames (MSS 1460 vs 1452)
set_pppoe -e <0|1>                             # Enable / disable PPPoE
```

### AP (WiFi Clients)

```bash
set_ap <ssid> <password>                       # Configure AP (empty password = open)
set_ap_ip <ip>                                 # Change AP subnet (e.g. 192.168.4.1)
set_ap_dns <ip>                                # Custom DNS for clients (empty = upstream)
set_ap_auth <wpa2|wpa3|wpa2wpa3>              # Auth mode (requires restart)
set_ap_hidden <on|off>                         # Hide SSID (requires restart)
set_ap_channel <0-13>                          # 0 = auto (requires restart)
set_ap_nat <on|off>                            # Enable / disable NAT (requires restart)
ap <enable|disable>                            # Enable or disable AP immediately
```

### DHCP Reservations

Reserve a fixed IP for a device by MAC address. Reserved IPs are never handed to other devices.

```bash
dhcp_reserve add <mac> <ip> [-n <name>]        # Reserve IP for device
dhcp_reserve del <mac>                         # Remove reservation
dhcp_reserve block <mac> [-n <name>]           # Block device from getting any IP
```

### Port Forwarding

```bash
portmap add TCP <ext_port> <int_ip> <int_port> # Add TCP mapping
portmap add UDP <ext_port> <int_ip> <int_port> # Add UDP mapping
portmap del TCP <ext_port>                     # Delete TCP mapping
portmap del UDP <ext_port>                     # Delete UDP mapping
```

Device names from DHCP reservations can be used in place of IP addresses.

### Other Network Settings

```bash
set_sta_static <ip> <subnet> <gw>             # Static Ethernet WAN IP (PPPoE disabled only)
set_sta_static dhcp                           # Revert WAN to DHCP (requires restart)
set_ap_mac <xx:xx:xx:xx:xx:xx>               # Override AP MAC
set_hostname <name>                           # DHCP client hostname (max 32 chars)
set_ttl <0-255>                               # TTL override (0 = disabled)
set_tx_power <2-20|0>                         # WiFi TX power in dBm (0 = max/default)
```

### Firewall

The stateless firewall evaluates packets against one of four ordered ACL lists. First-match wins; unmatched packets are allowed by default.

**ACL lists:**

| List | Direction |
|------|-----------|
| `to_esp` | Internet → router (uplink inbound) |
| `from_esp` | Router → Internet (uplink outbound) |
| `to_ap` | WiFi clients → router |
| `from_ap` | Router → WiFi clients |

#### Rule Syntax (CLI)

```bash
acl <list> <proto> <src> [<sport>] <dst> [<dport>] <action>
```

**proto:** `ip`, `tcp`, `udp`, `icmp`

**address:** CIDR notation (`192.168.1.0/24`) or `any`

**port:** port number or `any` (TCP/UDP only; ignored for `ip`/`icmp`)

**action:** `allow`, `deny`, `allow_monitor` (allow + PCAP capture), `deny_monitor`

**Examples:**

```bash
acl to_esp TCP any any any 22 allow            # Allow SSH inbound to router
acl from_ap TCP any any any 443 deny           # Block HTTPS from AP clients
acl to_esp IP 10.0.0.0/8 any deny             # Drop RFC-1918 inbound
acl to_esp del 0                               # Delete rule at index 0
acl to_esp clear                               # Remove all rules from to_esp
show acl                                       # Show all lists and hit counts
```

### Packet Capture

Packets are streamed as a PCAP file over a TCP connection on port 19000. Open the stream directly in Wireshark: **File → Open → TCP connection**.

#### Capture Modes

| Mode | Behavior |
|------|----------|
| `off` | Capture disabled |
| `acl` | Only packets matching an ACL rule with the `monitor` flag |
| `promisc` | All traffic on the PPP/uplink interface |

```bash
pcap mode <off|acl|promisc>                    # Set capture mode
pcap snaplen <64-1600>                         # Max bytes per packet
pcap status                                    # Show current mode and stats
```

### Remote Console

Network-accessible CLI on TCP (default port 2323). Requires the router password to be set before enabling.

```bash
remote_console enable                          # Enable (requires password set)
remote_console disable                         # Disable
remote_console port <port>                     # Change TCP port (default 2323)
remote_console timeout <seconds>               # Idle timeout (0 = no timeout)
remote_console kick                            # Disconnect active session
remote_console status                          # Show status
```

Connect with `telnet <router_ip> 2323` or `nc <router_ip> 2323`.

### Syslog

Forward log messages to a remote syslog server (UDP, RFC 3164).

```bash
syslog enable <server_ip> [<port>]             # Enable (default port 514)
syslog disable                                 # Disable
syslog status                                  # Show configuration
```

---

## CLI Reference

Connect to the serial console at **115200 bps** or via the remote console.

### Network

| Command | Description |
|---------|-------------|
| `set_sta_static <ip> <sub> <gw>` | Static IP for Ethernet WAN (PPPoE disabled only) |
| `set_sta_static dhcp` | Revert WAN to DHCP (restart required) |
| `set_ap <ssid> [pass]` | Configure WiFi AP (empty pass = open) |
| `set_ap_ip <ip>` | Change AP subnet IP |
| `set_ap_dns [ip]` | DNS for AP clients (empty = upstream) |
| `set_ap_mac <mac>` | Override AP MAC address |
| `set_ap_nat <on\|off>` | Enable / disable NAT (restart required) |
| `set_ap_hidden <on\|off>` | Hide AP SSID (restart required) |
| `set_ap_auth <mode>` | AP auth: wpa2, wpa3, wpa2wpa3 (restart required) |
| `set_ap_channel <0-13>` | AP WiFi channel (0=auto, restart required) |
| `set_hostname [name]` | DHCP client hostname (empty = default) |
| `set_ttl [0-255]` | TTL override for upstream packets (0=off) |
| `set_tx_power [2-20\|0]` | WiFi AP TX power in dBm (0=max, applies immediately) |
| `ap [enable\|disable]` | Show or enable/disable AP immediately |

### PPPoE

| Command | Description |
|---------|-------------|
| `set_pppoe -u <user> -p <pass>` | Set ISP credentials |
| `set_pppoe -a <0\|1\|2>` | Auth: 0=auto, 1=PAP, 2=CHAP |
| `set_pppoe -s <service>` | Service name (optional) |
| `set_pppoe -v <vlan>` | VLAN tag (0=disabled) |
| `set_pppoe -j <0\|1>` | Baby-jumbo frames |
| `set_pppoe -e <0\|1>` | Enable / disable PPPoE |

### DHCP and Port Mapping

| Command | Description |
|---------|-------------|
| `dhcp_reserve add <mac> <ip> [-n <name>]` | Add DHCP reservation |
| `dhcp_reserve del <mac>` | Delete reservation |
| `dhcp_reserve block <mac> [-n <name>]` | Block device |
| `portmap add <TCP\|UDP> <ext> <ip> <int>` | Add port forwarding rule |
| `portmap del <TCP\|UDP> <ext_port>` | Delete port forwarding rule |

### Firewall

| Command | Description |
|---------|-------------|
| `show acl` | Show all four ACL lists with rules and hit counts |
| `acl <list> <proto> <src> [<sport>] <dst> [<dport>] <action>` | Add rule |
| `acl <list> del <index>` | Delete rule by index |
| `acl <list> clear` | Clear all rules in list |
| `acl <list> clear_stats` | Reset hit counters for list |

Lists: `to_esp`, `from_esp`, `to_ap`, `from_ap` — Protocols: `IP`, `TCP`, `UDP`, `ICMP` — Actions: `allow`, `deny`, `allow_monitor`, `deny_monitor`

### Packet Capture

| Command | Description |
|---------|-------------|
| `pcap mode [off\|acl\|promisc]` | Get / set capture mode |
| `pcap snaplen [<n>]` | Get / set max bytes per packet (64–1600) |
| `pcap status` | Show capture state |

### Remote Console and Syslog

| Command | Description |
|---------|-------------|
| `remote_console status` | Show remote console state |
| `remote_console enable` | Enable TCP console |
| `remote_console disable` | Disable TCP console |
| `remote_console port <port>` | Set TCP port |
| `remote_console timeout <sec>` | Set idle timeout |
| `remote_console kick` | Disconnect current session |
| `syslog enable <ip> [<port>]` | Enable remote syslog |
| `syslog disable` | Disable syslog |
| `syslog status` | Show syslog config |

### Web Interface

| Command | Description |
|---------|-------------|
| `web_ui enable` | Enable web interface (restart required) |
| `web_ui disable` | Disable web interface (restart required) |
| `web_ui port <port>` | Set HTTP port (restart required) |
| `set_router_password <pass>` | Set web / console password (empty = disable) |
| `web_ui wan_access enable` | Allows access to web interface and remote console from internet (wan port) |
| `web_ui wan_access disable` | Disables all management access from internet (wan port) |

### Status and System

| Command | Description |
|---------|-------------|
| `show status` | Connection, clients, NAPT usage, heap, uptime |
| `show config` | AP / PPPoE configuration |
| `show mappings` | DHCP pool, reservations, port forwarding |
| `show acl` | All four firewall ACL lists with hit counts |
| `show pppoe` | PPPoE link status and session details |
| `show ota` | OTA partition info |
| `bytes [reset]` | Show or reset WAN byte counters |
| `client_stats <enable\|disable>` | Per-client traffic stats |
| `ping <host> [-c <n>] [-i <ms>] [-W <ms>] [-s <bytes>]` | ICMP echo from the router |
| `heap` | Current and minimum free heap size |
| `version` | Chip model, IDF version, flash size |
| `log_level [<level>] [-t <tag>]` | Get/set log verbosity (none/error/warn/info/debug/verbose) |
| `set_tz [<TZ string>\|clear]` | Set timezone (POSIX, e.g. `CET-1CEST,M3.5.0,M10.5.0/3`) |
| `factory_reset` | Erase all settings and restart |
| `restart` | Restart the router |

### Hardware

| Command | Description |
|---------|-------------|
| `set_led_gpio <gpio\|none>` | Status LED GPIO pin (-1 / `none` = disabled) |
| `set_led_lowactive <on\|off>` | LED polarity (on = active-low/inverted) |

### MQTT / Home Assistant *(optional build feature)*

| Command | Description |
|---------|-------------|
| `mqtt status` | Show broker, connection state, device ID |
| `mqtt enable` | Enable and start MQTT client |
| `mqtt disable` | Disable MQTT client |
| `mqtt broker <uri>` | Set broker URI (e.g. `mqtt://192.168.1.2`) |
| `mqtt user <user> <pass>` | Set broker credentials |
| `mqtt interval <seconds>` | State publish interval (5–3600 s) |
| `mqtt rediscover` | Re-publish Home Assistant discovery configs |

---

## Security

### Management Interface Exposure

The web interface and remote console are accessible from the LAN (AP subnet) only by default. Any connection from outside the AP subnet is dropped at the TCP open callback. The same gate applies to both the web server and the remote console. The web server is additionally protected by an automatically inserted ACL rule, the remote console listens only an the AP interface. A connection is only allowed if:

1. The `wan_access` flag is enabled (opt-in, disabled by default), **or**
2. The client IP falls within the AP's /24 subnet.

Enable WAN access only if the router's management port is not reachable from the internet (e.g., in a local environmet or behind another NAT).

```bash
web_ui wan_access on    # Allow management from WAN (takes effect immediately for web interface, console after reboot)
web_ui wan_access off   # Restore LAN-only access immediately
```

### Authentication

A single shared password protects the web interface and the remote console. With no password set, the managment interface would be fully open. In this case wan access is generally prohibited.

**Password storage:** Passwords are stored in NVS as `salt_hex:hash_hex` — a 16-byte random salt followed by a SHA-256 hash of `salt || password`.

**Web sessions:** After login, the server issues a 31-character random hex token (drawn from `esp_random()`) as a session cookie. Sessions expire after 30 minutes of inactivity; activity resets the timer. Only one session exists at a time. The cookie is set with `SameSite=Strict` but without `HttpOnly` or `Secure` (no TLS).

**Remote console:** The console enforces a maximum of 3 failed login attempts per connection, after which the connection is dropped and a 5-second delay is imposed before reconnection. Failed attempts are logged and counted in `remote_console status`.

### Transport Security

Neither the web interface (HTTP) nor the remote console (plain TCP) are encrypted. Passwords and session tokens are transmitted in cleartext on the wire. This is acceptable on a trusted local WiFi network but means:

- The web session cookie and any passwords entered via the browser are visible to anyone with network access.
- The remote console password is visible in the TCP stream.

### Firewall

The stateless ACL firewall provides packet-level filtering across four traffic directions. No rules are installed by default — all traffic is allowed unless rules are explicitly added. 

See the [Firewall](#firewall) section for full rule syntax.

---

## Building

Prerequisites: ESP-IDF v5.5 or later with the `xtensa-esp32-elf` toolchain.

```bash
# Set target
idf.py set-target esp32

# Build
idf.py build
```

---

## Installation

Flash the firmware and monitor the boot log:

```bash
idf.py -p /dev/ttyUSB0 flash monitor
```

On first boot the router starts with default settings:

| Setting | Default |
|---------|---------|
| AP SSID | `ESP32_PPPoE_Router` |
| AP password | open |
| AP IP | `192.168.4.1` |
| Web interface | `http://192.168.4.1` |
| PPPoE | disabled |

Connect to the AP, open `http://192.168.4.1` (should be automated by captive portal), and configure the password, the PPPoE credentials and any other settings. Changes take effect after a restart (use the **Restart** button in the web interface or `restart` from the CLI).

To erase all settings and return to factory defaults:

```bash
factory_reset          # from CLI
# or
esptool.py erase_flash # full flash erase (also removes firmware)
```
