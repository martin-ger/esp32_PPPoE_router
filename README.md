# ESP32 PPPoE Router

An ESP32-based NAT WAN router for the **[WT32-ETH01](https://github.com/egnor/wt32-eth01)** board with a wired uplink. It can speak PPPoE directly to a WAN/DSL/cable modem, but it also supports DHCP for pure Ethernet uplink. Clients connect via WiFi (softAP). Includes a full web interface, firewall, DHCP reservations, port forwarding, WireGuard VPN, and optional PCAP capture.

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
- WireGuard VPN client (route-all or split-tunnel, kill switch, VPN-bound port maps)
- Dynamic DNS (DDNS) with automatic WAN IP registration — supports NoIP, DuckDNS, Selfhost.de, Dynu, and Namecheap
- PCAP packet capture streamed to Wireshark over TCP — optional build feature, disabled by default
- Remote CLI console over TCP (password-protected)
- Remote syslog forwarding (UDP, RFC 3164)
- OTA firmware update via web interface
- Configuration backup / restore via web interface (plain JSON or passphrase-encrypted)
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
- PCAP monitoring settings (mode, snaplen) — only shown when built with `CONFIG_PCAP_CAPTURE`
- System settings (OTA update, config backup / restore)

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

**VPN**

WireGuard configuration: private key, peer public key, optional preshared key, endpoint host and port, tunnel IP, netmask, persistent keepalive, route-all / split-tunnel toggle, and kill switch. Also shows live connection state, tunnel IP, and MSS/PMTU values.

**DDNS**

Dynamic DNS configuration page (only shown when built with `CONFIG_DDNS_ENABLED=y`). Provides provider selection (NoIP, DuckDNS, Selfhost.de, Dynu, Namecheap), hostname/subdomain, credentials or token fields (shown/hidden per provider), keep-alive interval (hours), and a "Trigger Update" button for immediate DNS push. Live status (enabled/disabled, provider, last-update timestamp, last-reported WAN IP) is displayed.

### Password Protection

An optional password protects all pages except the status dashboard. Set via the web interface or `set_router_password`. Authentication uses SHA-256 with a 16-byte random salt. Sessions are cookie-based with a 30-minute idle timeout. Clearing the password opens all pages without authentication.

### Config Backup / Restore

The **Configuration** page exports the full NVS config as a JSON file and can import it back.

**Export — two modes depending on whether a passphrase is entered:**

| Export type | WiFi passwords | WireGuard private key + PSK | PPPoE password |
|-------------|----------------|-----------------------------|----------------|
| Plain (no passphrase) | included | **omitted** | **omitted** |
| Encrypted (passphrase) | included | included | included |

Encrypted exports use XChaCha20-Poly1305 AEAD with a 32-byte key derived from the passphrase via PBKDF2-HMAC-SHA256 (10 000 iterations, 16-byte random salt). The ciphertext is wrapped in a JSON envelope `{"enc":1,"s":"…","n":"…","c":"…"}` so encrypted and plain files share the same `.json` extension and the import handler detects the format automatically.

**Import:** if the file is encrypted, enter the passphrase in the *Import* passphrase field before choosing the file. A wrong passphrase is rejected by the authentication tag before any NVS keys are touched.

Both endpoints (`/api/config-export`, `/api/config-import`) require an active session when password protection is enabled and are guarded by the CSRF Origin check.

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

### WireGuard VPN

A WireGuard client tunnel that protects all AP client traffic. Two routing modes are supported:

| Mode | Behaviour |
|------|-----------|
| **Route-all** | All AP client traffic is sent through the tunnel. The WireGuard netif becomes the default route. |
| **Split tunnel** | Only traffic destined for the configured VPN subnet is sent through the tunnel; everything else goes directly to the WAN. |

A **kill switch** can be enabled to block all non-local AP traffic whenever the VPN is enabled but not yet connected, preventing internet leakage during reconnection. Port-forwarding rules can be flagged as VPN-bound so they activate only while the tunnel is up.

MTU and MSS are adjusted automatically to account for WireGuard overhead (60 bytes: 20 IP + 8 UDP + 16 WireGuard header + 16 authentication tag).

### Dynamic DNS (DDNS)

Automatically registers your WAN (PPPoE) IP address with a dynamic DNS provider when the uplink comes up or when the WAN IP changes. All connections use HTTPS.

Supported providers:

| Provider | Setup |
|------|------|
| **NoIP** | Username, password, full FQDN |
| **DuckDNS** | Subdomain name, authentication token |
| **Selfhost.de** | Username, password (DynAccount credentials — no hostname needed) |
| **Dynu** | Username, password (DynAccount credentials — no hostname needed) |
| **Namecheap** | API key or password, full hostname |

When DDNS is enabled the router automatically updates the DNS record:

- **Immediately** on every PPPoE connect
- **Periodically** at the configured keep-alive interval (default 24 h) — unconditional re-registration regardless of IP change, satisfying NoIP's 30-day keepalive requirement

Configuration is accessed via the web interface (**DDNS** page) or CLI:

```bash
# Enable DDNS
ddns enable 1

# Select provider (0=NoIP, 1=DuckDNS, 2=Selfhost.de, 3=Dynu, 4=Namecheap)
ddns provider 1

# NoIP: set hostname, username and password
ddns hostname myhost.no-ip.org
ddns token myusername
ddns password mypassword

# DuckDNS: set subdomain and token
ddns token 12345-abcde-token

# Selfhost.de: set username and password (DynAccount credentials)
ddns token myusername
ddns password mypassword

# Dynu: set username and password (DynAccount credentials)
ddns token myusername
ddns password mypassword

# Namecheap: set hostname and API key or password
ddns hostname example.com
ddns token my-api-key-or-password
ddns poll 24

# Trigger an immediate update
ddns update

# Show current DDNS status
ddns status
```

Home Assistant sensors are published automatically (status, provider, hostname, last-update timestamp).

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

**action:** `allow`, `deny`, `allow_monitor` (allow + PCAP capture), `deny_monitor` — monitor actions available only when `CONFIG_PCAP_CAPTURE` is enabled

**Examples:**

```bash
acl to_esp TCP any any any 22 allow            # Allow SSH inbound to router
acl from_ap TCP any any any 443 deny           # Block HTTPS from AP clients
acl to_esp IP 10.0.0.0/8 any deny             # Drop RFC-1918 inbound
acl to_esp del 0                               # Delete rule at index 0
acl to_esp clear                               # Remove all rules from to_esp
show acl                                       # Show all lists and hit counts
```

### Packet Capture *(optional build feature)*

> **Disabled by default.** Enable with `idf.py menuconfig` → *PCAP Capture* → *Enable PCAP packet capture* (`CONFIG_PCAP_CAPTURE=y`). When disabled, the TCP server task and ring buffer are omitted and the PCAP section does not appear in the web interface or CLI.

Packets are streamed as a live PCAP file over a TCP connection on port 19000, bound to the AP interface only (never exposed on the WAN). Open the stream directly in Wireshark:

```bash
nc <router_ap_ip> 19000 | wireshark -k -i -
```

#### Capture Modes

| Mode | Behaviour |
|------|-----------|
| `off` | Capture disabled |
| `acl` | Only packets matching an ACL rule with `allow_monitor` or `deny_monitor` |
| `promisc` | All traffic passing through the PPP/Ethernet uplink interface |

In `acl` mode, adding `allow_monitor` or `deny_monitor` as the action on a firewall rule causes matching packets to be captured regardless of the global mode, making it easy to watch specific hosts or ports.

```bash
pcap mode <off|acl|promisc>                    # Set capture mode
pcap snaplen <64-1600>                         # Max bytes per packet (default 64/96)
pcap status                                    # Show mode, client, and packet stats
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

Lists: `to_esp`, `from_esp`, `to_ap`, `from_ap` — Protocols: `IP`, `TCP`, `UDP`, `ICMP` — Actions: `allow`, `deny`; also `allow_monitor`, `deny_monitor` when `CONFIG_PCAP_CAPTURE` is enabled

### WireGuard VPN

| Command | Description |
|---------|-------------|
| `show vpn` | VPN status and full configuration |
| `set_vpn <privkey>` | Set private key (base64) |
| `set_vpn <pubkey>` | Set peer public key (base64) |
| `set_vpn <endpoint>` | Set peer host / IP |
| `set_vpn <address>` | Set tunnel IP address |
| `set_vpn -m <netmask>` | Tunnel netmask (default 255.255.255.0) |
| `set_vpn -p <port>` | Peer UDP port (default 51820) |
| `set_vpn -a <seconds>` | Persistent keepalive (0 = disabled) |
| `set_vpn -k <psk>` | Preshared key (base64, optional) |
| `set_vpn -e <0|1>` | Enable / disable VPN |
| `set_vpn -K <0|1>` | Kill switch on/off |
| `set_vpn -R <0|1>` | 1 = route-all, 0 = split tunnel |

### Dynamic DNS (CONFIG_DDNS_ENABLED)

| Command | Description |
|---------|-------------|
| `ddns status` | Show current DDNS config and status |
| `ddns enable <0|1>` | Toggle DDNS |
| `ddns provider <0-4>` | Select provider: 0=NoIP, 1=DuckDNS, 2=Selfhost.de, 3=Dynu, 4=Namecheap |
| `ddns hostname <fqdn>` | Set hostname (or subdomain for DuckDNS) |
| `ddns token <token>` | Set token (DuckDNS), username (NoIP/Selfhost.de/Dynu), or API key/password (Namecheap) |
| `ddns password <pw>` | Set password (NoIP/Selfhost.de/Dynu) |
| `ddns poll <hours>` | Set keep-alive interval (1–168 hours, default 24) |
| `ddns update` | Trigger an immediate DDNS update |

### Packet Capture *(CONFIG_PCAP_CAPTURE)*

| Command | Description |
|---------|-------------|
| `pcap mode [off\|acl\|promisc]` | Get / set capture mode |
| `pcap snaplen [<n>]` | Get / set max bytes per packet (64–1600) |
| `pcap status` | Show capture state, client, and packet counts |

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

Home Assistant auto-discovers these entities (when enabled):

| Entity | Type | Description |
|---------|---------|-----------|
| WAN IP | sensor | Current WAN IP address |
| Up link | binary sensor | Uplink connectivity status |
| PPPoE | binary sensor | PPPoE session state |
| Web UI | switch | Enable / disable web interface |
| Remote Console | switch | Enable / disable remote console |
| Restart | button | Trigger router restart |
(All entities publish to the shared router state topic alongside uplink, client count, byte counters, heap, uptime, and WAN IP.)

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

## Building

Prerequisites: ESP-IDF v5.5 or later with the `xtensa-esp32-elf` toolchain.

```bash
# Set target
idf.py set-target esp32

# (Optional) configure build-time features
idf.py menuconfig

# Build
idf.py build
```

### Build-time Options

| Kconfig symbol | Default | Description |
|-----|---------|-----|
| `CONFIG_PCAP_CAPTURE` | **off** | Enable live PCAP capture over TCP. Adds ~16–32 KB RAM for the ring buffer and a TCP server task. When off, the `pcap` CLI command and PCAP config page are absent and `allow_monitor`/`deny_monitor` ACL actions are unavailable. |
| `CONFIG_MQTT_HOMEASSISTANT` | on | Publish router telemetry to an MQTT broker with Home Assistant auto-discovery. Adds ~58 KB flash; RAM is used only when a broker is configured. |
| `CONFIG_DDNS_ENABLED` | **off** | Enable Dynamic DNS client for automatic WAN IP registration with NoIP, DuckDNS, Selfhost.de, Dynu, or Namecheap. All five providers are compiled; the default provider is selected at config time. Uses HTTPS (TLS) for all API calls. |

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
