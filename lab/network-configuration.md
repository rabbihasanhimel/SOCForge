# SOCForge: Network Configuration & Subnet Isolation

This document outlines the VirtualBox network configuration and host-only adapter settings.

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/f0705c89-19d3-47ec-baad-b3898628665e" />

---

## 1. Subnet Architecture

| Subnet | Purpose | Gateway / DHCP | Scope |
|:---|:---|:---|:---|
| **`192.168.56.0/24`** | Isolated Security Operations Lab | `192.168.56.1` (VirtualBox Host Adapter) | Static IPs (`.101`, `.104`, `.105`) |
| **`10.0.3.0/24`** | NAT Internet Access (Tools & Updates) | `10.0.3.2` | Isolated virtual NAT |

---

## 2. Static IP Allocations

```text
192.168.56.1   - VirtualBox Host Interface
192.168.56.101 - Kali Linux (Attacker)
192.168.56.104 - Ubuntu Server (Wazuh SIEM Manager)
192.168.56.105 - Windows 11 Enterprise (Monitored Endpoint)
```

---
<img width="620" height="250" alt="image" src="https://github.com/user-attachments/assets/0e483e50-83d8-4f6f-a97b-1ab555f0d09c" />

## 3. Network Verification Tests

```bash
# From Kali (192.168.56.101)
ping -c 2 192.168.56.104   # Wazuh Manager -> 0% packet loss
ping -c 2 192.168.56.105   # Windows Target -> 0% packet loss
```
