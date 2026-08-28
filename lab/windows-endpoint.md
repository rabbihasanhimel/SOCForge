# SOCForge: Windows 11 Endpoint Setup & Sysmon Pipeline

This document details the configuration of the monitored Windows 11 target endpoint (`OniNaruto`).

---

## 1. Specifications

- **OS:** Windows 11 Enterprise (64-bit)
- **Hostname:** `OniNaruto`
- **Agent ID:** `002`
- **IP Addresses:**
  - Host-Only Subnet: `192.168.56.105`
  - NAT Subnet: `10.0.3.15`

---

## 2. Microsoft Sysmon Installation

Sysmon v15.21 (Schema 4.90) is deployed as the primary endpoint detection sensor.

```powershell
# Install Sysmon with modular configuration
Sysmon64.exe -i sysmonconfig.xml -accepteula
```

---

## 3. Wazuh Agent EventChannel Integration

Configured in `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.56.104</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

Restart agent service:
```powershell
Restart-Service Wazuh
```
