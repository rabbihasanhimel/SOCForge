# SOCForge: Architecture & Network Topology

This document details the virtual security operations center (SOC) architecture, isolated subnet topology, host specifications, and the end-to-end security telemetry pipeline.

---
<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/43b50633-68e7-4a0d-8d01-3b17476407ec" />

## 1. Network Topology Diagram
<img width="600" height="400" alt="image" src="https://github.com/user-attachments/assets/1eb464d4-8ff2-45f3-80a5-409b596330a8" />


---

## 2. Host Inventory & Specifications

| Hostname | Role | OS | IP Address | MAC Address | Key Software / Services |
|:---|:---|:---|:---|:---|:---|
| **`socforgewazuh`** | SIEM / Manager | Ubuntu Server 24.04 LTS | `192.168.56.104` | `08:00:27:17:81:c9` | Wazuh Manager v4.14.7, OpenSearch, Wazuh Dashboard |
| **`OniNaruto`** | Target Endpoint | Windows 11 Enterprise (22H2) | `192.168.56.105` | `08:00:27:cf:f0:76` | Wazuh Agent v4.14.7, Microsoft Sysmon v15.21 |
| **`kali`** | Adversary (C2) | Kali Linux 2026.x | `192.168.56.101` | `08:00:27:63:b0:05` | Nmap, Python 3 HTTP Server, Metasploit Framework |

---

## 3. Security Telemetry Pipeline

```text
┌───────────────────────────┐
│ Windows 11 Target System  │
│ (Process / Network / File)│
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│ Microsoft Sysmon (v15.21) │  Logs events to Microsoft-Windows-Sysmon/Operational
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│  Wazuh Agent (EventChannel│  Forwards telemetry securely over TCP 1514
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│ Wazuh Manager (Analysisd) │  Matches events against pre-compiled decoders & custom rules
└─────────────┬─────────────┘
              │
              ├──► /var/ossec/logs/archives/archives.json (Raw telemetry for threat hunting)
              ├──► /var/ossec/logs/alerts/alerts.json     (Triggered detection alerts)
              └──► OpenSearch Indexer → Wazuh Dashboard   (Visual dashboards & analytics)
```
