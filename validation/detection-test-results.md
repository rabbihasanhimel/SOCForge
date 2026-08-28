# SOCForge: Detection Engineering Validation Matrix

This document tracks unit testing (`wazuh-logtest`) and live endpoint validation for all 6 custom SOCForge detection rules.

---

## 1. Detection Engineering Validation Summary

| Rule ID | Detection Name | ATT&CK ID | Severity | Unit Test (`logtest`) | Live Telemetry (`alerts.json`) | Status |
|:---:|:---|:---:|:---:|:---:|:---:|:---:|
| **`100100`** | PowerShell Process Execution | `T1059.001` | Level 7 | ✅ PASSED | ✅ PASSED | **Validated** |
| **`100101`** | Encoded PowerShell Command | `T1059.001` / `T1027` | Level 10 | ✅ PASSED | ✅ PASSED | **Validated** |
| **`100102`** | CMD Spawned by PowerShell | `T1059.003` | Level 8 | ✅ PASSED | ✅ PASSED | **Validated** |
| **`100103`** | Suspicious Outbound Connection | `T1071.001` | Level 9 | ✅ PASSED | ✅ PASSED | **Validated** |
| **`100104`** | Scheduled Task Persistence | `T1053.005` | Level 10 | ✅ PASSED | ✅ PASSED | **Validated** |
| **`100105`** | Local Account / Privilege Escalation | `T1136.001` / `T1098` | Level 10 | ✅ PASSED | ✅ PASSED | **Validated** |

---

## 2. Metric Summary

```text
Total Custom Detections Engineered: 6
Validated Against Live Attacks:     6 (100%)
Unit Test Coverage:                 6 (100%)
False Positive Rate Observed:       0% during active attack window
```

---

## 3. Unit Test Verification Logs (`wazuh-logtest`)

### Test Case #1: Rule 100101 — Encoded PowerShell
```json
{"win":{"system":{"eventID":"1"},"eventdata":{"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","commandLine":"powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAUwBPAEMARgBvAHIAYwBlACcA"}}}
```
**Output:**
```text
**Phase 1: Completed pre-decoding.
**Phase 2: Completed decoding.
**Phase 3: Completed filtering (rules).
   id: '100101'
   level: '10'
   description: 'SOCForge: Suspicious encoded PowerShell command detected'
   groups: '["socforge", "powershell", "encoded_command", "process_creation"]'
   mitre.id: '["T1059.001", "T1027"]'
```

### Test Case #2: Rule 100102 — CMD Spawned by PowerShell
```json
{"win":{"system":{"eventID":"1"},"eventdata":{"parentImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","image":"C:\\Windows\\System32\\cmd.exe","commandLine":"cmd.exe /c whoami"}}}
```
**Output:**
```text
**Phase 3: Completed filtering (rules).
   id: '100102'
   level: '8'
   description: 'SOCForge: Command Shell spawned by PowerShell detected'
   mitre.id: '["T1059.003"]'
```

### Test Case #3: Rule 100104 — Scheduled Task Persistence
```json
{"win":{"system":{"eventID":"1"},"eventdata":{"image":"C:\\Windows\\System32\\schtasks.exe","commandLine":"schtasks.exe /create /tn SOCForgePersistence /tr calc.exe /sc onlogon /f"}}}
```
**Output:**
```text
**Phase 3: Completed filtering (rules).
   id: '100104'
   level: '10'
   description: 'SOCForge: Persistence via Scheduled Task creation detected'
   mitre.id: '["T1053.005"]'
```

### Test Case #4: Rule 100105 — Local Backdoor Account Creation
```json
{"win":{"system":{"eventID":"1"},"eventdata":{"image":"C:\\Windows\\System32\\net.exe","commandLine":"net.exe user socforge_backdoor P@ssw0rd123! /add"}}}
```
**Output:**
```text
**Phase 3: Completed filtering (rules).
   id: '100105'
   level: '10'
   description: 'SOCForge: Local account creation or privilege escalation detected via net.exe'
   mitre.id: '["T1136.001", "T1098"]'
```
