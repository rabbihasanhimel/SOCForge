# Threat Hunt: Hypothesis 001 — Adversary Living-off-the-Land (LOLBin) Activity

- **Hunt ID:** `HUNT-001`
- **Target Subnet:** `192.168.56.0/24`
- **Data Source:** Microsoft Sysmon Event IDs 1, 3, 7, 11 (Wazuh `archives.json`)
- **Status:** **Completed / Confirmed Compromise**

---

## 1. Hypothesis
*An external adversary has gained initial access to a Windows endpoint and is leveraging native Windows utilities (LOLBins: `powershell.exe`, `cmd.exe`, `schtasks.exe`, `net.exe`) to perform reconnaissance, bypass execution policies, and establish persistence without triggering traditional antivirus.*

---

## 2. Investigation & Evidence Extraction

```bash
# Query: Extract all process creations from agent 002 involving LOLBins
sudo grep -E '"agent":{"id":"002".*"eventID":"1"' \
  /var/ossec/logs/archives/archives.json \
  | grep -Ei 'powershell|payload\.ps1|schtasks|net\.exe|net1\.exe|cmd\.exe' \
  | tail -30
```

---

## 3. Findings
- **Confirmed:** 8 malicious LOLBin executions traced back to root interactive PowerShell session (`PID 572`).
- **Persistence Confirmed:** `schtasks.exe` loaded `taskschd.dll` to create `SOCForgePersistence`.
- **Privilege Escalation Confirmed:** `net.exe` created `socforge_backdoor` and added it to `Administrators`.
- **Ingress Tool Transfer Confirmed:** `Invoke-WebRequest` to `192.168.56.101:8080` dropped `C:\Windows\Temp\payload.ps1`.
