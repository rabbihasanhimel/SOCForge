# IR Playbook: Scheduled Task Persistence Eradication

- **Playbook ID:** `IR-PLAYBOOK-001`
- **Threat Vector:** `T1053.005` (Scheduled Task Persistence)

---

## 1. Identification
Query Wazuh or Sysmon for task creations:
```powershell
schtasks.exe /query /tn "SOCForgePersistence"
```

---

## 2. Containment & Eradication
```powershell
# Forcefully delete the malicious task
schtasks.exe /delete /tn "SOCForgePersistence" /f
```

---

## 3. Forensic Verification
Check Sysmon Event ID 12 in `archives.json`:
- Verifies `DeleteKey` on `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SOCForgePersistence`.
- Query endpoint to confirm error returned:
```powershell
schtasks.exe /query /tn "SOCForgePersistence"
# Expected: ERROR: The system cannot find the file specified.
```
