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
<img width="929" height="358" alt="image" src="https://github.com/user-attachments/assets/dea34abb-3cf9-4808-b298-1f7ec4cffb67" />

## 3. Forensic Verification
Check Sysmon Event ID 12 in `archives.json`:
- Verifies `DeleteKey` on `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SOCForgePersistence`.
- Query endpoint to confirm error returned:
```powershell
schtasks.exe /query /tn "SOCForgePersistence"
# Expected: ERROR: The system cannot find the file specified.
```
