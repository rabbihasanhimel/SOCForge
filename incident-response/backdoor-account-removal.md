# IR Playbook: Rogue Backdoor Administrator Removal

- **Playbook ID:** `IR-PLAYBOOK-002`
- **Threat Vector:** `T1136.001` (Local Account), `T1098` (Account Manipulation)

---

## 1. Identification
```powershell
Get-LocalUser -Name "socforge_backdoor"
Get-LocalGroupMember -Group "Administrators"
```

---

## 2. Containment & Eradication
```powershell
# Remove backdoor user
net.exe user socforge_backdoor /delete
```

---

## 3. Forensic Verification
```powershell
Get-LocalUser -Name "socforge_backdoor" -ErrorAction SilentlyContinue
# Expected: Empty / Null output
```
Sysmon telemetry confirms:
- Process Terminated (Event ID 5) for `net1.exe` (PID 6336).
- Prefetch file updated: `NET1.EXE-509326A5.pf` (Event ID 11).
