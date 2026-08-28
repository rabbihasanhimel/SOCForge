# Detection Rule: Local Account Creation & Privilege Escalation

- **Rule ID:** `100105`
- **Severity Level:** Level 10 (High)
- **MITRE ATT&CK:** `T1136.001` (Local Account), `T1098` (Account Manipulation)
- **Data Source:** Microsoft Sysmon (Event ID 1: Process Creation)
- **Platform:** Windows

---

## 1. Detection Objective
Detects the unauthorized creation of local user accounts and addition of users to privileged groups (such as `Administrators`) using Windows native utilities `net.exe` and `net1.exe`.

---

## 2. Wazuh Rule Logic

```xml
<rule id="100105" level="10">
  <field name="win.system.eventID">^1$</field>
  <field name="win.eventdata.image">\\net\.exe$|\\net\.EXE$|\\net1\.exe$|\\net1\.EXE$</field>
  <field name="win.eventdata.commandLine">/add|/Add|-add|-Add</field>
  <description>SOCForge: Local account creation or privilege escalation detected via net.exe</description>
  <mitre><id>T1136.001</id><id>T1098</id></mitre>
  <group>socforge,privilege_escalation,persistence,account_manipulation,process_creation,</group>
</rule>
```

---

## 3. Simulation & Validation

```powershell
net.exe user socforge_backdoor P@ssw0rd123! /add
net.exe localgroup administrators socforge_backdoor /add
```

### Observed Alert:
- **Rule ID:** `100105` / Native `92033` / Native `92031`
- **Process:** `net.exe` (PID 5000 / 1944) → `net1.exe` (PID 3528 / 5980)
- **Parent Process:** `powershell.exe` (PID 572)
- **SHA256 (net.exe):** `AFBE51517092256504F797F6A5ABC02515A09D603E8C046AE31D7D7855568E91`
- **SHA256 (net1.exe):** `1879DB2ABFF726A5438DD1AE48F20EBED736619C27A32526D09F70AF7EADD0E5`
