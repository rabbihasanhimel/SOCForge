# Detection Rule: Scheduled Task Persistence Creation

- **Rule ID:** `100104`
- **Severity Level:** Level 10 (High)
- **MITRE ATT&CK:** `T1053.005` (Scheduled Task/Job: Scheduled Task)
- **Data Source:** Microsoft Sysmon (Event ID 1: Process Creation & Event ID 7: Image Load)
- **Platform:** Windows

---

## 1. Detection Objective
Detects the creation of unauthorized persistence mechanisms via Windows Task Scheduler (`schtasks.exe`) using command-line arguments such as `/create`, `/Create`, `-create`, or `-Create`.

---

## 2. Wazuh Rule Logic

```xml
<rule id="100104" level="10">
  <field name="win.system.eventID">^1$</field>
  <field name="win.eventdata.image">\\schtasks\.exe$|\\schtasks\.EXE$</field>
  <field name="win.eventdata.commandLine">/create|/Create|-create|-Create</field>
  <description>SOCForge: Persistence via Scheduled Task creation detected</description>
  <mitre><id>T1053.005</id></mitre>
  <group>socforge,persistence,scheduled_task,process_creation,</group>
</rule>
```

---

## 3. Simulation & Validation

```powershell
schtasks.exe /create /tn "SOCForgePersistence" /tr "C:\Windows\System32\calc.exe" /sc onlogon /f
```

### Observed Alert:
- **Rule ID:** `100104` / Native `92154` (taskschd.dll load)
- **Process:** `schtasks.exe` (PID 5704)
- **Parent Process:** `powershell.exe` (PID 572)
- **SHA256:** `DDDE64F0F55751763C1BCD53DE9CDFFC0D725D45A8476464A2A0422661813004`
