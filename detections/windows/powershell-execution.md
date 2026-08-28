# Detection Rule: PowerShell & Encoded Command Execution

- **Rule IDs:** `100100` (PowerShell Process), `100101` (Encoded Command)
- **Severity Levels:** Level 7 (Medium) / Level 10 (High)
- **MITRE ATT&CK:** `T1059.001` (Command and Scripting: PowerShell), `T1027` (Obfuscation)
- **Data Source:** Microsoft Sysmon (Event ID 1: Process Creation)
- **Platform:** Windows

---

## 1. Detection Objective
Detects when PowerShell is invoked, with child rule inheritance triggering on Base64 obfuscated command-line arguments (`-EncodedCommand`, `-encodedcommand`, `-enc`, `-Enc`) commonly used by adversaries to hide script intent.

---

## 2. Wazuh Rule Logic

```xml
<!-- Base Rule: PowerShell Execution -->
<rule id="100100" level="7">
  <field name="win.system.eventID">^1$</field>
  <field name="win.eventdata.image">\\powershell\.exe$</field>
  <description>SOCForge: PowerShell process execution detected</description>
  <mitre><id>T1059.001</id></mitre>
  <group>socforge,powershell,process_creation,</group>
</rule>

<!-- Child Rule: Encoded PowerShell Command -->
<rule id="100101" level="10">
  <if_sid>100100</if_sid>
  <field name="win.eventdata.commandLine">-EncodedCommand|-encodedcommand|-enc |-Enc </field>
  <description>SOCForge: Suspicious encoded PowerShell command detected</description>
  <mitre><id>T1059.001</id><id>T1027</id></mitre>
  <group>socforge,powershell,encoded_command,process_creation,</group>
</rule>
```

---

## 3. Simulation & Validation

```powershell
powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAUwBPAEMARgBvAHIAYwBlACAAUgBlAGQAIABUAGUAYQBtACAAQQB0AHQAYQBjAGsAIABTAGkAbQB1AGwAYQB0AGkAbwBuACcA
```

### Observed Alert:
- **Rule ID:** `100101` / Native `92057`
- **Level:** `10` / `12`
- **Parent Image:** `powershell.exe` (PID 572)
- **SHA256:** `529EE9D30EEF7E331B24E66D68205AB4554B6EB3487193D53ED3A840CA7DDE5D`
