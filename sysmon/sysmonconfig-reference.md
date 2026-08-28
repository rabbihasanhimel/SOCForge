# SOCForge: Sysmon Configuration & Telemetry Reference

This document outlines the Microsoft Sysmon configuration, monitored Event IDs, and Wazuh agent event-channel pipeline utilized in the SOCForge detection environment.

---

## Sysmon Sensor Specifications

| Specification | Value |
|:---|:---|
| **Software** | Microsoft System Monitor (Sysmon) |
| **Version** | v15.21 |
| **Schema Version** | 4.90 |
| **Host System** | Windows 11 Enterprise (Agent `002` / `OniNaruto`) |
| **Base Configuration** | SwiftOnSecurity Sysmon-Modular baseline |

---

## Monitored Sysmon Event IDs

The following Sysmon events were ingested and correlated during the SOCForge attack simulation:

| Event ID | Event Name | Detection Purpose in SOCForge |
|:---:|:---|:---|
| **1** | Process Creation | Tracks process spawns, command-line arguments, parent process PIDs/GUIDs, integrity levels, and binary SHA256 hashes. |
| **3** | Network Connection | Detects outbound C2 staging connections to Kali (`192.168.56.101:8080`) and inbound port scanning. |
| **5** | Process Terminated | Records the exact termination time and PID of processes during eradication. |
| **7** | Image Loaded | Detects DLL loads into processes (e.g., `taskschd.dll` loaded by `schtasks.exe` triggering Rule `92154`). |
| **11** | File Create | Monitors malicious payload staging (`C:\Windows\Temp\payload.ps1`) and prefetch file generation (`NET.EXE-*.pf`). |
| **12** | Registry Object Added/Deleted | Captures task scheduler registry deletion (`TaskCache\Tree\SOCForgePersistence`) verifying persistence eradication. |
| **13** | Registry Value Set | Monitors unauthorized changes to autorun keys and system configuration. |

---

## Wazuh Agent `ossec.conf` Sysmon EventChannel Configuration

To forward Sysmon telemetry from the Windows endpoint to the Wazuh Manager, the following block was configured in `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

---

## Sysmon XML Filtering Reference (Sample Rules)

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Event ID 1: Process Creation -->
    <RuleGroup name="Process Creation" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="end with">\powershell.exe</Image>
        <Image condition="end with">\cmd.exe</Image>
        <Image condition="end with">\schtasks.exe</Image>
        <Image condition="end with">\net.exe</Image>
        <Image condition="end with">\net1.exe</Image>
        <Image condition="end with">\whoami.exe</Image>
        <Image condition="end with">\ipconfig.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event ID 3: Network Connection -->
    <RuleGroup name="Network Connection" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is">8080</DestinationPort>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 11: File Creation -->
    <RuleGroup name="File Creation" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\Windows\Temp\</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```
