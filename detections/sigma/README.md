# 📜 SOCForge Sigma Detection Rules Catalog

This directory contains the **Sigma (Generic Signature Format for SIEM Systems)** equivalents of the 6 custom detection rules engineered for the SOCForge detection pipeline.

---

## 🎯 Why Sigma?

While Wazuh uses XML decoders and rules, **Sigma is SIEM-agnostic**. Developing rules in Sigma format ensures that defensive engineering can be ported seamlessly to:
* **Splunk** (SPL)
* **Elasticsearch / Kibana** (Lucene / EQL / ES|QL)
* **Microsoft Sentinel** (KQL)
* **QRadar** (AQL)
* **Wazuh / OpenSearch**

---

## 📋 Rule Mapping Matrix

### Windows Detection Rules (100100 - 100105)
| Sigma Rule File | Wazuh Rule ID | MITRE ATT&CK | Level | Detection Focus |
|:---|:---:|:---:|:---:|:---|
| [`proc_creation_win_powershell_execution.yml`](proc_creation_win_powershell_execution.yml) | `100100` | `T1059.001` | Medium | Base PowerShell execution telemetry |
| [`proc_creation_win_powershell_encoded_command.yml`](proc_creation_win_powershell_encoded_command.yml) | `100101` | `T1059.001`, `T1027` | **High** | Obfuscated Base64 PowerShell execution |
| [`proc_creation_win_powershell_spawning_cmd.yml`](proc_creation_win_powershell_spawning_cmd.yml) | `100102` | `T1059.003` | Medium | Command Prompt spawned by PowerShell |
| [`net_connection_win_c2_suspicious_traffic.yml`](net_connection_win_c2_suspicious_traffic.yml) | `100103` | `T1071.001` | **High** | Outbound C2 traffic to adversary staging IP |
| [`proc_creation_win_schtasks_persistence.yml`](proc_creation_win_schtasks_persistence.yml) | `100104` | `T1053.005` | **High** | Scheduled Task persistence creation |
| [`proc_creation_win_net_account_creation.yml`](proc_creation_win_net_account_creation.yml) | `100105` | `T1136.001`, `T1098` | **High** | Rogue local user creation via `net.exe` |

### Linux Detection Rules (100200 - 100203)
| Sigma Rule File | Wazuh Rule ID | MITRE ATT&CK | Level | Detection Focus |
|:---|:---:|:---:|:---:|:---|
| [`proc_creation_lnx_useradd_backdoor.yml`](proc_creation_lnx_useradd_backdoor.yml) | `100200` | `T1136.001` | **High** | Rogue local user creation via `useradd` |
| [`proc_creation_lnx_usermod_sudoers.yml`](proc_creation_lnx_usermod_sudoers.yml) | `100201` | `T1098`, `T1548.003` | **High** | Account elevated to privileged sudo group |
| [`proc_creation_lnx_cron_persistence.yml`](proc_creation_lnx_cron_persistence.yml) | `100202` | `T1053.003` | **High** | Scheduled persistence via `/etc/cron*` |
| [`lnx_ingress_tool_transfer_curl.yml`](lnx_ingress_tool_transfer_curl.yml) | `100203` | `T1105`, `T1071.001` | Medium | Ingress payload download via curl/wget |


---

## 🔄 Compiling Sigma Rules to SIEM Query Formats

Using `sigma-cli` / `pySigma`, these rules can be converted dynamically into any SIEM query format:

### 1. Convert to Splunk SPL:
```bash
sigma convert -t splunk -p sysmon proc_creation_win_powershell_encoded_command.yml
```
*Generated Splunk Query:*
```spl
EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe") (CommandLine="*-EncodedCommand*" OR CommandLine="*-encodedcommand*" OR CommandLine="*-enc *" OR CommandLine="*-Enc *" OR CommandLine="*-e *")
```

### 2. Convert to Microsoft Sentinel (KQL):
```bash
sigma convert -t microsoft365defender -p sysmon proc_creation_win_schtasks_persistence.yml
```
*Generated KQL Query:*
```kql
DeviceProcessEvents
| where (FolderPath endswith @"\schtasks.exe" and (ProcessCommandLine contains @"/create" or ProcessCommandLine contains @"/Create" or ProcessCommandLine contains @"-create" or ProcessCommandLine contains @"-Create"))
```

### 3. Convert to Elasticsearch (Lucene Query):
```bash
sigma convert -t elasticsearch -p sysmon proc_creation_win_net_account_creation.yml
```
*Generated Lucene Query:*
```lucene
winlog.event_data.Image.keyword:(*\\net.exe OR *\\net1.exe) AND winlog.event_data.CommandLine.keyword:(*\/add* OR *\/Add* OR *\ -add* OR *\ -Add*)
```
