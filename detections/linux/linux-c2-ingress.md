# Detection Rule: Linux Ingress Tool Transfer & Stager Retrieval

- **Rule ID:** `100203`
- **Severity Level:** Level 8 (Medium-High)
- **MITRE ATT&CK:** `T1105` (Ingress Tool Transfer), `T1071.001` (Web Protocols)
- **Data Source:** Linux Auditd / Syslog
- **Platform:** Linux (Ubuntu 24.04 LTS / Debian)

---

## 1. Detection Objective
Detects command execution invoking `curl` or `wget` targeting remote staging servers or non-standard ports (`:8080`) to stage external malicious scripts or tooling.

---

## 2. Wazuh Rule Logic

```xml
<rule id="100203" level="8">
  <regex type="pcre2">(?i)(curl|wget).*(http|8080)</regex>
  <description>SOCForge: Ingress tool transfer or external script staging detected</description>
  <mitre>
    <id>T1105</id>
    <id>T1071.001</id>
  </mitre>
  <group>socforge,c2,ingress_transfer,linux,</group>
</rule>
```

---

## 3. Sigma Equivalent
- [`lnx_ingress_tool_transfer_curl.yml`](../sigma/lnx_ingress_tool_transfer_curl.yml)
