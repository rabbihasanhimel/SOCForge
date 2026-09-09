# Detection Rule: Linux Scheduled Cron Persistence Creation

- **Rule ID:** `100202`
- **Severity Level:** Level 10 (High)
- **MITRE ATT&CK:** `T1053.003` (Scheduled Task/Job: Cron)
- **Data Source:** Linux Auditd / Syslog (Sudo command execution)
- **Platform:** Linux (Ubuntu 24.04 LTS / Debian)

---

## 1. Detection Objective
Detects unauthorized persistence mechanisms established via Linux cron scheduling directories (`/etc/cron.d/`, `/etc/cron.daily/`, etc.) executed via administrative tools (`tee`, `chmod`, `touch`, `cp`, `crontab`).

---

## 2. Wazuh Rule Logic

```xml
<rule id="100202" level="10">
  <if_sid>5402, 5403</if_sid>
  <field name="command" type="pcre2">(?i)(tee|chmod|touch|cp|mv).*/etc/cron</field>
  <description>SOCForge: Persistence established via scheduled Cron job creation</description>
  <mitre><id>T1053.003</id></mitre>
  <group>socforge,persistence,cron,linux,</group>
</rule>
```

---

## 3. Sigma Equivalent
- [`proc_creation_lnx_cron_persistence.yml`](../sigma/proc_creation_lnx_cron_persistence.yml)
