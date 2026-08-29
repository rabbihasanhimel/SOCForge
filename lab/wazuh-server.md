# SOCForge: Wazuh SIEM Server Setup & Configuration

This guide details the deployment and configuration of the Wazuh SIEM Server (`socforgewazuh`).

---

## 1. Specifications

- **OS:** Ubuntu Server 24.04 LTS
- **IP Address:** `192.168.56.104/24` (Host-Only `enp0s8`)
- **Software Stack:** Wazuh Manager v4.14.7, Wazuh Indexer (OpenSearch), Wazuh Dashboard
- **Web UI:** `https://192.168.56.104/`

---

## 2. Manager Configuration (`/var/ossec/etc/ossec.conf`)

### Archive Ingestion (Crucial for Threat Hunting)
To preserve all raw endpoint telemetry (even non-alerting events) in `archives.json`:

```xml
<ossec_config>
  <global>
    <logall_json>yes</logall_json>
  </global>
</ossec_config>
```

### Port Allocation
- `TCP 1514` — Wazuh Agent secure communication protocol
- `TCP 1515` — Agent enrollment service (authd)
- `TCP 55000` — Wazuh REST API
- `TCP 443` — Wazuh Dashboard Web Interface

---

## 3. Custom Rule Deployment
Custom detection rules are managed in `/var/ossec/etc/rules/local_rules.xml`.

To test rules before applying:
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

To test an event against the live rule engine:
```bash
sudo /var/ossec/bin/wazuh-logtest
```

## 4. Creating Backup for future use
<img width="600" height="200" alt="image" src="https://github.com/user-attachments/assets/8c426aea-a14a-4920-99ec-251109b14e46" />
