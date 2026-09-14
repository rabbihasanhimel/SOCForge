# IR Playbook: Linux Rogue Backdoor & Cron Persistence Eradication

- **Playbook ID:** `IR-PLAYBOOK-003`
- **Threat Vectors:** `T1136.001` (Local Account), `T1098` (Account Manipulation), `T1053.003` (Cron Persistence)
- **Target Platform:** Linux (`SOCForge-Linux` / Ubuntu 24.04 LTS)

---

## 1. Identification & Triaging

```bash
# Check for rogue user account
id socforge_backdoor
grep "socforge_backdoor" /etc/passwd

# Check for rogue sudoers membership
groups socforge_backdoor
grep -E "socforge_backdoor" /etc/group /etc/sudoers /etc/sudoers.d/*

# Inspect cron directories for persistence artifacts
ls -la /etc/cron.d/
cat /etc/cron.d/socforge_persistence
```

---

## 2. Containment & Eradication

```bash
# 1. Terminate any active sessions or processes owned by the rogue user
sudo pkill -u socforge_backdoor

# 2. Eradicate persistence cron job and temporary heartbeats
sudo rm -f /etc/cron.d/socforge_persistence /tmp/.socforge_heartbeat

# 3. Delete rogue backdoor user account and home directory
sudo deluser --remove-home socforge_backdoor
```

---

## 3. Forensic Verification

```bash
# Verify user account deletion
id socforge_backdoor
# Expected output: id: ‘socforge_backdoor’: no such user

# Verify group membership removal
grep "socforge_backdoor" /etc/group
# Expected output: (Empty)

# Verify cron persistence removal
ls -la /etc/cron.d/socforge_persistence
# Expected output: ls: cannot access '/etc/cron.d/socforge_persistence': No such file or directory
```

---

## 4. Remediation Telemetry Proof

![Linux Eradication Proof](../../screenshots/incident-response/06_linux_eradication_backdoor_and_cron.png)
*Figure 1: Terminal verification demonstrating process termination, persistence cron removal, and user account purge.*

