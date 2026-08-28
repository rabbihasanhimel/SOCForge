# SOCForge: Kali Linux Adversary Node Setup

This guide details the adversary node configuration and attack tooling on Kali Linux (`kali`).

---

## 1. Specifications

- **OS:** Kali Linux 2026.x
- **Hostname:** `kali`
- **IP Address (Host-Only `eth0`):** `192.168.56.101/24`
- **MAC Address:** `08:00:27:63:b0:05`

---

## 2. Dual-Homed Network Configuration

To allow external tool installation and updates while simulating targeted attacks inside the isolated subnet:

- **Adapter 1 (Host-Only):** `eth0` — `192.168.56.101` (Direct connectivity to `192.168.56.105` Windows target)
- **Adapter 2 (NAT):** `eth1` — DHCP internet access for package updates

---

## 3. Adversary Tooling & C2 Setup

### Network Reconnaissance
```bash
sudo nmap -Pn -sS -sV -p 135,139,445,3389,5985 192.168.56.105
```

### Python HTTP C2 Staging Server
```bash
# Create benign test stager
echo "Write-Host 'SOCForge Stager Executed from Kali C2!'" > payload.ps1

# Start HTTP server on port 8080
python3 -m http.server 8080
```
