
# SIEM-INTERNSHIP-PHASE-2  
**Advanced Threat Detection & Post-Exploitation Simulation on Linux**

---

## 📌 Overview

This repository presents the second phase of the SIEM internship, focusing on detecting post-exploitation attacker behavior using **Splunk Enterprise**. The setup simulates real-world adversarial techniques and analyzes them through log data collected from Linux systems using the **Splunk Universal Forwarder**.

It includes realistic attacker emulation using tools such as **LinPEAS**, **CrackMapExec**, **Metasploit**, **LaZagne**, **Ansible**, and memory-based techniques like **gcore** and **volatility** to simulate exploitation, lateral movement, and credential access.

---

## 🏗️ Architecture

![Architecture Diagram](https://github.com/user-attachments/assets/678abed8-b117-4735-9364-d7b530aadf61)

The simulation covers attacker actions such as privilege escalation, lateral movement, credential dumping, C2 communication, and more, with real-time monitoring and alerting via Splunk.

---

## 🔓 Exploitation & Post-Exploitation Techniques Simulated

- **Privilege Escalation** using `LinPEAS`
- **Lateral Movement** via `SSH`, `Ansible`, or `CrackMapExec`
- **Suspicious File Downloads** using `wget`, `curl`, `ftp`, `scp`
- **Credential Dumping** via `LaZagne`, `gcore`, `strings`, `volatility`
- **Command and Control** using `Metasploit Meterpreter`
- **SQL Injection & Remote Shell** via unrestricted file upload
- **Anomalous User Behavior** detection and analysis

---

## 🧍 Privilege Escalation Detection

Detect when an attacker attempts to elevate privileges or add users to administrative groups:
- Use of `sudo`, `usermod`, `useradd`, `LinPEAS`, or direct editing of `/etc/passwd`

**Log Source**: `/var/log/auth.log`, `/etc/passwd`, `/etc/group`, `auditd`  
**Detection**: Monitor privilege modification commands and changes in group memberships.

---

## 🧠 Credential Dumping via `gcore`, `strings`, and `volatility`

Simulated dumping of memory from the `sshd` or `login` process to extract in-memory credentials.

### Tools Used

- `gcore`: Core dump of target process
- `strings`: Extract readable data from memory
- `volatility`: Parse and analyze memory dump

### Exploitation Flow

1. Attacker gains shell access on target Linux system  
2. Identifies active `sshd`/`login` process:  
   ```bash
   ps aux | grep sshd
   ```
3. Dumps process memory using:  
   ```bash
   sudo gcore -o /tmp/ssh_mem <PID>
   ```
4. Extracts credentials using:  
   ```bash
   strings /tmp/ssh_mem.<PID> | grep -i password
   ```
5. Optionally exports full memory and analyzes using volatility:  
   ```bash
   volatility -f memory.raw --profile=Linux... linux_pslist
   volatility -f memory.raw --profile=Linux... linux_bash
   ```

### Detection & Logging

- `auditd` for syscall logging: capture `ptrace`, `gcore`, or `core_pattern` activity  
- `syslog`: Commands run by attacker (`gcore`, `strings`)  
- `bash_history`: Reverse shell or manual command history  

**Log Sources**:
- `/var/log/audit/audit.log`  
- `/var/log/syslog`  
- `/home/*/.bash_history`  

### Recommendations

- Disable unnecessary debugging tools (`gcore`, `gdb`) on production systems  
- Enable `core dump` restrictions via:  
  ```bash
  echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
  sysctl -p
  ```
- Monitor for suspicious access to processes with `ptrace`, `gcore`, or access to `/proc/<pid>/mem`  
- Use `auditd` to alert on suspicious memory access patterns  

---

## 🔄 Lateral Movement Detection (Ansible, SSH, etc.)

Simulate and detect lateral movement across Linux systems:

- **Mount‑Based Lateral Movement** using `NFS`, `SMB`, `SSHFS`  
- **Outbound Connections to Internal IPs**  
- **Automated Lateral Movement via Ansible**

### Detection Mechanisms

- `auditd` for mounts  
- `sysmon` for outbound connections  
- `auth.log` for SSH keys, Ansible temp file execution  

---

## 🧪 Suspicious File Downloads & Execution

Detect payload downloads and execution patterns:

- Download via `wget`, `curl`, `scp`  
- Execution using `bash`, `chmod`, `./payload`  

**Log Source**: `auditd`, `syslog`, `bash_history`  

---

## 📡 C2 Beaconing Detection

Monitor for reverse shell or beacon traffic (Metasploit, netcat, curl beaconing):

- Use `Sysmon` for network events  
- Flag repeated or timed connections  

---

## 🧨  Exploitation on Linux Server: SQL Injection + File Upload + Remote Shell

Full flow of web attack using `sqlmap`, `admin panel upload`, and `netcat` reverse shell:

- Detect anomalous upload activity  
- Monitor `/admin/upload/*.php` execution  
- Trace outbound connection from web server  

---

## 🗂️ Log Sources for Detection

- `/var/log/auth.log`  
- `/var/log/audit/audit.log`  
- `/var/log/syslog`  
- `/home/*/.bash_history`  
- `/etc/passwd`, `/etc/group`, `/etc/shadow`  

---

## 🖥️ Splunk Universal Forwarder Setup

- `inputs.conf` for path monitoring  
- `outputs.conf` for forwarding logs to indexer  
- Logs indexed under `postexploitation_logs`  

---

## 🧬 MITRE ATT&CK Mapping

| Tactic               | Technique Example                      |
|----------------------|----------------------------------------|
| Initial Access        | Web shell via file upload             |
| Execution             | Bash scripts, memory dumps            |
| Privilege Escalation  | sudo abuse, /etc/passwd edit          |
| Credential Access     | `LaZagne`, `gcore`, `/etc/shadow`     |
| Lateral Movement      | SSH, mount, Ansible, CrackMapExec     |
| Command and Control   | Metasploit beacon, netcat reverse     |
| Defense Evasion       | Use of common tools in stealth mode   |

---

## 📖 References

- MITRE ATT&CK: https://attack.mitre.org/  
- Sysmon for Linux: https://github.com/Sysinternals/SysmonForLinux  
- Auditd Rules: https://github.com/Neo23x0/auditd  
- Volatility: https://github.com/volatilityfoundation/volatility  
- LaZagne: https://github.com/AlessandroZ/LaZagne  

---

## ✅ Outcome

This simulation enhances visibility into post-compromise attacker behaviors on Linux systems using Splunk as the central detection engine. It offers practical detection logic, real attacker emulation, and log collection to support SOC analysis and threat hunting.
