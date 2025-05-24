# SIEM-INTERNSHIP-PHASE-2
Advanced Threat Detection & Post-Exploitation Simulation on Linux

## 📌 Overview

This repository presents the second phase of the SIEM internship, focusing on detecting post-exploitation attacker behavior using **Splunk Enterprise**. The setup simulates real-world adversarial techniques and analyzes them through log data collected from Linux systems using **Splunk Universal Forwarder**.

It includes realistic attacker emulation using tools such as **LinPEAS**, **CrackMapExec**, **Metasploit**, and **LaZagne** to simulate exploitation, lateral movement, and credential access.

## 🏗️ Architecture

![mermaid-ai-diagram-2025-05-23-152514](https://github.com/user-attachments/assets/678abed8-b117-4735-9364-d7b530aadf61)


The simulation covers attacker actions such as privilege escalation, lateral movement, credential dumping, C2 communication, and more, with real-time monitoring and alerting via Splunk.

---

## 🔓 Exploitation & Post-Exploitation Techniques Simulated

- **Privilege Escalation** using `LinPEAS`
- **Lateral Movement** via `SSH` and tools like `CrackMapExec`
- **Suspicious File Downloads** using `wget`, `curl`, `ftp`, `scp`
- **Credential Dumping** via `LaZagne`, and parsing `/etc/passwd` or `/etc/shadow`
- **Command and Control** using `Metasploit Meterpreter`
- **Anomalous User Behavior** detection and analysis

---

### 🧍 Privilege Escalation Detection

Detect when an attacker attempts to elevate privileges or add users to administrative groups:
- Use of `sudo`, `usermod`, `useradd`, `LinPEAS`, or direct editing of `/etc/passwd`

**Log Source**: `/var/log/auth.log`, `/etc/passwd`, `/etc/group`, `auditd`

**Detection**: Monitor privilege modification commands and changes in group memberships.

---

### 🔄 Lateral Movement Detection (Non-SSH)

Simulate and detect lateral movement across Linux systems with **mount‑based lateral movement**, **outbound connections to internal IPs**, and tools such as **CrackMapExec**.

### 🚨 Mount‑Based Lateral Movement

Attackers may leverage NFS, SMB, or SSHFS mounts to access or transfer files laterally.

- **Detection Mechanism**: auditd rules  
- **Log Source**: `/var/log/audit/audit.log`

### 📡 Outbound Connections to Internal IPs

Identify unauthorized network activity to other internal hosts (e.g., 10.0.0.0/8, 192.168.0.0/16), which can include reverse shells or frameworks like CrackMapExec.

- **Detection Mechanism**: Sysmon for Linux (Event ID 3 – Network Connection)  
- **Log Source**: Sysmon logs ( `/var/log/sysmon/sysmon.log` )
- 
---

### 🧪 Suspicious File Downloads & Execution

Attackers often download and execute payloads:
- Download using `wget`, `curl`, `ftp`, `scp`
- Execute with `bash`, `chmod`, or `./`

**Log Source**: `auditd`, `syslog`, `bash_history`

**Detection**: Correlate file downloads to executions, and flag use of temp directories or uncommon extensions (`.sh`, `.py`, `.elf`).

---

### 🧠 Credential Dumping

Simulate extraction of stored credentials:
- Access to `/etc/passwd` or `/etc/shadow`
- Use of tools like `LaZagne` for plaintext credentials

**Log Source**: `auditd`, `syslog`

**Detection**: Identify access to sensitive files and suspicious credential extraction tools.

---

### 🧭 Anomalous User Behavior

Post-compromise behavior varies from normal users:
- Off-hour logins, burst activity
- Accessing sensitive directories or copying large files

**Log Source**: `/var/log/auth.log`, `audit.log`, `syslog`

**Detection**: Use behavior analytics to identify anomalies in user actions and patterns.

---

### 📡 Command and Control (C2) Beaconing

Simulated C2 traffic using **Metasploit Meterpreter**:
- Regular outbound connections (beacons)
- Periodic use of `curl`, `wget`

**Log Source**: `audit.log`, `syslog`, network logs (if available)

**Detection**: Flag repeated access to external IPs/domains with fixed intervals.

---

### 🗂️ Log Sources for Detection

The following Linux logs are monitored:
- `/var/log/auth.log`
- `/var/log/audit/audit.log`
- `/var/log/syslog`
- `/home/*/.bash_history`
- `/etc/passwd`, `/etc/group`, `/etc/shadow`

These are forwarded using the **Splunk Universal Forwarder** to **Splunk Enterprise**.

---

### 🖥️ Splunk Universal Forwarder + Post-Exploitation Integration

To enable detection:

- **Configured log sources**:
  - `/var/log/auth.log`
  - `/var/log/audit/audit.log`
  - `/var/log/syslog`
  - `/home/*/.bash_history`
  - `/etc/passwd`, `/etc/group`, `/etc/shadow`

- **Forwarder Configuration Files**:
  - `inputs.conf`: paths to monitor
  - `outputs.conf`: forwards to indexer (TCP 9997)

- **Index**: Logs indexed under `postexploitation_logs` with sourcetypes such as `auth`, `syslog`, `auditd`, `bash`

---

These detections align with MITRE ATT&CK tactics:
- **Privilege Escalation**
- **Lateral Movement**
- **Credential Access**
- **Execution**
- **Command and Control**
- **Defense Evasion**

This setup enhances visibility into post-compromise activity on Linux endpoints using Splunk as the central detection engine.
