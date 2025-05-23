# SIEM-INTERNSHIP-PHASE-1
Threat Detection Environment through SIEM.

## 📌 Overview

This repository demonstrates the detection of common adversarial behaviors on a Linux system using **Splunk Enterprise** and **Splunk Universal Forwarder**. Logs are collected from Linux systems and ingested into Splunk for real-time analysis and alerting.

## 🏗️ Architecture


![mermaid-ai-diagram-2025-05-16-100656](https://github.com/user-attachments/assets/f45da94b-ff63-481b-984f-d92bd78992b5)


Using Splunk's powerful search and alerting capabilities, the following security scenarios are covered:

### 🔄 Lateral Movement

Lateral movement involves an attacker expanding their access across systems in the network. We monitor for:
- SSH login from one internal host to another
- Repeated logins between systems within a short time window
- Unusual IP-to-IP login patterns

**Log Source**: `/var/log/auth.log`, `/var/log/syslog`

**Detection**: Monitor SSH sessions with internal IPs, detect abnormal pivot behavior.

---

### 🧹 Log Tampering

Attackers often attempt to cover their tracks by deleting or modifying log files. We monitor for:
- Commands like `rm /var/log/*`, `echo > /var/log/auth.log`
- Suspicious use of `truncate`, `shred`, or `> logfile`

**Log Source**: `.bash_history`, `auditd`, `syslog`

**Detection**: Identify file access/modification patterns to critical log files.

---

### 🕒 Suspicious Login After Hours

Detect logins that occur outside of defined working hours (e.g., 9 AM–7 PM). These often indicate unauthorized access attempts.

**Log Source**: `/var/log/auth.log`

**Detection**: Compare login timestamps to a defined working hour schedule and flag outliers.

---

### 👤 Unauthorized User Creation

Adversaries may create new users to maintain access. We monitor for:
- Use of `useradd`, `adduser`, or modifications in `/etc/passwd`

**Log Source**: `auditd`, `auth.log`, `bash_history`

**Detection**: Real-time detection of system user creation or privilege escalation.

---

### 🔐 Brute Force Detection

A classic attack where multiple login attempts are made to guess a user's password. We detect:
- 10+ failed SSH login attempts from the same IP
- Followed by a successful login within 2 minutes

**Log Source**: `/var/log/auth.log`

**Detection**: Stream-based correlation of login failures and success with `streamstats` in Splunk.

---

### 🖥️ Splunk Universal Forwarder + Linux Log Integration

To enable these detections, **Splunk Universal Forwarder** is installed on Linux endpoints to collect and forward logs to **Splunk Enterprise**.

- **Configured log sources**:
  - `/var/log/auth.log`
  - `/var/log/syslog`
  - `/var/log/audit/audit.log`
  - `/home/*/.bash_history`
- **Forwarder Configuration Files**:
  - `inputs.conf` – defines which files to monitor
  - `outputs.conf` – sets Splunk indexer connection (TCP 9997)
- **Index**: All logs are sent to the `linux_logs` index with relevant sourcetypes (`auth`, `syslog`, `auditd`)

---

These detection techniques align with MITRE ATT&CK tactics such as **Persistence**, **Defense Evasion**, **Lateral Movement**, and **Credential Access**, helping security teams gain real-time visibility into adversary behavior within a Linux environment.
