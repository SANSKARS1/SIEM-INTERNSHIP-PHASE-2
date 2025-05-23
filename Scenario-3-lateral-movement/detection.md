# Detection Use Case: Lateral Movement via SSH and File Transfers

##  Scenario Description
Lateral movement is a common tactic where an attacker, after compromising a system, uses SSH (`sshd`) or file transfer utilities (`scp`, `sftp`) to move laterally across the network. This detection identifies such activities by parsing system logs for successful SSH logins, logouts, and file transfers.

##  Objective
Detect potential lateral movement by monitoring:
- SSH logins (`Accepted password` or `Accepted publickey`)
- SSH logouts (`session closed`)
- File transfers (`scp`, `sftp`)

##  Tools Used
- **SIEM**: Splunk Enterprise
- **Log Source**: Linux Syslog (`/var/log/syslog`, `/var/log/auth.log`)
- **Lab Setup**:
  - Multiple Linux VMs (e.g., Kali, Ubuntu) with Splunk Universal Forwarder
  - Windows host running Splunk Enterprise
  - Logs forwarded over TCP port `9997`

---

##  Data Source Mapping

### 🔍 Syslog/Auth Events

| Field       | Example Value                    | Description                                    |
|------------|-----------------------------------|------------------------------------------------|
| `_time`     | `2025-05-21T11:25:45.321`         | Timestamp of the event                         |
| `host`      | `ubuntu-vm`                      | Host receiving the SSH connection              |
| `user`      | `alice`                          | User who logged in or transferred a file       |
| `src_ip`    | `192.168.1.101`                  | IP address of the source initiating the action |
| `event_type`| `ssh_login`, `ssh_logout`, `file_transfer_scp`, `file_transfer_sftp` | Event categorization |

---

## 🛡️ Detection Logic: SSH and File Transfers

Detects lateral movement by classifying events from system logs into types of SSH logins, logouts, and file transfers using regex and conditional logic.

### 🔎 SPL Query

```spl
index="linux_logs" sourcetype="auth"
("Accepted password" OR "Accepted publickey" OR "session opened for user root")
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| rex "for (?<target_user>\w+) from"
| rex "user (?<source_user>\w+)"
| eval event_type="ssh_login"
| table _time, host, source_user, target_user, src_ip, event_type
| append [
    search index="linux_logs" sourcetype="syslog" ("scp" OR "sftp")
    | rex field=_raw "(?<command>scp|sftp)\s+(?<args>[^\s]+)"
    | eval event_type="file_transfer"
    | table _time, host, command, args, event_type
]
| sort -_time
```

---


##  Alert 

![Screenshot 2025-05-22 154820](https://github.com/user-attachments/assets/d69ddda0-8711-4e58-8f28-b3b6ae66333c)


## Log / Sample Event

| `_time`                         | `event_type`    | `command/args`        | Interpretation                                                                |
| ------------------------------- | --------------- | --------------------- | ----------------------------------------------------------------------------- |
| `15:42:05.508`                  | `file_transfer` | `scp cleaned_id.key`  | Attacker uses `scp` to upload a private key or a public key file.             |
| `15:42:05.515` → `15:42:07.075` | `file_transfer` | *(no args)*           | Possibly transferring multiple chunks or files (including `authorized_keys`). |
| `15:42:06.924`                  | `ssh_login`     | `src_ip=192.168.1.11` | Attacker logs in to target machine via SSH (possibly using the uploaded key). |

![Screenshot 2025-05-22 154405](https://github.com/user-attachments/assets/1a2291c4-bd71-434f-8098-3422d86e69e9)

---


## ✅ Detection Status

✅ **Working** – Verified in a lab environment using:
- `ssh`, `scp`, and `sftp` commands from different source machines
- Splunk Universal Forwarder to ship `/var/log/syslog` and `/var/log/auth.log` to Splunk Enterprise

---
## Analyst Notes / Recommendations

- **Actions:**
  - Identify the initial point of compromise and scope the spread of the attack.
  - Investigate unusual or unauthorized access between hosts, especially with privilege escalation.
  - Review logs for the use of administrative tools or commands that facilitate lateral movement.
- **Possible False Positives:**
  - Legitimate administrative or maintenance activities across systems.
  - Automated patch management or configuration management tools.

---

## 🔗 MITRE ATT&CK Mapping

| Tactic             | Technique                          | ID        |
|--------------------|-------------------------------------|-----------|
| Lateral Movement   | Remote Services: SSH                | T1021.004 |
| Command and Control| Ingress Tool Transfer               | T1105     |

---


