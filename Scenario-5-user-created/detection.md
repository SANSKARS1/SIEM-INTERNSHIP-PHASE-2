# Detection Use Case: Malicious User Creation on Linux

##  Scenario Description
An attacker gains access to a Linux system and adds a new user using commands like `useradd`, `adduser`, or modifies existing accounts using `passwd -d`, `passwd -l`, or `usermod`. This behavior can be part of persistence tactics.

##  Objective
Detect potentially unauthorized or malicious account creation or modification on Linux systems by monitoring command-line activities.

##  Tools Used
- **SIEM**: Splunk Enterprise
- **Log Source**: Linux Syslog (`/var/log/auth.log`)
- **Lab Setup**:
  - Kali Linux VM with Splunk Universal Forwarder
  - Windows host running Splunk Enterprise
  - Logs forwarded from `/var/log/auth.log` to Splunk over TCP port `9997`

---

##  Data Source Mapping

### 🔍 Authlog (Auth Events)

| Field     | Example Value           | Description                                |
|----------|--------------------------|--------------------------------------------|
| `_time`  | `2025-05-20T21:50:40.123` | Timestamp of the event                     |
| `host`   | `kali`                   | Hostname where the command was executed    |
| `user`   | `root`                   | User that executed the command             |
| `new_user` | `suspicioususer`      | Username being added or modified           |
| `_raw`   | `useradd suspicioususer` | Raw log entry showing the exact command    |

---

## 🛡️ Detection Logic: User Addition or Modification

Detect user creation or modification commands by parsing logs for specific binaries and arguments.

### 🔎 SPL Query

```spl
index="linux_logs" sourcetype="auth" 
("useradd" OR "adduser" OR "passwd -l" OR "passwd -d" OR "usermod")
| rex "useradd\s+(?<new_user>\w+)"
| table _time host user new_user _raw
| sort -_time
```
## Alert

![2](https://github.com/user-attachments/assets/3ea8d364-af2f-4033-b207-dac98dc5579f)

![image](https://github.com/user-attachments/assets/a5c1ec76-869d-4b0b-b12e-5fe0c1812b79)


## Log / Sample Event

| _time                       | host | user | new_user | _raw |
|----------------------------|------|------|----------|------|
| 2025-05-15T16:23:58.938+0530 | kali |      |          | 2025-05-15T16:23:58.938449+05:30 kali usermod[378984]: add 'u1' to shadow group 'sudo' |
| 2025-05-15T16:23:58.938+0530 | kali |      |          | 2025-05-15T16:23:58.938035+05:30 kali usermod[378984]: add 'u1' to group 'sudo' |
| 2025-05-15T16:23:58.916+0530 | kali |      |          | 2025-05-15T16:23:58.916198+05:30 kali sudo: root : TTY=pts/0 ; PWD=/r        |

## Detection Status

✅ Working – Tested on Kali Linux VM with Splunk Universal Forwarder → Windows Splunk Enterprise. Captures any executed useradd, adduser, passwd -d, passwd -l, and usermod commands.

## Analyst Notes / Recommendations

- **Actions:**
  - Verify if the new user account creation was authorized and aligns with change management policies.
  - Investigate the source and context of the account creation (e.g., scripts, admins).
  - Check for follow-up suspicious activities by the new user such as privilege escalation or unusual access.
- **Possible False Positives:**
  - Routine onboarding or provisioning of new employees.
  - Automated user account creation via approved system processes or configuration management.

## 🔗 MITRE ATT&CK Mapping

| MITRE Technique ID | Technique Name                                                                             | Description                                                          |
| ------------------ | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| T1136              | Create Account                                                                             | Adversaries create new user accounts to maintain persistence.        |
| T1543.003          | Create or Modify System Process: Windows Service (Linux equivalent: system services/users) | Creating or modifying system-level accounts or services.             |
| T1059.004          | Command and Scripting Interpreter: Unix Shell                                              | Using shell commands like `useradd` or `usermod` to create accounts. |

