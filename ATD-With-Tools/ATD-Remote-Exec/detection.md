
# Detection Use Case: Remote Scheduled Task Creation and Suspicious File Execution on Linux

## Scenario Description
An attacker gains access to a Linux machine and creates a scheduled task via crontab or modifies systemd unit files to achieve persistence. Simultaneously, they may execute suspicious shell scripts or commands such as reverse shells or arbitrary bash instructions to maintain control or exfiltrate data.

## Objective
Detect potential persistence and command execution techniques by identifying cron or systemd file modifications and suspicious script executions using shell commands.

## Tools Used
**SIEM:** Splunk Enterprise  
**Log Sources:** Linux Auditd and Syslog
**Auditd-Rules:** 
![Screenshot 2025-05-28 184409](https://github.com/user-attachments/assets/0ba380e1-3e95-4b31-ab54-17207b01a148)


### Lab Setup:
- Kali Linux VM with Splunk Universal Forwarder installed
- Splunk Enterprise running on a Windows host
- Logs from `/var/log/audit/audit.log` and system syslog forwarded to Splunk

---

## Data Source Mapping

### 📘 Auditd and Syslog

| Field          | Example Value                    | Description |
|----------------|----------------------------------|-------------|
| `_time`        | 2025-05-22T15:03:45.231          | Timestamp of the event |
| `host`         | kali                             | Hostname where the event occurred |
| `command`      | crontab                          | Binary used to modify cron/systemd |
| `exe`          | /usr/bin/crontab                 | Path to the binary |
| `mod_key`      | cron_mod                         | Key indicating what was modified (cron/systemd) |
| `status`       | Success                          | Outcome of the action |
| `description`  | This shows the actual cron file modification using /usr/bin/crontab | Contextual description |
| `command_line` | bash -c "nc -e /bin/bash ..."    | Suspicious command execution |
| `image`        | /usr/bin/bash                    | Binary path of executed script |
| `parent_image` | /usr/bin/gnome-terminal-server   | Parent process |
| `parent_cmd`   | bash                             | Parent command |
| `user`         | kali                             | User executing the command |
| `user_dir`     | /home/kali                       | User's current working directory |

---

## 🛡️ Detection Logic: Cron/Systemd Modification and Suspicious Script Execution

### 🔎 SPL Query
```splunk
index=linux_logs sourcetype=linux_audit (key="cron_mod" OR key="systemd_mod")
| rex field=_raw "comm=\"(?<command>[^"]+)\""
| rex field=_raw "exe=\"(?<exe>[^"]+)\""
| rex field=_raw "success=(?<success>\w+)"
| rex field=_raw "exit=(?<exit_code>[-\d]+)"
| rex field=_raw "auid=(?<audit_uid>\d+)"
| rex field=_raw "key=\"(?<mod_key>[^"]+)\""
| eval user=if(audit_uid=="1000", "kali", "root_or_other")
| eval status=if(success=="yes", "Success", "Failure")
| eval description=case(
    mod_key=="cron_mod" AND status=="Success", "This shows the actual cron file modification using " . exe,
    mod_key=="systemd_mod" AND status=="Success", "This shows a systemd unit file was accessed/modified using " . exe,
    true(), ""
)
| eval event_type="Cron or Systemd Modification"
| table _time, host, event_type, command, exe, user, status, exit_code, mod_key, description

| append [
    search index=linux_logs sourcetype=syslog
    | rex field=_raw "<Data Name=\"CommandLine\">(?<command_line>[^<]+)</Data>"
    | rex field=_raw "<Data Name=\"Image\">(?<image>[^<]+)</Data>"
    | rex field=_raw "<Data Name=\"ParentImage\">(?<parent_image>[^<]+)</Data>"
    | rex field=_raw "<Data Name=\"ParentCommandLine\">(?<parent_cmd>[^<]+)</Data>"
    | rex field=_raw "<Data Name=\"User\">(?<user>[^<]+)</Data>"
    | rex field=_raw "<Data Name=\"CurrentDirectory\">(?<user_dir>[^<]+)</Data>"
    | where (
        like(command_line, "%.sh%") OR
        like(command_line, "%/dev/tcp/%") OR
        like(command_line, "%nc -e%") OR
        like(command_line, "%bash -c%")
    )
    AND NOT (
        like(command_line, "%xfce4-panel-genmon-vpnip.sh%") OR
        like(image, "/usr/lib/x86_64-linux-gnu/%") OR
        like(command_line, "%/usr/share/kali-themes/%") OR
        like(command_line, "%/opt/splunkforwarder/%") OR
        like(command_line, "%pid_check.sh%")
    )
    | eval event_type="Suspicious Bash Execution"
    | table _time, host, event_type, command_line, image, parent_image, parent_cmd, user, user_dir
]
| sort -_time
```
## Alert
---
## Log / Sample Event
![Screenshot 2025-05-28 184253](https://github.com/user-attachments/assets/1adb765d-3eca-4117-8178-3b915aae264c)

---

## ✅ Detection Status
**Working** – Tested in a lab using Splunk Universal Forwarder on Kali Linux. Detected cron/systemd file changes and suspicious script activity.

---

## 🧠 Analyst Notes / Recommendations

**Actions:**
- Review cron or systemd file changes to determine if they were legitimate or attacker-created.
- Investigate any bash command invoking network tools or running suspicious scripts.
- Examine parent processes to understand attack chains (e.g., from terminal emulators or unknown binaries).

**Possible False Positives:**
- Automated system management tools (e.g., Ansible, Puppet) may alter cron/systemd as part of routine updates.
- Admin scripts using bash or cron for monitoring or backups.

---

## 🔗 MITRE ATT&CK Mapping

| MITRE Technique ID | Technique Name | Description |
|--------------------|----------------|-------------|
| T1053.003          | Scheduled Task/Job: Cron | Using crontab to maintain persistence |
| T1053.002          | Scheduled Task/Job: Systemd Timers | Using systemd for persistence |
| T1059.004          | Command and Scripting Interpreter: Unix Shell | Bash script execution |
| T1547              | Boot or Logon Autostart Execution | Cron/systemd-based autostart |
