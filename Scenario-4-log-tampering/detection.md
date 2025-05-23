# Detection Use Case: Log Tampering via Suspicious Command Execution

## Scenario Description
An attacker tries to cover their tracks after gaining access by clearing or reading sensitive logs and history files like `/var/log/*`, `.bash_history`, and `.zsh_history` using shell commands such as `cat`, `rm`, or `history -c`.

## Objective
Detect suspicious shell commands executed by a user that indicate potential log tampering or attempts to erase forensic evidence on a Linux system.

## Tools Used
- **SIEM**: Splunk Enterprise
- **Log Source**: Linux Syslog (`/var/log/syslog`)
- **Lab Setup**:
  - Kali Linux VM forwarding logs to Splunk via Universal Forwarder
  - TCP Port: `9997`
  - Monitoring Bash command executions logged in syslog

---

## 🗂️ Data Source Mapping

| Field Name     | Description / Sample Value                         |
|----------------|----------------------------------------------------|
| `_time`        | `2025-05-20T23:44:12.000+0530`                     |
| `user`         | `root`, `kali`, etc.                               |
| `host`         | `kali`                                             |
| `command`      | `rm ~/.bash_history`, `history -c`, `cat /var/log/auth.log` |
| `source`       | `/var/log/syslog`                                  |
| `sourcetype`   | `syslog`                                           |
| `index`        | `linux_logs`                                       |
| `event_type`   | `log_tampering_command`                            |

---

## 🔍 Detection Logic / SPL Query

This SPL identifies suspicious log/history file access or deletion commands from syslog:

```spl
index="linux_logs" sourcetype=syslog (
    "cat /var/log/" OR  "history -c" OR  "history -w" OR  "history" OR  "rm /var/log/vlog" OR  "rm /var/log/vlog*" OR  "rm ~/.bash_history" OR 
    "rm /root/.bash_history" OR  "rm ~/.zsh_history" OR  "rm /root/.zsh_history" OR  "cat ~/.bash_history" OR  "cat /root/.bash_history" OR 
    "cat ~/.zsh_history" OR "cat /root/.zsh_history"
)
| spath input=_raw path=EventData.Data{} output=eventdata | eval Image=mvfilter(match(eventdata, "\"Image\"")) | eval CommandLine=mvfilter(match(eventdata, "\"CommandLine\""))
| eval User=mvfilter(match(eventdata, "\"User\"")) | eval ProcessId=mvfilter(match(eventdata, "\"ProcessId\""))
| eval ParentProcessId=mvfilter(match(eventdata, "\"ParentProcessId\"")) | eval ParentImage=mvfilter(match(eventdata, "\"ParentImage\""))
| eval ParentUser=mvfilter(match(eventdata, "\"ParentUser\"")) | eval UtcTime=mvfilter(match(eventdata, "\"UtcTime\""))
| rex field=_raw "<Data Name=\"Image\">(?<Image>[^<]+)</Data>" | rex field=_raw "<Data Name=\"CommandLine\">(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"User\">(?<User>[^<]+)</Data>" | rex field=_raw "<Data Name=\"ProcessId\">(?<ProcessId>[^<]+)</Data>" | rex field=_raw "<Data Name=\"ParentProcessId\">(?<ParentProcessId>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"ParentImage\">(?<ParentImage>[^<]+)</Data>" | rex field=_raw "<Data Name=\"ParentUser\">(?<ParentUser>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"UtcTime\">(?<UtcTime>[^<]+)</Data>" | table _time Image CommandLine User ProcessId ParentProcessId ParentImage ParentUser UtcTime
| sort -_time
```
## Alert

![image](https://github.com/user-attachments/assets/7020ba14-e4dd-44c3-84f8-b539f6d6ffb5)


## Log / Sample event

| _time                   | Image        | CommandLine           | User | ProcessId | ParentProcessId | ParentImage   | ParentUser | UtcTime |
|-------------------------|--------------|-----------------------|------|-----------|-----------------|---------------|------------|---------|
| 2025-05-20T23:50:13.789+0530 | /usr/bin/cat | cat /var/log/auth.log | root | 64977     | 2275            | /usr/bin/zsh  | root       | 20:13.8 |
| 2025-05-20T23:50:05.416+0530 | /usr/bin/cat | cat /var/log/syslog   | root | 64907     | 2275            | /usr/bin/zsh  | root       | 20:05.4 |



## Detection Status
✅ Working – Verified on Kali Linux by running commands like rm ~/.bash_history, history -c, and cat /var/log/auth.log. Triggered alerts in Splunk via syslog.

## Analyst Notes / Recommendations

- **Actions:**
  - Immediately check for signs of tampering across all critical logs and audit trails.
  - Preserve all current logs and system states for forensic analysis.
  - Harden logging configurations and review permissions on log files.
- **Possible False Positives:**
  - Log rotation or archival processes that delete or compress old logs.
  - Legitimate administrative log cleanup operations.

## 🔗 MITRE ATT&CK Mapping


| MITRE Technique ID | Technique Name                              | Description                                                                                    |
| ------------------ | ------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| T1070.001          | Indicator Removal: Clear Logs               | Deleting or altering logs to cover tracks and avoid detection.                                 |
| T1565.001          | Data Manipulation: Stored Data Manipulation | Modifying stored data including logs to hide malicious activity.                               |
| T1495              | Firmware Corruption                         | Manipulating device firmware that could affect log generation. (less common for log tampering) |

