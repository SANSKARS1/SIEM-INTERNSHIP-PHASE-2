# Detection Use Case: Privilege Escalation Attempt on Linux

## Scenario Description
An attacker already inside a Linux system attempts to escalate privileges using various enumeration and exploitation commands like `find / -perm -u=s`, `sudo -l`, `getcap -r /`, and path manipulation. Such activity is common during the post-exploitation phase.

## Objective
Detect potential privilege escalation attempts by monitoring for command-line patterns that enumerate or exploit setuid files, elevated permissions, or environment misconfigurations.

##  Tools Used
- **SIEM**: Splunk Enterprise
- **Log Source**: Linux Syslog 
- **Lab Setup**:
  - Kali Linux VM with Splunk Universal Forwarder
  - Windows host running Splunk Enterprise
  - Logs forwarded from `syslog` to Splunk over TCP port `9997`

**Lab Setup**:
- Kali Linux VM with Splunk Universal Forwarder  
- Windows host running Splunk Enterprise  
- Logs forwarded from `/var/log/syslog` to Splunk over TCP port 9997

## Data Source Mapping
🔍 **Syslog (Linux Command Events)**

| Field     | Example Value             | Description                               |
|-----------|---------------------------|-------------------------------------------|
| _time     | 2025-05-20T21:50:40.123   | Timestamp of the event                    |
| host      | kali                      | Hostname where the command was executed   |
| User      | root                      | User that executed the command            |
| commands  | find / -perm -u=s         | Detected command(s)                       |
| Image     | /bin/bash                 | Process image or shell used               |

## 🛡️ Detection Logic: Privilege Escalation Command Monitoring
Monitor for commands related to privilege escalation including binary capabilities, SUID/SGID file scans, sudo listing, and path export abuse.

## 🔎 SPL Query
```spl
index=linux_logs sourcetype=syslog
| rex "<Data Name=\"CommandLine\">(?<cmd>[^\<]+)</Data>"
| rex "<Data Name=\"User\">(?<User>[^\<]+)</Data>"
| rex "<Data Name=\"Image\">(?<Image>[^\<]+)</Data>"
| eval is_priv_esc_cmd=if(
    match(cmd, "find\\s+/\\s+-type\\s+f\\s+-perm\\s+-04000") OR
    match(cmd, "find\\s+/\\s+-perm\\s+-u=s") OR
    match(cmd, "getcap\\s+-r\\s+/") OR
    match(cmd, "export\\s+PATH=.*:\\\$PATH") OR
    match(cmd, "sudo\\s+-l"), 1, 0)
| eval is_recon_cmd=if(
    match(cmd, "(^|\\s)hostname(\\s|$)") OR
    match(cmd, "(^|\\s)uname(\\s|$)") OR
    match(cmd, "(^|\\s)ps(\\s|$)") OR
    match(cmd, "(^|\\s)env(\\s|$)") OR
    match(cmd, "(^|\\s)history(\\s|$)"), 1, 0)
| bin _time span=1m
| stats 
    values(cmd) as commands,
    sum(is_priv_esc_cmd) as priv_esc_count,
    sum(is_recon_cmd) as recon_cmd_count
  by User Image _time host
| eval DetectionType=case(
    priv_esc_count > 0, "Privilege Escalation Command",
    recon_cmd_count >= 3, "Recon Activity (Multiple Commands)"
)
| where DetectionType!=""
| table _time host User commands Image DetectionType
| sort -_time
```

## Alert
**Trigger Condition**: Presence of high-confidence privilege escalation or multiple recon commands.


## Log / Sample Event

| _time                      | host | User | commands                                                 | Image             | DetectionType                  |
|---------------------------|------|------|----------------------------------------------------------|-------------------|---------------------------------|
| 2025-05-25T17:43:00.000+0530 | kali | root | getcap -r                                                | /usr/sbin/getcap  | Privilege Escalation Command   |
| 2025-05-25T17:33:00.000+0530 | kali | root | find / -type f -perm -04000 -ls                          | /usr/bin/find     | Privilege Escalation Command   |
| 2025-05-25T17:31:00.000+0530 | kali | root | sudo -l                                                  | /usr/bin/sudo     | Privilege Escalation Command   |
| 2025-05-25T17:28:00.000+0530 | kali | root | sudo -l                                                  | /usr/bin/sudo     | Privilege Escalation Command   |
| 2025-05-25T17:25:00.000+0530 | kali | root | find / -type f -perm -04000 find / -type f -perm -04000 -ls | /usr/bin/find     | Privilege Escalation Command   |


![1](https://github.com/user-attachments/assets/39ac3671-99c7-4e26-978e-7326c0e6353c)


## Detection Status
✅ **Working** – Tested on Kali Linux VM with Splunk Universal Forwarder → Windows Splunk Enterprise. Detects SUID search, `sudo -l`, and similar recon commands.

## Analyst Notes / Recommendations

**Actions**:
- Confirm the legitimacy of the commands executed.
- Cross-reference with user behavior and session history.
- Investigate whether the commands led to access escalation or lateral movement.

**Possible False Positives**:
- Admins running audits or checks during scheduled assessments.
- System processes conducting environment inventory.

## 🔗 MITRE ATT&CK Mapping

| MITRE Technique ID | Technique Name                                  | Description                                                    |
|--------------------|--------------------------------------------------|----------------------------------------------------------------|
| T1068              | Exploitation for Privilege Escalation            | Exploiting SUID binaries or vulnerable applications.           |
| T1087              | Account Discovery                                | Using recon commands like `whoami`, `id`, `env`, `hostname`.   |
| T1548.003          | Abuse Elevation Control Mechanism: Sudo and su   | Using `sudo -l`, exporting `$PATH` to run high privilege tools |
