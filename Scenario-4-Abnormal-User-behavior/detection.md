
# Detection Use Case: Abnormal User Behavior on Linux

## Scenario Description
An attacker exhibiting suspicious behavior on a Linux host may attempt unauthorized file shares, access large volumes of files in a short time, or login during unusual hours. These behaviors may indicate data exfiltration, lateral movement, or compromised credentials.

## Objective
Detect abnormal user behavior patterns such as unauthorized network mounts, bursts of file access, or logins during off-hours on Linux systems.

## Tools Used
- **SIEM**: Splunk Enterprise  
- **Log Source**: Linux Syslog (`/var/log/syslog`), Custom File Copy Alert Logs, Auth Logs
- **Custom File Copy Alert Script** :
- ![Screenshot 2025-05-27 005331](https://github.com/user-attachments/assets/9ab4b8cd-c6a7-4438-ba0f-e82b2332bf73)


**Lab Setup**:
- Kali Linux VM with Splunk Universal Forwarder
- Windows host running Splunk Enterprise
- Logs forwarded to Splunk over TCP port 9997
- 

## Data Source Mapping
🔍 Linux Syslog, File Copy Alerts, Auth Logs

| Field | Example Value | Description |
|-------|----------------|-------------|
| _time | 2025-05-21T05:41:22.000 | Timestamp of the event |
| host | kali | Host where activity was detected |
| event_type | Suspicious Login Hour | Categorized behavior |
| type | nfs / cifs | Filesystem type used in mount |
| share_path | //192.168.1.10/share | Source of the mounted network drive |
| mount_location | /mnt/share | Target mount location |
| file_count | 120 | Number of files accessed |
| duration | 5 | Duration in seconds for bulk access |
| file_list | /mnt/share/doc1.txt ... | List of accessed files |
| hour_12_num | 3 | Hour of the event (12-hr format) |
| ampm | AM | Whether event occurred in AM or PM |
| time_12hr | 03:14:22 AM | Readable time format |

---

## 🛡️ Detection Logic: Abnormal Behavior Heuristics

This use case uses a union of multiple detections including:
- Mounting of NFS or CIFS shares
- Accessing many files quickly (file copy bursts)
- Login or root session activities during unusual hours (e.g., before 9 AM or after 7 PM)

## 🔎 SPL Query

```spl
index="linux_logs" sourcetype=syslog host="kali" "mount -t"
| rex field=_raw "<Data Name=\"CommandLine\">mount -t (?<type>\w+)(?:.*?) (?<source>\/\/[^ ]+|[0-9.:]+:[^ ]+) (?<mount_point>\/[^<]+)<\/Data>"
| eval event_type=case(
    type=="nfs", "NFS Mount",
    type=="cifs", "CIFS/SMB Mount",
    true(), "Other Mount"
  )
| eval share_path=source, mount_location=mount_point, file_count=null(), duration=null(), file_list=null(), hour_12_num=null(), ampm=null(), time_12hr=null()
| table _time, host, event_type, type, share_path, mount_location, file_count, duration, file_list, hour_12_num, ampm, time_12hr
| append [
    search index="linux_logs" source="/var/log/file_copy_alerts.log"
    | rex mode=sed field=_raw "s/\r//g"
    | rex field=_raw "\[ALERT\] (?<log_date>[A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} [APM]{2}) IST \d{4}: Detected (?<file_count>\d+) files accessed in (?<duration>\d+) seconds\."
    | rex max_match=0 field=_raw "\s+- (?<file_list>/[^\s]+)"
    | eval event_type="File Access Burst", type=null(), share_path=null(), mount_location=null(), hour_12_num=null(), ampm=null(), time_12hr=null()
    | table _time, host, event_type, type, share_path, mount_location, file_count, duration, file_list, hour_12_num, ampm, time_12hr
]
| append [
    search index="linux_logs" sourcetype="auth"
    ("Accepted password for kali" OR "Accepted publickey for kali" OR 
     "session opened for user root" OR 
     "COMMAND=")
    | eval hour_12=strftime(_time, "%I"), ampm=strftime(_time, "%p"), time_12hr=strftime(_time, "%I:%M:%S %p")
    | eval hour_12_num=tonumber(hour_12)
    | eval event_type=case(
        like(_raw, "%Accepted password for kali%") OR like(_raw, "%Accepted publickey for kali%"), "login",
        like(_raw, "%session opened for user root%"), "root_session",
        like(_raw, "%COMMAND=%") AND like(_raw, "%kali%"), "command_as_root",
        true(), "other"
      )
    | where event_type IN ("login", "root_session", "command_as_root")
        AND (
            (ampm="AM" AND hour_12_num < 9) OR
            (ampm="PM" AND hour_12_num > 7 AND hour_12_num < 12)
        )
    | stats earliest(_time) as _time by host, hour_12_num, ampm
    | eval event_type="Suspicious Login Hour", type=null(), share_path=null(), mount_location=null(), file_count=null(), duration=null(), file_list=null(), time_12hr=strftime(_time, "%I:%M:%S %p")
    | table _time, host, event_type, type, share_path, mount_location, file_count, duration, file_list, hour_12_num, ampm, time_12hr
]
| sort -_time
```
## Alert
![image](https://github.com/user-attachments/assets/5e889cc3-67e2-40a5-b6c8-36e10f28392c)


---
## Log / Sample Event

| _time                      | host | event_type              | type | share_path               | mount_location | file_count | duration | file_list                                                                                         | hour_12_num | ampm | time_12hr   |
|---------------------------|------|--------------------------|------|---------------------------|----------------|-------------|----------|---------------------------------------------------------------------------------------------------|--------------|------|-------------|
| 2025-05-27T13:28:49.840+0530 | kali | CIFS/SMB Mount           | cifs | //192.168.1.11/shared     | /mnt/share     |             |          |                                                                                                   |              |      |             |
| 2025-05-27T13:28:49.815+0530 | kali | Other Mount              |      | /var/log/syslog           |                |             |          |                                                                                                   |              |      |             |
| 2025-05-27T13:28:17.043+0530 | kali | NFS Mount                | nfs  | 192.168.1.11:/exports     | /mnt/nfs       |             |          |                                                                                                   |              |      |             |
| 2025-05-27T12:59:32.000+0530 | kali | File Access Burst        |      |                           |                | 101         | 10       | "/mnt/file100.txt<br>/mnt/file101.txt<br>/mnt/file10.txt<br>/mnt/file11.txt<br>/mnt/file12.txt" |              |      |             |
| 2025-05-27T01:04:19.411+0530 | kali | Suspicious Login Hour    |      |                           |                |             |          |                                                                                                   | 1            | AM   | 1:04:19 AM  |

![Screenshot 2025-05-27 135025](https://github.com/user-attachments/assets/db7ff4f4-d412-4266-a190-aba8f39fcf60)


## Detection Status
✅ Working – Validated with sample events simulating abnormal file mounts, mass file access, and off-hours login activity on a Kali Linux VM forwarded to Splunk.

## Analyst Notes / Recommendations

**Actions**:
- Correlate suspicious mounts with known IPs or shares.
- Investigate large file access bursts for exfiltration.
- Alert on logins outside business hours without valid change records.

**Possible False Positives**:
- Scheduled automated backups or file syncs
- System admin performing tasks in off-hours under valid change ticket

## 🔗 MITRE ATT&CK Mapping

| MITRE Technique ID | Technique Name | Description |
|--------------------|----------------|-------------|
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Mounting remote shares via SMB/NFS |
| T1030 | Data Transfer Size Limits | Transferring large sets of files rapidly |
| T1078 | Valid Accounts | Using legitimate credentials to login |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell commands for mounts and data access |
