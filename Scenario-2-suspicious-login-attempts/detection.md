# Detection Use Case: Suspicious Login Attempt After Business Hours

## Scenario Description
A user logs into the Linux system outside standard working hours (valid login window: 9:00 AM to 7:00 PM). Such activity could indicate unauthorized or suspicious access.

## Objective
This detection aims to identify login events occurring outside of defined working hours (09:00–19:00), which may indicate lateral movement or unauthorized access attempts.

## Tools Used
- **SIEM**: Splunk Enterprise
- **Log Source**: Linux (`/var/log/auth.log`)
- **Lab Setup**:
  - Linux VM (Kali) running Splunk Universal Forwarder
  - Windows host running Splunk Enterprise
  - Logs monitored: `/var/log/auth.log`
  - Logs forwarded to Splunk via TCP port `9997`

---

## Data Source Mapping

| Field Name         | Description / Sample Value                             |
|--------------------|--------------------------------------------------------|
| Log Source         | `/var/log/auth.log`                                    |
| Sourcetype         | `auth`                                                 |
| Index              | `linux_logs`                                           |
| Host               | `kali`                                                 |
| Splunk Server      | `KANHA`                                                |
| Timestamp (_time)  | `2025-05-20T21:42:53.609+0530`                         |
| User               | `root`                                                 |
| Event Type         | `login`, `root_session`, `command_as_root`             |
| TTY                | `unknown`                                              |
| AM/PM              | `PM`                                                   |
| Hour (12hr)        | `09`                                                   |



## Detection Logic / Query (Splunk SPL)
```spl
index="linux_logs" sourcetype="auth"
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
| sort _time
```
## Alert

![image](https://github.com/user-attachments/assets/a39283e9-9822-4743-bab6-7a9125cab9c9)

## Logs / Sample event 

| COMMAND                   | CWD         | TTY     | USER | _raw                                                                                                                                                                  | _time                          | ampm | date_hour | date_mday | date_minute | date_month | date_second | date_wday | date_year | date_zone | event_type     | host | hour_12 | hour_12_num | index      | source             | sourcetype | splunk_server | time_12hr     |
|---------------------------|-------------|---------|------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------|------|------------|-----------|--------------|-------------|--------------|------------|------------|------------|----------------|------|----------|--------------|------------|--------------------|-------------|----------------|----------------|
|                           |             |         |      | 2025-05-20T21:41:11.449974+05:30 kali su[1205]: pam_unix(su:session): session opened for user root(uid=0) by (uid=0)                                                  | 2025-05-20T21:41:11.449+0530  | PM   | 21         | 20        | 41           | may         | 11           | tuesday    | 2025       | 330        | root_session   | kali | 09       | 9            | linux_logs | /var/log/auth.log | auth        | KANHA          | 9:41:11 PM     |
|                           |             |         |      | 2025-05-20T21:41:11.718517+05:30 kali (systemd): pam_unix(systemd-user:session): session opened for user root(uid=0) by root(uid=0)                                   | 2025-05-20T21:41:11.718+0530  | PM   | 21         | 20        | 41           | may         | 11           | tuesday    | 2025       | 330        | root_session   | kali | 09       | 9            | linux_logs | /var/log/auth.log | auth        | KANHA          | 9:41:11 PM     |
|                           |             |         |      | 2025-05-20T21:42:53.609040+05:30 kali pkexec: pam_unix(polkit-1:session): session opened for user root(uid=0) by kali(uid=1000)                                       | 2025-05-20T21:42:53.609+0530  | PM   | 21         | 20        | 42           | may         | 53           | tuesday    | 2025       | 330        | root_session   | kali | 09       | 9            | linux_logs | /var/log/auth.log | auth        | KANHA          | 9:42:53 PM     |
| /usr/bin/x-terminal-emulator | /home/kali | unknown | root | 2025-05-20T21:42:53.615409+05:30 kali pkexec[2229]: kali: Executing command [USER=root] [TTY=unknown] [CWD=/home/kali] [COMMAND=/usr/bin/x-terminal-emulator]         | 2025-05-20T21:42:53.615+0530  | PM   | 21         | 20        | 42           | may         | 53           | tuesday    | 2025       | 330        | command_as_root | kali | 09       | 9            | linux_logs | /var/log/auth.log | auth        | KANHA          | 9:42:53 PM     |
|                           |             |         |      | 2025-05-20T21:45:01.836709+05:30 kali CRON[3930]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)                                          | 2025-05-20T21:45:01.836+0530  | PM   | 21         | 20        | 45           | may         | 1            | tuesday    | 2025       | 330        | root_session   | kali | 09       | 9            | linux_logs | /var/log/auth.log | auth        | KANHA          | 9:45:01 PM     |

---

![image](https://github.com/user-attachments/assets/377da64d-6abb-4d68-9d3f-190b68d8de8d)

## Detection Status

✅ Working – Detection successfully validated using test logins at 9:42 PM and CRON root session.

## Analyst Notes / Recommendations

- **Actions:**
  - Verify whether the login is consistent with user’s typical behavior or authorized remote access policies.
  - Reach out to the user or the security team for validation if the login looks suspicious.
  - Monitor subsequent activity from the user session for anomalies.
- **Possible False Positives:**
  - Users working late or remotely outside normal hours.
  - Scheduled batch jobs or automated scripts authenticating during off-hours.

## 🔗 MITRE ATT&CK Mapping

| MITRE Technique ID | Technique Name       | Description                                                                                         |
| ------------------ | -------------------- | --------------------------------------------------------------------------------------------------- |
| T1078              | Valid Accounts       | Use of valid credentials potentially at unusual times indicating unauthorized access.               |
| T1110              | Brute Force          | Repeated login attempts during odd hours to evade detection.                                        |
| T1021.004          | Remote Services: SSH | Remote access via SSH during off-hours possibly indicating lateral movement or unauthorized access. |

