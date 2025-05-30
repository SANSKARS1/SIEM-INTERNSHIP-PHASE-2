
# Detection Use Case: Lateral Movement Detection on Linux

## Scenario Description
Detecting attempts at lateral movement within a Linux environment by monitoring for tools and commands such as `enum4linux`, `smbclient`, `nmap` with SMB scripts, and SSH login anomalies.

## Objective
Detect possible lateral movement through SMB enumeration, port probing, and automated SSH sessions using tools like `sshpass`.

## Tools Used
- **SIEM**: Splunk Enterprise
- **Log Source**: Linux Syslog
- **Lab Setup**:
  - Kali Linux VM with Splunk Universal Forwarder
  - Windows host running Splunk Enterprise
  - Logs forwarded from `/var/log/syslog` and `/var/log/auth.log` to Splunk over TCP port 9997

## Data Source Mapping

| Field         | Example Value                                | Description                               |
|---------------|----------------------------------------------|-------------------------------------------|
| _time         | 2025-05-30T13:05:44.456                      | Timestamp of the event                    |
| host          | kali                                          | Hostname where the activity was observed  |
| User          | root                                          | User that executed the command            |
| CommandLine   | enum4linux -a                                 | Command executed                          |
| Image         | /usr/bin/python3                              | Process image                             |
| ParentImage   | /bin/bash                                     | Parent process                            |
| DestinationIp | 192.168.1.5                                   | Target IP of the command                  |

## 🛡️ Detection Logic: SMB & SSH-based Lateral Movement

### 🔎 SPL Query

```spl
index="linux_logs" sourcetype="syslog"
| rex field=_raw "<Data Name=\"CommandLine\">(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"Image\">(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"User\">(?<User>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"ParentImage\">(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"DestinationIp\">(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"UtcTime\">(?<UtcTime>[^<]+)</Data>"
| eval _time=strptime(UtcTime, "%Y-%m-%d %H:%M:%S.%3N")
| eval is_enum4linux=if(match(CommandLine, "(?i)enum4linux.*-a"), 1, 0)
| eval is_smbclient=if(match(CommandLine, "(?i)smbclient\s+-L"), 1, 0)
| eval is_nmap_smb=if(match(CommandLine, "(?i)nmap.*smb-enum-shares"), 1, 0)
| eval is_smb_port_activity=if(match(CommandLine, "(?i)(nc|ncat|telnet).*(139|445)"), 1, 0)
| eval attack_type=case(
    is_enum4linux=1, "Enum4linux SMB Probe",
    is_smbclient=1, "SMBClient Probe",
    is_nmap_smb=1, "Nmap SMB Scan",
    is_smb_port_activity=1, "Port 139/445 Probe",
    true(), null()
)
| where is_enum4linux=1 OR is_smbclient=1 OR is_nmap_smb=1 OR is_smb_port_activity=1
| eval detection_type="Lateral Movement"
| table _time host User Image ParentImage CommandLine DestinationIp attack_type detection_type

| append [

  search index="linux_logs" (source="/var/log/auth.log" OR source="/var/log/secure")
  "Accepted password for" AND "sshd"
  | where NOT match(_raw, "session opened for user.*tty")
  | eval _time=_time
  | eval User=coalesce(user, "-"), Image="sshd", ParentImage="-"
  | eval CommandLine="Detected automated SSH session likely using sshpass, indicating possible lateral movement."
  | eval DestinationIp="-"
  | eval attack_type="Automated SSH Session (sshpass)"
  | eval detection_type="Lateral Movement"
  | table _time host User Image ParentImage CommandLine DestinationIp attack_type detection_type
]

| sort -_time
```

## Alert
**Trigger Condition**: Match found in SMB tool usage or anomalous SSH logins (likely automated).

## Sample Log/Event Table
| Time                         | Host | User | Image                 | Command Line                                                | Destination IP  | Attack Type               | Detection Type     |
|------------------------------|------|------|-----------------------|-------------------------------------------------------------|-----------------|---------------------------|--------------------|
| 2025-05-30T15:25:16.253+0530 | kali | -    | sshd                  | Detected automated SSH session likely using sshpass          | -               | Automated SSH Session (sshpass) | Lateral Movement   |
| 2025-05-30T14:26:59.604+0530 | kali | -    | sshd                  | Detected automated SSH session likely using sshpass          | -               | Automated SSH Session (sshpass) | Lateral Movement   |
| 2025-05-30T14:26:49.712+0530 | kali | -    | sshd                  | Detected automated SSH session likely using sshpass          | -               | Automated SSH Session (sshpass) | Lateral Movement   |
| 2025-05-29T00:46:10.184+0530 | kali | root | /usr/bin/smbclient    | smbclient -L 192.168.1.11 -N                                 | 192.168.1.11    | SMBClient Probe            | Lateral Movement   |
| 2025-05-29T00:00:31.818+0530 | kali | root | /usr/bin/smbclient    | smbclient -L 192.168.1.11 -N                                 | 192.168.1.11    | SMBClient Probe            | Lateral Movement   |
| 2025-05-29T00:00:03.193+0530 | kali | root | /usr/lib/nmap/nmap    | /usr/lib/nmap/nmap -p 139,445 --script smb-enum-shares 192.168.1.11 | 192.168.1.11    | Nmap SMB Scan              | Lateral Movement   |
| 2025-05-29T00:00:03.193+0530 | kali | root | /usr/bin/dash         | sh /usr/bin/nmap -p 139,445 --script smb-enum-shares 192.168.1.11 | 192.168.1.11    | Nmap SMB Scan              | Lateral Movement   |
| 2025-05-29T00:00:03.193+0530 | kali | root | /usr/bin/env          | /usr/bin/env sh /usr/bin/nmap -p 139,445 --script smb-enum-shares 192.168.1.11 | 192.168.1.11    | Nmap SMB Scan              | Lateral Movement   |
| 2025-05-28T23:57:05.603+0530 | kali | root | /usr/bin/perl         | /usr/bin/perl ./enum4linux.pl -a 192.168.1.11 -u root -p kali | 192.168.1.11    | Enum4linux SMB Probe       | Lateral Movement   |
| 2025-05-28T23:57:05.603+0530 | kali | root | /usr/bin/dash         | sh /usr/bin/enum4linux -a 192.168.1.11 -u root -p kali       | 192.168.1.11    | Enum4linux SMB Probe       | Lateral Movement   |
| 2025-05-28T23:57:05.603+0530 | kali | root | /usr/bin/env          | /usr/bin/env sh /usr/bin/enum4linux -a 192.168.1.11 -u root -p kali | 192.168.1.11    | Enum4linux SMB Probe       | Lateral Movement   |
| 2025-05-28T23:55:59.197+0530 | kali | root | /usr/bin/perl         | /usr/bin/perl ./enum4linux.pl -a 192.168.1.11               | 192.168.1.11    | Enum4linux SMB Probe       | Lateral Movement   |
| 2025-05-28T23:55:59.197+0530 | kali | root | /usr/bin/dash         | sh /usr/bin/enum4linux -a 192.168.1.11                       | 192.168.1.11    | Enum4linux SMB Probe       | Lateral Movement   |
| 2025-05-28T23:55:59.197+0530 | kali | root | /usr/bin/env          | /usr/bin/env sh /usr/bin/enum4linux -a 192.168.1.11         | 192.168.1.11    | Enum4linux SMB Probe       | Lateral Movement   |

![Screenshot 2025-05-30 155936](https://github.com/user-attachments/assets/4c1df56a-4221-4152-bb59-1784da6b6604)

## Detection Status
✅ **Working** – Validated with simulated SMB probes and sshpass connections.

## Analyst Notes / Recommendations
- Investigate the command history to confirm intent.
- Verify if lateral movement led to sensitive data access or further privilege escalation.
- Review session and network activity for correlated indicators.

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Technique Name                         | Description                                        |
|--------------|----------------------------------------|----------------------------------------------------|
| T1021.002    | Remote Services: SMB/Windows Admin Shares | Use of SMB for lateral movement                    |
| T1021.004    | Remote Services: SSH                   | Use of SSH and sshpass for automated logins       |
| T1046        | Network Service Scanning               | Probing ports like 139/445 for SMB enumeration    |
