#  Detection Use Case: Credential Dumping on Linux

## Scenario Description
An attacker attempts to extract credentials from a Linux system using tools such as `gcore`, `strings`, `grep`, or memory forensics utilities like Volatility. This behavior is indicative of post-exploitation activities and often aims to access credentials stored in memory or process dumps.

## Objective
Detect suspicious commands that resemble credential dumping behavior using tools such as `gcore`, `strings core.<pid>`, `volatility`, and `grep password` patterns.

## Tools Used
- **SIEM**: Splunk Enterprise
- **Log Sources**: Syslog logs collected via Splunk Universal Forwarder

## Lab Setup
- Kali Linux VM with Splunk Universal Forwarder installed
- Splunk Enterprise running on a Windows host
- Syslog forwarded to Splunk from `/var/log/syslog`

## Data Source Mapping
| Field       | Example Value                          | Description                              |
|-------------|----------------------------------------|------------------------------------------|
| _time       | 2025-05-27T13:28:49.840                | Timestamp of the event                   |
| host        | kali                                   | Host where the command was executed      |
| User        | kali                                   | User running the command                 |
| CommandLine | strings core.1234                      | Command used to dump or scan memory      |
| Image       | /usr/bin/strings                       | Executable path of the command           |
| Command     | strings_core_pid / gcore / volatility  | Classification of the command            |

## 🔎 SPL Query
```spl
index="linux_logs" sourcetype="syslog" host="kali"
| rex field=_raw "<Data Name=\"CommandLine\">(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"Image\">(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"User\">(?<User>[^<]+)</Data>"
| eval CommandLine=coalesce(CommandLine, "")
| where CommandLine!=""
| eval is_strings_core=if(match(CommandLine, "(?i)^strings\\s+core\\.\\d+"), 1, 0)
| eval is_grep_password=if(match(CommandLine, "(?i)^grep.*password"), 1, 0)
| eval is_volatility=if(match(CommandLine, "(?i)(vol\\.py|volatility|linux_pslist|linux_.*)"), 1, 0)
| eval is_gcore=if(match(CommandLine, "(?i)^gcore"), 1, 0)
| eval is_python=if(match(CommandLine, "(?i)^python.*"), 1, 0)
| where is_strings_core=1 OR is_grep_password=1 OR is_volatility=1 OR is_gcore=1 OR is_python=1
| eval Command = 
    case(
        is_strings_core=1, "strings_core_pid",
        is_grep_password=1, "grep_password",
        is_volatility=1, "volatility_tools",
        is_gcore=1, "gcore",
        is_python=1, "python_command",
        true(), "other"
    )
| table _time host User Command Image CommandLine
| sort -_time
```
## Alert

## Log / Sample Event

| Time                         | Host | User | Command              | Executable                           | Command Line                                                   |
|-----------------------------|------|------|----------------------|--------------------------------------|----------------------------------------------------------------|
| 2025-05-28T19:34:30.920+0530 | kali | root | volatility_tools     | /usr/bin/snap                        | /usr/bin/snap advise-snap --format=json --command volatility   |
| 2025-05-28T19:34:30.748+0530 | kali | root | volatility_tools     | /usr/bin/python3.13                  | /usr/bin/python3 /usr/lib/command-not-found -- volatility      |
| 2025-05-28T19:34:15.768+0530 | kali | root | volatility_tools     | /usr/bin/python3.13                  | python3 vol.py -f mem.raw linux_pslist                         |
| 2025-05-28T19:31:46.601+0530 | kali | root | grep_password        | /usr/bin/grep                        | grep --color=auto -i password core_strings.txt                 |
| 2025-05-28T19:31:35.053+0530 | kali | root | strings_core_pid     | /usr/bin/x86_64-linux-gnu-strings    | strings core.1093                                              |

![Screenshot 2025-05-28 194422](https://github.com/user-attachments/assets/c8eff0de-ac1a-40a4-85cd-dac0381ae13f)


## ✅ Detection Status
**Working** – Tested in a lab environment using Splunk Universal Forwarder on Kali Linux and Splunk Enterprise. Successfully detected credential dumping attempts.

## 🧠 Analyst Notes / Recommendations
### Actions:
- Investigate usage of `gcore`, `strings`, `volatility`, or `grep password` in production environments.
- Validate if any memory dumps were created or exfiltrated.
- Check for repeated or scheduled execution of these commands.

### Possible False Positives:
- Developers or sysadmins performing legitimate memory analysis or debugging.
- Forensic investigations or performance diagnostics.

## 🔗 MITRE ATT&CK Mapping
| MITRE Technique ID | Technique Name                             | Description                                         |
|--------------------|--------------------------------------------|-----------------------------------------------------|
| T1003              | OS Credential Dumping                      | Attempts to extract credentials from memory         |
| T1059.004          | Command and Scripting Interpreter: Unix Shell | Using Unix shell for credential dumping tools     |
| T1086              | PowerShell / Python / Bash (where applicable) | Use of interpreted scripting languages             |

