
# Detection Use Case: C2 Beaconing Detection

## Scenario Description
This detection aims to identify Command and Control (C2) beaconing behavior, such as DNS tunneling using tools like `dig` with long subdomains, and repeated outbound connections to external IPs, which are common indicators of beaconing activity.

## Objective
Detect suspicious DNS queries with long subdomains and high-frequency outbound connections from Linux hosts, potentially indicating malware beaconing to a C2 server.

## Tools Used
- **SIEM**: Splunk Enterprise
- **Log Source**: Linux (Syslog/XML Events)
- **Lab Setup**:
  - Linux VMs running Splunk Universal Forwarder
  - Splunk Enterprise on central server
  - Syslog forwarding configured
  - DNS and network logs monitored

---

## Data Source Mapping

| Field Name        | Description / Sample Value            |
|------------------|----------------------------------------|
| `_time`          | `2025-05-23T16:40:22.000+0000`         |
| `host`           | `linux-host`                           |
| `User`           | `root`                                 |
| `domain`         | `abcde1234567890verylongsubdomain.com` |
| `subdomain_len`  | `44`                                   |
| `ProcessId`      | `1234`                                 |
| `ParentProcessId`| `4321`                                 |
| `DestinationIp`  | `192.168.1.7`                              |
| `count`          | `4`                                    |
| `detection_type` | `LongSubdomainBeacon` / `HighFrequencyOutbound` |

---

## 🛡️ Detection Logic: C2 Beaconing via Long Subdomain or Repeated Connections

This SPL query identifies suspicious activity in two parts:
- **Part 1**: Long subdomain DNS queries using `dig`, a common tactic in DNS tunneling.
- ![image](https://github.com/user-attachments/assets/77271ff9-1e75-4f98-8b13-d9fe64042306)

- **Part 2**: High frequency of outbound connections to external IPs within short intervals.
- ![1](https://github.com/user-attachments/assets/f437c4bd-96fe-4bd0-827f-f13ec67785a5)


### 🔍 SPL Query Used:

```spl
index=linux_logs sourcetype=syslog "Image">/usr/bin/dig"
| rex "<Data Name=\"CommandLine\">dig\s+(?<domain>[a-zA-Z0-9\-\.]+)</Data>"
| eval subdomain=mvindex(split(domain, "."), 0)
| eval subdomain_len = len(subdomain)
| where subdomain_len > 40
| rex "<Data Name=\"User\">(?<User>[^\<]+)</Data>"
| rex "<Data Name=\"ProcessId\">(?<ProcessId>[^\<]+)</Data>"
| rex "<Data Name=\"ParentProcessId\">(?<ParentProcessId>[^\<]+)</Data>"
| eval detection_type="LongSubdomainBeacon"
| table _time host User domain subdomain_len ProcessId ParentProcessId detection_type

| append [
  search index=linux_logs sourcetype=syslog "EventID>3"
  | rex "<Data Name=\"UtcTime\">(?<UtcTime>[^\<]+)</Data>"
  | rex "<Data Name=\"DestinationIp\">(?<DestinationIp>[^\<]+)</Data>"
  | rex "<Data Name=\"Image\">(?<Image>[^\<]+)</Data>"
  | eval _time=strptime(UtcTime, "%Y-%m-%d %H:%M:%S.%3N")
  | where DestinationIp!="0:0:0:0:0:0:0:0" AND DestinationIp!="192.168.1.254"
  | bin _time span=1m
  | stats count by _time DestinationIp
  | where count > 3
  | eval detection_type="HighFrequencyOutbound"
  | table _time DestinationIp count detection_type
]

| sort - _time
```
## Alert

![6](https://github.com/user-attachments/assets/f12be8ac-79dc-4630-9cb2-89aae5e7b3e0)

---

## Log / Sample Event

**1.** 
| _time                      | DestinationIp | count |
|---------------------------|----------------|-------|
| 2025-05-22T09:34:00.000+0530 | 192.168.1.7   | 4     |
| 2025-05-22T09:33:00.000+0530 | 192.168.1.7   | 4     |

**2.**
| _time                      | host | User | domain                                                        | subdomain_len | ProcessId | ParentProcessId | detection_type         | DestinationIp   | count |
|---------------------------|------|------|----------------------------------------------------------------|----------------|-----------|------------------|-------------------------|------------------|--------|
| 2025-05-25T14:45:05.564+0530 | kali | root | oyn13lo2zusyu56r07evdutg6sf3xkg9xzbfcqk2j7r4qaex2y.attacker.com | 50             | 1219916   | 2275             | LongSubdomainBeacon     |                  |        |
| 2025-05-25T14:45:03.042+0530 | kali | root | v6tkafg5rezeova6anwj43eztdfjozvceuap9bds9anird4rok.attacker.com | 50             | 1219893   | 2275             | LongSubdomainBeacon     |                  |        |
| 2025-05-25T14:40:10.726+0530 | kali | root | k9tiec20hph2enjx4go59v7y4z85sho9kq1lmb8w7dnmk7gsvm.attacker.com | 50             | 1217542   | 2275             | LongSubdomainBeacon     |                  |        |
| 2025-05-25T14:40:09.505+0530 | kali | root | ij42xml0o195xje42ul993v0cl9gg9crzvwg3p1osswaktkylj.attacker.com | 50             | 1217528   | 2275             | LongSubdomainBeacon     |                  |        |
| 2025-05-25T14:40:08.286+0530 | kali | root | dngp3rv1p2rbrpuu5f8q0o45x9e67jr7esbt8zjks5f4w0qpqv.attacker.com | 50             | 1217506   | 2275             | LongSubdomainBeacon     |                  |        |
| 2025-05-25T14:40:07.032+0530 | kali | root | pxq19op4i15gjpdfr1k0morozmlmnmfqi9wgs5h2aw0hrya9zj.attacker.com | 50             | 1217492   | 2275             | LongSubdomainBeacon     |                  |        |
| 2025-05-25T14:40:05.545+0530 | kali | root | r7eh095xfonv56s6opvtmd3nef5v2cf30i2z1cc8p49w7nfyw9.attacker.com | 50             | 1217478   | 2275             | LongSubdomainBeacon     |                  |        |
| 2025-05-25T14:40:03.923+0530 | kali | root | di5dwp93cya6k94csgmgh4abuek4f08i1whphs7mafz1ohlz3s.attacker.com | 50             | 1217456   | 2275             | LongSubdomainBeacon     |                  |        |
| 2025-05-25T14:39:52.530+0530 | kali | root | wfr1pvkiom2ph1qifpm3co9lrgt74no4gc4j1rq5enzk1zsjhp.attacker.com | 50             | 1217362   | 2275             | LongSubdomainBeacon     |                  |        |
| 2025-05-22T09:47:00.000+0530 |      |      |                                                                |                |           |                  | HighFrequencyOutbound   | 192.168.1.11      | 4      |
| 2025-05-22T09:36:00.000+0530 |      |      |                                                                |                |           |                  | HighFrequencyOutbound   | 192.168.1.7       | 4      |
| 2025-05-22T09:34:00.000+0530 |      |      |                                                                |                |           |                  | HighFrequencyOutbound   | 192.168.1.7       | 4      |
| 2025-05-22T09:33:00.000+0530 |      |      |                                                                |                |           |                  | HighFrequencyOutbound   | 192.168.1.7       | 4      |

![5](https://github.com/user-attachments/assets/54ef58d4-300b-49a6-bd37-c87dd7ee0719)

---

## Detection Status
✅ Working – Validated in lab using simulated DNS tunneling and outbound traffic generation

## Analyst Notes / Recommendations

### C2 Beaconing Detection
- **Actions:**
  - Investigate long subdomain patterns for signs of data exfiltration or DNS tunneling.
  - Check for additional suspicious outbound activity from the host.
  - Consider correlating with firewall/proxy logs for external communications.
- **False Positives:**
  - Security software using DNS for updates or telemetry.
  - Misconfigured services with verbose DNS queries.

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Name                             | Tactic             | Platform |
|--------------|----------------------------------|--------------------|----------|
| T1071.004    | Application Layer Protocol: DNS  | Command and Control | Linux   |
| T1041        | Exfiltration Over C2 Channel     | Exfiltration        | Linux   |
| T1071        | Application Layer Protocol       | Command and Control | Linux   |
