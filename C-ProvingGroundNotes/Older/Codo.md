---
tags: [ProvingGround]
---

Codo 5/21/25

---------------------------------

## 1. sudo nmap -p- -sC -sV -Pn -n --open 192.168.208.23 -oN nmap/initial
[sudo] password for kali:
Sorry, try again.
[sudo] password for kali:
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-21 19:13 MDT
Stats: 0:01:37 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 52.90% done; ETC: 19:16 (0:01:26 remaining)
Nmap scan report for 192.168.208.23
Host is up (0.080s latency).
Not shown: 65533 filtered tcp ports (no-response)
Bug in http-generator: no string output.
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: All topics | CODOLOGIC
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
## 2. Ran a nikto scan and saw an interesting site http://192.168.208.23/admin/index.php?page=login
## 3. Tried admin/admin for login.
## 4. At login saw version was CodoForum 5.1.
## 5. Found file upload exploit. Created php reverse shell. Uploaded to admin profile pic. Then visited http://192.168.208.23//sites/default/assets/img/attachments/shell.php
## 6. Received reverse shell as www-data.
## 7. Ran linpeas.sh.
## 8. Found username and password in the /var/www/html/sites/default/config.php codo/FatPanda123.
## 9. Used password in su root attempt.