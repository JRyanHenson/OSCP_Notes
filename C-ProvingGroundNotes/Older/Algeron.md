---
tags: [ProvingGround]
---

Algernon 5/15/25

----------------------------------

## 1. Nmap scan report for 192.168.208.65
```
Host is up (0.081s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
9998/tcp open  distinct32
```
## 2. FTP server requires username/password
## 3. Website on port 80 is defualt IIS page
## 4. Able to login into FTP with anonymouus - downloaded Logs directroy and searched for keywords username and password.
```
Another option could have been wget -r ftp://Anonymous:pass@$IP
```
## 5. Port 9998 is a SmarterMail server.
## 6. Tried CVE-2019-7214 exploit. No luck.
7, gobuster dir -u http://192.168.208.65 \
-w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
-x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz

/.                    (Status: 200) [Size: 696]
/iisstart.htm         (Status: 200) [Size: 696]

## 8. Tried a new nmap scan sudo nmap -Pn -n $IP -sC -sV -p- --open
## 9. See that 17001 is open, look again at vulns for SmarterMail and see that 49216 uses port 17001.
## 10. Run exploit.