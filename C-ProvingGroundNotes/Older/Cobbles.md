---
tags: [ProvingGround]
---

Cobbles 5/22/25

-----------------------------

## 1. sudo nmap -p- -sC -sV -Pn -n --open 192.168.208.214 -oN nmap/initial
[sudo] password for kali:
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-22 13:51 MDT
Nmap scan report for 192.168.208.214
Host is up (0.078s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey:
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp open  http    Apache httpd 2.4.53
|_http-title: Cobbles
|_http-server-header: Apache/2.4.53 (Debian)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.01 seconds

## 2.