**Metadata**

- Exercise Name: Shenzi
- IP Address: 192.168.148.55
- Hostname:
- OS:
- Found Credentials/Users:

Main Objectives:

Local.txt =
Proof.txt =

**Enumeration**

1. NMAP Scans Output (TCP/UDP)

```
- TCP Quick: `OK` | `nmap -sC -sV --top-ports 1000 -T4 -oA /home/kali/ProvingGround/Shenzi/NMAP/tcp_quick 192.168.148.55`
- TCP Full: `OK` | `nmap -p- -sC -sV -T4 -oA /home/kali/ProvingGround/Shenzi/NMAP/tcp_full 192.168.148.55`
- XML files: `tcp_full.xml`, `tcp_quick.xml`, `udp_quick.xml`
  
  
  Nmap scan report for 192.168.148.55
Host is up (0.072s latency).
Not shown: 65520 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
80/tcp    open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.148.55/dashboard/
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
| http-title: Welcome to XAMPP
|_Requested resource was https://192.168.148.55/dashboard/
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MariaDB 10.3.24 or later (unauthorized)
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-02-14T18:18:44
|_  start_date: N/A

```

2. Service Enumeration

Recommendation Source: Static fallback (Static: 15)

FTP Enumeration Port 21

```
Run: ftp 192.168.148.55 21
Check anonymous login and writable directories.
Download all files and inspect for credentials/scripts/source code.
Resource: HackTricks > FTP and ippsec walkthroughs for FTP footholds.

21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla

ftp 192.168.148.55 21                                                                                                      
Connected to 192.168.148.55.
220-FileZilla Server version 0.9.41 beta
220-written by Tim Kosse (Tim.Kosse@gmx.de)
220 Please visit http://sourceforge.net/projects/filezilla/
Name (192.168.148.55:kali): anonymous
331 Password required for anonymous
Password: 
530 Login or password incorrect!
ftp: Login failed
ftp> 

```

HTTP Enumeration Port 80

```
Run: ffuf -u http://192.168.148.55:80/FUZZ -w /usr/share/wordlists/dirb/common.txt
Run: nikto -h http://192.168.148.55:80
Check source comments, hidden endpoints, and default credentials.
Resource: HackTricks > Pentesting Web and PortSwigger Web Security Academy.

80/tcp    open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.148.55/dashboard/
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6

Open Directories:
http://192.168.148.55:80/img
http://192.168.148.55:80/xampp
http://192.168.148.55:80/dashboard

Site Visit: 
- Looks like a defualt page for XAMPP
- PHPInfo data available http://192.168.148.55/dashboard/phpinfo.php
  
  
```

MSRPC Enumeration Port 135

```
Enumerate MSRPC on tcp/135 with nmap NSE scripts.
Check default credentials, anonymous access, and known CVEs for detected version.
Correlate findings with credential reuse and local file disclosure opportunities.
Resource: HackTricks service index and searchsploit for version-specific paths.
```

NetBIOS/SMB Enumeration Port 139

```
Enumerate NetBIOS/SMB on tcp/139 with nmap NSE scripts.
Check default credentials, anonymous access, and known CVEs for detected version.
Correlate findings with credential reuse and local file disclosure opportunities.
Resource: HackTricks service index and searchsploit for version-specific paths.
```

HTTP Enumeration Port 443

```
Run: ffuf -u http://192.168.148.55:443/FUZZ -w /usr/share/wordlists/dirb/common.txt
Run: nikto -h http://192.168.148.55:443
Check source comments, hidden endpoints, and default credentials.
Resource: HackTricks > Pentesting Web and PortSwigger Web Security Academy.
```

SMB Enumeration Port 445

```
Enumerate SMB on tcp/445 with nmap NSE scripts.
Check default credentials, anonymous access, and known CVEs for detected version.
Correlate findings with credential reuse and local file disclosure opportunities.
Resource: HackTricks service index and searchsploit for version-specific paths.


 cat passwords.txt                                                                   
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: wampp 

4) WEBDAV: 

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf
   
   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so  
   
   Please do not forget to refresh the WEBDAV authentification (users and passwords).     

5) WordPress:

   User: admin

```

MySQL Enumeration Port 3306

```
Run: mysql -h 192.168.148.55 -P 3306 -u root -p
Test blank/default credentials in lab environments.
Enumerate databases/tables for password reuse and web app linkage.
Resource: HackTricks > MySQL and GTFOBins for post-login abuse.

 sudo nmap -p 3306 --script=mysql-info,mysql-enum,mysql-databases,mysql-users,mysql-variables,mysql-empty-password,mysql-brute 192.168.148.55 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-14 11:51 MST
Nmap scan report for 192.168.148.55
Host is up (0.085s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
|_mysql-empty-password: Host '192.168.45.215' is not allowed to connect to this MariaDB server
| mysql-enum: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 10 guesses in 2 seconds, average tps: 5.0
| mysql-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 50009 guesses in 467 seconds, average tps: 104.7


```

Unknown Service Enumeration Port 5040

```
Enumerate Unknown Service on tcp/5040 with nmap NSE scripts.
Check default credentials, anonymous access, and known CVEs for detected version.
Correlate findings with credential reuse and local file disclosure opportunities.
Resource: HackTricks service index and searchsploit for version-specific paths.
```

PANDO-PUB Enumeration Port 7680

```
Enumerate PANDO-PUB on tcp/7680 with nmap NSE scripts.
Check default credentials, anonymous access, and known CVEs for detected version.
Correlate findings with credential reuse and local file disclosure opportunities.
Resource: HackTricks service index and searchsploit for version-specific paths.
```

MSRPC Enumeration Port 49664

```
Enumerate MSRPC on tcp/49664 with nmap NSE scripts.
Check default credentials, anonymous access, and known CVEs for detected version.
Correlate findings with credential reuse and local file disclosure opportunities.
Resource: HackTricks service index and searchsploit for version-specific paths.
```

MSRPC Enumeration Port 49665

```
Enumerate MSRPC on tcp/49665 with nmap NSE scripts.
Check default credentials, anonymous access, and known CVEs for detected version.
Correlate findings with credential reuse and local file disclosure opportunities.
Resource: HackTricks service index and searchsploit for version-specific paths.
```

MSRPC Enumeration Port 49666

```
Enumerate MSRPC on tcp/49666 with nmap NSE scripts.
Check default credentials, anonymous access, and known CVEs for detected version.
Correlate findings with credential reuse and local file disclosure opportunities.
Resource: HackTricks service index and searchsploit for version-specific paths.
```

MSRPC Enumeration Port 49667

```
Enumerate MSRPC on tcp/49667 with nmap NSE scripts.
Check default credentials, anonymous access, and known CVEs for detected version.
Correlate findings with credential reuse and local file disclosure opportunities.
Resource: HackTricks service index and searchsploit for version-specific paths.
```

MSRPC Enumeration Port 49668

```
Enumerate MSRPC on tcp/49668 with nmap NSE scripts.
Check default credentials, anonymous access, and known CVEs for detected version.
Correlate findings with credential reuse and local file disclosure opportunities.
Resource: HackTricks service index and searchsploit for version-specific paths.
```

MSRPC Enumeration Port 49669

```
Enumerate MSRPC on tcp/49669 with nmap NSE scripts.
Check default credentials, anonymous access, and known CVEs for detected version.
Correlate findings with credential reuse and local file disclosure opportunities.
Resource: HackTricks service index and searchsploit for version-specific paths.
```

3. Possible Exploits

```

```

4. Other Notes

```

```

**Initial Foothold**

1. Exploit Steps

```

```

2. Shell Access

```

```

**Post-Exploitation**

1. Shell / Context (reference)

```

```

2. Identity & System Info

```

```

3. Environment Info

```

```

4. Users & Groups

```

```

5. AD Enumeration

```
# Powershell

Get-ADUser -Filter * (domain joined)
Get-ADGroup -Filter *
Get-ADGroupMember "Domain Admins"
```

6. Privileges & Tokens

```

```

8. Processes & Services

```

```

9. Scheduled Tasks

```

```

10. Network

```

```

11. Software

```

```

12. Shares & Drivers

```

```

13. Loot Files & Credentials

```

```

5. Automated Enumeration

```

```

5. Possible PE Paths

```

```

**Privilege Escalation**

1. PE Steps

```

```

2. Notes

```

```
