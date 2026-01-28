**Metadata**

- IP Address:  192.168.
- Hostname: HUTCHDC
- OS:  Server 2019 Build 17763 x64
- Found Credentials/Users:

Main Objectives:

Local.txt = 
Proof.txt = 

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.162.122 -oN - 
# Nmap 7.95 scan initiated Tue Jan 27 15:34:21 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.162.122
Nmap scan report for 192.168.162.122
Host is up (0.082s latency).
Not shown: 987 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5985/tcp open  wsman

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.162.122 -oN /home/kali/ProvingGround/Hutch/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Hutch/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-27 15:34 MST
Nmap scan report for 192.168.162.122
Host is up (0.070s latency).
Not shown: 65514 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-27 22:36:31Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
49756/tcp open  msrpc         Microsoft Windows RPC


```

2. Interesting Ports/Services

```
[+] Open TCP ports (open only): 53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 49666, 49668, 49673, 49674, 49676, 49692, 49756
[+] Open UDP ports (open only): <none>

```

3. FTP Enumeration

```
nmap -p 21 -sS --open <IP>

nc <IP> 21

nmap -p 21 -sV <IP>

ftp <IP>

Credentials to try:

Username: anonymous
Password: anonymous

or any password

After login:

ls
pwd
cd /
cd pub
binary
passive

---

Anonymous Upload Test

Create a test file:

echo test > test.txt

Upload:

put test.txt

---

Download Everything (Loot First)

From local machine:

wget -r ftp://anonymous:anonymous@<IP>/

From ftp client:

prompt
mget *
```

4. Web Enumeration 

```
whatweb -v http://192.168.162.122
WhatWeb report for http://192.168.162.122
Status    : 200 OK
Title     : IIS Windows Server
IP        : 192.168.162.122
Country   : RESERVED, ZZ

Summary   : HTTPServer[Microsoft-IIS/10.0], Microsoft-IIS[10.0], X-Powered-By[ASP.NET]

Detected Plugins:
[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        String       : Microsoft-IIS/10.0 (from server string)

[ Microsoft-IIS ]
        Microsoft Internet Information Services (IIS) for Windows 
        Server is a flexible, secure and easy-to-manage Web server 
        for hosting anything on the Web. From media streaming to 
        web application hosting, IIS's scalable and open 
        architecture is ready to handle the most demanding tasks. 

        Version      : 10.0
        Website     : http://www.iis.net/

[ X-Powered-By ]
        X-Powered-By HTTP header 

        String       : ASP.NET (from x-powered-by string)

HTTP Headers:
        HTTP/1.1 200 OK
        Content-Type: text/html
        Last-Modified: Wed, 04 Nov 2020 05:35:35 GMT
        Accept-Ranges: bytes
        ETag: "965c9516cb2d61:0"
        Server: Microsoft-IIS/10.0
        X-Powered-By: ASP.NET
        Date: Tue, 27 Jan 2026 23:01:06 GMT
        Connection: close
        Content-Length: 703


nikto -h 192.168.101.110

curl -i http://192.168.101.110

curl -s http://192.168.50.122/robots.txt | html2text
curl -s http://192.168.50.122/sitemap.xml | html2text
# Enumerating Meta Files

[+] Running: Gobuster BASIC (80)
[+] Command: gobuster dir -u http://192.168.162.122:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Hutch/gobuster/Hutch_192.168.162.122_80_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.122:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/aspnet_client        (Status: 301) [Size: 163] [--> http://192.168.162.122:80/aspnet_client/]
Progress: 4414 / 4613 (95.69%)
===============================================================
Finished

[+] Running: Gobuster ADVANCED (80)
[+] Command: gobuster dir -u http://192.168.162.122:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Hutch/gobuster/Hutch_192.168.162.122_80_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.122:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 400) [Size: 3420]
/*checkout*           (Status: 400) [Size: 3420]
/*docroot*            (Status: 400) [Size: 3420]
/*                    (Status: 400) [Size: 3420]
/devinmoore*          (Status: 400) [Size: 3420]
/200109*              (Status: 400) [Size: 3420]
/*sa_                 (Status: 400) [Size: 3420]
/*dc_                 (Status: 400) [Size: 3420]
Progress: 220445 / 220558 (99.95%)
Progress: 220558 / 220558 (100.00%)===============================================================
Finished

[+] Running: Gobuster FILE search (80)
[+] Command: gobuster dir -u http://192.168.162.122:80 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Hutch/gobuster/Hutch_192.168.162.122_80_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.122:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              old,zip,tar,php,jsp,txt,bak,tar.gz,asp,aspx,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/aspnet_client        (Status: 301) [Size: 163] [--> http://192.168.162.122:80/aspnet_client/]
/index.aspx           (Status: 500) [Size: 3420]
/Index.aspx           (Status: 500) [Size: 3420]
Progress: 55142 / 55356 (99.61%)
Progress: 55356 / 55356 (100.00%)===============================================================
Finished

[+] Running: Gobuster LOWERCASE dir (80)
[+] Command: gobuster dir -u http://192.168.162.122:80 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Hutch/gobuster/Hutch_192.168.162.122_80_dir_lowercase.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.122:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 400) [Size: 3420]
/*checkout*           (Status: 400) [Size: 3420]
/*docroot*            (Status: 400) [Size: 3420]
/*                    (Status: 400) [Size: 3420]
/devinmoore*          (Status: 400) [Size: 3420]
/200109*              (Status: 400) [Size: 3420]
/*sa_                 (Status: 400) [Size: 3420]
/*dc_                 (Status: 400) [Size: 3420]
Progress: 207492 / 207641 (99.93%)
===============================================================
Progress: 207641 / 207641 (100.00%)Finished

[+] Running: Curl snapshot (80)
[+] Command: curl -k -L -sS -i --connect-timeout 5 --max-time 30 http://192.168.162.122:80 
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Wed, 04 Nov 2020 05:35:35 GMT
Accept-Ranges: bytes
ETag: "965c9516cb2d61:0"
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Wed, 28 Jan 2026 00:08:05 GMT
Content-Length: 703

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS Windows Server</title>
<style type="text/css">
<!--
body {
        color:#000000;
        background-color:#0072C6;
        margin:0;
}

#container {
        margin-left:auto;
        margin-right:auto;
        text-align:center;
        }

a img {
        border:none;
}

-->
</style>
</head>
<body>
<div id="container">
<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="iisstart.png" alt="IIS" width="960" height="600" /></a>
</div>
</body>

[+] Running: Nikto (80)
[+] Command: nikto -h http://192.168.162.122:80 -output /home/kali/ProvingGround/Hutch/web/192.168.162.122_80/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.162.122
+ Target Hostname:    192.168.162.122
+ Target Port:        80
+ Start Time:         2026-01-27 17:08:07 (GMT-7)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ /: Retrieved x-powered-by header: ASP.NET.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /LUlF5Twj.: Retrieved x-aspnet-version header: 4.0.30319.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK .
+ HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ OPTIONS: Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK .
+ HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ OPTIONS: WebDAV enabled (LOCK PROPPATCH PROPFIND UNLOCK MKCOL COPY listed as allowed).
+ 8254 requests: 0 error(s) and 13 item(s) reported on remote host
+ End Time:           2026-01-27 17:18:58 (GMT-7) (651 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested


```

5. RPC Port 111 Enumeration 

```
rpcinfo -p 192.168.101.110

rpcclient -U "username%password" <target-ip>

rpcclient -U '' -N IP

rpcclient -U "username%password" <target-ip> -c 'stop service_name'
```


6. SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.162.122 -U anonymous

smbmap -H 192.168.162.122                  

nxc smb 192.168.162.122 -u '' -p ''
# Enumerate Null Sessions

nxc smb 192.168.162.122 -u '' -p '' --generate-hosts-file /tmp/hosts
# Generate Hosts File

nxc smb 192.168.162.122 -u 'guest' -p ''
# Enumerate Guest Sessions

nxc smb 192.168.162.122 -u '' -p '' --rid-brute
# Enumerate Users By RID Bruteforcing

nxc smb 192.168.162.122 -u users.txt -p <pass> -d <domain> --continue-on-success
# Password Spraying

```

7. LDAP Port 389, 3268 Enumeration

```
ldapsearch -x -H LDAP://192.168.50.122 -s base
# LDAP Anonymous Bind

nxc ldap 192.168.50.122 -u '' -p '' --users
# Users Enumeration

nxc ldap 192.168.50.122 -u '' -p '' --groups
# Groups Enumeration

bloodhound-ce-python -d hutch.offsec -u '<username>' -p '<password>' -ns
192.168.50.122 -c all --zip
# Bloodhound Data Collection
```

8. Bloodhound Queries 

```

MATCH (u:User)
WHERE u.dontreqpreauth = true
AND u.enabled = true
RETURN u
LIMIT 100
# ASPREP Roastable Users

MATCH (u:User)
WHERE u.hasspn=true
AND u.enabled = true
AND NOT u.objectid ENDS WITH '-502'
AND NOT COALESCE(u.gmsa, false) = true
NOT COALESCE(u.msa, false) = true
RETURN u
LIMIT 100
# All Kerberoastable Users

MATCH p=shortestPath((t:Group)<-[:AD_ATTACK_PATHS*1..]-(s:Base))
WHERE t.objectid ENDS WITH '-512' AND s<>t
RETURN p
LIMIT 1000
# Shortest Paths To Domain Admins

MATCH p=shortestPath((s:Base)-[:AD_ATTACK_PATHS*1..]->(t:Base))
WHERE ((s:Tag_Owned) OR COALESCE(s.system_tags, '') CONTAINS 'owned')
AND s<>t
RETURN p
LIMIT 1000
# Shortest Paths From Owned Objects


```

7. Possible Exploits

```

```

8. Other Notes

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

1. Basic System Info

```
#CMD
whoami
whoami /priv
whoami /groups
hostname
systeminfo
ver
echo %USERNAME%
echo %COMPUTERNAME%
echo %USERDOMAIN%
set
wmic os get Caption,Version,BuildNumber,OSArchitecture
wmic computersystem get Model,Manufacturer,SystemType
wmic qfe get HotFixID,InstalledOn

#Powershell
$env:USERNAME
$env:COMPUTERNAME
$env:USERDOMAIN
Get-ComputerInfo
Get-WmiObject Win32_OperatingSystem
Get-WmiObject Win32_ComputerSystem
Get-HotFix

```

2. User Enumeration

```
#CMD
net user
net user <username>
net localgroup
net localgroup administrators
query us

#Powershell
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
Get-ADUser -Filter *    (domain joined)
Get-ADGroup -Filter *
Get-ADGroupMember "Domain Admins"
whoami /all


```

3. Network Information

```
#CMD
ipconfig /all
arp -a
route print
netstat -ano
net use
net share
net session
nltest /domain_trusts
nltest /dsgetdc:<domain>

#Powershell
Get-NetIPConfiguration
Get-NetIPAddress
Get-NetRoute
Get-NetTCPConnection
Get-SmbShare
Get-SmbSession
Resolve-DnsName <hostname>
```

4. Software, Service, and Process Information

```
#CMD
wmic product get name,version
wmic product where "Vendor like '%Microsoft%'" get Name,Version
dir "C:\Program Files"
dir "C:\Program Files (x86)"

sc query
sc qc <service_name>
wmic service list brief
wmic service get name,displayname,pathname,startmode

tasklist
tasklist /v
tasklist /svc
wmic process list brief

#Powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
Get-Package

Get-Service
Get-WmiObject Win32_Service | Select Name,StartMode,State,PathName
Get-Service | Where-Object {$_.Status -eq "Running"}

Get-Process
Get-Process -IncludeUserName
Get-WmiObject Win32_Process | Select Name,ProcessId,ExecutablePath

```

4. Loot files.
```
# CMD
dir C:\
dir C:\Users
dir C:\Users\<user>\Desktop
dir C:\Users\<user>\Documents
dir C:\Users\<user>\Downloads
dir C:\Users\<user>\AppData\Roaming
dir C:\Users\<user>\AppData\Local
dir C:\inetpub\wwwroot
dir C:\xampp
dir C:\wamp

dir /s /b *.txt *.ini *.cfg *.conf *.xml *.log *.bak *.ps1 *.kdbx *.rdp *.ppk *.pem

#Powershell
Get-ChildItem C:\Users -Recurse -Include *.txt,*.ini,*.cfg,*.xml,*.kdbx -ErrorAction SilentlyContinue
Get-ChildItem C:\ -Recurse -Include *pass*,*cred*,*secret* -ErrorAction SilentlyContinue



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

