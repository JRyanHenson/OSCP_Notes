**Metadata**

- IP Address:  192.168.162.81
- Hostname: 
- OS: 	
- Found Credentials/Users:

Main Objectives:

Local.txt = 
Proof.txt = 

**Enumeration**

1. NMAP Scans (TCP/UDP)

```

[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.162.61 -oN - 
# Nmap 7.95 scan initiated Fri Jan 23 19:03:48 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.162.61
Nmap scan report for 192.168.162.61
Host is up (0.079s latency).
Not shown: 944 closed tcp ports (reset), 50 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8081/tcp open  blackice-icecap

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.162.61 -oN /home/kali/ProvingGround/BillyBoss/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/BillyBoss/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-23 19:03 MST
Nmap scan report for 192.168.162.61
Host is up (0.095s latency).
Not shown: 64740 closed tcp ports (reset), 782 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
8081/tcp  open  http          Jetty 9.4.18.v20190429
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 566.00 seconds




```

2. Interesting Ports/Services

```

```

3. FTP Enumeration

```
21/tcp    open  ftp           Microsoft ftpd

ftp 192.168.162.61 
Connected to 192.168.162.61.
220 Microsoft FTP Service
Name (192.168.162.61:kali): anonymous
534 Policy requires SSL.
ftp: Login failed
ftp> 

wget -r ftp://anonymous:anonymous@192.168.162.61                                                           
--2026-01-23 19:08:03--  ftp://anonymous:*password*@192.168.162.61/
           => ‘192.168.162.61/.listing’
Connecting to 192.168.162.61:21... connected.
Logging in as anonymous ... 
The server refuses login.
Retrying.

```

4. Web Enumeration (80)

```
nikto -h 192.168.101.110

curl -i http://192.168.101.110

Site Visit: 
1. Site is running BaGet
2. Has upload functionality at http://192.168.162.61/upload
3. 

Possibe Exploits:
1. 

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

```

5. Web Enumeration (8081) 

```
nikto -h 192.168.101.110

curl -i http://192.168.101.110

Site Visit: 
1. Sonatype Nexus Repository ManagerOSS 3.21.0-05
2. Authenticated with nexus/nexus
   
Possible Exploits:
3. https://www.exploit-db.com/exploits/49385
4. https://www.exploit-db.com/exploits/52101


gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

```

6. SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.101.110 -U anonymous
Password for [WORKGROUP\anonymous]:
session setup failed: NT_STATUS_LOGON_FAILURE

smbmap -H 192.168.101.110                  

smbclient //192.168.101.110/Backup -N          
Anonymous login successful


```

6. Port 5040 Enumeration

```

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

