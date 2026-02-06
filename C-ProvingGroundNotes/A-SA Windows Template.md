**Metadata**

- IP Address:  192.168.
- Hostname: 
- OS: 	
- Found Credentials/Users:

Main Objectives:

Local.txt = 
Proof.txt = 

**Enumeration**

1. NMAP Scans (TCP/UDP)

```

The below commands will run as part of pg_recon.sh or you can run manually. 

sudo nmap -sS -Pn -n --top-ports 1000 -T4 --open "$IP" -oN nmap/TCP_Basic_Out
# Fast scan to start with

sudo nmap -sS -Pn -n -p- -T4 --open -sV --version-all "$IP" -oN nmap/TCP_Full_Out
# Full TCP scan.

sudo nmap -vv --reason -Pn -A --open --osscan-guess --version-all -p- -oN nmap/nmap_veryfull 192.168.173.66 
# Not run by automated script.

sudo nmap -sS -Pn -n -p "$tcp_ports" -sC -sV "$IP" -oN nmap/Scripts_Out 
# Run Scripts on open ports

sudo nmap -sU -Pn -n --top-ports 100 -T4 --open "$IP" -oN nmap/UDP_BASIC_OUT
# Fast UDP scan

nmap -sU -Pn -n --top-ports 1000 -T4 --open -sV --version-intensity 5 --max-retries 1 --host-timeout 20m "$IP" -oN nmap/UDP_Medium_Out
# Medium UDP scan

nmap -sU -Pn -n -p- -T4 --open -sV --version-all --max-retries 2 --host-timeout 60m "$IP" -oN nmap/UDP_Full_Out
# Full UDP Scan. Not run automatically with automated script (must be explicitly picked)

```

2. Interesting Ports/Services

```

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
Webserver Info - 
Running Applications - 
Site Visit - 

whatweb -v http://target

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

curl -i http://target

```

4. RPC Port 111 Enumeration 

```
rpcinfo -p 192.168.101.110

rpcclient -U "username%password" <target-ip>

rpcclient -U '' -N IP

rpcclient -U "username%password" <target-ip> -c 'stop service_name'
```

5. NFS Port 2049 Enumeration

```
# List NFS shares
showmount -e 192.168.101.110
clnt_create: RPC: Timed out

# Mount NFS share
mkdir /mnt/nfs
mount -t nfs target.com:/share /mnt/nfs

# Mount with specific NFS version
mount -t nfs -o vers=3 target.com:/share /mnt/nfs
mount -t nfs -o vers=4 target.com:/share /mnt/nfs

# Mount without root squashing
mount -t nfs -o nolock target.com:/share /mnt/nfs

# Read-only mount
mount -t nfs -o ro target.com:/share /mnt/nfs

# Unmount
umount /mnt/nfs
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

1. Shell / Context (reference)

```

# Powershell

powershell -NoP -NonI -W Hidden -Exec Bypass
set-alias wget Invoke-WebRequest
set-alias curl Invoke-WebRequest

```
  
2. Identity & System Info

```

# CMD

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
  

# Powershell

$env:USERNAME
$env:COMPUTERNAME
$env:USERDOMAIN
Get-ComputerInfo
Get-WmiObject Win32_OperatingSystem
Get-WmiObject Win32_ComputerSystem
Get-HotFix

```

3. Environment

```

# Powershell

Get-ChildItem Env:
$env:Path
Get-ExecutionPolicy -List

```

  4. Users & Groups

```

# CMD

net user
net user <username>
net localgroup
net localgroup administrators
query us

  

# Powershell

Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
whoami /all

```

  5.  AD Enumeration

```

# Powershell

Get-ADUser -Filter * (domain joined)
Get-ADGroup -Filter *
Get-ADGroupMember "Domain Admins"

```

  6. Privileges & Tokens

```

# CMD

whoami /priv
whoami /groups

```

  7. UAC & Policy Checks

```

# CMD

reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA

reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

```

  8. Processes & Services

```

# CMD

sc query
sc qc <service_name>
wmic service list brief
wmic service get name,displayname,pathname,startmode
tasklist
tasklist /v
tasklist /svc
wmic process list brief

  

# Powershell

Get-Service
Get-WmiObject Win32_Service | Select Name,StartMode,State,PathName
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-Process
Get-Process -IncludeUserName
Get-WmiObject Win32_Process | Select Name,ProcessId,ExecutablePath

```

  9.  Scheduled Tasks

```

# CMD

schtasks /query /fo LIST /v

  

# Powershell

Get-ScheduledTask

```

  10.  Network

```

# CMD

ipconfig /all
arp -a
route print
netstat -ano
net use
net share
net session
nltest /domain_trusts
nltest /dsgetdc:<domain>

  

# Powershell

Get-NetIPConfiguration
Get-NetIPAddress
Get-NetRoute
Get-NetTCPConnection
Get-SmbShare
Get-SmbSession
Resolve-DnsName <hostname>

```

  11. Software

```

# CMD

wmic product get name,version
wmic product where "Vendor like '%Microsoft%'" get Name,Version
dir "C:\Program Files"
dir "C:\Program Files (x86)"

  

# Powershell

Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*

Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*

Get-Package

```

  12. Shares & Drivers

```

# CMD

net share
driverquery /v

```

  13. Loot Files & Credentials

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

  

# Powershell

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

