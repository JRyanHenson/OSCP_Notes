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

5. RPC Port 111 Enumeration 

```
rpcinfo -p 192.168.101.110

rpcclient -U "username%password" <target-ip>

rpcclient -U '' -N IP

rpcclient -U "username%password" <target-ip> -c 'stop service_name'
```


6. SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.101.110 -U anonymous

smbmap -H 192.168.101.110                  

nxc smb 192.168.50.122 -u '' -p ''
# Enumerate Null Sessions

nxc smb 192.168.50.122 -u '' -p '' --generate-hosts-file /tmp/hosts
# Generate Hosts File

nxc smb 192.168.50.122 -u 'guest' -p ''
# Enumerate Guest Sessions

nxc smb 192.168.50.122 -u '' -p '' --rid-brute
# Enumerate Users By RID Bruteforcing

nxc smb 192.168.50.122 -u users.txt -p <pass> -d <domain> --continue-on-success
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

9. Possible Exploits

```

```

10. Other Notes

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

