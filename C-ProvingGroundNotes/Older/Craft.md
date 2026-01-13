**Metadata**

- IP Address:  192.168.183.169
- Hostname: 
- OS: 	
- Found Credentials/Users:

Main Objectives:


Local.txt = 
Proof.txt = 

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
sudo nmap -sS --top-ports 100 --open -T4 -Pn --max-retries 1 --min-rate 500 --host-timeout 60s -oA nmap/nmap_fast 192.168.183.169
# Fast scan to start with

PORT   STATE SERVICE
80/tcp open  http

sudo nmap -sT -p- --open -T4 -Pn --max-retries 2 --min-rate 300 -oA nmap/nmap_full 192.168.183.169
# Full TCP scan.

PORT   STATE SERVICE
80/tcp open  http

sudo nmap -vv --reason -Pn -A --open --osscan-guess --version-all -p- -oN nmap/nmap_veryfull 192.168.183.169
# Very full NMAP

PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 125 Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-title: Craft
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

sudo nmap -sU --open --top-ports 100 -T4 --max-retries 1 --host-timeout 90s -oA nmap/udp_fast 192.168.183.169
# Fast UDP scan

Nmap done: 1 IP address (0 hosts up) scanned in 0.60 seconds

sudo nmap -sU -p- --open -T4 --max-retries 0 --min-rate 300 --host-timeout 10m -oA nmap/udp_full 192.168.183.169
# Full UDP Scan

Nmap done: 1 IP address (0 hosts up) scanned in 0.60 seconds
```

2. Interesting Ports/Services

```

```

3. Web Enumeration 

```
- Site Visit: Looks like a company called Craft website. 
- Upload capability on main page along with upload directory accessible.
  
  
nikto -h 192.168.183.169

+ Server: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
+ /: Retrieved x-powered-by header: PHP/8.0.7.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Apache/2.4.48 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/8.0.7 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ OpenSSL/1.1.1k appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8909 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2025-12-26 15:04:48 (GMT-7) (823 seconds)


gobuster dir -u http://192.168.183.169 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing
/uploads              (Status: 301) [Size: 344] [--> http://192.168.183.169/uploads/]
/assets               (Status: 301) [Size: 343] [--> http://192.168.183.169/assets/]
/css                  (Status: 301) [Size: 340] [--> http://192.168.183.169/css/]
/js                   (Status: 301) [Size: 339] [--> http://192.168.183.169/js/]
/examples             (Status: 503) [Size: 404]
/Assets               (Status: 301) [Size: 343] [--> http://192.168.183.169/Assets/]
/*checkout*           (Status: 403) [Size: 304]
/CSS                  (Status: 301) [Size: 340] [--> http://192.168.183.169/CSS/]
/JS                   (Status: 301) [Size: 339] [--> http://192.168.183.169/JS/]
/Uploads              (Status: 301) [Size: 344] [--> http://192.168.183.169/Uploads/]


gobuster dir -u http://192.168.183.169 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

/Index.php            (Status: 200) [Size: 9635]
/assets               (Status: 301) [Size: 343] [--> http://192.168.183.169/assets/]
/css                  (Status: 301) [Size: 340] [--> http://192.168.183.169/css/]
/examples             (Status: 503) [Size: 404]
/index.php            (Status: 200) [Size: 9635]
/index.php            (Status: 200) [Size: 9635]
/js                   (Status: 301) [Size: 339] [--> http://192.168.183.169/js/]
/upload.php           (Status: 200) [Size: 537]
/uploads              (Status: 301) [Size: 344] [--> http://192.168.183.169/uploads/]

gobuster dir -u http://192.168.183.169 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files
/index.php            (Status: 200) [Size: 9635]
/.                    (Status: 200) [Size: 9635]
/upload.php           (Status: 200) [Size: 537]
/Index.php            (Status: 200) [Size: 9635]

```

4. RPC Port 111 Enumeration 

```
rpcinfo -p 192.168.101.110

rpcclient -U "username%password" <target-ip>

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

