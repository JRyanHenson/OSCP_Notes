---
tags: [ProvingGround]
---

5/6/2025

--------------------


## 1. NMAP'd found multiple ports open 80,135,139,445 - HTTP,MSRPC,NetBIOS,SMB
## 2. Guest accounts enebaled
## 3. Message signing disabled
## 4. Ran nmap --script smb-vul-*
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
## 5. Trying metasploit exploit for ms17-010
search ms17_010
## 6. use exploit/windows/smb/ms17_010_eternalblue
## 7. MSF exploit failed due to system being 32 bit
## 8. Found python tool to scan and exploit windows 7 32/64 - Failed
## 9. Realized EternalBlue might be a rabbit hole after multipe failed attempts to exploit.
## 10. Relooked at nmap scan and see port 80 is open. Visted site and see it HP Manager. Google default creds admin/admin.
## 11. Logged into HP Power Manager and see version is 4.2.7.
## 12. Find multiple vulns.
## 13. Use Metasploit to exploit
## 14. use exploit/windows/http/hp_power_manager_filename
show options
set options
run