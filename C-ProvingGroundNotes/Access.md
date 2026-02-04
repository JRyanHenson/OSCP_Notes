**Metadata**

- IP Address:  192.168.240.187
- Hostname: Access
- Domain: Offsec
- OS: Windows 10 / Server 2019 Build 17763 x64 (name:SERVER) (domain:access.offsec)
- Found Credentials/Users:

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

```

9. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

```



```

2. Shell Access

```

```

**Post-Exploitation**

1. Basic System Info

```
#CMD
whoami
whoami /priv
whoami /groups
hostname
systeminfo
ver
echo %USERNAME%
echo %COMPUTERNAME%
echo %USERDOMAIN%
set
wmic os get Caption,Version,BuildNumber,OSArchitecture
wmic computersystem get Model,Manufacturer,SystemType
wmic qfe get HotFixID,InstalledOn

#Powershell
$env:USERNAME
$env:COMPUTERNAME
$env:USERDOMAIN
Get-ComputerInfo
Get-WmiObject Win32_OperatingSystem
Get-WmiObject Win32_ComputerSystem
Get-HotFix

```

2. User Enumeration

```
#CMD
net user
net user <username>
net localgroup
net localgroup administrators
query us

#Powershell
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
Get-ADUser -Filter *    (domain joined)
Get-ADGroup -Filter *
Get-ADGroupMember "Domain Admins"
whoami /all


```

3. Network Information

```
#CMD
ipconfig /all
arp -a
route print
netstat -ano
net use
net share
net session
nltest /domain_trusts
nltest /dsgetdc:<domain>

#Powershell
Get-NetIPConfiguration
Get-NetIPAddress
Get-NetRoute
Get-NetTCPConnection
Get-SmbShare
Get-SmbSession
Resolve-DnsName <hostname>
```

4. Software, Service, and Process Information

```
#CMD
wmic product get name,version
wmic product where "Vendor like '%Microsoft%'" get Name,Version
dir "C:\Program Files"
dir "C:\Program Files (x86)"

sc query
sc qc <service_name>
wmic service list brief
wmic service get name,displayname,pathname,startmode

tasklist
tasklist /v
tasklist /svc
wmic process list brief

#Powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
Get-Package

Get-Service
Get-WmiObject Win32_Service | Select Name,StartMode,State,PathName
Get-Service | Where-Object {$_.Status -eq "Running"}

Get-Process
Get-Process -IncludeUserName
Get-WmiObject Win32_Process | Select Name,ProcessId,ExecutablePath

```

4. Loot files.
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

#Powershell
Get-ChildItem C:\Users -Recurse -Include *.txt,*.ini,*.cfg,*.xml,*.kdbx -ErrorAction SilentlyContinue
Get-ChildItem C:\ -Recurse -Include *pass*,*cred*,*secret* -ErrorAction SilentlyContinue



```

5. Automated Enumeration

```




```
5. Possible PE Paths

```



```

**Privilege Escalation**

1. PE Steps

```

```

2. Notes

```

```

