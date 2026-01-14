**Metadata**

- IP Address:  192.168.162.117
- Hostname: 
- OS: 	Linux/CentOS
- Found Credentials/Users:

Main Objectives:

Local.txt = 
Proof.txt = 

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

```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

```



```

2. Shell Upgrade

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
whoami

id

hostname

pwd

uname -a

cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null

```

2. Environment

```
env

set 2>/dev/null | head -n 50

echo "$PATH"

echo "HOME=$HOME"; echo "SHELL=$SHELL"

```

3. User & Home Directories

```
cat /etc/passwd

ls -la /home

ls -la /root 2>/dev/null

sudo -l 2>/dev/null

sudo -V 2>/dev/null | head -n 10
```

4. Writable Paths & Permissions

```
find / -writable -type d 2>/dev/null | head -n 50

find / -writable -type f 2>/dev/null | head -n 50

echo "$PATH" | tr ':' '\n' | while read -r p; do [ -z "$p" ] && continue; if [ -w "$p" ]; then echo "WRITABLE: $p"; else echo "OK: $p"; fi; done

find / -user "$(id -un)" -type f 2>/dev/null | head -n 50

ls -l /etc/passwd 2>/dev/null

ls -l /etc/shadow 2>/dev/null

ls -la / 2>/dev/null

```

4. SUID / SGID / Capabilities

```
find / -perm -4000 -type f 2>/dev/null

find / -perm -2000 -type f 2>/dev/null

getcap -r / 2>/dev/null

```

5. Cron & Scheduled Tasks

```
cat /etc/crontab 2>/dev/null

ls -la /etc/cron.* 2>/dev/null

crontab -l 2>/dev/null
```

6. Processes & Network

```
ps aux

ps -ef

ss -tulwn 2>/dev/null

netstat -tulnp 2>/dev/null
```

7.  Software / Packages

```
dpkg -l 2>/dev/null | head -n 200

rpm -qa 2>/dev/null | head -n 200
```

8. Loot Files & Credentials

```
grep -R "password" /etc 2>/dev/null | head -n 50

ls -la /var/www 2>/dev/null

grep -R "password\|db\|user" /var/www 2>/dev/null | head -n 50

find /home -type f -name "*.txt" 2>/dev/null

find /home -type f -name "*history*" 2>/dev/null

find /home -type f \( -name "id_rsa" -o -name "id_*" \) 2>/dev/null

grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head -n 50

find / -name "*.bak" -o -name "*~" 2>/dev/null | head -n 50
```

9.  Containers / Virtualization

```
ls -la /.dockerenv 2>/dev/null

grep -i docker /proc/1/cgroup 2>/dev/null
```

10. Possible PE Paths

```

```

**Privilege Escalation**

1. PE Steps

```

```

2. Notes

```

```

