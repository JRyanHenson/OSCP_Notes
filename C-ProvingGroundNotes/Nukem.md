**Metadata**

- IP Address:  192.168.162.105
- Hostname: 
- OS: 	
- Found Credentials/Users:

Main Objectives:

Local.txt = 
Proof.txt = 

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

```

10. Other Notes

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

10. Automated Enumeration 

```


```

11. Possible PE Paths

```

```

**Privilege Escalation**

1. PE Steps

```

```

2. Notes

```

```

