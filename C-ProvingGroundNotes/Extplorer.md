**Metadata**

- IP Address:  192.168.148.16
- Hostname: dora
- OS: 	Linux Ubuntu
- Found Credentials/Users:
dora / doraemon

Main Objectives:

Local.txt = d5d971a8a618483134cd4d305d3535db
Proof.txt = 

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.148.16 -oN - 
# Nmap 7.95 scan initiated Tue Mar  3 14:59:49 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.148.16
Nmap scan report for 192.168.148.16
Host is up (0.081s latency).
Not shown: 998 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.148.16 -oN /home/kali/ProvingGround/Extplorer/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Extplorer/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-03 14:59 MST
Nmap scan report for 192.168.148.16
Host is up (0.079s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel




```

2. Interesting Ports/Services

```

```

3. SSH Enumeration

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)

```

4. Telnet Enumeration

```

```

4. SMTP Enumeration

```

```

5. Web Enumeration 

```
Webserver Info - Apache 2.4.41
Running Applications - 
Site Visit - 

1. Looks like a WordPress site. 
2. First visit opens a setup wizard to setup DB.
3. Went http://192.168.148.16/filemanager and was able to login as admin/admin
 
whatweb http://192.168.148.16 
http://192.168.148.16 [302 Found] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.148.16], RedirectLocation[http://192.168.148.16/wp-admin/setup-config.php]
http://192.168.148.16/wp-admin/setup-config.php [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.148.16], JQuery[3.6.3], PHP, Script[text/javascript], Title[WordPress &rsaquo; Setup Configuration File]
                                       
[+] Directory search BASIC on HTTP ports: 80
[+] Running: Gobuster BASIC (80)
[+] Command: gobuster dir -u http://192.168.148.16:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Extplorer/gobuster/Extplorer_192.168.148.16_80_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.16:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/filemanager          (Status: 301) [Size: 322] [--> http://192.168.148.16/filemanager/]
/index.php            (Status: 302) [Size: 0] [--> http://192.168.148.16:80/wp-admin/setup-config.php]
/wordpress            (Status: 301) [Size: 320] [--> http://192.168.148.16/wordpress/]
/wp-admin             (Status: 301) [Size: 319] [--> http://192.168.148.16/wp-admin/]
/wp-includes          (Status: 301) [Size: 322] [--> http://192.168.148.16/wp-includes/]
/wp-content           (Status: 301) [Size: 321] [--> http://192.168.148.16/wp-content/]
/xmlrpc.php           (Status: 302) [Size: 0] [--> http://192.168.148.16:80/wp-admin/setup-config.php]
Progress: 4613 / 4613 (100.00%)
===============================================================
Progress: 4613 / 4613 (100.00%)Finished


curl -i http://target

```

6. Possible Exploits

```
When going to http://192.168.148.16/filemanager able to login as admin/admin and upload files to webserver.
```

7. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

- Logged onto http://192.168.148.16/filemanager and logged on as admin/admin.

![[Pasted image 20260303151930.png]]

- Uploaded reverse.php. 

![[Pasted image 20260303152027.png]]

- Navigated to website and executed reverse shell.

![[Pasted image 20260303152111.png]]

- Received reverse shell but did not have the permission to access the local.txt

![[Pasted image 20260303152200.png]]

- Searched the username dora in the /var/www/html/filemanager and found Dora's hashed password. 

![[Pasted image 20260303163916.png]]

- Ran hashcat on the bcrypt hash. 

![[Pasted image 20260303164138.png]]

```
hashcat -m 3200 -a 0  hash_dora /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best66.rule  
```

- Received cracked password. 


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
www-data@dora:/home/dora$ whoami
www-data
www-data@dora:/home/dora$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@dora:/home/dora$ hostname
dora
www-data@dora:/home/dora$ uname -a
Linux dora 5.4.0-146-generic #163-Ubuntu SMP Fri Mar 17 18:26:02 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
www-data@dora:/home/dora$ cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal

```

2. Environment

```
www-data@dora:/home/dora$ env
SHELL=/usr/bin/bash
PWD=/home/dora
APACHE_LOG_DIR=/var/log/apache2
LANG=C
INVOCATION_ID=0c8de1b31908411ab25fc5a0f838428a
APACHE_PID_FILE=/var/run/apache2/apache2.pid
TERM=xterm-256color
APACHE_RUN_GROUP=www-data
APACHE_LOCK_DIR=/var/lock/apache2
SHLVL=2
LC_CTYPE=C.UTF-8
APACHE_RUN_DIR=/var/run/apache2
JOURNAL_STREAM=9:154098
APACHE_RUN_USER=www-data
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
_=/usr/bin/env
OLDPWD=/home
www-data@dora:/home/dora$ set 2>/dev/null | head -n 50
AHRcztDLkb=UaBWmuQUhb
APACHE_LOCK_DIR=/var/lock/apache2
APACHE_LOG_DIR=/var/log/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
APACHE_RUN_DIR=/var/run/apache2
APACHE_RUN_GROUP=www-data
APACHE_RUN_USER=www-data
BASH=/usr/bin/bash
BASHOPTS=checkwinsize:cmdhist:complete_fullquote:expand_aliases:extquote:force_fignore:globasciiranges:hostcomplete:interactive_comments:progcomp:promptvars:sourcepath
BASH_ALIASES=()
BASH_ARGC=([0]="0")
BASH_ARGV=()
BASH_CMDS=()
BASH_LINENO=()
BASH_SOURCE=()
BASH_VERSINFO=([0]="5" [1]="0" [2]="17" [3]="1" [4]="release" [5]="x86_64-pc-linux-gnu")
BASH_VERSION='5.0.17(1)-release'
COLUMNS=116
DIRSTACK=()
EUID=33
GROUPS=()
HISTFILE=/var/www/.bash_history
HISTFILESIZE=500
HISTSIZE=500
HOSTNAME=dora
HOSTTYPE=x86_64
IFS=$' \t\n'
INVOCATION_ID=0c8de1b31908411ab25fc5a0f838428a
JOURNAL_STREAM=9:154098
LANG=C
LC_CTYPE=C.UTF-8
LINES=59
MACHTYPE=x86_64-pc-linux-gnu
MAILCHECK=60
OLDPWD=/home
OPTERR=1
OPTIND=1
OSTYPE=linux-gnu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
PIPESTATUS=([0]="0")
PPID=110597
PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
PS2='> '
PS4='+ '
PWD=/home/dora
RVrypfZjhM=XBVSWWfQQS
SHELL=/usr/bin/bash
SHELLOPTS=braceexpand:emacs:hashall:histexpand:history:interactive-comments:monitor
SHLVL=2
TERM=xterm-256color
www-data@dora:/home/dora$ echo "$PATH"
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
www-data@dora:/home/dora$ echo "HOME=$HOME"; echo "SHELL=$SHELL"
HOME=
SHELL=/usr/bin/bash


```

3. User & Home Directories

```
cat /etc/passwd

ls -la /home

ls -la /root 2>/dev/null

sudo -l 2>/dev/null
www-data@dora:/home/dora$ env
SHELL=/usr/bin/bash
PWD=/home/dora
APACHE_LOG_DIR=/var/log/apache2
LANG=C
INVOCATION_ID=0c8de1b31908411ab25fc5a0f838428a
APACHE_PID_FILE=/var/run/apache2/apache2.pid
TERM=xterm-256color
APACHE_RUN_GROUP=www-data
APACHE_LOCK_DIR=/var/lock/apache2
SHLVL=2
LC_CTYPE=C.UTF-8
APACHE_RUN_DIR=/var/run/apache2
JOURNAL_STREAM=9:154098
APACHE_RUN_USER=www-data
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
_=/usr/bin/env
OLDPWD=/home
www-data@dora:/home/dora$ set 2>/dev/null | head -n 50
AHRcztDLkb=UaBWmuQUhb
APACHE_LOCK_DIR=/var/lock/apache2
APACHE_LOG_DIR=/var/log/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
APACHE_RUN_DIR=/var/run/apache2
APACHE_RUN_GROUP=www-data
APACHE_RUN_USER=www-data
BASH=/usr/bin/bash
BASHOPTS=checkwinsize:cmdhist:complete_fullquote:expand_aliases:extquote:force_fignore:globasciiranges:hostcomplete:interactive_comments:progcomp:promptvars:sourcepath
BASH_ALIASES=()
BASH_ARGC=([0]="0")
BASH_ARGV=()
BASH_CMDS=()
BASH_LINENO=()
BASH_SOURCE=()
BASH_VERSINFO=([0]="5" [1]="0" [2]="17" [3]="1" [4]="release" [5]="x86_64-pc-linux-gnu")
BASH_VERSION='5.0.17(1)-release'
COLUMNS=116
DIRSTACK=()
EUID=33
GROUPS=()
HISTFILE=/var/www/.bash_history
HISTFILESIZE=500
HISTSIZE=500
HOSTNAME=dora
HOSTTYPE=x86_64
IFS=$' \t\n'
INVOCATION_ID=0c8de1b31908411ab25fc5a0f838428a
JOURNAL_STREAM=9:154098
LANG=C
LC_CTYPE=C.UTF-8
LINES=59
MACHTYPE=x86_64-pc-linux-gnu
MAILCHECK=60
OLDPWD=/home
OPTERR=1
OPTIND=1
OSTYPE=linux-gnu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
PIPESTATUS=([0]="0")
PPID=110597
PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
PS2='> '
PS4='+ '
PWD=/home/dora
RVrypfZjhM=XBVSWWfQQS
SHELL=/usr/bin/bash
SHELLOPTS=braceexpand:emacs:hashall:histexpand:history:interactive-comments:monitor
SHLVL=2
TERM=xterm-256color
www-data@dora:/home/dora$ echo "$PATH"
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
www-data@dora:/home/dora$ echo "HOME=$HOME"; echo "SHELL=$SHELL"
HOME=
SHELL=/usr/bin/bash

sudo -V 2>/dev/null | head -n 10
```

4. Writable Paths & Permissions

```
find / -writable -type d 2>/dev/null | head -n 50
/dev/mqueue
/dev/shm
/run/screen
/run/lock
/run/lock/apache2
/proc/111035/task/111035/fd
/proc/111035/fd
/proc/111035/map_files
/tmp
/var/crash
/var/lib/php/sessions
/var/cache/apache2/mod_cache_disk
/var/tmp
/var/www/html
/var/www/html/wordpress
/var/www/html/wp-content
/var/www/html/wp-content/themes
/var/www/html/wp-content/themes/twentytwentytwo
/var/www/html/wp-content/themes/twentytwentytwo/assets
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/dm-sans
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/source-serif-pro
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/inter
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/ibm-plex
/var/www/html/wp-content/themes/twentytwentytwo/assets/videos
/var/www/html/wp-content/themes/twentytwentytwo/assets/images
/var/www/html/wp-content/themes/twentytwentytwo/templates
/var/www/html/wp-content/themes/twentytwentytwo/inc
/var/www/html/wp-content/themes/twentytwentytwo/inc/patterns
/var/www/html/wp-content/themes/twentytwentytwo/parts
/var/www/html/wp-content/themes/twentytwentytwo/styles
/var/www/html/wp-content/themes/twentytwentyone
/var/www/html/wp-content/themes/twentytwentyone/assets
/var/www/html/wp-content/themes/twentytwentyone/assets/js
/var/www/html/wp-content/themes/twentytwentyone/assets/sass
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/01-settings
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/06-components
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/02-tools
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/04-elements
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/03-generic
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/05-blocks
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/05-blocks/media-text
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/05-blocks/code
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/05-blocks/columns
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/05-blocks/gallery
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/05-blocks/verse
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/05-blocks/rss
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/05-blocks/pullquote
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/05-blocks/latest-posts
/var/www/html/wp-content/themes/twentytwentyone/assets/sass/05-blocks/social-icons

find / -writable -type f 2>/dev/null | head -n 50
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/attr/exec
/sys/kernel/security/apparmor/attr/current
/sys/kernel/security/apparmor/.access
/sys/fs/cgroup/memory/user.slice/cgroup.event_control
/sys/fs/cgroup/memory/cgroup.event_control
/sys/fs/cgroup/memory/init.scope/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/irqbalance.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-update-utmp.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-sysusers.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/cloud-init-hotplugd.socket/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/system-systemd\x2dfsck.slice/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/system-systemd\x2dfsck.slice/systemd-fsck@dev-disk-by\x2duuid-c1f1cf69\x2d1d06\x2d429c\x2d8e83\x2d732717012c4b.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/iscsid.socket/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-udevd-control.socket/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/lvm2-monitor.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-journal-flush.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/open-vm-tools.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-sysctl.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/snapd.apparmor.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-udevd-kernel.socket/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/finalrd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/boot.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-remount-fs.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/networkd-dispatcher.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/lvm2-lvmpolld.socket/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/multipathd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-tmpfiles-setup.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/-.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/system-modprobe.slice/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-journald-dev-log.socket/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/ModemManager.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/cloud-init-local.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-networkd.socket/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/console-setup.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-udev-trigger.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control

echo "$PATH" | tr ':' '\n' | while read -r p; do [ -z "$p" ] && continue; if [ -w "$p" ]; then echo "WRITABLE: $p"; else echo "OK: $p"; fi; done
OK: /usr/local/sbin
OK: /usr/local/bin
OK: /usr/sbin
OK: /usr/bin
OK: /sbin
OK: /bin
OK: /snap/bin


find / -user "$(id -un)" -type f 2>/dev/null | head -n 50

ls -l /etc/passwd 2>/dev/null
-rw-r--r-- 1 root root 1892 Apr  6  2023 /etc/passwd

ls -l /etc/shadow 2>/dev/null
-rw-r----- 1 root shadow 1191 Apr  6  2023 /etc/shadow


ls -la / 2>/dev/null
total 1992780
drwxr-xr-x  19 root root       4096 Jan 24  2023 .
drwxr-xr-x  19 root root       4096 Jan 24  2023 ..
lrwxrwxrwx   1 root root          7 Aug 31  2022 bin -> usr/bin
drwxr-xr-x   4 root root       4096 Mar  3 22:10 boot
drwxr-xr-x  18 root root       4060 Mar 29  2025 dev
drwxr-xr-x 100 root root       4096 Mar  3 22:10 etc
drwxr-xr-x   3 root root       4096 Apr  6  2023 home
lrwxrwxrwx   1 root root          7 Aug 31  2022 lib -> usr/lib
lrwxrwxrwx   1 root root          9 Aug 31  2022 lib32 -> usr/lib32
lrwxrwxrwx   1 root root          9 Aug 31  2022 lib64 -> usr/lib64
lrwxrwxrwx   1 root root         10 Aug 31  2022 libx32 -> usr/libx32
drwx------   2 root root      16384 Jan 24  2023 lost+found
drwxr-xr-x   2 root root       4096 Aug 31  2022 media
drwxr-xr-x   2 root root       4096 Aug 31  2022 mnt
drwxr-xr-x   2 root root       4096 Aug 31  2022 opt
dr-xr-xr-x 285 root root          0 Mar 29  2025 proc
drwx------   6 root root       4096 Mar  3 21:58 root
drwxr-xr-x  33 root root       1040 Mar  3 22:10 run
lrwxrwxrwx   1 root root          8 Aug 31  2022 sbin -> usr/sbin
drwxr-xr-x   6 root root       4096 Aug 31  2022 snap
drwxr-xr-x   2 root root       4096 Aug 31  2022 srv
-rw-------   1 root root 2040528896 Jan 24  2023 swap.img
dr-xr-xr-x  13 root root          0 Mar 29  2025 sys
drwxrwxrwt   2 root root       4096 Mar  3 22:15 tmp
drwxr-xr-x  14 root root       4096 Aug 31  2022 usr
drwxr-xr-x  14 root root       4096 Apr  6  2023 var

```

4. SUID / SGID / Capabilities

```
find / -perm -4000 -type f 2>/dev/null
/snap/core20/1852/usr/bin/chfn
/snap/core20/1852/usr/bin/chsh
/snap/core20/1852/usr/bin/gpasswd
/snap/core20/1852/usr/bin/mount
/snap/core20/1852/usr/bin/newgrp
/snap/core20/1852/usr/bin/passwd
/snap/core20/1852/usr/bin/su
/snap/core20/1852/usr/bin/sudo
/snap/core20/1852/usr/bin/umount
/snap/core20/1852/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1852/usr/lib/openssh/ssh-keysign
/snap/core20/1611/usr/bin/chfn
/snap/core20/1611/usr/bin/chsh
/snap/core20/1611/usr/bin/gpasswd
/snap/core20/1611/usr/bin/mount
/snap/core20/1611/usr/bin/newgrp
/snap/core20/1611/usr/bin/passwd
/snap/core20/1611/usr/bin/su
/snap/core20/1611/usr/bin/sudo
/snap/core20/1611/usr/bin/umount
/snap/core20/1611/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1611/usr/lib/openssh/ssh-keysign
/snap/snapd/18596/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/at
/usr/bin/su
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/umount
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/gpasswd

find / -perm -2000 -type f 2>/dev/null
/snap/core20/1852/usr/bin/chage
/snap/core20/1852/usr/bin/expiry
/snap/core20/1852/usr/bin/ssh-agent
/snap/core20/1852/usr/bin/wall
/snap/core20/1852/usr/sbin/pam_extrausers_chkpwd
/snap/core20/1852/usr/sbin/unix_chkpwd
/snap/core20/1611/usr/bin/chage
/snap/core20/1611/usr/bin/expiry
/snap/core20/1611/usr/bin/ssh-agent
/snap/core20/1611/usr/bin/wall
/snap/core20/1611/usr/sbin/pam_extrausers_chkpwd
/snap/core20/1611/usr/sbin/unix_chkpwd
/usr/lib/x86_64-linux-gnu/utempter/utempter
/usr/bin/at
/usr/bin/bsd-write
/usr/bin/chage
/usr/bin/expiry
/usr/bin/ssh-agent
/usr/bin/crontab
/usr/sbin/unix_chkpwd
/usr/sbin/pam_extrausers_chkpwd

getcap -r / 2>/dev/null
/snap/core20/1852/usr/bin/ping = cap_net_raw+ep
/snap/core20/1611/usr/bin/ping = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep

```

5. Cron & Scheduled Tasks

```
cat /etc/crontab 2>/dev/null
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

ls -la /etc/cron.* 2>/dev/null
ls -la /etc/cron.* 2>/dev/null
/etc/cron.d:
total 24
drwxr-xr-x   2 root root 4096 Apr  6  2023 .
drwxr-xr-x 100 root root 4096 Mar  3 22:10 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--   1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--   1 root root  712 Mar 27  2020 php
-rw-r--r--   1 root root  190 Aug 31  2022 popularity-contest

/etc/cron.daily:
total 52
drwxr-xr-x   2 root root 4096 Mar  3 22:05 .
drwxr-xr-x 100 root root 4096 Mar  3 22:10 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root  539 Feb 23  2021 apache2
-rwxr-xr-x   1 root root  376 Dec  4  2019 apport
-rwxr-xr-x   1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x   1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x   1 root root 1123 Feb 25  2020 man-db
-rwxr-xr-x   1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x   1 root root  214 Apr 25  2022 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Aug 31  2022 .
drwxr-xr-x 100 root root 4096 Mar  3 22:10 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Aug 31  2022 .
drwxr-xr-x 100 root root 4096 Mar  3 22:10 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x   2 root root 4096 Apr  6  2023 .
drwxr-xr-x 100 root root 4096 Mar  3 22:10 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root  813 Feb 25  2020 man-db
-rwxr-xr-x   1 root root  403 Apr 25  2022 update-notifier-common

crontab -l 2>/dev/null
```

6. Processes & Network

```
ps aux

ps -ef

ss -tulwn 2>/dev/null
Netid      State       Recv-Q      Send-Q           Local Address:Port           Peer Address:Port     Process      
udp        UNCONN      0           0                127.0.0.53%lo:53                  0.0.0.0:*                     
tcp        LISTEN      0           511                    0.0.0.0:80                  0.0.0.0:*                     
tcp        LISTEN      0           4096             127.0.0.53%lo:53                  0.0.0.0:*                     
tcp        LISTEN      0           128                    0.0.0.0:22                  0.0.0.0:*                     
tcp        LISTEN      0           128                       [::]:22                     [::]:*    

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
Nothing returned

grep -i docker /proc/1/cgroup 2>/dev/null
Nothing returned
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

