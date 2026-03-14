**Metadata**

- IP Address:  192.168.219.210
- Hostname: pc
- OS: 	Ubuntu 20.04.6 LTS
- Found Credentials/Users:

Main Objectives:

Local.txt = 
Proof.txt = 

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.219.210 -oN - 
# Nmap 7.95 scan initiated Fri Mar 13 19:03:17 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.219.210
Nmap scan report for 192.168.219.210
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.219.210 -oN /home/kali/ProvingGround/pc/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/pc/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-13 19:03 MDT
Nmap scan report for 192.168.219.210
Host is up (0.084s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http    ttyd 1.7.3-a2312cb (libwebsockets 3.2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

2. Interesting Ports/Services

```
[+] Open TCP ports (open only): 22, 8000
[+] Open UDP ports (open only): <none>

```

4. SSH Enumeration

```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)

```

5. Web Enumeration 

```
8000/tcp open  http    ttyd 1.7.3-a2312cb (libwebsockets 3.2.0)
|_http-title: ttyd - Terminal
|_http-server-header: ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


Webserver Info - 
Running Applications - 
Site Visit - 

whatweb -v http://target

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

curl -i http://target

```

10. Possible Exploits

```

```

11. Other Notes

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
user@pc:/home/user$ whoami
user

user@pc:/home/user$ id
uid=1000(user) gid=1000(user) groups=1000(user)

user@pc:/home/user$ hostname
pc

user@pc:/home/user$ pwd
/home/user

user@pc:/home/user$ uname -a
Linux pc 5.4.0-156-generic #173-Ubuntu SMP Tue Jul 11 07:25:22 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
user@pc:/home/user$ cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null
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
user@pc:/home/user$ env
SNAP_REVISION=199
SUPERVISOR_GROUP_NAME=ttyd
SNAP_REAL_HOME=/home/user
SNAP_USER_COMMON=/home/user/snap/ttyd/common
SUPERVISOR_SERVER_URL=unix:///var/run/supervisor.sock
SNAP_INSTANCE_KEY=
SNAP_EUID=1000
PWD=/home/user
SNAP_CONTEXT=f5trVIPV5it_zed7qDaMS3JndGwNxlSKuQIByMGb4Ezg32jyffwZ
LD_PRELOAD=/snap/ttyd/199/lib/homeishome.so
LANG=en_US.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SNAP_ARCH=amd64
SNAP_INSTANCE_NAME=ttyd
SNAP_USER_DATA=/home/user/snap/ttyd/199
INVOCATION_ID=4029044a0c9e43a6b51967af4669facd
SNAP_REEXEC=
SNAP_UID=1000
LESSCLOSE=/usr/bin/lesspipe %s %s
TERM=xterm-256color
LESSOPEN=| /usr/bin/lesspipe %s
SNAP=/snap/ttyd/199
SNAP_COMMON=/var/snap/ttyd/common
SNAP_VERSION=1.7.3
SHLVL=1
SNAP_LIBRARY_PATH=/var/lib/snapd/lib/gl:/var/lib/snapd/lib/gl32:/var/lib/snapd/void
SNAP_COOKIE=f5trVIPV5it_zed7qDaMS3JndGwNxlSKuQIByMGb4Ezg32jyffwZ
SNAP_DATA=/var/snap/ttyd/199
SUPERVISOR_PROCESS_NAME=ttyd
SNAP_NAME=ttyd
JOURNAL_STREAM=9:23768
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
SUPERVISOR_ENABLED=1
_=/usr/bin/env
user@pc:/home/user$ set 2>/dev/null | head -n 50
BASH=/usr/bin/bash
BASHOPTS=checkwinsize:cmdhist:complete_fullquote:expand_aliases:extglob:extquote:force_fignore:globasciiranges:histappend:interactive_comments:progcomp:promptvars:sourcepath
BASH_ALIASES=()
BASH_ARGC=([0]="0")
BASH_ARGV=()
BASH_CMDS=()
BASH_COMPLETION_VERSINFO=([0]="2" [1]="10")
BASH_LINENO=()
BASH_SOURCE=()
BASH_VERSINFO=([0]="5" [1]="0" [2]="17" [3]="1" [4]="release" [5]="x86_64-pc-linux-gnu")
BASH_VERSION='5.0.17(1)-release'
COLUMNS=119
DIRSTACK=()
EUID=1000
GROUPS=()
HISTCONTROL=ignoreboth
HISTFILE=/home/user/.bash_history
HISTFILESIZE=2000
HISTSIZE=1000
HOSTNAME=pc
HOSTTYPE=x86_64
IFS=$' \t\n'
INVOCATION_ID=4029044a0c9e43a6b51967af4669facd
JOURNAL_STREAM=9:23768
LANG=en_US.UTF-8
LD_PRELOAD=/snap/ttyd/199/lib/homeishome.so
LESSCLOSE='/usr/bin/lesspipe %s %s'
LESSOPEN='| /usr/bin/lesspipe %s'
LINES=61
LS_COLORS='rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:'
MACHTYPE=x86_64-pc-linux-gnu
MAILCHECK=60
OPTERR=1
OPTIND=1
OSTYPE=linux-gnu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
PIPESTATUS=([0]="0")
PPID=1009
PS1='\[\e]0;\u@\h: \w\a\]${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
PS2='> '
PS4='+ '
PWD=/home/user
SHELL=/bin/bash
SHELLOPTS=braceexpand:emacs:hashall:histexpand:history:interactive-comments:monitor
SHLVL=1
SNAP=/snap/ttyd/199
SNAP_ARCH=amd64
SNAP_COMMON=/var/snap/ttyd/common
SNAP_CONTEXT=f5trVIPV5it_zed7qDaMS3JndGwNxlSKuQIByMGb4Ezg32jyffwZ
SNAP_COOKIE=f5trVIPV5it_zed7qDaMS3JndGwNxlSKuQIByMGb4Ezg32jyffwZ
user@pc:/home/user$ echo "$PATH"
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
user@pc:/home/user$ echo "HOME=$HOME"; echo "SHELL=$SHELL"
HOME=
SHELL=/bin/bash

```

3. User & Home Directories

```
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
user:x:1000:1000:,,,:/home/user:/bin/bash

ls -la /home
total 12
drwxr-xr-x  3 root root 4096 Aug 25  2023 .
drwxr-xr-x 19 root root 4096 Jun 15  2022 ..
drwxr-xr-x  3 user user 4096 Aug 25  2023 user

ls -la /root 2>/dev/null

sudo -l 2>/dev/null

sudo -V 2>/dev/null | head -n 10
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
```

4. Writable Paths & Permissions

```
find / -writable -type d 2>/dev/null | head -n 50
/var/crash
/var/tmp
/proc/2215/task/2215/fd
/proc/2215/fd
/proc/2215/map_files
/run/screen
/run/lock
/dev/mqueue
/dev/shm
/home/user
/home/user/snap
/home/user/snap/ttyd
/home/user/snap/ttyd/325
/home/user/snap/ttyd/199
/home/user/snap/ttyd/common
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.XIM-unix
/tmp/.X11-unix
/tmp/.font-unix

find / -writable -type f 2>/dev/null | head -n 50
/proc/sys/kernel/ns_last_pid
/proc/1/task/1/attr/current
/proc/1/task/1/attr/exec
/proc/1/task/1/attr/fscreate
/proc/1/task/1/attr/keycreate
/proc/1/task/1/attr/sockcreate
/proc/1/task/1/attr/display
/proc/1/task/1/attr/smack/current
/proc/1/task/1/attr/apparmor/current
/proc/1/task/1/attr/apparmor/exec
/proc/1/attr/current
/proc/1/attr/exec
/proc/1/attr/fscreate
/proc/1/attr/keycreate
/proc/1/attr/sockcreate
/proc/1/attr/display
/proc/1/attr/smack/current
/proc/1/attr/apparmor/current
/proc/1/attr/apparmor/exec
/proc/1/timerslack_ns
/proc/2/task/2/attr/current
/proc/2/task/2/attr/exec
/proc/2/task/2/attr/fscreate
/proc/2/task/2/attr/keycreate
/proc/2/task/2/attr/sockcreate
/proc/2/task/2/attr/display
/proc/2/task/2/attr/smack/current
/proc/2/task/2/attr/apparmor/current
/proc/2/task/2/attr/apparmor/exec
/proc/2/attr/current
/proc/2/attr/exec
/proc/2/attr/fscreate
/proc/2/attr/keycreate
/proc/2/attr/sockcreate
/proc/2/attr/display
/proc/2/attr/smack/current
/proc/2/attr/apparmor/current
/proc/2/attr/apparmor/exec
/proc/2/timerslack_ns
/proc/3/task/3/attr/current
/proc/3/task/3/attr/exec
/proc/3/task/3/attr/fscreate
/proc/3/task/3/attr/keycreate
/proc/3/task/3/attr/sockcreate
/proc/3/task/3/attr/display
/proc/3/task/3/attr/smack/current
/proc/3/task/3/attr/apparmor/current
/proc/3/task/3/attr/apparmor/exec
/proc/3/attr/current
/proc/3/attr/exec

echo "$PATH" | tr ':' '\n' | while read -r p; do [ -z "$p" ] && continue; if [ -w "$p" ]; then echo "WRITABLE: $p"; else echo "OK: $p"; fi; done
OK: /usr/local/sbin
OK: /usr/local/bin
OK: /usr/sbin
OK: /usr/bin
OK: /sbin
OK: /bin
OK: /snap/bin

find / -user "$(id -un)" -type f 2>/dev/null | head -n 50
/proc/1009/task/1009/fdinfo/0
/proc/1009/task/1009/fdinfo/1
/proc/1009/task/1009/fdinfo/2
/proc/1009/task/1009/fdinfo/3
/proc/1009/task/1009/fdinfo/4
/proc/1009/task/1009/fdinfo/5
/proc/1009/task/1009/fdinfo/6
/proc/1009/task/1009/fdinfo/7
/proc/1009/task/1009/fdinfo/8
/proc/1009/task/1009/fdinfo/9
/proc/1009/task/1009/fdinfo/10
/proc/1009/task/1009/fdinfo/11
/proc/1009/task/1009/fdinfo/12
/proc/1009/task/1009/fdinfo/13
/proc/1009/task/1009/fdinfo/14
/proc/1009/task/1009/fdinfo/15
/proc/1009/task/1009/fdinfo/16
/proc/1009/task/1009/fdinfo/17
/proc/1009/task/1009/fdinfo/19
/proc/1009/task/1009/fdinfo/20
/proc/1009/task/1009/fdinfo/21
/proc/1009/task/1009/fdinfo/22
/proc/1009/task/1009/environ
/proc/1009/task/1009/auxv
/proc/1009/task/1009/status
/proc/1009/task/1009/personality
/proc/1009/task/1009/limits
/proc/1009/task/1009/sched
/proc/1009/task/1009/comm
/proc/1009/task/1009/syscall
/proc/1009/task/1009/cmdline
/proc/1009/task/1009/stat
/proc/1009/task/1009/statm
/proc/1009/task/1009/maps
/proc/1009/task/1009/children
/proc/1009/task/1009/numa_maps
/proc/1009/task/1009/mem
/proc/1009/task/1009/mounts
/proc/1009/task/1009/mountinfo
/proc/1009/task/1009/clear_refs
/proc/1009/task/1009/smaps
/proc/1009/task/1009/smaps_rollup
/proc/1009/task/1009/pagemap
/proc/1009/task/1009/attr/current
/proc/1009/task/1009/attr/prev
/proc/1009/task/1009/attr/exec
/proc/1009/task/1009/attr/fscreate
/proc/1009/task/1009/attr/keycreate
/proc/1009/task/1009/attr/sockcreate
/proc/1009/task/1009/attr/display

ls -l /etc/passwd 2>/dev/null
-rw-r--r-- 1 root root 1897 Aug 25  2023 /etc/passwd

ls -l /etc/shadow 2>/dev/null
-rw-r----- 1 root shadow 1191 Aug 25  2023 /etc/shadow

ls -la / 2>/dev/null
drwxr-xr-x  19 root root       4096 Jun 15  2022 .
drwxr-xr-x  19 root root       4096 Jun 15  2022 ..
lrwxrwxrwx   1 root root          7 Feb 23  2022 bin -> usr/bin
drwxr-xr-x   4 root root       4096 Aug 18  2023 boot
drwxr-xr-x  18 root root       4060 Aug  3  2024 dev
drwxr-xr-x  99 root root       4096 Aug 25  2023 etc
drwxr-xr-x   3 root root       4096 Aug 25  2023 home
lrwxrwxrwx   1 root root          7 Feb 23  2022 lib -> usr/lib
lrwxrwxrwx   1 root root          9 Feb 23  2022 lib32 -> usr/lib32
lrwxrwxrwx   1 root root          9 Feb 23  2022 lib64 -> usr/lib64
lrwxrwxrwx   1 root root         10 Feb 23  2022 libx32 -> usr/libx32
drwx------   2 root root      16384 Jun 15  2022 lost+found
drwxr-xr-x   2 root root       4096 Feb 23  2022 media
drwxr-xr-x   2 root root       4096 Feb 23  2022 mnt
drwxr-xr-x   3 root root       4096 Aug 25  2023 opt
dr-xr-xr-x 267 root root          0 Aug  3  2024 proc
drwx------   6 root root       4096 Mar 14 01:00 root
drwxr-xr-x  32 root root        960 Mar 14 01:00 run
lrwxrwxrwx   1 root root          8 Feb 23  2022 sbin -> usr/sbin
drwxr-xr-x   7 root root       4096 Aug 25  2023 snap
drwxr-xr-x   2 root root       4096 Feb 23  2022 srv
-rw-------   1 root root 2092957696 Jun 15  2022 swap.img
dr-xr-xr-x  13 root root          0 Aug  3  2024 sys
drwxrwxrwt  15 root root       4096 Mar 14 01:08 tmp
drwxr-xr-x  14 root root       4096 Feb 23  2022 usr
drwxr-xr-x  13 root root       4096 Feb 23  2022 var

```

4. SUID / SGID / Capabilities

```
find / -perm -4000 -type f 2>/dev/null
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/su
/usr/bin/umount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/at
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/snap/core20/2015/usr/bin/chfn
/snap/core20/2015/usr/bin/chsh
/snap/core20/2015/usr/bin/gpasswd
/snap/core20/2015/usr/bin/mount
/snap/core20/2015/usr/bin/newgrp
/snap/core20/2015/usr/bin/passwd
/snap/core20/2015/usr/bin/su
/snap/core20/2015/usr/bin/sudo
/snap/core20/2015/usr/bin/umount
/snap/core20/2015/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2015/usr/lib/openssh/ssh-keysign
/snap/core20/1950/usr/bin/chfn
/snap/core20/1950/usr/bin/chsh
/snap/core20/1950/usr/bin/gpasswd
/snap/core20/1950/usr/bin/mount
/snap/core20/1950/usr/bin/newgrp
/snap/core20/1950/usr/bin/passwd
/snap/core20/1950/usr/bin/su
/snap/core20/1950/usr/bin/sudo
/snap/core20/1950/usr/bin/umount
/snap/core20/1950/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1950/usr/lib/openssh/ssh-keysign
/snap/snapd/19993/usr/lib/snapd/snap-confine
/snap/snapd/19457/usr/lib/snapd/snap-confine

find / -perm -2000 -type f 2>/dev/null
/usr/sbin/unix_chkpwd
/usr/sbin/pam_extrausers_chkpwd
/usr/bin/bsd-write
/usr/bin/crontab
/usr/bin/wall
/usr/bin/expiry
/usr/bin/chage
/usr/bin/at
/usr/bin/ssh-agent
/usr/lib/x86_64-linux-gnu/utempter/utempter
/snap/core20/2015/usr/bin/chage
/snap/core20/2015/usr/bin/expiry
/snap/core20/2015/usr/bin/ssh-agent
/snap/core20/2015/usr/bin/wall
/snap/core20/2015/usr/sbin/pam_extrausers_chkpwd
/snap/core20/2015/usr/sbin/unix_chkpwd
/snap/core20/1950/usr/bin/chage
/snap/core20/1950/usr/bin/expiry
/snap/core20/1950/usr/bin/ssh-agent
/snap/core20/1950/usr/bin/wall
/snap/core20/1950/usr/sbin/pam_extrausers_chkpwd
/snap/core20/1950/usr/sbin/unix_chkpwd

getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/snap/core20/2015/usr/bin/ping = cap_net_raw+ep
/snap/core20/1950/usr/bin/ping = cap_net_raw+ep
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

ls -la /etc/cron.* 2>/dev/null
/etc/cron.d:
total 20
drwxr-xr-x  2 root root 4096 Jun 16  2022 .
drwxr-xr-x 99 root root 4096 Aug 25  2023 ..
-rw-r--r--  1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--  1 root root  191 Feb 23  2022 popularity-contest

/etc/cron.daily:
total 48
drwxr-xr-x  2 root root 4096 Jun 19  2023 .
drwxr-xr-x 99 root root 4096 Aug 25  2023 ..
-rwxr-xr-x  1 root root  376 Dec  4  2019 apport
-rwxr-xr-x  1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x  1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x  1 root root 1123 Feb 25  2020 man-db
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x  1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x  1 root root  214 May 14  2021 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Feb 23  2022 .
drwxr-xr-x 99 root root 4096 Aug 25  2023 ..
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Feb 23  2022 .
drwxr-xr-x 99 root root 4096 Aug 25  2023 ..
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Jun 19  2023 .
drwxr-xr-x 99 root root 4096 Aug 25  2023 ..
-rwxr-xr-x  1 root root  813 Feb 25  2020 man-db
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x  1 root root  403 Aug  5  2021 update-notifier-common

crontab -l 2>/dev/null
no crontab for user
```

6. Processes & Network

```
ps aux

ps -ef

ss -tulwn 2>/dev/null
udp        UNCONN      0           0                127.0.0.53%lo:53                    0.0.0.0:*                      
tcp        LISTEN      0           4096             127.0.0.53%lo:53                    0.0.0.0:*                      
tcp        LISTEN      0           128                    0.0.0.0:22                    0.0.0.0:*                      
tcp        LISTEN      0           2048                 127.0.0.1:65432                 0.0.0.0:*                      
tcp        LISTEN      0           128                    0.0.0.0:8000                  0.0.0.0:*                      
tcp        LISTEN      0           128                       [::]:22                       [::]:*    

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
/usr/bin/gettext.sh 

/tmp/tmux-1000

uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

 127.0.0.1:65432 
 
 Vulnerable to CVE-2021-3560
 
 /dev/disk/by-id/dm-uuid-LVM-oozS1Psfbd0yGJw7GP46obC3Z47PqMSvyhRbbIPHmEbg8r42t9b230PoeLzexb6m / ext4 defaults 0 1    
/dev/disk/by-uuid/93bda39f-263a-4008-b15c-51c9d87c566b /boot ext4 defaults 0 1
/swap.img       none    swap    sw      0       0



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

