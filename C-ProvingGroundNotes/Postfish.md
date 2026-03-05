**Metadata**

- IP Address:  192.168.148.137
- Hostname: postfish
- OS: 	
- Found Credentials/Users:

Main Objectives:

Local.txt = 
Proof.txt = 

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

