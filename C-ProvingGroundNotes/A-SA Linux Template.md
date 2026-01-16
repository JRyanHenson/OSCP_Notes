**Metadata**

- IP Address:  192.168.
- Hostname: 
- OS: 	
- Found Credentials/Users:

Main Objectives:

Local.txt = 
Proof.txt = 

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
sudo nmap -sS --top-ports 100 -T4 -Pn --max-retries 1 --min-rate 500 --host-timeout 60s -oA nmap/nmap_fast 192.168.136.52
# Fast scan to start with

sudo nmap -sT -p- -T4 -Pn --max-retries 2 --min-rate 300 -oA nmap/nmap_full 192.168.136.52
# Full TCP scan.

nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN nmap/nmap_veryfull 192.168.236.47  
# Very full NMAP

sudo nmap -sC -p 22,80,111,139,445,2049 -T4 -oA nmap/nmap_scripts 192.168.101.110
# Run Scripts on open ports

sudo nmap -sU --top-ports 100 -T4 --max-retries 1 --host-timeout 90s -oA nmap/udp_fast 192.168.101.110
# Fast UDP scan

sudo nmap -sU -p- -T4 --max-retries 0 --min-rate 300 --host-timeout 10m -oA nmap/udp_full 192.168.101.110
# Full UDP Scan


```

2. Interesting Ports/Services

```

```

3. FTP Enumeration

```
FTP (21/tcp) Enumeration & Exploitation – OSCP Cheat Sheet

Metadata
IP:
Hostname:
Service:
Version:

1. Initial Detection

nmap -p 21 -sS --open <IP>

Confirm FTP is open and responding.

---

2. Banner & Version Enumeration

nc <IP> 21

nmap -p 21 -sV <IP>

Look for:

* FTP server type (vsftpd, ProFTPD, Pure-FTPd, FileZilla)
* Exact version numbers
* Anonymous login hints

---

3. Anonymous Login Test (ALWAYS)

ftp <IP>

Credentials to try:

Username: anonymous
Password: anonymous

or any password

After login:

ls
pwd
cd /
cd pub
binary
passive

---

4. Anonymous Upload Test

Create a test file:

echo test > test.txt

Upload:

put test.txt

If upload succeeds:

* Check if directory maps to web root
* Attempt webshell upload
* Look for cron/script abuse

---

5. Download Everything (Loot First)

From local machine:

wget -r ftp://anonymous:anonymous@<IP>/

From ftp client:

prompt
mget *

Look for:

* Credentials
* .bak / .old / .zip / .tar.gz
* Source code
```

4. Web Enumeration 

```
Webserver Info - 


gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files

gobuster dir -u http://192.168.101.110 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files

```

4. RPC Port 111 Enumeration 

```

rpcinfo -p 192.168.101.110

rpcclient -U "username%password" <target-ip>

rpcclient -U "username%password" <target-ip> -c 'stop service_name'
```

5. NFS Port 2049 Enumeration

```
# List NFS shares
showmount -e 192.168.101.110
clnt_create: RPC: Timed out

# Mount NFS share
mkdir /mnt/nfs
mount -t nfs target.com:/share /mnt/nfs

# Mount with specific NFS version
mount -t nfs -o vers=3 target.com:/share /mnt/nfs
mount -t nfs -o vers=4 target.com:/share /mnt/nfs

# Mount without root squashing
mount -t nfs -o nolock target.com:/share /mnt/nfs

# Read-only mount
mount -t nfs -o ro target.com:/share /mnt/nfs

# Unmount
umount /mnt/nfs
```

6. SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.101.110 -U anonymous
ls
mget 
put dork.txt

enum4linux $IP

smbmap -H 192.168.101.110                  

smbclient //192.168.101.110/Backup -N          



```

7. Possible Exploits

```

```

8. Other Notes

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

