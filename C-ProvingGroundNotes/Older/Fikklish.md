---
tags: [ProvingGround]
---

Fikklish 5/12/25

------------------------

## 1. Nmap scan report for 192.168.208.19
Host is up (0.079s latency).

PORT     STATE  SERVICE VERSION
22/tcp   open   ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4e:eb:da:e8:00:da:40:3d:f4:22:ad:fb:41:2c:2a:4c (ECDSA)
|_  256 de:dc:7b:84:9e:6e:d8:fa:98:23:2b:9e:71:67:88:fe (ED25519)
80/tcp   open   http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Book Bargains Online
|_http-server-header: Apache/2.4.52 (Ubuntu)
443/tcp  closed https
8000/tcp open   http    WSGIServer 0.2 (Python 3.10.12)
|_http-server-header: WSGIServer/0.2 CPython/3.10.12
| http-robots.txt: 31 disallowed entries (15 shown)
| /admin/ /js/ /accounts/ /source/ /comment/ /commit/
| /update/ /push/ /reset/ /lock/ /unlock/ /changes/ /changes/csv/
|_/search/ /replace/
|_http-title:   Weblate

## 2.gobuster dir -u http://192.168.208.19 -w /usr/share/seclists/Discovery/Web-Content/common.txt

/css                  (Status: 301) [Size: 314] [--> http://192.168.208.19/css/]
/fonts                (Status: 301) [Size: 316] [--> http://192.168.208.19/fonts/]
/images               (Status: 301) [Size: 317] [--> http://192.168.208.19/images/]
/index.html           (Status: 200) [Size: 18258]
/javascript           (Status: 301) [Size: 321] [--> http://192.168.208.19/javascript/]
/js                   (Status: 301) [Size: 313] [--> http://192.168.208.19/js/]
/server-status        (Status: 403) [Size: 279]

## 3. gobuster dir -u http://192.168.208.19:8000 -w /usr/share/seclists/Discovery/Web-Content/common.txt

/about                (Status: 301) [Size: 0] [--> /about/]
/admin                (Status: 301) [Size: 0] [--> /admin/]
/changes              (Status: 301) [Size: 0] [--> /changes/]
/checks               (Status: 301) [Size: 0] [--> /checks/]
/contact              (Status: 301) [Size: 0] [--> /contact/]
/counts               (Status: 301) [Size: 0] [--> /counts/]
/credits              (Status: 301) [Size: 0] [--> /credits/]
/data                 (Status: 301) [Size: 0] [--> /data/]
/favicon.ico          (Status: 301) [Size: 0] [--> /static/favicon.ico]
/healthz              (Status: 301) [Size: 0] [--> /healthz/]
/hosting              (Status: 301) [Size: 0] [--> /hosting/]
/keys                 (Status: 301) [Size: 0] [--> /keys/]
/languages            (Status: 301) [Size: 0] [--> /languages/]
/manage               (Status: 301) [Size: 0] [--> /manage/]
/memory               (Status: 301) [Size: 0] [--> /memory/]
/projects             (Status: 301) [Size: 0] [--> /projects/]
/robots.txt           (Status: 200) [Size: 676]
/search               (Status: 301) [Size: 0] [--> /search/]
/sitemap.xml          (Status: 200) [Size: 585]
/stats                (Status: 301) [Size: 0] [--> /stats/]
/trial                (Status: 301) [Size: 0] [--> /trial/]
/user                 (Status: 301) [Size: 0] [--> /user/]
/widgets              (Status: 301) [Size: 0] [--> /widgets/]

## 4. at http://192.168.208/19:8000/stats - found user admin

## 5. cewl 192.168.208.19 -w keywords.txt - found interesting word Niffenegger

## 6. Account combo admin/niffenegger worked to login into 192.168.208.19

## 7.
