# Cadaver (WebDAV) – OSCP Cheat Sheet

## Connect
```bash
cadaver http://TARGET/
cadaver http://TARGET/webdav/
cadaver https://TARGET/dav/
```

With credentials:
```bash
cadaver http://TARGET/ -u username
```

---

## Basic Enumeration
```bash
ls              # list files/directories
ll              # detailed listing
pwd             # current remote directory
cd dir_name     # change directory
```

---

## File Transfer

Upload file:
```bash
put shell.php
put shell.aspx
put test.txt
```

Download file:
```bash
get backup.zip
```

Upload with rename:
```bash
put shell.php shell2.php
```

---

## Directory Operations
```bash
mkdir uploads
rmdir old_dir
```

---

## File Operations
```bash
delete file.txt
move old.php new.php
copy a.txt b.txt
```

---

## Permissions / Metadata
```bash
propget file.txt
propget .
```

---

## OSCP Tips
- Try **multiple extensions**:
  - `.php`, `.phtml`, `.php5`
  - `.asp`, `.aspx`
  - `.jsp`
- If upload works but execution fails:
  - Verify upload location with `ls`
  - Rename the file
  - Upload into existing directories
- Pair with:
  ```bash
  davtest -url http://TARGET/
  ```
- Always test execution:
  ```bash
  curl http://TARGET/shell.php
  ```

---

## Exit
```bash
exit
```
