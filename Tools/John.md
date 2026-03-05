n# John the Ripper — Quick Cheatsheet (OSCP)

## 📦 Basic Workflow
1. **Extract hash**  
2. **Use correct John format**  
3. **Run John with wordlist (e.g., rockyou.txt)**  
4. **Show cracked creds**

---

## 🔑 Show Cracked Passwords
```
john --show <hashfile>
```

---

## 🧩 SSH Private Key (passphrase cracking)
Convert SSH private key to a John-readable hash:
```
ssh2john id_rsa > ssh_hash
john ssh_hash --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## 🔐 KeePass (KDBX / KeePass2)
Extract hash from `.kdbx` file:
```
keepass2john database.kdbx > kdbx_hash
john kdbx_hash --wordlist=/usr/share/wordlists/rockyou.txt
```

If keyfile is used:
```
keepass2john database.kdbx keyfile.key > kdbx_hash
```

---

## 💾 Zip File Cracking
```
zip2john archive.zip > zip_hash
john zip_hash --wordlist=/usr/share/wordlists/rockyou.txt
```

---
## PDF Password Cracking
```
pdf2john Infrastructure.pdf > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash --rules=sshrules  
```

---
## 📁 RAR Archive Cracking
```
rar2john archive.rar > rar_hash
john rar_hash --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## ⚙️ Linux /etc/shadow Hashes
```
john shadow_hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## 🎫 Windows NTLM Hashes
```
john ntlm_hashes --format=nt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## 🔐 Cracking /etc/passwd + /etc/shadow Together
```
unshadow /etc/passwd /etc/shadow > full_hash
john full_hash --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## 🌐 Web Hashes (MD5, SHA1, etc.)
```
john hash.txt --format=RAW-MD5 --wordlist=rockyou.txt
```

List formats:
```
john --list=formats | grep -i <type>
```

---
## 🌐 Kerberos

```
john hashes.kerboroast --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs --rules=sshRules
```


## 🧰 Custom Rules
```
john hash.txt --wordlist=rockyou.txt --rules
```

---

## 🚀 Resume / Incremental Mode
Resume:
```
john --restore
```

Incremental:
```
john hash.txt --incremental
```

## Example Usage

```
ssh2john <ssh.key> > ssh.hash

john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules ssh.hash

keepass2john Database.kdbx
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules keepasshash.txt 

```