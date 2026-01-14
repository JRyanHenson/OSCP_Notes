# Minimal Linux Enumeration Command Set  
**For OSCP / CTF Privilege Escalation**

A streamlined, copy-paste-ready checklist for fast manual Linux enumeration.  
Includes: interactive shell upgrade, env vars, home-dir file search, and high-value privilege escalation checks.

---

# 0. Upgrade to a Full Interactive Bash Shell

If you land in a restricted / dumb shell, run:

### Spawn a PTY
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

If python3 isn’t available:
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
```

### Fix terminal quirks
```bash
export TERM=xterm
export SHELL=/bin/bash
```

### Enable job control + restore terminal
Press:
```
Ctrl + Z
```

Then run locally:
```bash
stty raw -echo; fg
reset
```

---

# 1. Identity & System Info

```bash
whoami
id
hostname
pwd
uname -a
cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null
```

---

# 2. Environment Variables (Often Contain Secrets)

```bash
env
set 2>/dev/null | head -n 50
echo $PATH
echo $HOME
echo $SHELL
```

**Look for:**  
API keys, tokens, passwords, unusual PATH entries (writable dirs = PATH hijacking).

---

# 3. Users & Home Directory Recon

```bash
cat /etc/passwd
ls -la /home
ls -la /root 2>/dev/null


```

### Search **all home dirs** for credentials, keys, notes, flags

#### Text files
```bash
find /home -type f -name "*.txt" 2>/dev/null
```

#### History files
```bash
find /home -type f -name "*history*" 2>/dev/null
```

#### SSH keys
```bash
find /home -type f -name "id_rsa" -o -name "id_*" 2>/dev/null
```

#### Sensitive strings
```bash
grep -Ri "password\|passwd\|secret\|token\|key" /home 2>/dev/null | head
```

---

# 4. Sudo Misconfigurations (High Value Target)

```bash
sudo -l 2>/dev/null
sudo -V 2>/dev/null | head
```

Red flags:
- `NOPASSWD`
- Commands running as root
- GTFOBins matches (`find`, `awk`, `tar`, `vim`, etc.)
- Scripts with uncontrolled inputs or wildcards

---

# 5. Writable Paths & Permission Issues

### World-writable directories
```bash
find / -writable -type d 2>/dev/null | head
find . -writable -type d 2>/dev/null | head
```

### World-writable files
```bash
find / -writable -type f 2>/dev/null | head

```

### Check PATH order
```bash

```

Writable dirs in PATH → **command hijacking → root**.

---

# 6. SUID / SGID Binaries (Critical Priv-Esc)

### SUID binaries:
```bash
find / -perm -4000 -type f 2>/dev/null
```

### SGID:
```bash
find / -perm -2000 -type f 2>/dev/null
```

Look for:
- GTFOBins candidates
- Custom binaries in `/opt`, `/usr/local`, or home dirs
- Anything unusual or non-default

---

# 7. Processes & Network Services

```bash
ps aux
ps -ef
ss -tulwn
netstat -tulnp 2>/dev/null
```

Look for:
- Root processes loading writable configs
- Passwords in command arguments
- Internal-only listening services (localhost)

---

# 8. Cron Jobs & Scheduled Tasks

```bash
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.*
crontab -l 2>/dev/null
```

Red flags:
- Scripts stored in `/home`, `/tmp`, `/var/www`, `/opt`
- Wildcards (`*`) inside root cron scripts
- Writable paths used by cron jobs

---

# 9. Config Files, Backups, Logs

### Credentials in /etc
```bash
grep -R "password" /etc 2>/dev/null | head
```

### Web app configs
```bash
ls -la /var/www 2>/dev/null
grep -R "password\|db\|user" /var/www 2>/dev/null | head
```

### Backup files
```bash
find / -name "*.bak" -o -name "*~" 2>/dev/null | head
```

---

# 10. Capabilities & Containers

### Linux Capabilities
```bash
getcap -r / 2>/dev/null
```

### Docker / LXC detection
```bash
id
ls -lagetcap -r / 2>/dev/nullgetcap -r / 2>/dev/null /.dockerenv 2>/dev/null
grep -i docker /proc/1/cgroup 2>/dev/null
```

User in `docker` group = **instant root** (container breakout).

---

# 11. Full Minimal Copy/Paste Enumeration Block

```bash
# Shell upgrade
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# System
whoami; id; hostname; uname -a
cat /etc/os-release 2>/dev/null

# Environment
env
echo $PATH

# Users & homes
cat /etc/passwd
ls -la /home
find /home -name "*.txt" 2>/dev/null
grep -Ri "password\|secret\|token" /home 2>/dev/null | head

# Sudo
sudo -l

# Permissions
find / -writable -type d 2>/dev/null | head
find / -perm -4000 -type f 2>/dev/null

# Processes
ps aux
ss -tulwn

# Cron
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.*

# Web/configs
grep -R "password" /etc 2>/dev/null | head
ls -la /var/www 2>/dev/null

# Capabilities / containers
getcap -r / 2>/dev/null
id
```

---

