# WPScan — OSCP Cheatsheet

## Purpose
Enumerate WordPress vulnerabilities, users, themes, and plugins during web exploitation.

---

## Basic Scan
```bash
wpscan --url http://$IP
```

---

## Aggressive Enumeration (OSCP Standard)
```bash
wpscan --url http://$IP/shenzi -e ap,at,u --plugins-detection aggressive -t 20
```

**Options**
- `-e ap` Enumerate all plugins  
- `-e at` Enumerate all themes  
- `-e u` Enumerate users  
- `--plugins-detection aggressive` Actively probe plugins  
- `-t 20` Threads  

---

## User Enumeration
```bash
wpscan --url http://$IP -e u
```

---

## Plugin Enumeration

### Passive
```bash
wpscan --url http://$IP -e p
```

### Aggressive
```bash
wpscan --url http://$IP -e ap --plugins-detection aggressive
```

---

## Theme Enumeration
```bash
wpscan --url http://$IP -e t
```

---

## Exploit Hunting
```bash
searchsploit wordpress <plugin_name>
```

---

## XML-RPC Checks
```bash
curl -X POST http://$IP/xmlrpc.php
```

---

## Brute Force (If Allowed)
```bash
wpscan --url http://$IP -U users.txt -P passwords.txt
```

---

## Output to File
```bash
wpscan --url http://$IP -e ap,at,u --plugins-detection aggressive -o wpscan.txt
```

---

## Common Attack Paths
- Vulnerable plugin → RCE
- Admin creds → Theme editor → PHP shell
- File upload → /wp-content/uploads/
- Credentials in wp-config.php

---

## OSCP Checklist
- Confirm WordPress
- Enumerate users
- Enumerate plugins
- Identify exploit
- Gain shell
- Read wp-config.php
