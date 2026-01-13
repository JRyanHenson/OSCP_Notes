# Hashcat Quick Wiki

A tiny, no-nonsense cheat sheet for cracking hashes with Hashcat during CTFs, OSCP-style labs, and pentests.

## Basic Syntax

```
hashcat -m <hash_mode> -a <attack_mode> <hashfile> <wordlist>
```

## Common Hash Modes
- `0` MD5  
- `100` SHA1  
- `1400` SHA256  
- `500` Unix MD5 Crypt  
- `1800` SHA512crypt (Linux)  
- `1000` NTLM  
- `13100` Kerberos 5 TGS-REP  
- `5500` NetNTLMv1  
- `5600` NetNTLMv2  

## Common Attack Modes

- `0` Straight wordlist  
- `3` Brute force  
- `6` Wordlist + mask hybrid  
- `7` Mask + wordlist hybrid  

## Examples

### 1. Crack NTLM Hash with RockYou
```
hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt
```

### 2. Brute Force 8‑Character Password (Lowercase)
```
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l?l?l
```

### 3. Hybrid Attack (Dictionary + Mask)
Example: append 4 digits to wordlist entries  
```
hashcat -m 1000 -a 6 ntlm.txt wordlist.txt ?d?d?d?d
```

### 4. Crack Kerberos TGS Ticket (HASHCAT Mode 13100)
```
hashcat -m 13100 -a 0 krb_tgs.txt rockyou.txt
```

### 5. Apply Best64 Rules
```
hashcat -m 0 -a 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### 6. Restore an Interrupted Session
```
hashcat --restore
```

### 7. Show Cracked Results
```
hashcat -m 1000 --show ntlm.txt
```

### 8. Other Example Usage

```
hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt

# The Hashcat mode number for Atlassian (PBKDF2-HMAC-SHA1) hashes is 12001, so we can pass that to the -m mode flag. After copying the hashes into a file called hashes.txt, we'll pass this as the first positional argument. We can then pass the fastrack.txt password list that's built into Kali as the final positional argument.
```
## Useful Flags

- `--force` skip hardware warnings  
- `--status` show live session status  
- `--session <name>` custom session naming  
- `--potfile-disable` disable potfile for testing  
- `--outfile found.txt` save cracked creds  

## Tips

- Always identify hash type first. `hashid`, `hash-identifier`, or `hashcat --example-hashes`
- Use rules early; they dramatically improve success rate
- For NTLM/MD5, GPU cracking is extremely fast  
- For salted hashes (like sha512crypt), use wordlists + strong rules

