# smbclient — quick wiki (OSCP notes)

Short, practical reference focused on examples and common workflows.

---

## One-line cheat
List shares, connect, download recursively, or run single commands from the shell.

---

## Quick flags
- `//HOST/SHARE` — UNC-style target.  
- `-U user` — username (can be `user%pass`).  
- `-N` — no password (anonymous/null session).  
- `-L //HOST` — list available shares on host.  
- `-I IP` — target IP (useful when DNS misleading).  
- `-p PORT` — SMB port (default 445/139).  
- `-c 'cmd;cmd'` — run commands non-interactively and exit.  

---

## Common workflows & examples

### 1) List shares on a host
```bash
# interactive (prompts for password)
smbclient -L //TARGET -U username

# anonymous / null session
smbclient -L //TARGET -N

# force IP (skip DNS)
smbclient -L //TARGET -I 10.0.0.5 -N
```

### 2) Connect to a share (interactive shell)
```bash
# prompt for password
smbclient //10.0.0.5/share -U alice

# provide password inline (use with caution)
smbclient //10.0.0.5/share -U 'alice%S3cr3t!'

# anonymous connection
smbclient //10.0.0.5/share -N
```
Inside the smbclient shell you can use commands like `ls`, `cd`, `get`, `mget`, `put`, `mput`, `del`, `mkdir`, `rmdir`, `lcd`, `recurse`, `prompt`, `quit`.

### 2.1) Connect / authenticate with DOMAIN\user (domain examples)
```bash
# interactive: prompts for password (use double-backslash for escaping in shell)
smbclient //10.0.0.5/share -U 'DOMAIN\\alice'

# non-interactive inline password (visible in process list — use only in labs)
smbclient //10.0.0.5/share -U 'DOMAIN\\alice%P@ssw0rd'

# alternative using -W to specify domain/workgroup with username
smbclient //10.0.0.5/share -U 'alice' -W DOMAIN -c 'get secret.txt'

# using NTLM style principal (sometimes required)
smbclient //10.0.0.5/share -U 'alice@DOMAIN' -W DOMAIN -c 'ls'
```

### 3) Download a single file
```bash
# interactive
smbclient //10.0.0.5/share -U bob -c 'get secret.txt'

# non-interactive (single command)
smbclient //10.0.0.5/share -U 'bob%pass' -c 'get secret.txt'
```

### 4) Download entire tree (recursive)
```bash
# turn on recurse, turn off interactive prompting, then mget everything
smbclient //10.0.0.5/share -U 'bob%pass' -c 'recurse; prompt; mget *'
```

### 5) Upload a file
```bash
# interactive
smbclient //10.0.0.5/share -U alice -c 'put localfile.txt remotefile.txt'

# non-interactive
smbclient //10.0.0.5/share -U 'alice%pass' -c 'put /tmp/localfile.txt secrets/localfile.txt'
```

### 6) Enumerate with a null session (useful for older targets)
```bash
smbclient -L //10.0.0.5 -N
# or try specific IPC$
smbclient //10.0.0.5/ipc$ -N
```

### 7) Run multiple commands and exit
```bash
smbclient //10.0.0.5/share -U 'admin%pass' -c 'ls; cd dir; get file.txt; quit'
```

### 8) Use with IP and alternate port
```bash
smbclient //10.0.0.5/share -I 10.0.0.5 -p 139 -U 'user%pass'
```

### 9) Save non-interactive session output to local file
```bash
# example: run ls and save to local file via shell redirection
smbclient //10.0.0.5/share -U 'user%pass' -c 'ls' > smb_ls_output.txt
```

### 10) Mount-like behavior (download to tar stream) — quick trick
```bash
# download many files and pack locally (example)
smbclient //10.0.0.5/share -U 'user%pass' -c 'recurse; prompt; mget *' && tar -czf share_backup.tgz *
```
(Adjust to your workflow — smbclient is not a direct mount; use `mount.cifs` if you need a real mount.)

---

## Tips & gotchas
- `mget`/`mput` will ask per-file unless `prompt` is turned off (`prompt` toggles interactive prompting). Use `recurse` + `prompt` off to download directories.
- Use `-I` to avoid DNS name resolution issues (common in labs).
- Inline passwords (`user%pass`) are convenient in labs, but avoid in real environments (exposed in process list / shell history).
- Check for `IPC$`, `ADMIN$`, and oddly named shares — they may expose sensitive files.
- If `smbclient -L` times out, try `-p 139` or `-I <ip>`; older SMB may be on 139 rather than 445.
- For scripting, `-c` is very handy to run a sequence and exit.

---

## Minimal reference (copyable)
```text
# list shares
smbclient -L //10.0.0.5 -N

# interactive connect
smbclient //10.0.0.5/share -U alice

# download recursively
smbclient //10.0.0.5/share -U 'alice%pass' -c 'recurse; prompt; mget *'

# single command
smbclient //10.0.0.5/share -U 'bob%pass' -c 'get secret.txt'
```

---

Filename suggestion for your notes: `smbclient_oscp.md` — drop into your OSCP notes under `tools/` or `smb/`.
