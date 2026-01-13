# Swaks (Swiss Army Knife for SMTP) — Quick Wiki

A concise, practical cheat sheet for using **swaks** to test SMTP servers during troubleshooting, pentests, and labs.

---

## Basic syntax

```
swaks [options]
```

Common long options shown below — short aliases also exist (`-t` / `--to`, `-f` / `--from`, etc.).

---

## Common options

- `--to` / `-t` \<recipient\> — recipient address  
- `--from` / `-f` \<sender\> — envelope sender address  
- `--server` / `-s` \<host[:port]\> — SMTP server and optional port  
- `--port` \<port\> — explicit port if not included in `--server`  
- `--helo` / `--ehlo` \<hostname\> — set HELO/EHLO hostname  
- `--auth` \<method\> — authentication method (e.g., `PLAIN`, `LOGIN`, `CRAM-MD5`, `NTLM`)  
- `--auth-user` \<user\> — username for auth  
- `--auth-password` \<password\> — password for auth (or use `--auth-password-file`)  
- `--tls` — negotiate STARTTLS (typical for port 587)  
- `--tls-on-connect` — use SMTPS / TLS-on-connect (typical for port 465)  
- `--tls-cert` / `--tls-key` — present client cert/key (if required by server)  
- `--header` `'<Header: Value>'` — add or replace an SMTP header (e.g., `--header 'Subject: Test'`)  
- `--body` \<text\> — provide message body inline  
- `--attach` `@/path/to/file` — attach a file (can be used multiple times)  
- `--data` \<file\> — use an RFC-822 formatted file as the DATA (full message)  
- `--timeout` \<seconds\> — network timeout  
- `--quit-after` \<stage\> — quit after a given SMTP stage (useful to test specific steps)  
- `--help` — show full help and options

---

## Practical examples

### 1) Simple send (no auth, no TLS)
```
swaks --from sender@example.com --to recipient@example.com --server smtp.example.com:25 --header 'Subject: Hello from swaks' --body 'This is a test'
```

### 2) Send with STARTTLS + LOGIN auth (port 587)
```
swaks   --from sender@example.com   --to recipient@example.com   --server smtp.example.com:587   --auth LOGIN   --auth-user 'smtpuser'   --auth-password 'smtppass'   --tls   --header 'Subject: STARTTLS + LOGIN test'   --body 'Hello — authenticated via LOGIN over STARTTLS'
```

### 3) Send with SMTPS (TLS-on-connect, port 465)
```
swaks --from sender@example.com --to recipient@example.com --server smtp.example.com:465 --tls-on-connect --auth PLAIN --auth-user user --auth-password pass --header 'Subject: SMTPS test' --body 'Using TLS-on-connect'
```

### 4) Send with an attachment (multiple allowed)
```
swaks   --from sender@example.com   --to recipient@example.com   --server smtp.example.com:587   --tls   --auth PLAIN --auth-user user --auth-password pass   --header 'Subject: Attachment test'   --body 'See attached files'   --attach @/tmp/report.pdf   --attach @/tmp/image.png
```

### 5) Use an RFC-822 formatted file as the message DATA
```
swaks --server smtp.example.com --to recipient@example.com --from sender@example.com --data /path/to/message.eml
```

### 6) Test authentication only (connect, authenticate, quit)
```
swaks --server smtp.example.com:587 --tls --auth LOGIN --auth-user user --auth-password pass --quit-after AUTH
```

### 7) Custom HELO/EHLO and headers
```
swaks --server smtp.example.com --from a@b.com --to c@d.com --ehlo mytesthost.local --header 'X-Test: swaks' --header 'Subject: Custom HELO'
```

---

## Tips & troubleshooting

- Use `--tls` for STARTTLS (submission port 587). Use `--tls-on-connect` for SMTPS (port 465).  
- If a password on the CLI is a concern, use `--auth-password-file` to point to a file with restricted permissions.  
- `--attach @/path` is the common way to attach files; add `--attach-type` if you need to set a MIME type explicitly.  
- If you want to replicate an entire message (headers + body), prepare an RFC-822 `.eml` and use `--data file.eml`.  
- For scripting, check `--timeout` and capture exit codes; swaks outputs detailed SMTP transaction logs which are very helpful for debugging.  
- Read the man page (`man swaks`) for advanced options like SASL, proxying, TLS cert options, and limiting output sections.

---

## References / further reading

- Official swaks homepage & docs: https://jetmore.org/john/code/swaks/  
- Man page (`swaks`): see your system manpages (`man swaks`) or online copies (e.g., manpages.ubuntu.com)

---

*File generated for export — suitable for saving in your notes or dropping into an OSCP/CTF cheat-sheet collection.*
