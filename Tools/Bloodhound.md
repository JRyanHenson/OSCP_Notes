# BloodHound CE – Run, Collect, and Troubleshoot Cheat Sheet (Kali)

Battle-tested notes for running **BloodHound Community Edition (CE)** on Kali,
collecting data, and quickly troubleshooting issues.
Optimized for **OSCP / lab usage**.

---

## 📍 Install Location

Installed via `bloodhound-cli` (recommended):
```
~/bhce
```

All commands below assume you are in this directory.

---

## ▶️ Running BloodHound CE

### Start BloodHound CE
```bash
sudo ./bloodhound-cli start
```

### Stop BloodHound CE
```bash
sudo ./bloodhound-cli stop
```

### Restart (first fix for almost everything)
```bash
sudo ./bloodhound-cli restart
```

### Check status
```bash
sudo ./bloodhound-cli status
```

---

## 🌐 Web UI

- URL:
```
http://127.0.0.1:8080/ui/login
```

- Default user: `admin`
- Password: set during install

### Reset admin password
```bash
sudo ./bloodhound-cli resetpwd
```

---

## 🐳 Docker Sanity Checks

### Containers running?
```bash
docker ps
```

You should see multiple `bloodhound-*` containers (API, UI, Postgres, etc).

### Docker daemon running?
```bash
sudo systemctl status docker
```

---

## 📜 Logs (Always Check These First)

### View logs
```bash
sudo ./bloodhound-cli logs
```

### Tail logs
```bash
sudo ./bloodhound-cli logs --tail 200
```

---

## 🚑 Common Problems & Fixes

### ❌ UI does not load
```bash
sudo ./bloodhound-cli status
sudo ss -lntp | grep ':8080'
```

**Fix**
```bash
sudo ./bloodhound-cli restart
```

---

### ❌ Port 8080 already in use
```bash
sudo ss -lntp | grep ':8080'
```

Stop the conflicting service, then:
```bash
sudo ./bloodhound-cli start
```

---

### ❌ Containers exited / unhealthy
```bash
docker ps -a | grep bloodhound
```

**Fix**
```bash
sudo ./bloodhound-cli restart
```

---

### ❌ Docker networking weirdness
```bash
sudo systemctl restart docker
sudo ./bloodhound-cli start
```

---

### ❌ Nuclear reset (data loss)
⚠️ Deletes all BloodHound CE data
```bash
sudo ./bloodhound-cli stop
sudo ./bloodhound-cli uninstall
sudo ./bloodhound-cli install
```

---

## 🔍 30-Second Health Check

```bash
docker ps
sudo ./bloodhound-cli status
curl -I http://127.0.0.1:8080
```

---

## 🧠 Key Mental Model

- BloodHound CE **does NOT use Neo4j**
- Uses **PostgreSQL (Dockerized)**
- No `neo4j.conf`, no `bhapi.json`
- `bloodhound-cli` controls everything
- If stuck: **restart → logs**

---

# 📥 Data Collection

## 🪟 SharpHound (Windows)

```powershell
SharpHound.exe -c All
```

Stealthier:
```powershell
SharpHound.exe -c DCOnly
```

Upload the resulting `.zip` in the UI.

---

## 🐧 bloodhound-python (Linux)

```bash
bloodhound-python -u USER -p 'PASS' -d DOMAIN.LOCAL -ns DC_IP -c All
```

Upload all generated JSON files.

---

## 🧭 Practical OSCP Tips

- Find **shortest path to Domain Admin**
- Abuse:
  - GenericAll
  - GenericWrite
  - WriteDACL
  - RBCD
- Validate with Impacket / bloodyAD
- Re-collect after exploitation

---

## ✅ One-Line Reminder

```bash
sudo ./bloodhound-cli start
```

## Example Bloodhound Queries

```
● AS-REP Roastable Users
MATCH (u:User)
WHERE u.dontreqpreauth = true
AND u.enabled = true
RETURN u
LIMIT 100

● All Kerberoastable Users
MATCH (u:User)
WHERE u.hasspn=true
AND u.enabled = true
AND NOT u.objectid ENDS WITH '-502'
AND NOT COALESCE(u.gmsa, false) = true
AND NOT COALESCE(u.msa, false) = true
RETURN u
LIMIT 100

● Shortest Paths To Domain Admins
MATCH p=shortestPath((t:Group)<-[:AD_ATTACK_PATHS*1..]-(s:Base))
WHERE t.objectid ENDS WITH '-512' AND s<>t
RETURN p
LIMIT 1000

● Shortest Paths From Owned Objects
MATCH p=shortestPath((s:Base)-[:AD_ATTACK_PATHS*1..]->(t:Base))
WHERE ((s:Tag_Owned) OR COALESCE(s.system_tags, '') CONTAINS 'owned')
AND s<>t
RETURN p
LIMIT 1000

```
