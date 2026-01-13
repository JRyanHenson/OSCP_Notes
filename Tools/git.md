# Git Cheatsheet for CTFs (OSCP)

## 🔍 Check Repo Status
```
git status
```

## 📜 View Commit History
```
git log
```

**Compact view:**
```
git log --oneline --graph
```

## 🧭 Browse Previous Versions
```
git checkout <commit_hash>
```
Return to latest:
```
git checkout main
```

## 🔎 Search for Secrets in History
```
git log -p | grep -i "password"
```

Search entire repo:
```
git grep -i "password"
```

## 🔄 Show Changes in a Commit
```
git show <commit_hash>
```

## 📂 Recover Deleted or Overwritten Files
```
git log --diff-filter=D --summary
```
Restore:
```
git checkout <commit_hash> -- path/to/file
```

## 🎣 Inspect Stashes
```
git stash list
git stash show -p stash@{0}
```

## 🗂️ List Branches
```
git branch -a
```

## 📦 Clone a Repository
```
git clone http://target/repo.git
```

## 📌 Tips
- Inspect logs/diffs/stashes for leaked creds.
- Check for exposed `.git/` directories.
- Deleted history often contains SSH keys/DB creds.
