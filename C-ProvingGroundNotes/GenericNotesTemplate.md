**Metadata**

- IP Address:  192.168.
- Hostname: 
- OS: 	
- Found Credentials/Users:

Main Objectives:

Local.txt = 
Proof.txt = 

**Enumeration**

1. NMAP Scans Output (TCP/UDP)

```


```

2. Service Enumeration Port XX

3. Possible Exploits

```

```

4. Other Notes

```

```

**Initial Foothold** 

1. Exploit Steps

```



```

2. Shell Access

```

```

**Post-Exploitation**

1. Shell / Context (reference)

```


```
  
2. Identity & System Info

```


```

3. Environment Info

```

```

  4. Users & Groups

```

```

  5.  AD Enumeration

```

# Powershell

Get-ADUser -Filter * (domain joined)
Get-ADGroup -Filter *
Get-ADGroupMember "Domain Admins"

```

  6. Privileges & Tokens

```


```

  8. Processes & Services

```

```

  9.  Scheduled Tasks

```

```

  10.  Network

```

```

  11. Software

```

```

  12. Shares & Drivers

```


```

  13. Loot Files & Credentials

```

```

5. Automated Enumeration

```




```
5. Possible PE Paths

```



```

**Privilege Escalation**

1. PE Steps

```

```

2. Notes

```

```

