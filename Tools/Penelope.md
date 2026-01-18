# Penelope Shell Handler Cheat Sheet (OSCP)

## What is Penelope?

Penelope is an advanced shell listener/handler that automatically
upgrades dumb shells into interactive TTYs with history, tab completion,
job control, file transfer helpers, and more.

Replaces:\
- netcat listeners\
- manual python pty upgrades\
- rlwrap hacks

------------------------------------------------------------------------

## Basic Listener

``` bash
penelope -p 4444
```

Listen on port 4444.

------------------------------------------------------------------------

## Listen on specific interface

``` bash
penelope -i tun0 -p 4444
```

Useful for VPN labs (PG / HTB / OSCP).

------------------------------------------------------------------------

## Multiple ports

``` bash
penelope -p 4444,5555,6666
```

------------------------------------------------------------------------

## Auto-upgrade shell (default behavior)

Penelope automatically: - Detects shell type - Spawns PTY - Fixes stty -
Enables tab + arrows - Stabilizes reverse shells

No manual upgrade needed.

------------------------------------------------------------------------

## File Upload from Kali to Target

Inside Penelope session:

    upload localfile remote_path

Example:

    upload linpeas.sh /tmp/linpeas.sh

------------------------------------------------------------------------

## File Download from Target

    download remote_file local_path

Example:

    download /etc/passwd .

------------------------------------------------------------------------

## Spawn fully interactive shell manually (if needed)

    spawn

------------------------------------------------------------------------

## Background shell

    background

Return later with:

    sessions
    interact <id>

------------------------------------------------------------------------

## Run local command while shell is active

    ! <command>

Example:

    ! ifconfig tun0

------------------------------------------------------------------------

## Port forwarding (pivot helper)

    forward local_port remote_ip remote_port

Example:

    forward 8080 127.0.0.1 80

------------------------------------------------------------------------

## Upgrade limited shells (sh → bash)

    upgrade

------------------------------------------------------------------------

## Built-in helpers

    help

Key built-ins: - upload - download - spawn - upgrade - forward -
sessions - interact - background

------------------------------------------------------------------------

## Useful OSCP Combo

Start listener:

``` bash
penelope -i tun0 -p 4444
```

Then catch ANY reverse shell (bash, nc, php, python) with full TTY
automatically.

------------------------------------------------------------------------

## Why it's amazing for OSCP

-   No manual TTY fix
-   No stty rows/cols pain
-   No rlwrap
-   Works with webshells instantly
-   Easy file transfer mid-shell
-   Stable during privilege escalation
