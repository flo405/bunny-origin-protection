# Bunny Origin Protection (bop)

Lock your origin to bunny.net’s edge network with an automated, idempotent firewall sync.

`bop` fetches the current bunny.net edge server IPs and maintains a dedicated **iptables** chain that:
- **Allows** only those IPs to reach **TCP 443**
- **Drops** everything else to that port

It’s designed to be safe to re-run (e.g., via cron), and ships with a POSIX-`sh` installer that backs up your current firewall configuration so you can **cleanly uninstall/rollback** later.

---

## Features

- 🔐 Origin protection for **HTTPS (port 443)** via `iptables`
- 🔁 Idempotent sync: add new bunny IPs, remove stale ones
- 🧰 Works with both `iptables (legacy)` and `iptables-nft` frontends
- 🧪 One-liner install (**curl**/**wget** → `sh`)
- 🗓️ Optional cron refresh (e.g., every 10 minutes)
- 🧯 Safe rollback: `iptables-save` backups for uninstall
- 🐍 Python ≥ 3.7 only; **stdlib only** (no pip deps)

---

## Quick start (one-liners)

> ⚠️ You are piping to `sh`. Review the script if that’s a concern (see “Safer install” below).

**Install (no cron):**
```bash
curl -fsSL https://raw.githubusercontent.com/flo405/bunny-origin-protection/refs/heads/main/setup-bop.sh | sudo sh
