# Bunny Origin Protection

Allow **only bunny.net edge IPs** to reach your origin on **ports 80 and 443** using **nftables** sets. Atomic, idempotent, and easy to install with a single command.

## Why this tool?

* ✅ **nftables-first**: uses an `inet` table with IP sets for clean, fast matching
* 🔐 **Strict origin lockdown**: accept bunny IPs, drop everyone else on 80/443
* 🔁 **Idempotent updates**: only set contents change; rules remain stable
* 🧯 **Safe by default**: IPv6 can be *blocked* entirely
* 🕒 **Automatic refresh**: systemd timer (or cron fallback)
* ↩️ **Rollback**: nft ruleset snapshot saved & restored on uninstall

---

## One‑liner install

> Piping to shell is convenient; review the script if you prefer (see **Manual install** below).

```bash
curl -fsSL https://raw.githubusercontent.com/flo405/bunny-origin-protection/refs/heads/main/setup-bop.sh | sudo sh
```

### Setup

* Refresh every 5 minutes and block IPv6 completely:

```bash
curl -fsSL https://raw.githubusercontent.com/flo405/bunny-origin-protection/refs/heads/main/setup-bop.sh \
  | sudo sh -s -- --refresh 5 --ipv6 block
```

**Uninstall & rollback:**

```bash
curl -fsSL https://raw.githubusercontent.com/flo405/bunny-origin-protection/refs/heads/main/setup-bop.sh \
  | sudo sh -s -- --uninstall
```

---

## What gets installed

* **Controller**: `/usr/local/bin/bop-nft` (single-file Python; stdlib-only)
* **State & snapshot**: `/var/lib/bop/`

  * `bunny_edges.txt` — last fetched list (debug)
  * `backup.nft` — nft ruleset snapshot before first install
* **Scheduler**:

  * **systemd**: `bop-nft.service` + `bop-nft.timer` (runs every *N* minutes)
  * **cron fallback**: `/etc/cron.d/bop-nft`

---

## How it works (nftables layout)

This tool owns a dedicated table: `table inet bop`.

```nft
table inet bop {
  sets {
    bunny_v4 { type ipv4_addr; flags interval; }
    bunny_v6 { type ipv6_addr; flags interval; }
  }
  chains {
    gate {
      type filter hook input priority -150; policy accept;
      tcp dport {80,443} ip  saddr @bunny_v4 accept
      # (optional, if --ipv6 allow)
      tcp dport {80,443} ip6 saddr @bunny_v6 accept
      tcp dport {80,443} drop
    }
  }
}
```

On each refresh we **only update the set contents** (`bunny_v4` / `bunny_v6`), keeping rules stable and drop‑first safe.

---

## CLI reference (controller)

```bash
sudo bop-nft [--table bop] [--chain gate] \
             [--ports 80,443] [--ipv6 allow|block] \
             [--list-file /var/lib/bop/bunny_edges.txt] [--dry-run]
```

* `--ipv6 block` (default): drops *all* IPv6 to the protected ports
* `--ipv6 allow`: allowlists IPv6 using bunny’s published v6 edges
* `--dry-run`: prints the nft script it would apply (no changes)

---

## Contributions

PRs and issues welcome!
