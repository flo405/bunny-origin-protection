#!/usr/bin/env python3
"""
BOP-NFT — Bunny.net Origin Protection (nftables-only)

- Fetches Bunny edge server IPs (XML or JSON)
- Maintains nftables table `inet bop` with sets `bunny_v4` / `bunny_v6`
- Enforces that ONLY those IPs can reach TCP ports (default: 80,443)
- IPv6 behaviour: allow (use v6 list) or block (drop everything to ports)
- Idempotent: only updates set contents; chain stays static once created

Requires: python3 (>=3.7), `nft` binary (nftables)
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from typing import Iterable, List, Sequence, Set, Tuple

EDGE_URLS = [
    "https://bunnycdn.com/api/system/edgeserverlist",
    "https://api.bunny.net/system/edgeserverlist",
]

DEFAULT_TABLE = "bop"
DEFAULT_CHAIN = "gate"
DEFAULT_PORTS = (80, 443)
DEFAULT_LIST_FILE = "/var/lib/bop/bunny_edges.txt"


# -------------------- utils --------------------

def run(cmd: Sequence[str], check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(shlex.quote(c) for c in cmd)}\n"
            f"STDERR: {proc.stderr.decode(errors='ignore')}"
        )
    return proc


# -------------------- fetching --------------------

def fetch_bunny_ips() -> Tuple[List[str], List[str]]:
    """Return (ipv4_list, ipv6_list). Robust to XML/JSON/HTML.
    Leaves order unspecified; caller may sort.
    """
    headers = {
        "User-Agent": "bop-nft/1.0",
        "Accept": "application/xml, text/xml, application/json;q=0.9, */*;q=0.1",
    }
    last_error: Exception | None = None
    preview = ""
    for url in EDGE_URLS:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                ctype = (resp.headers.get("Content-Type") or "").lower()
            text = raw.decode("utf-8", errors="replace").lstrip("\ufeff").strip()
            preview = text[:200]

            v4: Set[str] = set()
            v6: Set[str] = set()

            def add_candidate(s: str) -> None:
                s = s.strip()
                if not s:
                    return
                try:
                    ip = ipaddress.ip_address(s)
                    if ip.version == 4:
                        v4.add(str(ip))
                    else:
                        v6.add(str(ip))
                except ValueError:
                    pass

            # JSON?
            if "json" in ctype or (text[:1] in "[{"):
                try:
                    obj = json.loads(text)
                    if isinstance(obj, list):
                        for x in obj:
                            add_candidate(str(x))
                    elif isinstance(obj, dict):
                        for key in ("items", "data", "ips"):
                            if isinstance(obj.get(key), list):
                                for x in obj[key]:
                                    add_candidate(str(x))
                except Exception as e:
                    last_error = e

            # XML?
            if not (v4 or v6) and ("xml" in ctype or text.startswith("<")):
                try:
                    root = ET.fromstring(text)
                    for el in root.iter():
                        if el.text:
                            add_candidate(el.text)
                except Exception as e:
                    last_error = e

            # Fallback regex from any body
            if not (v4 or v6):
                for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9A-Fa-f:]{3,}\b", text):
                    add_candidate(m.group(0))

            if v4 or v6:
                return sorted(v4, key=lambda s: tuple(int(x) for x in s.split('.'))), sorted(v6)
        except Exception as e:
            last_error = e
            continue
    raise RuntimeError(f"Failed to fetch/parse Bunny edge IPs. Last error: {last_error}; preview={preview!r}")


# -------------------- nftables helpers --------------------

def ensure_nft_available() -> None:
    if not shutil.which("nft") if 'shutil' in globals() else None:
        import shutil as _sh
        if not _sh.which("nft"):
            raise SystemExit("'nft' command not found. Please install nftables or use the installer.")


def nft_list(kind: str, *args: str) -> subprocess.CompletedProcess:
    return run(["nft", "list", kind, *args], check=False)


def nft_apply(script: str, dry_run: bool) -> None:
    if dry_run:
        sys.stdout.write("\n# --- nft script (dry-run) ---\n" + script + "\n")
        return
    with tempfile.NamedTemporaryFile("w", delete=False, prefix="bopnft_", suffix=".nft") as f:
        f.write(script)
        path = f.name
    try:
        run(["nft", "-f", path])
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


# -------------------- render nft script --------------------

def render_bootstrap(table: str, chain: str, ports: Sequence[int], ipv6_mode: str) -> str:
    ports_list = ", ".join(str(p) for p in sorted(set(int(p) for p in ports)))
    lines: List[str] = []
    # Define/replace our table with minimal, widely-compatible syntax
    lines.append(f"table inet {table} {{")
    lines.append("  set bunny_v4 { type ipv4_addr; }")
    lines.append("  set bunny_v6 { type ipv6_addr; }")
    lines.append("")
    lines.append(f"  chain {chain} {{ type filter hook input priority -150; policy accept; }}")
    lines.append("}")
    # Rebuild chain content to ensure correct rules
    lines.append(f"flush chain inet {table} {chain}")
    lines.append(f"add rule inet {table} {chain} tcp dport {{ {ports_list} }} ip saddr @bunny_v4 accept")
    if ipv6_mode == "allow":
        lines.append(f"add rule inet {table} {chain} tcp dport {{ {ports_list} }} ip6 saddr @bunny_v6 accept")
    lines.append(f"add rule inet {table} {chain} tcp dport {{ {ports_list} }} drop")
    return "
".join(lines)


def render_set_update(table: str, v4: Sequence[str], v6: Sequence[str], ipv6_mode: str) -> str:
    chunks: List[str] = []
    # IPv4 set
    chunks.append(f"flush set inet {table} bunny_v4")
    if v4:
        # Chunk to avoid super long commands
        elems = [f"{ip}" for ip in v4]
        for i in range(0, len(elems), 512):
            part = ", ".join(elems[i:i+512])
            chunks.append(f"add element inet {table} bunny_v4 {{ {part} }}")
    # IPv6 set
    chunks.append(f"flush set inet {table} bunny_v6")
    if ipv6_mode == "allow" and v6:
        elems6 = [f"{ip}" for ip in v6]
        for i in range(0, len(elems6), 512):
            part = ", ".join(elems6[i:i+512])
            chunks.append(f"add element inet {table} bunny_v6 {{ {part} }}")
    return "\n".join(chunks)


# -------------------- main --------------------

def parse_ports(spec: str) -> Tuple[int, ...]:
    try:
        ports = tuple(sorted({int(p.strip()) for p in spec.split(',') if p.strip()}))
    except Exception:
        raise argparse.ArgumentTypeError("ports must be comma-separated integers, e.g. 80,443")
    if not ports:
        raise argparse.ArgumentTypeError("at least one port required")
    for p in ports:
        if not (1 <= p <= 65535):
            raise argparse.ArgumentTypeError(f"invalid port: {p}")
    return ports


def main() -> None:
    ap = argparse.ArgumentParser(description="Bunny origin protection (nftables-only)")
    ap.add_argument("--table", default=DEFAULT_TABLE, help="nftables table name (inet) [default: bop]")
    ap.add_argument("--chain", default=DEFAULT_CHAIN, help="nftables chain name [default: gate]")
    ap.add_argument("--ports", type=parse_ports, default=DEFAULT_PORTS, help="comma-separated TCP ports [default: 80,443]")
    ap.add_argument("--ipv6", choices=["allow", "block"], default="block", help="IPv6 behaviour for ports [default: block]")
    ap.add_argument("--list-file", default=DEFAULT_LIST_FILE, help="optional file to store fetched IPs (debug)")
    ap.add_argument("--dry-run", action="store_true", help="print planned nft script without applying")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run as root (needed for nft).")

    # Ensure nft present
    try:
        import shutil as _sh
        if not _sh.which("nft"):
            sys.exit("'nft' command not found. Install nftables first.")
    except Exception:
        pass

    # Bootstrap table/chain rules (idempotent for our private table)
    bootstrap = render_bootstrap(args.table, args.chain, args.ports, args.ipv6)
    nft_apply(bootstrap, args.dry_run)

    # Fetch edge IPs
    v4, v6 = fetch_bunny_ips()

    # Optionally write a debug snapshot
    try:
        os.makedirs(os.path.dirname(args.list_file), exist_ok=True)
        with open(args.list_file, "w", encoding="utf-8") as f:
            for ip in v4 + v6:
                f.write(ip + "\n")
    except Exception:
        pass

    # Apply set updates atomically
    script = render_set_update(args.table, v4, v6, args.ipv6)
    nft_apply(script, args.dry_run)

    print(f"Applied nftables sets: v4={len(v4)} IPv4 addresses; v6={'blocked' if args.ipv6=='block' else len(v6)}")


if __name__ == "__main__":
    main()
