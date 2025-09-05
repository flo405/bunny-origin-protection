#!/usr/bin/env python3
"""
BOP — Bunny.net Origin Protection

Fetches Bunny.net edge server IPs and manages iptables rules so that
only those IPs can reach TCP port 443 (HTTPS) on this host.

Behaviour:
  1) Downloads IP list from https://bunnycdn.com/api/system/edgeserverlist
  2) Stores the list locally (one IP per line) at --list-file
  3) Compares with previous run; if there are changes, updates iptables:
     - Ensures a custom chain (default: BOP_HTTPS) exists
     - Ensures INPUT has a jump rule to that chain for tcp dport 443
     - Ensures ACCEPT rules for each Bunny IP in that chain
     - Ensures a final DROP rule in that chain to block all other sources

Notes:
  * Requires root privileges to manipulate iptables.
  * Designed for classic iptables (v4). If your system uses nftables,
    consider adapting to `nft` or iptables-nft accordingly.
  * Idempotent: safe to run repeatedly (eg. via cron).

Examples:
  sudo ./bop.py
  sudo ./bop.py --dry-run
  sudo ./bop.py --port 443 --chain BOP_HTTPS --list-file /var/lib/bop/bunny_edges.txt
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shlex
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from typing import Iterable, List, Set
import json

EDGE_URL = "https://bunnycdn.com/api/system/edgeserverlist"
DEFAULT_LIST_FILE = "/var/lib/bop/bunny_edges.txt"
DEFAULT_CHAIN = "BOP_HTTPS"
DEFAULT_PORT = 443

class Shell:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.iptables_bin = self._find_bin(["iptables"])  # classic v4

    def _find_bin(self, names: List[str]) -> str:
        # Try PATH and common sbin locations
        for name in names:
            path = shutil.which(name) if 'shutil' in globals() else None
            if not path:
                # Lazy import (keeps imports tidy at top but optional here)
                import shutil as _sh
                path = _sh.which(name)
            if path:
                return path
        # Fallback to bare name; let exec fail with good error
        return names[0]

    def run(self, args: List[str], check: bool = True) -> subprocess.CompletedProcess:
        cmd = args
        if self.dry_run:
            print(f"DRY-RUN: {' '.join(shlex.quote(a) for a in cmd)}")
            # Simulate a successful process
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"Command failed ({proc.returncode}): {' '.join(cmd)}\nSTDERR: {proc.stderr.decode(errors='ignore')}"
            )
        return proc

    def ipt(self, *iptables_args: str, check: bool = True) -> subprocess.CompletedProcess:
        return self.run([self.iptables_bin, *iptables_args], check=check)

    def ipt_exists(self, *iptables_args: str) -> bool:
        # iptables -C returns 0 if rule exists, nonzero otherwise
        proc = self.ipt(*iptables_args, check=False)
        return proc.returncode == 0

    def ipt_chain_exists(self, chain: str) -> bool:
        proc = self.ipt("-S", chain, check=False)
        return proc.returncode == 0


def fetch_bunny_ips() -> List[str]:
    """
    Fetch Bunny edge IPs robustly (XML or JSON), with graceful fallbacks.
    """
    urls = [
        "https://bunnycdn.com/api/system/edgeserverlist",
        "https://api.bunny.net/system/edgeserverlist",
    ]
    headers = {
        "User-Agent": "bop/1.1",
        "Accept": "application/xml, text/xml, application/json;q=0.9, */*;q=0.1",
    }
    last_error = None
    preview = ""

    for url in urls:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                ctype = (resp.headers.get("Content-Type") or "").lower()

            text = raw.decode("utf-8", errors="replace").lstrip("\ufeff").strip()
            preview = text[:160]
            ips: Set[str] = set()

            def try_add(seq: Iterable[str]) -> None:
                for s in seq:
                    if not s:
                        continue
                    s = str(s).strip()
                    try:
                        ipaddress.ip_address(s)
                        ips.add(s)
                    except ValueError:
                        pass

            # JSON branch
            if "json" in ctype or (text[:1] in "[{]"):
                try:
                    obj = json.loads(text)
                    if isinstance(obj, list):
                        try_add(obj)
                    elif isinstance(obj, dict) and isinstance(obj.get("items"), list):
                        try_add(obj["items"])
                except Exception as e:
                    last_error = e

            # XML branch
            if not ips and ("xml" in ctype or text.startswith("<")):
                try:
                    root = ET.fromstring(text)
                    try_add([el.text for el in root.iter() if getattr(el, "text", None)])
                except Exception as e:
                    last_error = e

            # Fallback: grab any IP-ish tokens from text/HTML
            if not ips and text:
                for m in re.finditer(r"(?:\b\d{1,3}(?:\.\d{1,3}){3}\b)|(?:\b[0-9A-Fa-f:]{3,}\b)", text):
                    s = m.group(0)
                    try:
                        ipaddress.ip_address(s)
                        ips.add(s)
                    except ValueError:
                        pass

            if ips:
                v4 = [ip for ip in ips if "." in ip]  # IPv4 only by default
                return sorted(v4, key=lambda s: tuple(int(x) for x in s.split(".")))
        except Exception as e:
            last_error = e
            continue

    raise RuntimeError(f"Could not retrieve/parse edge IPs. Last error: {last_error}; preview: {preview!r}")


def read_local_ips(path: str) -> Set[str]:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def write_local_ips(path: str, ips: Iterable[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="bop_ips_", text=True)
    try:
        with os.fdopen(tmp_fd, 'w', encoding='utf-8') as f:
            for ip in sorted(set(ips)):
                f.write(ip + "\n")
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        raise


class FirewallManager:
    def __init__(self, shell: Shell, chain: str, port: int):
        self.sh = shell
        self.chain = chain
        self.port = port

    def ensure_chain_and_jump(self) -> None:
        # Create chain if needed
        if not self.sh.ipt_chain_exists(self.chain):
            self.sh.ipt("-N", self.chain)
        # Ensure INPUT jump exists for tcp --dport port
        jump_rule = [
            "-C", "INPUT", "-p", "tcp", "--dport", str(self.port), "-j", self.chain
        ]
        if not self.sh.ipt_exists(*jump_rule):
            # Insert near top to run early
            self.sh.ipt("-I", "INPUT", "1", "-p", "tcp", "--dport", str(self.port), "-j", self.chain)

    def _strip_trailing_drops(self) -> None:
        # Remove any existing unconditional -j DROP in our chain so we can re-append once at the end
        rules = self.sh.ipt("-S", self.chain).stdout.decode()
        for line in rules.splitlines():
            if not line.startswith(f"-A {self.chain} "):
                continue
            if re.search(r"\s-j\s+DROP(\s|$)", line):
                # Delete matching DROP rule
                parts = line.split()[2:]  # drop '-A CHAIN'
                self.sh.ipt("-D", self.chain, *parts)

    def ensure_final_drop(self) -> None:
        # Ensure a final DROP exists and is last
        self._strip_trailing_drops()
        self.sh.ipt("-A", self.chain, "-j", "DROP")

    def rule_for_ip_exists(self, ip: str) -> bool:
        return self.sh.ipt_exists("-C", self.chain, "-s", ip, "-j", "ACCEPT")

    def add_ip(self, ip: str) -> None:
        # Insert at top so it precedes the final DROP
        if not self.rule_for_ip_exists(ip):
            self.sh.ipt("-I", self.chain, "1", "-s", ip, "-j", "ACCEPT")

    def remove_ip(self, ip: str) -> None:
        # Attempt delete; if not present, ignore
        self.sh.ipt("-D", self.chain, "-s", ip, "-j", "ACCEPT", check=False)

    def sync(self, wanted_ips: Iterable[str], previous_ips: Iterable[str]) -> None:
        wanted = list(dict.fromkeys(wanted_ips))  # preserve order
        prev = set(previous_ips)
        add = [ip for ip in wanted if ip not in prev]
        remove = [ip for ip in prev if ip not in set(wanted)]

        if add:
            print(f"Adding {len(add)} IP(s): {', '.join(add)}")
        if remove:
            print(f"Removing {len(remove)} IP(s): {', '.join(remove)}")

        # Ensure chain and jump exist before modifying rules
        self.ensure_chain_and_jump()

        # Add new allows first
        for ip in add:
            self.add_ip(ip)
        # Remove stale allows
        for ip in remove:
            self.remove_ip(ip)

        # Ensure there's a final DROP for anything not matched
        self.ensure_final_drop()


def require_root():
    if os.geteuid() != 0:
        sys.exit("This script must be run as root to modify iptables.")


def main():
    parser = argparse.ArgumentParser(description="Bunny.net Origin Protection (iptables manager)")
    parser.add_argument("--list-file", default=DEFAULT_LIST_FILE, help="Path to store the fetched IP list (default: %(default)s)")
    parser.add_argument("--chain", default=DEFAULT_CHAIN, help="iptables chain to manage (default: %(default)s)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP port to protect (default: %(default)s)")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without changing iptables or files")

    args = parser.parse_args()

    if not args.dry_run:
        require_root()

    # 1) Fetch remote IPs
    try:
        remote_ips = fetch_bunny_ips()
    except Exception as e:
        sys.exit(f"Failed to fetch Bunny edge IPs: {e}")

    if not remote_ips:
        sys.exit("No valid IPs retrieved from Bunny endpoint; aborting.")

    # 2) Read local snapshot
    local_ips = read_local_ips(args.list_file)

    # 3) If changed, update firewall
    shell = Shell(dry_run=args.dry_run)
    fw = FirewallManager(shell, args.chain, args.port)
    fw.sync(remote_ips, local_ips)

    # 4) Persist new list
    if args.dry_run:
        print(f"DRY-RUN: would write {len(remote_ips)} IPs to {args.list_file}")
    else:
        write_local_ips(args.list_file, remote_ips)
        print(f"Wrote {len(remote_ips)} IPs to {args.list_file}")
        print("Done.")


if __name__ == "__main__":
    main()
