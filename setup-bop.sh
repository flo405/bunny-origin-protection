#!/bin/bash
# setup-bop.sh — POSIX installer for bunny-origin-protection (iptables)
# - Downloads bop.py directly from GitHub
# - Detects OS / Python / iptables
# - Saves current iptables config for easy rollback
# - Installs cron (optional)
# - Uninstall mode restores the saved iptables config and removes files
#
# Usage:
#   sudo ./setup-bop.sh [--install-dir /usr/local/bin] \
#                      [--list-file /var/lib/bop/bunny_edges.txt] \
#                      [--enable-cron] [--cron-schedule "*/10 * * * *"] \
#                      [--url https://.../bop.py] \
#                      [--dry-run]
#   sudo ./setup-bop.sh --uninstall

set -eu

# Defaults
INSTALL_DIR="/usr/local/bin"
DEST_NAME="bop"
LIST_FILE="/var/lib/bop/bunny_edges.txt"
ENABLE_CRON=0
CRON_SCHEDULE="*/10 * * * *"
DRY_RUN=0
UNINSTALL=0
BOP_URL="https://raw.githubusercontent.com/flo405/bunny-origin-protection/refs/heads/main/bop.py"

# Backup locations
STATE_DIR="/var/lib/bop"
BACKUP_V4="$STATE_DIR/iptables.backup.v4"
BACKUP_V6="$STATE_DIR/iptables.backup.v6"

say() { printf "[1;34m==>[0m %s\n" "$*"; }
warn() { printf "[1;33m[warn][0m %s\n" "$*"; }
err() { printf "[1;31m[err][0m %s\n" "$*"; }
run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRY-RUN: ' ; printf '%s ' "$@" ; printf '\n'
  else
    "$@"
  fi
}

usage() {
  cat <<'USAGE'
Usage:
  Install:
    sudo ./setup-bop.sh [--install-dir DIR] [--list-file PATH] \
                        [--enable-cron] [--cron-schedule SPEC] [--url URL] [--dry-run]
  Uninstall:
    sudo ./setup-bop.sh --uninstall

Options:
  --install-dir DIR      Install destination (default: /usr/local/bin)
  --list-file PATH       State file for IPs (default: /var/lib/bop/bunny_edges.txt)
  --enable-cron          Install cron entry to refresh IPs
  --cron-schedule SPEC   Cron spec (default: "*/10 * * * *")
  --url URL              Override bop.py download URL
  --uninstall            Restore iptables from backup and remove installed files
  --dry-run              Print actions without changing the system
  -h, --help             Show this help
USAGE
}

need_root() {
  uid=`id -u`
  if [ "$uid" -ne 0 ]; then
    err "Please run as root (sudo)."
    exit 1
  fi
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --install-dir) INSTALL_DIR="$2"; shift 2;;
      --list-file) LIST_FILE="$2"; shift 2;;
      --enable-cron) ENABLE_CRON=1; shift;;
      --cron-schedule) CRON_SCHEDULE="$2"; shift 2;;
      --url) BOP_URL="$2"; shift 2;;
      --dry-run) DRY_RUN=1; shift;;
      --uninstall) UNINSTALL=1; shift;;
      -h|--help) usage; exit 0;;
      *) err "Unknown arg: $1"; usage; exit 2;;
    esac
  done
}

OS_ID=""; OS_LIKE=""; PKG=""

detect_os() {
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release || true
    OS_ID=${ID:-}
    OS_LIKE=${ID_LIKE:-}
  fi
  say "Detected OS: ID='${OS_ID:-unknown}', ID_LIKE='${OS_LIKE:-unknown}'"
}

find_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then PKG=apt; return; fi
  if command -v dnf >/dev/null 2>&1; then PKG=dnf; return; fi
  if command -v yum >/dev/null 2>&1; then PKG=yum; return; fi
  if command -v zypper >/dev/null 2>&1; then PKG=zypper; return; fi
  if command -v pacman >/dev/null 2>&1; then PKG=pacman; return; fi
  if command -v apk >/dev/null 2>&1; then PKG=apk; return; fi
  PKG=""
}

pkg_install() {
  case "$PKG" in
    apt)
      run apt-get update -y
      run apt-get install -y "$@"
      ;;
    dnf)
      run dnf install -y "$@"
      ;;
    yum)
      run yum install -y "$@"
      ;;
    zypper)
      run zypper -n install "$@"
      ;;
    pacman)
      run pacman -Sy --noconfirm "$@"
      ;;
    apk)
      run apk add --no-cache "$@"
      ;;
    *)
      warn "Unknown package manager. Please install manually: python3 iptables curl( or wget ) cron(ie)"
      ;;
  esac
}

ensure_packages() {
  say "Ensuring required packages are installed"

  if ! command -v python3 >/dev/null 2>&1; then
    say "Installing python3"; pkg_install python3 || true
  fi

  # Fetch tool (curl preferred, fallback wget)
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    say "Installing curl (or wget)"
    case "$PKG" in
      apt|zypper) pkg_install curl || pkg_install wget || true ;;
      pacman|dnf|yum|apk) pkg_install curl || pkg_install wget || true ;;
    esac
  fi

  # Cron if requested
  if [ "$ENABLE_CRON" -eq 1 ]; then
    case "$PKG" in
      apt|zypper) pkg_install cron || true ;;
      pacman|dnf|yum|apk) pkg_install cronie || true ;;
    esac
  fi

  if ! command -v iptables >/dev/null 2>&1; then
    say "Installing iptables"
    case "$PKG" in
      pacman) pkg_install iptables-nft || pkg_install iptables || true ;;
      *) pkg_install iptables || pkg_install iptables-nft || true ;;
    esac
  fi
}

report_python() {
  if command -v python3 >/dev/null 2>&1; then
    PYBIN=`command -v python3`
    PYVER=`$PYBIN -c 'import sys;print(".".join(map(str,sys.version_info[:3])))' 2>/dev/null || echo unknown`
    say "Python: $PYBIN (version $PYVER)"
    MAJOR=`$PYBIN -c 'import sys;print(sys.version_info[0])'`
    MINOR=`$PYBIN -c 'import sys;print(sys.version_info[1])'`
    if [ "$MAJOR" -lt 3 ] || { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 7 ]; }; then
      err "Python >= 3.7 required. Found $PYVER"; exit 1
    fi
  else
    err "python3 not found after attempted install."; exit 1
  fi
}

check_python_packages() {
  say "Verifying Python modules used by bop.py"
  if python3 - <<'PY'
import sys
mods = [
    "argparse","ipaddress","xml.etree.ElementTree","urllib.request",
    "json","re","shlex","subprocess","tempfile","os","sys"
]
missing = []
for m in mods:
    try:
        __import__(m)
    except Exception as e:
        missing.append(f"{m} ({e})")
if missing:
    print("MISSING:" + ", ".join(missing)); sys.exit(1)
print("OK")
PY
  then
    say "All required Python stdlib modules are present (no pip packages needed)."
  else
    err "Missing Python modules detected (listed above). Ensure a complete Python3 installation."; exit 1
  fi
}

report_iptables() {
  if command -v iptables >/dev/null 2>&1; then
    VER=`iptables -V 2>/dev/null || true`
    say "iptables: ${VER:-unknown}"
  else
    err "iptables not found."; exit 1
  fi
}

backup_rules() {
  say "Saving current iptables configuration to $STATE_DIR"
  run install -d -m 0755 "$STATE_DIR"
  if [ ! -s "$BACKUP_V4" ]; then
    if command -v iptables-save >/dev/null 2>&1; then
      if [ "$DRY_RUN" -eq 1 ]; then
        say "Would run: iptables-save > $BACKUP_V4"
      else
        iptables-save > "$BACKUP_V4" || warn "iptables-save failed"
      fi
    fi
  else
    say "Existing IPv4 backup found at $BACKUP_V4 (leaving it untouched)"
  fi
  if command -v ip6tables-save >/dev/null 2>&1; then
    if [ ! -s "$BACKUP_V6" ]; then
      if [ "$DRY_RUN" -eq 1 ]; then
        say "Would run: ip6tables-save > $BACKUP_V6"
      else
        ip6tables-save > "$BACKUP_V6" || warn "ip6tables-save failed"
      fi
    else
      say "Existing IPv6 backup found at $BACKUP_V6 (leaving it untouched)"
    fi
  fi
}

restore_rules() {
  say "Restoring iptables configuration from backup (if available)"
  if [ -s "$BACKUP_V4" ] && command -v iptables-restore >/dev/null 2>&1; then
    if [ "$DRY_RUN" -eq 1 ]; then
      say "Would run: iptables-restore < $BACKUP_V4"
    else
      iptables-restore < "$BACKUP_V4" || warn "iptables-restore (v4) failed"
    fi
  else
    warn "IPv4 backup not found at $BACKUP_V4"
  fi
  if [ -s "$BACKUP_V6" ] && command -v ip6tables-restore >/dev/null 2>&1; then
    if [ "$DRY_RUN" -eq 1 ]; then
      say "Would run: ip6tables-restore < $BACKUP_V6"
    else
      ip6tables-restore < "$BACKUP_V6" || warn "ip6tables-restore (v6) failed"
    fi
  fi
}

download_bop() {
  TMP=`mktemp`
  say "Downloading bop.py from: $BOP_URL"
  if command -v curl >/dev/null 2>&1; then
    if [ "$DRY_RUN" -eq 1 ]; then
      say "Would: curl -fsSL $BOP_URL -o $TMP"
    else
      if ! curl -fsSL "$BOP_URL" -o "$TMP"; then
        rm -f "$TMP"; err "Download failed (curl)."; exit 1
      fi
    fi
  elif command -v wget >/dev/null 2>&1; then
    if [ "$DRY_RUN" -eq 1 ]; then
      say "Would: wget -qO $TMP $BOP_URL"
    else
      if ! wget -qO "$TMP" "$BOP_URL"; then
        rm -f "$TMP"; err "Download failed (wget)."; exit 1
      fi
    fi
  else
    err "Neither curl nor wget available."; exit 1
  fi
  echo "$TMP"
}

install_bop() {
  # Create state dir and backups
  backup_rules

  # Fetch bop.py
  SRC_TMP=`download_bop`

  # Install binary
  run install -d -m 0755 "$INSTALL_DIR"
  DST="$INSTALL_DIR/$DEST_NAME"
  if [ "$DRY_RUN" -eq 1 ]; then
    say "Would install bop to $DST"
  else
    install -m 0755 "$SRC_TMP" "$DST"
  fi
  [ "$DRY_RUN" -eq 1 ] || rm -f "$SRC_TMP"
  say "Installed: $DST"

  # Ensure state dir exists
  run install -d -m 0755 "$STATE_DIR"

  # Defaults file
  DEFAULTS=/etc/default/bop
  if [ "$DRY_RUN" -eq 1 ]; then
    say "Would write $DEFAULTS"
    cat <<EOF
BOP_LIST_FILE="$LIST_FILE"
BOP_CHAIN="BOP_HTTPS"
BOP_PORT=443
EOF
  else
    umask 022
    cat > "$DEFAULTS" <<EOF
BOP_LIST_FILE="$LIST_FILE"
BOP_CHAIN="BOP_HTTPS"
BOP_PORT=443
EOF
    chmod 0644 "$DEFAULTS"
    say "Wrote defaults to $DEFAULTS"
  fi

  # Wrapper
  WRAPPER="$INSTALL_DIR/bop-run"
  if [ "$DRY_RUN" -eq 1 ]; then
    say "Would install wrapper $WRAPPER"
    cat <<'WRAP'
#!/bin/sh
set -eu
DEFAULTS=/etc/default/bop
if [ -f "$DEFAULTS" ]; then . "$DEFAULTS"; fi
exec bop --list-file "${BOP_LIST_FILE:-/var/lib/bop/bunny_edges.txt}" \
         --chain "${BOP_CHAIN:-BOP_HTTPS}" \
         --port "${BOP_PORT:-443}" "$@"
WRAP
  else
    umask 022
    cat > "$WRAPPER" <<'WRAP'
#!/bin/sh
set -eu
DEFAULTS=/etc/default/bop
if [ -f "$DEFAULTS" ]; then . "$DEFAULTS"; fi
exec bop --list-file "${BOP_LIST_FILE:-/var/lib/bop/bunny_edges.txt}" \
         --chain "${BOP_CHAIN:-BOP_HTTPS}" \
         --port "${BOP_PORT:-443}" "$@"
WRAP
    chmod 0755 "$WRAPPER"
    say "Installed helper: $WRAPPER"
  fi
}

setup_cron() {
  if [ "$ENABLE_CRON" -ne 1 ]; then
    say "Cron not enabled (--enable-cron to enable)."
    return 0
  fi
  say "Configuring cron schedule: $CRON_SCHEDULE"
  CRONFILE=/etc/cron.d/bop
  LINE="$CRON_SCHEDULE root $INSTALL_DIR/bop-run >> /var/log/bop.log 2>&1"
  if [ "$DRY_RUN" -eq 1 ]; then
    say "Would write $CRONFILE with:"; printf '%s\n' "$LINE"
  else
    umask 022
    printf '%s\n' "$LINE" > "$CRONFILE"
    chmod 0644 "$CRONFILE"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl enable --now cron.service 2>/dev/null || \
      systemctl enable --now crond.service 2>/dev/null || \
      systemctl enable --now cronie.service 2>/dev/null || true
    fi
    say "Cron installed at $CRONFILE"
  fi
}

remove_files() {
  say "Removing installed files"
  CRONFILE=/etc/cron.d/bop
  [ "$DRY_RUN" -eq 1 ] || rm -f "$CRONFILE"
  [ "$DRY_RUN" -eq 1 ] || rm -f "$INSTALL_DIR/bop-run"
  [ "$DRY_RUN" -eq 1 ] || rm -f "$INSTALL_DIR/$DEST_NAME"
  [ "$DRY_RUN" -eq 1 ] || rm -f /etc/default/bop
  say "Files removed (backups remain in $STATE_DIR)"
}

uninstall() {
  restore_rules
  remove_files
  say "Uninstall complete."
}

main() {
  need_root
  parse_args "$@"
  detect_os
  find_pkg_manager
  say "Using package manager: ${PKG:-none}"
  ensure_packages
  report_python
  check_python_packages
  report_iptables

  if [ "$UNINSTALL" -eq 1 ]; then
    uninstall
  else
    install_bop
    setup_cron
    say "Installation complete. Try: sudo bop --dry-run"
  fi
}

main "$@"
