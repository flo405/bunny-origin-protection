#!/bin/sh
set -eu
# setup-bop.sh — Installer for Bunny Origin Protection (nftables-only)
# - Installs requirements (nftables, python3, curl/wget)
# - Downloads bop-nft.py and installs to /usr/local/bin/bop-nft
# - Creates nftables table/chain via first run
# - Sets up systemd timer (preferred) or cron fallback
# - Saves & restores nft ruleset on uninstall
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/flo405/bunny-origin-protection/refs/heads/main/setup-bop.sh | sudo sh
#   curl -fsSL .../setup-bop.sh | sudo sh -s -- --ports 80,443 --ipv6 block --refresh 10
#   curl -fsSL .../setup-bop.sh | sudo sh -s -- --uninstall

BOP_URL="https://raw.githubusercontent.com/flo405/bunny-origin-protection/refs/heads/main/bop-nft.py"
INSTALL_DIR="/usr/local/bin"
DEST_NAME="bop-nft"
STATE_DIR="/var/lib/bop"
LIST_FILE="$STATE_DIR/bunny_edges.txt"
REFRESH_MIN=10
PORTS="80,443"
IPV6_MODE="block"   # "allow" to allowlist v6; "block" to drop all v6 to ports
DRY_RUN=0
UNINSTALL=0

say()  { printf "==> %s\n" "$*" 1>&2; }
warn() { printf "[warn] %s\n" "$*" 1>&2; }
err()  { printf "[err] %s\n" "$*" 1>&2; }
run()  { if [ "$DRY_RUN" -eq 1 ]; then printf 'DRY-RUN: %s\n' "$*" 1>&2; else "$@"; fi; }

need_root() { [ "$(id -u)" -eq 0 ] || { err "Run as root (sudo)."; exit 1; }; }

usage() {
  cat <<USAGE
Options:
  --ports X,Y       TCP ports to protect (default: 80,443)
  --ipv6 MODE       'allow' or 'block' (default: block)
  --refresh MIN     Refresh interval in minutes (default: 10)
  --dry-run         Print actions without changing the system
  --uninstall       Remove files and restore nft ruleset snapshot
USAGE
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --ports) PORTS="$2"; shift 2;;
      --ipv6) IPV6_MODE="$2"; shift 2;;
      --refresh) REFRESH_MIN="$2"; shift 2;;
      --dry-run) DRY_RUN=1; shift;;
      --uninstall) UNINSTALL=1; shift;;
      -h|--help) usage; exit 0;;
      *) err "Unknown arg: $1"; usage; exit 2;;
    esac
  done
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
    apt)    run apt-get update -y; run apt-get install -y "$@" ;;
    dnf)    run dnf install -y "$@" ;;
    yum)    run yum install -y "$@" ;;
    zypper) run zypper -n install "$@" ;;
    pacman) run pacman -Sy --noconfirm "$@" ;;
    apk)    run apk add --no-cache "$@" ;;
    *) warn "Install these manually: nftables python3 curl (or wget)" ;;
  esac
}

ensure_reqs() {
  say "Ensuring requirements"
  # nftables
  if ! command -v nft >/dev/null 2>&1; then
    say "Installing nftables"
    case "$PKG" in
      apt|dnf|yum|zypper|pacman|apk) pkg_install nftables || true ;;
    esac
  fi
  command -v nft >/dev/null 2>&1 || { err "nft not found after install."; exit 1; }
  # python3
  command -v python3 >/dev/null 2>&1 || pkg_install python3 || true
  command -v python3 >/dev/null 2>&1 || { err "python3 not found after install."; exit 1; }
  # fetch
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    pkg_install curl || pkg_install wget || true
  fi
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    err "Neither curl nor wget is available."; exit 1
  fi
}

backup_nft() {
  run install -d -m 0755 "$STATE_DIR"
  if [ ! -s "$STATE_DIR/backup.nft" ]; then
    say "Saving nft ruleset snapshot"
    if [ "$DRY_RUN" -eq 1 ]; then
      say "Would: nft list ruleset > $STATE_DIR/backup.nft"
    else
      nft list ruleset > "$STATE_DIR/backup.nft" || warn "could not save nft ruleset"
    fi
  else
    say "Existing snapshot found at $STATE_DIR/backup.nft"
  fi
}

restore_nft() {
  if ! command -v nft >/dev/null 2>&1; then
    warn "nft not found; cannot restore nftables snapshot"
    return 0
  fi
  if [ -s "$STATE_DIR/backup.nft" ]; then
    say "Restoring nft ruleset snapshot"
    if [ "$DRY_RUN" -eq 1 ]; then
      say "Would: flush ruleset then apply $STATE_DIR/backup.nft"
    else
      # avoid duplicate object errors: flush entire ruleset first
      TMP=$(mktemp -t boprestore.XXXXXX) || { err "mktemp failed"; return 1; }
      printf 'flush ruleset\n' > "$TMP"
      cat "$STATE_DIR/backup.nft" >> "$TMP"
      nft -f "$TMP" || warn "restore failed"
      rm -f "$TMP"
    fi
  else
    warn "No snapshot found; best-effort cleanup only"
    # remove our table if present
    nft delete table inet bop 2>/dev/null || nft flush table inet bop 2>/dev/null || true
  fi
}

download_bop() {
  tmp=`mktemp -t bopnft.XXXXXXXX` || { err "mktemp failed"; exit 1; }
  say "Downloading bop-nft from: $BOP_URL"
  if command -v curl >/dev/null 2>&1; then
    if [ "$DRY_RUN" -eq 1 ]; then
      say "Would: curl -fsSL $BOP_URL -o $tmp"
    else
      curl -fsSL "$BOP_URL" -o "$tmp" || { rm -f "$tmp"; err "download failed"; exit 1; }
    fi
  else
    if [ "$DRY_RUN" -eq 1 ]; then
      say "Would: wget -qO $tmp $BOP_URL"
    else
      wget -qO "$tmp" "$BOP_URL" || { rm -f "$tmp"; err "download failed"; exit 1; }
    fi
  fi
  printf '%s\n' "$tmp"
}

install_files() {
  f=`download_bop`
  run install -d -m 0755 "$INSTALL_DIR"
  run install -m 0755 "$f" "$INSTALL_DIR/$DEST_NAME"
  [ "$DRY_RUN" -eq 1 ] || rm -f "$f"
  say "Installed: $INSTALL_DIR/$DEST_NAME"
}

write_systemd() {
  if ! command -v systemctl >/dev/null 2>&1; then
    say "systemd not detected; will use cron"
    return 1
  fi
  say "Installing systemd units"
  SVC=/etc/systemd/system/bop-nft.service
  TMR=/etc/systemd/system/bop-nft.timer
  umask 022
  if [ "$DRY_RUN" -eq 1 ]; then
    say "Would write $SVC and $TMR"
  else
    cat > "$SVC" <<EOF
[Unit]
Description=Bunny origin protection (nftables)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/$DEST_NAME --ports $PORTS --ipv6 $IPV6_MODE --list-file $LIST_FILE

[Install]
WantedBy=multi-user.target
EOF
    cat > "$TMR" <<EOF
[Unit]
Description=Refresh bunny edge IPs (nftables)

[Timer]
OnBootSec=2min
OnUnitActiveSec=${REFRESH_MIN}min
Unit=bop-nft.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now bop-nft.timer
  fi
  return 0
}

write_cron() {
  say "Installing cron schedule"
  CRON=/etc/cron.d/bop-nft
  LINE="*/$REFRESH_MIN * * * * root $INSTALL_DIR/$DEST_NAME --ports $PORTS --ipv6 $IPV6_MODE --list-file $LIST_FILE >> /var/log/bop-nft.log 2>&1"
  if [ "$DRY_RUN" -eq 1 ]; then
    say "Would write $CRON"; printf '%s\n' "$LINE" 1>&2
  else
    umask 022
    printf '%s\n' "$LINE" > "$CRON"
    chmod 0644 "$CRON"
  fi
}

first_apply() {
  say "Applying rules now"
  if [ "$DRY_RUN" -eq 1 ]; then
    say "Would run: $INSTALL_DIR/$DEST_NAME --ports $PORTS --ipv6 $IPV6_MODE --list-file $LIST_FILE"
  else
    "$INSTALL_DIR/$DEST_NAME" --ports "$PORTS" --ipv6 "$IPV6_MODE" --list-file "$LIST_FILE"
  fi
}

uninstall() {
  say "Uninstalling"
  # stop schedulers first so they don't re-apply rules mid-restore
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now bop-nft.timer 2>/dev/null || true
    systemctl disable --now bop-nft.service 2>/dev/null || true
    rm -f /etc/systemd/system/bop-nft.timer /etc/systemd/system/bop-nft.service
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -f /etc/cron.d/bop-nft

  # proactively drop our table to avoid conflicts; then restore snapshot
  if command -v nft >/dev/null 2>&1; then
    nft delete table inet bop 2>/dev/null || nft flush table inet bop 2>/dev/null || true
  fi
  restore_nft

  # remove binaries
  rm -f "$INSTALL_DIR/$DEST_NAME"
  say "Uninstall complete."
}


main() {
  need_root
  parse_args "$@"
  find_pkg_manager
  ensure_reqs
  if [ "$UNINSTALL" -eq 1 ]; then
    uninstall
    exit 0
  fi
  backup_nft
  install_files
  first_apply
  if ! write_systemd; then
    write_cron
  fi
  say "Installation complete. Ports: $PORTS | IPv6: $IPV6_MODE | Refresh: ${REFRESH_MIN}m"
}

main "$@"
