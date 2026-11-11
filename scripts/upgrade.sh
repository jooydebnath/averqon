#!/usr/bin/env bash
# Upgrade Averqon in place: backup -> install -> migrate -> restart, with rollback on failure.
set -euo pipefail
PREFIX=/opt/averqon; CONF=/etc/averqon; STATE=/var/lib/averqon
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -x "$PREFIX/venv/bin/pip" ] || { echo "Averqon is not installed; use install.sh" >&2; exit 1; }
TS="$(date -u +%Y%m%dT%H%M%SZ)"; BK="$STATE/upgrade-backup-$TS"
install -d -m 0700 "$BK"
cp -a "$CONF" "$BK/etc"
[ -f "$STATE/averqon.db" ] && cp -a "$STATE/averqon.db" "$BK/averqon.db"
"$PREFIX/venv/bin/averqon" backup --config "$CONF/averqon.yaml" >/dev/null 2>&1 || true
"$PREFIX/venv/bin/pip" freeze > "$BK/requirements.txt"
echo "backup written to $BK"

rollback() {
  echo "upgrade FAILED, rolling back" >&2
  "$PREFIX/venv/bin/pip" install -r "$BK/requirements.txt" >/dev/null 2>&1 || true
  [ -f "$BK/averqon.db" ] && cp -a "$BK/averqon.db" "$STATE/averqon.db"
  systemctl restart averqon-executor averqon-api averqon-daemon 2>/dev/null || true
  exit 1
}
trap rollback ERR
systemctl stop averqon-daemon averqon-api 2>/dev/null || true
"$PREFIX/venv/bin/pip" install --upgrade "$SRC"
"$PREFIX/venv/bin/averqon" init-db --config "$CONF/averqon.yaml"
for u in executor api daemon dashboard; do install -m 0644 "$SRC/deploy/systemd/averqon-$u.service" "/etc/systemd/system/averqon-$u.service"; done
systemctl daemon-reload
systemctl restart averqon-executor
sleep 2
systemctl is-active --quiet averqon-executor
systemctl start averqon-api averqon-daemon
systemctl is-active --quiet averqon-api
trap - ERR
echo "upgrade complete (backup kept in $BK)"
