#!/bin/sh
# Emergency recovery: remove ONLY Averqon-owned firewall objects. Needs no Python, no database, no API.
# Safe to run any time, as often as needed. Host/admin rules are never touched.
set -u
TABLE="${AVERQON_TABLE:-averqon}"
case "$TABLE" in *[!a-z0-9_]*|"") echo "invalid table name" >&2; exit 2;; esac
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

if command -v nft >/dev/null 2>&1; then
  printf 'add table inet %s\ndelete table inet %s\n' "$TABLE" "$TABLE" | nft -f - && echo "nft: table inet $TABLE removed"
fi
for ipt in iptables ip6tables; do
  command -v "$ipt" >/dev/null 2>&1 || continue
  for pair in "INPUT AVERQON-IN" "OUTPUT AVERQON-OUT"; do
    set -- $pair
    while "$ipt" -D "$1" -j "$2" 2>/dev/null; do :; done
    "$ipt" -F "$2" 2>/dev/null
    "$ipt" -X "$2" 2>/dev/null
  done
  echo "$ipt: AVERQON-* chains removed"
done
echo "Averqon firewall objects removed. Restart averqon-executor to re-apply the stored policy."
