#!/usr/bin/env bash
# Safe uninstall: stops services, removes ONLY Averqon firewall objects, then files.
#   sudo ./scripts/uninstall.sh [--purge]    (--purge also deletes config, database and the averqon user)
set -uo pipefail
PURGE=0; [ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
systemctl disable --now averqon-dashboard averqon-daemon averqon-api averqon-executor 2>/dev/null
if [ -x /usr/local/sbin/averqon-emergency-disable ]; then /usr/local/sbin/averqon-emergency-disable; fi
rm -f /etc/systemd/system/averqon-{executor,api,daemon,dashboard}.service /etc/sysctl.d/99-averqon.conf \
      /usr/local/bin/averqon /usr/local/sbin/averqon-emergency-disable
systemctl daemon-reload
rm -rf /opt/averqon /run/averqon
if [ "$PURGE" = 1 ]; then
  rm -rf /etc/averqon /var/lib/averqon
  id -u averqon >/dev/null 2>&1 && userdel averqon 2>/dev/null
  getent group averqon >/dev/null && groupdel averqon 2>/dev/null
  echo "purged configuration, data and service account"
else
  echo "kept /etc/averqon and /var/lib/averqon (use --purge to delete them)"
fi
echo "Averqon removed. Host firewall rules were not modified."
