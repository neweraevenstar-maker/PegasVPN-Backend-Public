#!/usr/bin/env bash
# Restore a saved release. DB/WireGuard restore is opt-in and may discard
# purchases or peer changes made after the backup; never do it implicitly.
set -Eeuo pipefail
umask 077
if [[ $# -lt 3 || $# -gt 4 || "$1" != --apply ]]; then
  echo "Usage: rollback_backend.sh --apply /var/backups/pegasvpn/SNAPSHOT api.service [--restore-data]" >&2
  exit 2
fi
BACKUP="$(realpath "$2")"
SERVICE="$3"
DATA_RESTORE="${4:-}"
[[ "$SERVICE" =~ ^[A-Za-z0-9_.@-]+\.service$ ]] || exit 2
[[ "$BACKUP" == /var/backups/pegasvpn/* ]] || exit 2
[[ -f "$BACKUP/code.tgz" && -f "$BACKUP/pegasvpn.db" ]] || exit 2
[[ -z "$DATA_RESTORE" || "$DATA_RESTORE" == --restore-data ]] || exit 2
[[ "${PEGASVPN_DEPLOYMENT:-}" == production ]] || exit 2
[[ "${PEGASVPN_CONFIRM_PRODUCTION_ROLLBACK:-}" == I_APPROVE_PEGASVPN_ROLLBACK ]] || exit 2
if [[ "$DATA_RESTORE" == --restore-data ]]; then
  [[ "${PEGASVPN_CONFIRM_DATA_LOSS:-}" == I_ACCEPT_POST_BACKUP_DATA_LOSS ]] || exit 2
fi
TARGET=/opt/onetapvpn-api
systemctl stop pegasvpn-peer-sync.timer 2>/dev/null || true
systemctl stop pegasvpn-peer-sync.service 2>/dev/null || true
systemctl stop "$SERVICE"
tar -C "$TARGET" -xzf "$BACKUP/code.tgz"
if [[ "$DATA_RESTORE" == --restore-data ]]; then
  rm -f "$TARGET/data/pegasvpn.db-wal" "$TARGET/data/pegasvpn.db-shm"
  cp -a "$BACKUP/pegasvpn.db" "$TARGET/data/pegasvpn.db"
  cp -a "$BACKUP/wg0.conf" /etc/wireguard/wg0.conf
  rsync -a "$BACKUP/peer-data/" "$TARGET/data/"
fi
systemctl start "$SERVICE"
echo "Code restored. Re-enable the peer-sync timer only after entitlement review."
echo "Backup retained: $BACKUP"
