#!/usr/bin/env bash
# Source-only template: NEVER runs without explicit production confirmation.
set -Eeuo pipefail
umask 077

if [[ ${1:-} != --apply || $# -ne 3 ]]; then
  echo "Usage: deploy_backend.sh --apply /absolute/checkout api.service" >&2
  exit 2
fi
SOURCE="$(realpath "$2")"
SERVICE="$3"
TARGET=/opt/onetapvpn-api
BACKUPS=/var/backups/pegasvpn
[[ "$SERVICE" =~ ^[A-Za-z0-9_.@-]+\.service$ ]] || exit 2
[[ "$SOURCE" = /* && "$SOURCE" != "$TARGET" && "$SOURCE" != "$TARGET/"* ]] || exit 2
[[ -f "$SOURCE/main.py" && -f "$SOURCE/db_migrations.py" ]] || exit 2
[[ "${PEGASVPN_DEPLOYMENT:-}" == production ]] || exit 2
# Pre-Apple releases must preserve existing guest access. Never deploy
# sandbox billing on the live VPN; Apple-only policy is activated later.
[[ "${PEGASVPN_BILLING_ENV:-production}" != sandbox ]] || exit 2
[[ "${PEGASVPN_CONFIRM_CLIENT_KEY_V2_ROLLOUT:-}" == I_HAVE_A_COMPATIBLE_CLIENT ]] || {
  echo "Refusing backend-only rollout: new iOS client public-key protocol required" >&2
  exit 2
}
[[ "${PEGASVPN_CONFIRM_PRODUCTION_DEPLOY:-}" == I_APPROVE_PEGASVPN_DEPLOY ]] || exit 2
[[ -f "$TARGET/data/pegasvpn.db" && -f /etc/wireguard/wg0.conf ]] || exit 2
[[ -f /etc/onetapvpn/pegasvpn.env ]] || {
  echo "Server environment file is missing" >&2
  exit 2
}
[[ -z "${PEGASVPN_DB_PATH:-}" || "${PEGASVPN_DB_PATH}" == "$TARGET/data/pegasvpn.db" ]] || exit 2
command -v rsync >/dev/null
command -v systemctl >/dev/null
mkdir -p -m 700 "$BACKUPS"
BACKUP="$BACKUPS/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -m 700 "$BACKUP"
echo "Backup: $BACKUP"

TIMER_ACTIVE=0
if systemctl is-active --quiet pegasvpn-peer-sync.timer; then TIMER_ACTIVE=1; fi
STOPPED=0
STARTED=0
RESTORING=0
recover() {
  local rc=$?
  trap - ERR
  if [[ "$RESTORING" == 0 ]]; then
    RESTORING=1
    echo "Deployment failed; attempting service recovery. Backup: $BACKUP" >&2
    if [[ "$STOPPED" == 1 ]]; then
      if [[ -f "$BACKUP/code.tgz" ]] && tar -tzf "$BACKUP/code.tgz" >/dev/null 2>&1; then
        tar -C "$TARGET" -xzf "$BACKUP/code.tgz" || true
      fi
      # A database rollback is safe only before successful service start.
      if [[ "$STARTED" == 0 && -f "$BACKUP/pegasvpn.db" ]]; then
        rm -f "$TARGET/data/pegasvpn.db-wal" "$TARGET/data/pegasvpn.db-shm"
        cp -a "$BACKUP/pegasvpn.db" "$TARGET/data/pegasvpn.db" || true
        if [[ -f "$BACKUP/wg0.conf" ]]; then
          cp -a "$BACKUP/wg0.conf" /etc/wireguard/wg0.conf || true
        fi
        if [[ -d "$BACKUP/peer-data" ]]; then
          rsync -a "$BACKUP/peer-data/" "$TARGET/data/" || true
        fi
      fi
      systemctl start "$SERVICE" || true
    fi
    if [[ "$TIMER_ACTIVE" == 1 ]]; then
      systemctl start pegasvpn-peer-sync.timer || true
    fi
  fi
  exit "$rc"
}
trap recover ERR
systemctl stop pegasvpn-peer-sync.timer 2>/dev/null || true
systemctl stop pegasvpn-peer-sync.service 2>/dev/null || true
STOPPED=1
systemctl stop "$SERVICE"

# Preserve the previous code, venv and all non-DB peer metadata.
tar -C "$TARGET" --exclude='./data' -czf "$BACKUP/code.tgz" .
"$TARGET/.venv/bin/python" - "$TARGET/data/pegasvpn.db" "$BACKUP/pegasvpn.db" <<'PY'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as src, sqlite3.connect(sys.argv[2]) as dst:
    src.backup(dst)
    assert dst.execute("PRAGMA integrity_check").fetchone() == ("ok",)
PY
chmod 600 "$BACKUP/pegasvpn.db"
cp -a /etc/wireguard/wg0.conf "$BACKUP/wg0.conf"
mkdir -m 700 "$BACKUP/peer-data"
rsync -a --exclude='pegasvpn.db*' "$TARGET/data/" "$BACKUP/peer-data/"
# Only source code and templates; never copy source data, keys or .env.
rsync -a --include='*/' --include='*.py' --include='*.sh' \
  --include='requirements-auth.txt' --include='*.service' \
  --include='*.timer' --exclude='*' "$SOURCE/" "$TARGET/"
"$TARGET/.venv/bin/python" -m pip install -r "$TARGET/requirements-auth.txt"
PEGASVPN_CONFIRM_PRODUCTION_MIGRATION=I_HAVE_STOPPED_API_AND_BACKED_UP_WIREGUARD \
  "$TARGET/.venv/bin/python" "$TARGET/scripts/migrate_database.py" \
  --apply --expected-mode production --backup-dir "$BACKUP"
systemctl start "$SERVICE"
STARTED=1
systemctl is-active --quiet "$SERVICE"
curl -fsS --max-time 15 https://api.vimvitae.net/health >/dev/null
if [[ "$TIMER_ACTIVE" == 1 ]]; then
  systemctl start pegasvpn-peer-sync.timer
fi
trap - ERR
echo "Code deployed; backup: $BACKUP"
echo "Systemd templates were NOT installed or enabled automatically."
