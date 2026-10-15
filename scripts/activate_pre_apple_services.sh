#!/usr/bin/env bash
# Pre-Apple timers: do not run until backend v2 is deployed and reviewed.
set -Eeuo pipefail
umask 077
ROOT=/opt/onetapvpn-api
SYSTEMD=/etc/systemd/system
ENVFILE=/etc/onetapvpn/pegasvpn.env
if [[ ${1:-} != --check && ${1:-} != --apply ]] || [[ $# != 1 ]]; then
  echo "Usage: activate_pre_apple_services.sh --check|--apply" >&2
  exit 2
fi
[[ "$(id -u)" == 0 ]] || { echo "root required" >&2; exit 2; }
[[ -f "$ENVFILE" && ! -L "$ENVFILE" ]] || {
  echo "Private server env file missing" >&2; exit 2;
}
[[ "$(stat -c %a "$ENVFILE")" =~ ^[0-6]00$ ]] || {
  echo "Environment file must be owner-only" >&2; exit 2;
}
[[ -x "$ROOT/.venv/bin/python" ]] || exit 2
[[ -f "$ROOT/data/pegasvpn.db" && -f /etc/wireguard/wg0.conf ]] || exit 2
[[ -f "$ROOT/systemd/pegasvpn-peer-sync.service" ]] || exit 2
[[ -f "$ROOT/systemd/pegasvpn-retention.service" ]] || exit 2
[[ -f "$ROOT/systemd/pegasvpn-peer-sync.timer" ]] || exit 2
[[ -f "$ROOT/systemd/pegasvpn-retention.timer" ]] || exit 2
"$ROOT/.venv/bin/python" - "$ROOT/data/pegasvpn.db" <<'PY'
import sqlite3, sys
db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro', uri=True)
try:
    assert db.execute(
        "SELECT 1 FROM schema_migrations WHERE migration_id='001_release'"
    ).fetchone(), "Release schema migration missing"
finally:
    db.close()
PY
echo "Pre-Apple service prerequisites: present"
if [[ "$1" == --check ]]; then
  echo "No timers installed or activated"
  exit 0
fi
[[ "${PEGASVPN_CONFIRM_TIMERS:-}" == I_APPROVE_PEER_REVOCATION_TIMER ]] || {
  echo "Explicit timer approval required" >&2; exit 2;
}
for name in pegasvpn-peer-sync pegasvpn-retention; do
  install -m 0644 "$ROOT/systemd/$name.service" "$SYSTEMD/$name.service"
  install -m 0644 "$ROOT/systemd/$name.timer" "$SYSTEMD/$name.timer"
done
systemctl daemon-reload
systemctl enable --now pegasvpn-peer-sync.timer pegasvpn-retention.timer
systemctl is-active --quiet pegasvpn-peer-sync.timer
systemctl is-active --quiet pegasvpn-retention.timer
echo "Pre-Apple timers enabled. Apple billing reconciliation remains disabled."
