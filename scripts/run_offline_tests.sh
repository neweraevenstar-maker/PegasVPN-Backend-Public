#!/usr/bin/env bash
# Offline-only regression suite. Never connects to a VPN server.
set -euo pipefail
cd "$(dirname "$0")/.."
export PEGASVPN_DEPLOYMENT=tests
export PEGASVPN_TEST_DATA_DIR
PEGASVPN_TEST_DATA_DIR="$(mktemp -d)"
unset PEGASVPN_DB_PATH
trap 'rm -rf -- "$PEGASVPN_TEST_DATA_DIR"' EXIT
python3 -m pip install -r requirements-auth.txt
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
