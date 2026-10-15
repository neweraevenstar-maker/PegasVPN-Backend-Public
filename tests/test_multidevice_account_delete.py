"""Deleting an account revokes every WireGuard device peer offline."""
import os
import subprocess
import sys
import tempfile
import unittest


class MultiDeviceDeletionTests(unittest.TestCase):
    def test_account_delete_removes_legacy_and_device_peers(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["PEGASVPN_DEPLOYMENT"] = "staging"
            env["PEGASVPN_STAGING_DATA_DIR"] = tmp
            script = r"""
import base64
import json
import pathlib
import sqlite3
import uuid
import unittest.mock as mock
import account_delete as a
import trial_reaper
from peer_records import record_path

root = pathlib.Path(__import__("os").environ["PEGASVPN_STAGING_DATA_DIR"])
user = str(uuid.uuid4())
device = str(uuid.uuid4())
key1 = base64.b64encode(b"a" * 32).decode()
key2 = base64.b64encode(b"b" * 32).decode()
records = [
    (record_path(root, user), key1, "10.66.66.10", None),
    (record_path(root, user, device), key2, "10.66.66.11", device),
]
for path, key, ip, device_id in records:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "user_id": user, "device_id": device_id,
        "public_key": key, "ip": ip
    }))
a.WG = root / "wg0.conf"
a.WG.write_text(
    "[Interface]\nPrivateKey = test\n"
    + "[Peer]\nPublicKey = " + key1
    + "\nAllowedIPs = 10.66.66.10/32\n"
    + "[Peer]\nPublicKey = " + key2
    + "\nAllowedIPs = 10.66.66.11/32\n"
)
with sqlite3.connect(a.DB_PATH) as db:
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, account_type TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP, is_active INTEGER DEFAULT 1
    )''')
    db.execute(
        "INSERT INTO users(id, account_type) VALUES (?, 'guest')", (user,)
    )

with (
    mock.patch.object(a, "require_live_wireguard"),
    mock.patch.object(trial_reaper, "require_live_wireguard"),
    mock.patch.object(a.subprocess, "check_output", return_value=key1 + "\n" + key2),
    mock.patch.object(a.subprocess, "run") as wg_set,
):
    result = a.erase_account(user)
    assert result["deleted"] is True
    assert wg_set.call_count == 2

assert not any(path.exists() for path, *_ in records)
assert key1 not in a.WG.read_text()
assert key2 not in a.WG.read_text()
with sqlite3.connect(a.DB_PATH) as db:
    assert db.execute(
        "SELECT COUNT(*) FROM users WHERE id=?", (user,)
    ).fetchone()[0] == 0
print("MULTI_DEVICE_DELETE_OK")
"""
            proc = subprocess.run(
                [sys.executable, "-c", script],
                env=env, capture_output=True, text=True, timeout=20
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("MULTI_DEVICE_DELETE_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
