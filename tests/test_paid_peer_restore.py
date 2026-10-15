"""Paid WireGuard peer restoration with no live server or interface."""
import os
import subprocess
import sys
import tempfile
import unittest


class PaidPeerRestoreTests(unittest.TestCase):
    def test_paid_peer_restore_is_atomic_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["PEGASVPN_DEPLOYMENT"] = "staging"
            env["PEGASVPN_STAGING_DATA_DIR"] = tmp
            script = r"""
import base64
import json
import pathlib
import unittest.mock as mock
import restore_paid as r
import trial_reaper
from peer_records import record_path

root = pathlib.Path(__import__("os").environ["PEGASVPN_STAGING_DATA_DIR"])
user = "11111111-1111-4111-8111-111111111111"
key = base64.b64encode(b"a" * 32).decode()
key2 = base64.b64encode(b"b" * 32).decode()
device = "44444444-4444-4444-8444-444444444444"
(root / (user + ".json")).write_text(json.dumps({
    "user_id": user, "public_key": key, "ip": "10.66.66.10"
}))
nested = record_path(root, user, device)
nested.parent.mkdir(parents=True)
nested.write_text(json.dumps({
    "user_id": user, "device_id": device,
    "public_key": key2, "ip": "10.66.66.11"
}))
r.WG = root / "wg0.conf"
r.LOCK = root / ".lock"
r.WG.write_text("[Interface]\nPrivateKey = test\n")
with (
    mock.patch.object(r, "require_live_wireguard"),
    mock.patch.object(trial_reaper, "require_live_wireguard"),
    mock.patch.object(r, "paid_status", return_value=(True, None)),
    mock.patch.object(r.subprocess, "check_output", return_value=""),
    mock.patch.object(r.subprocess, "run") as wg_set,
):
    r.restore()
    first = r.WG.read_text()
    assert first.count("PublicKey = " + key) == 1
    assert first.count("PublicKey = " + key2) == 1
    assert (root / "wg0.conf").stat().st_mode & 0o777 == 0o600
    r.restore()
    assert r.WG.read_text() == first
    assert wg_set.call_count == 4
print("PAID_PEER_RESTORE_OK")
"""
            proc = subprocess.run(
                [sys.executable, "-c", script],
                env=env, capture_output=True, text=True, timeout=20
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("PAID_PEER_RESTORE_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
