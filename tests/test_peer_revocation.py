"""Offline WireGuard peer reaper tests. All files live in a temporary dir."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class PeerRevocationTests(unittest.TestCase):
    def test_expired_peer_removed_but_paid_peer_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["PEGASVPN_DEPLOYMENT"] = "staging"
            env["PEGASVPN_STAGING_DATA_DIR"] = tmp
            script = r"""
import base64
import json
import pathlib
import unittest.mock as mock
import trial_reaper as r
from peer_records import record_path

root = pathlib.Path(__import__("os").environ["PEGASVPN_STAGING_DATA_DIR"])
expired = "11111111-1111-4111-8111-111111111111"
paid = "22222222-2222-4222-8222-222222222222"
bad = "33333333-3333-4333-8333-333333333333"
key1 = base64.b64encode(b"a" * 32).decode()
key2 = base64.b64encode(b"b" * 32).decode()
key3 = base64.b64encode(b"c" * 32).decode()
device = "44444444-4444-4444-8444-444444444444"
for user, key, ip in (
    (expired, key1, "10.66.66.10"),
    (paid, key2, "10.66.66.11"),
    (bad, key1, "192.0.2.1"),
):
    (root / (user + ".json")).write_text(json.dumps({
        "user_id": user, "public_key": key, "ip": ip
    }))
nested = record_path(root, expired, device)
nested.parent.mkdir(parents=True)
nested.write_text(json.dumps({
    "user_id": expired, "device_id": device,
    "public_key": key3, "ip": "10.66.66.12"
}))
assert r.valid_peer_record(nested, json.loads(nested.read_text()))
assert r.valid_peer_record(root / (expired + ".json"),
                           json.loads((root / (expired + ".json")).read_text()))
assert not r.valid_peer_record(root / (bad + ".json"),
                               json.loads((root / (bad + ".json")).read_text()))
assert not r.valid_peer_record(root / "wrong-name.json", {
    "user_id": expired, "public_key": key1, "ip": "10.66.66.10"
})
r.WG = root / "wg0.conf"
r.LOCK = root / ".lock"
r.WG.write_text(
    "[Interface]\nPrivateKey = test\n"
    + "[Peer]\nPublicKey = " + key1
    + "\nAllowedIPs = 10.66.66.10/32\n"
    + "[Peer]\nPublicKey = " + key2
    + "\nAllowedIPs = 10.66.66.11/32\n"
    + "[Peer]\nPublicKey = " + key3
    + "\nAllowedIPs = 10.66.66.12/32\n"
)
with (
    mock.patch.object(r, "require_live_wireguard"),
    mock.patch.object(r, "trial_status", side_effect=lambda u: {
        "has_access": u == paid
    }),
    mock.patch.object(r.subprocess, "check_output", return_value=key1 + "\n" + key2 + "\n" + key3),
    mock.patch.object(r.subprocess, "run") as wg_set,
):
    r.run()
    assert wg_set.call_count == 2
    commands = [call.args[0] for call in wg_set.call_args_list]
    assert ["wg", "set", "wg0", "peer", key1, "remove"] in commands
    assert ["wg", "set", "wg0", "peer", key3, "remove"] in commands
result = r.WG.read_text()
assert key1 not in result
assert key3 not in result
assert key2 in result
print("PEER_REVOCATION_OK")
"""
            proc = subprocess.run(
                [sys.executable, "-c", script],
                env=env, capture_output=True, text=True, timeout=20
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("PEER_REVOCATION_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
