"""Atomic WireGuard config backups must be private and bounded."""
import os
import subprocess
import sys
import tempfile
import unittest


class WireGuardBackupTests(unittest.TestCase):
    def test_atomic_write_private_backup_and_retention(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.update({
                "PEGASVPN_DEPLOYMENT": "staging",
                "PEGASVPN_STAGING_DATA_DIR": tmp,
            })
            script = r"""
import pathlib
import unittest.mock as mock
import trial_reaper as r
root = pathlib.Path(__import__("os").environ["PEGASVPN_STAGING_DATA_DIR"])
target = root / "wg0.conf"
target.write_text("[Interface]\nPrivateKey = TEST-ONLY\n")
with mock.patch.object(r, "require_live_wireguard"):
    for n in range(14):
        r.save_config(
            "[Interface]\nPrivateKey = TEST-ONLY\n# " + str(n),
            config_path=target,
        )
assert target.read_text().endswith("# 13")
assert target.stat().st_mode & 0o777 == 0o600
backups = list(root.glob("wg0.conf.peer-backup-*"))
assert len(backups) == r.MAX_CONFIG_BACKUPS == 10
assert all(b.stat().st_mode & 0o777 == 0o600 for b in backups)
assert all("PrivateKey = TEST-ONLY" in b.read_text() for b in backups)
print("WIREGUARD_BACKUP_OK")
"""
            result = subprocess.run(
                [sys.executable, "-c", script],
                env=env, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(
                result.returncode, 0, result.stdout + result.stderr
            )
            self.assertIn("WIREGUARD_BACKUP_OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
