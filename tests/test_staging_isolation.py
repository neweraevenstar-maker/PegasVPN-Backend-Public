"""No server needed: verify staging never writes to live VPN paths."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class StagingIsolationTests(unittest.TestCase):
    def test_staging_uses_only_temporary_database_and_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.update({
                "PEGASVPN_DEPLOYMENT": "staging",
                "PEGASVPN_STAGING_DATA_DIR": tmp,
                # Must not override the staging DB even if supplied.
                "PEGASVPN_DB_PATH": "/opt/onetapvpn-api/data/pegasvpn.db",
            })
            script = r"""
from pathlib import Path
import guest_auth, guest_refresh, subscription_entitlements
import trial_access, provision_guard, trial_reaper, restore_paid
import account_delete, billing_account
from runtime_paths import data_dir, db_path, require_live_wireguard
root = Path(__import__("os").environ["PEGASVPN_STAGING_DATA_DIR"])
expected = root / "pegasvpn.db"
assert data_dir() == root
assert db_path() == expected
assert Path(guest_auth.DB_PATH) == expected
assert Path(guest_refresh.DB) == expected
assert Path(subscription_entitlements.DB) == expected
assert Path(trial_access.DB) == expected
assert Path(provision_guard.DB) == expected
assert billing_account.SECRET == root / ".billing_secret"
assert expected.exists()
assert billing_account.SECRET.exists()
for operation in (
    require_live_wireguard,
    trial_reaper.run,
    restore_paid.restore,
    lambda: trial_reaper.save_config("nope"),
    lambda: account_delete.erase_account("11111111-1111-4111-8111-111111111111"),
):
    try:
        operation()
    except RuntimeError as error:
        assert "WireGuard" in str(error)
    else:
        raise AssertionError("Staging operation was not blocked")
print("STAGING_ISOLATION_OK")
"""
            proc = subprocess.run(
                [sys.executable, "-c", script],
                env=env, capture_output=True, text=True,
                timeout=20,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("STAGING_ISOLATION_OK", proc.stdout)
            self.assertTrue((Path(tmp) / "pegasvpn.db").exists())

    def test_missing_staging_directory_fails_closed(self):
        env = os.environ.copy()
        env["PEGASVPN_DEPLOYMENT"] = "staging"
        env.pop("PEGASVPN_STAGING_DATA_DIR", None)
        proc = subprocess.run(
            [sys.executable, "-c",
             "from runtime_paths import data_dir; data_dir()"],
            env=env, capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("PEGASVPN_STAGING_DATA_DIR is required", proc.stderr)


if __name__ == "__main__":
    unittest.main()
