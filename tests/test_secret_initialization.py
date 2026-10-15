"""Billing and email OTP secrets must be stable, private and nonempty."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class SecretInitializationTests(unittest.TestCase):
    def test_concurrent_workers_share_stable_billing_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.update({
                "PEGASVPN_DEPLOYMENT": "staging",
                "PEGASVPN_STAGING_DATA_DIR": tmp,
            })
            workers = [
                subprocess.Popen(
                    [sys.executable, "-c",
                     "from billing_account import account_token;"
                     "print(account_token('same-user'))"],
                    env=env, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True,
                )
                for _ in range(3)
            ]
            tokens = []
            for worker in workers:
                stdout, stderr = worker.communicate(timeout=15)
                self.assertEqual(worker.returncode, 0, stderr)
                tokens.append(stdout.strip())
            self.assertEqual(len(set(tokens)), 1)
            secret = Path(tmp) / ".billing_secret"
            self.assertEqual(len(secret.read_bytes()), 32)
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)

    def test_empty_billing_secret_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".billing_secret").write_bytes(b"")
            env = os.environ.copy()
            env.update({
                "PEGASVPN_DEPLOYMENT": "staging",
                "PEGASVPN_STAGING_DATA_DIR": tmp,
            })
            proc = subprocess.run(
                [sys.executable, "-c", "import billing_account"],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Billing secret is missing", proc.stderr)

    def test_email_otp_secret_is_stable_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.update({
                "PEGASVPN_DEPLOYMENT": "staging",
                "PEGASVPN_STAGING_DATA_DIR": tmp,
            })
            script = (
                "from email_auth import secret;"
                "a=secret(); b=secret();"
                "assert len(a)==32 and a==b;"
                "print('OTP_SECRET_OK')"
            )
            proc = subprocess.run(
                [sys.executable, "-c", script],
                env=env, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("OTP_SECRET_OK", proc.stdout)
            secret_path = Path(tmp) / ".email_auth_secret"
            self.assertEqual(secret_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
