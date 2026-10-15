"""IP abuse counters must never contain raw or plain-hashed addresses."""
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class RateLimitIdentityTests(unittest.TestCase):
    def test_hmac_is_stable_separate_and_not_plain_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.update({
                "PEGASVPN_DEPLOYMENT": "staging",
                "PEGASVPN_STAGING_DATA_DIR": tmp,
            })
            script = r"""
from rate_limit_identity import keyed_ip
a = keyed_ip("203.0.113.7", "guest")
b = keyed_ip("203.0.113.7", "guest")
c = keyed_ip("203.0.113.7", "email")
assert a == b and a != c and len(a) == 64
assert "203.0.113.7" not in a
print(a)
"""
            result = subprocess.run(
                [sys.executable, "-c", script],
                env=env, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(
                result.returncode, 0, result.stdout + result.stderr
            )
            digest = result.stdout.strip()
            self.assertNotEqual(
                digest, hashlib.sha256(b"203.0.113.7").hexdigest()
            )
            secret = Path(tmp) / ".rate_limit_secret"
            self.assertEqual(len(secret.read_bytes()), 32)
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
