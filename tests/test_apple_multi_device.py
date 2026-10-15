"""Offline Apple sign-in regression tests with identity verification mocked.

These tests use a temporary SQLite database and never contact Apple
or the production VPN service.
"""
import importlib
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


class AppleMultiDeviceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = str(Path(self.tmp.name) / "apple-test.db")
        previous = os.environ.get("PEGASVPN_DB_PATH")
        os.environ["PEGASVPN_DB_PATH"] = self.db_path

        def restore_env():
            if previous is None:
                os.environ.pop("PEGASVPN_DB_PATH", None)
            else:
                os.environ["PEGASVPN_DB_PATH"] = previous

        self.addCleanup(restore_env)

        with sqlite3.connect(self.db_path) as db:
            db.execute("""
                CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    account_type TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1
                )
            """)
            db.execute("""
                CREATE TABLE sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT
                )
            """)

        guest_auth = types.ModuleType("guest_auth")
        guest_auth.DB_PATH = self.db_path
        guest_auth.validate_session = lambda _: None
        prior_guest = sys.modules.get("guest_auth")
        sys.modules["guest_auth"] = guest_auth

        def restore_guest():
            if prior_guest is None:
                sys.modules.pop("guest_auth", None)
            else:
                sys.modules["guest_auth"] = prior_guest

        self.addCleanup(restore_guest)

        for name in ("guest_refresh", "apple_login"):
            sys.modules.pop(name, None)
        self.refresh = importlib.import_module("guest_refresh")
        self.apple = importlib.import_module("apple_login")
        self.verify_patch = patch.object(
            self.apple, "verify_identity", return_value="apple-user-1"
        )
        self.verify_patch.start()
        self.addCleanup(self.verify_patch.stop)

    def test_second_device_does_not_log_out_first(self):
        first = self.apple.login("mock-token", "mock-nonce")
        second = self.apple.login("mock-token", "mock-nonce")
        self.assertEqual(first["user_id"], second["user_id"])
        self.assertNotEqual(first["refresh_token"], second["refresh_token"])

        first_renewal = self.refresh.rotate(first["refresh_token"])
        second_renewal = self.refresh.rotate(second["refresh_token"])
        self.assertEqual(first_renewal["user_id"], first["user_id"])
        self.assertEqual(second_renewal["user_id"], first["user_id"])

    def test_signin_does_not_overwrite_other_devices(self):
        sessions = [
            self.apple.login("mock-token", "mock-nonce")
            for _ in range(3)
        ]
        for session in sessions:
            renewed = self.refresh.rotate(session["refresh_token"])
            self.assertEqual(renewed["user_id"], sessions[0]["user_id"])

    def test_only_one_identity_record(self):
        self.apple.login("mock-token", "mock-nonce")
        self.apple.login("mock-token", "mock-nonce")
        with sqlite3.connect(self.db_path) as db:
            users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            identities = db.execute(
                "SELECT COUNT(*) FROM apple_identities"
            ).fetchone()[0]
        self.assertEqual(users, 1)
        self.assertEqual(identities, 1)


if __name__ == "__main__":
    unittest.main()
