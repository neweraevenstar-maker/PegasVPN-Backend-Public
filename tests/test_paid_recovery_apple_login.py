"""Offline integration: recover a deleted paid Apple account by verified identity."""
import importlib
import os
import sqlite3
import sys
import tempfile
import types
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from paid_account_recovery import preserve


class DeletedPaidAppleLoginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dbpath = str(Path(self.temp.name) / "test.sqlite")
        self.secret_path = Path(self.temp.name) / "billing-secret"
        self.secret_path.write_bytes(b"integration-test-only-secret")
        self.original_user = str(uuid.uuid4())
        self.created_at = "2026-01-01T00:00:00+00:00"
        expiry = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        with sqlite3.connect(self.dbpath) as db:
            db.executescript("""
                CREATE TABLE users (id TEXT PRIMARY KEY,
                    account_type TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    is_active INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE sessions (id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL, token_hash TEXT NOT NULL,
                    expires_at TEXT NOT NULL, revoked_at TEXT);
                CREATE TABLE apple_identities (
                    apple_sub TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE);
                CREATE TABLE subscription_entitlements (
                    user_id TEXT PRIMARY KEY, original_transaction_id TEXT,
                    expires_at TEXT, revoked_at TEXT);
            """)
            db.execute(
                "INSERT INTO users(id, account_type, created_at) VALUES (?, 'guest', ?)",
                (self.original_user, self.created_at),
            )
            db.execute("INSERT INTO apple_identities VALUES (?, ?)",
                       ("apple-sub-original", self.original_user))
            db.execute(
                "INSERT INTO subscription_entitlements VALUES (?, ?, ?, NULL)",
                (self.original_user, "original-tx", expiry),
            )
            self.assertTrue(preserve(
                db, self.original_user, self.secret_path.read_bytes()
            ))
            db.execute("DELETE FROM apple_identities WHERE user_id=?",
                       (self.original_user,))
            db.execute("DELETE FROM subscription_entitlements WHERE user_id=?",
                       (self.original_user,))
            db.execute("DELETE FROM users WHERE id=?", (self.original_user,))

        names = ("guest_auth", "guest_refresh", "apple_login", "billing_account")
        saved = {name: sys.modules.get(name) for name in names}
        def restore():
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module
        self.addCleanup(restore)

        guest = types.ModuleType("guest_auth")
        guest.DB_PATH = self.dbpath
        guest.validate_session = lambda token: None
        billing = types.ModuleType("billing_account")
        billing.SECRET = self.secret_path
        sys.modules["guest_auth"] = guest
        sys.modules["billing_account"] = billing
        for name in ("guest_refresh", "apple_login"):
            sys.modules.pop(name, None)

        old = os.environ.get("PEGASVPN_DB_PATH")
        os.environ["PEGASVPN_DB_PATH"] = self.dbpath
        def restore_env():
            if old is None:
                os.environ.pop("PEGASVPN_DB_PATH", None)
            else:
                os.environ["PEGASVPN_DB_PATH"] = old
        self.addCleanup(restore_env)
        self.apple = importlib.import_module("apple_login")

    def test_verified_identity_restores_original_billing_uuid(self):
        with patch.object(self.apple, "verify_identity",
                          return_value="apple-sub-original"):
            session = self.apple.login("mock", "nonce")
        self.assertEqual(session["user_id"], self.original_user)
        with sqlite3.connect(self.dbpath) as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM paid_account_recovery"
            ).fetchone()[0], 0)
            self.assertEqual(db.execute(
                "SELECT created_at FROM users WHERE id=?",
                (self.original_user,)
            ).fetchone()[0], self.created_at)
            self.assertEqual(db.execute(
                "SELECT user_id FROM apple_identities"
            ).fetchone()[0], self.original_user)

    def test_other_verified_identity_cannot_claim_deleted_purchase(self):
        with patch.object(self.apple, "verify_identity",
                          return_value="unrelated-apple-sub"):
            session = self.apple.login("mock", "nonce")
        self.assertNotEqual(session["user_id"], self.original_user)
        with sqlite3.connect(self.dbpath) as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM paid_account_recovery"
            ).fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
