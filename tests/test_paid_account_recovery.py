"""Offline recovery regression tests; no production paths or Apple network."""
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from paid_account_recovery import consume, find, identity_hash, preserve

SECRET = b"isolated-test-key-not-used-in-production"
USER = "11111111-1111-4111-8111-111111111111"
CREATED = "2026-01-01T00:00:00+00:00"


class PaidAccountRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "isolated.sqlite"
        self.db = sqlite3.connect(self.path)
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE users (
                id TEXT PRIMARY KEY, account_type TEXT NOT NULL,
                created_at TEXT NOT NULL, is_active INTEGER DEFAULT 1
            );
            CREATE TABLE apple_identities (
                apple_sub TEXT PRIMARY KEY, user_id TEXT NOT NULL
            );
            CREATE TABLE email_identities (
                email TEXT PRIMARY KEY, user_id TEXT NOT NULL
            );
            CREATE TABLE subscription_entitlements (
                user_id TEXT PRIMARY KEY,
                original_transaction_id TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL, revoked_at TEXT
            );
        """)
        self.db.execute(
            "INSERT INTO users(id, account_type, created_at) VALUES (?, 'guest', ?)",
            (USER, CREATED),
        )
        self.db.execute(
            "INSERT INTO apple_identities VALUES (?, ?)",
            ("verified-apple-subject", USER),
        )
        self.db.execute(
            "INSERT INTO email_identities VALUES (?, ?)",
            ("verified@example.test", USER),
        )

    def add_purchase(self, days=30, revoked=None):
        expiry = (
            datetime.now(timezone.utc) + timedelta(days=days)
        ).isoformat()
        self.db.execute(
            "INSERT INTO subscription_entitlements VALUES (?, ?, ?, ?)",
            (USER, "original-transaction-1", expiry, revoked),
        )

    def delete_identity_and_account(self):
        for table in ("apple_identities", "email_identities",
                      "subscription_entitlements", "users"):
            self.db.execute(
                f"DELETE FROM {table} WHERE user_id=?" if table != "users"
                else "DELETE FROM users WHERE id=?",
                (USER,),
            )

    def test_verified_apple_and_email_can_restore_same_billing_uuid(self):
        self.add_purchase()
        self.assertTrue(preserve(self.db, USER, SECRET))
        self.delete_identity_and_account()
        self.assertEqual(
            find(self.db, "apple", "verified-apple-subject", SECRET),
            (USER, CREATED),
        )
        self.assertEqual(
            find(self.db, "email", "verified@example.test", SECRET),
            (USER, CREATED),
        )
        self.assertIsNone(
            find(self.db, "apple", "other-apple-user", SECRET)
        )
        self.assertIsNone(
            find(self.db, "email", "attacker@example.test", SECRET)
        )
        rows = self.db.execute(
            "SELECT identity_hash FROM paid_account_recovery"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertNotIn("verified-apple-subject", str(rows))
        self.assertNotIn("verified@example.test", str(rows))
        self.db.execute(
            """INSERT INTO users(id, account_type, created_at)
               VALUES (?, 'guest', ?)""", (USER, CREATED),
        )
        consume(self.db, USER)
        self.assertIsNone(
            find(self.db, "apple", "verified-apple-subject", SECRET)
        )

    def test_expired_or_revoked_purchase_is_not_preserved(self):
        for days, revoked in ((-1, None), (30, "2026-01-02")):
            self.db.execute("DELETE FROM subscription_entitlements")
            self.add_purchase(days, revoked)
            self.assertFalse(preserve(self.db, USER, SECRET))

    def test_no_purchase_and_no_verified_identity_are_not_preserved(self):
        self.assertFalse(preserve(self.db, USER, SECRET))
        self.add_purchase()
        self.db.execute("DELETE FROM apple_identities")
        self.db.execute("DELETE FROM email_identities")
        self.assertFalse(preserve(self.db, USER, SECRET))

    def test_recovery_rejects_active_uuid(self):
        self.add_purchase()
        self.assertTrue(preserve(self.db, USER, SECRET))
        with self.assertRaises(ValueError):
            find(self.db, "apple", "verified-apple-subject", SECRET)

    def test_fresh_login_does_not_require_production_billing_secret(self):
        # Empty recovery table: no import of billing_account, no /opt access.
        self.assertIsNone(find(self.db, "apple", "new-apple-user"))

    def test_hash_is_domain_separated(self):
        apple = identity_hash(SECRET, "apple", "same")
        email = identity_hash(SECRET, "email", "same")
        self.assertNotEqual(apple, email)
        self.assertEqual(len(apple), 64)
        with self.assertRaises(ValueError):
            identity_hash(SECRET, "guest", "same")


if __name__ == "__main__":
    unittest.main()
