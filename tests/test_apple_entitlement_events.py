"""Apple event lifecycle: offline SQLite tests with verified-event stubs.

No network, real Apple keys, production database, or WireGuard mutation.
"""
import importlib.util
import sqlite3
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from paid_account_recovery import setup as setup_recovery

PRODUCT = "com.pegasvpn.subscription.monthly"
USER = "user-A"
ORIGINAL = "original-tx-1"


def milliseconds(value):
    return int(value.timestamp() * 1000)


class AppleEventLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "events.sqlite")
        self.old = datetime.now(timezone.utc) + timedelta(days=10)
        self.new = datetime.now(timezone.utc) + timedelta(days=40)
        with sqlite3.connect(self.path) as db:
            db.execute("""CREATE TABLE subscription_entitlements (
                user_id TEXT PRIMARY KEY, product_id TEXT,
                original_transaction_id TEXT UNIQUE,
                expires_at TEXT, revoked_at TEXT, verified_at TEXT
            )""")

        billing = types.ModuleType("billing_account")
        billing.account_token = lambda user: "token-" + user
        entitlements = types.ModuleType("subscription_entitlements")
        entitlements.DB = self.path
        entitlements.parse_date = lambda value: datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
        source = Path(__file__).resolve().parents[1] / "apple_event_apply.py"
        spec = importlib.util.spec_from_file_location(
            "isolated_apple_event_apply", source
        )
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {
            "billing_account": billing,
            "subscription_entitlements": entitlements,
        }):
            spec.loader.exec_module(module)
        self.apply = module.apply_verified_event

    def notification(self, name):
        return SimpleNamespace(notificationType=name)

    def transaction(self, expiry=None, token="token-user-A", revoked=None):
        return SimpleNamespace(
            originalTransactionId=ORIGINAL,
            productId=PRODUCT,
            appAccountToken=token,
            expiresDate=milliseconds(expiry or self.new),
            revocationDate=milliseconds(revoked) if revoked else None,
        )

    def active(self):
        with sqlite3.connect(self.path) as db:
            db.execute("""INSERT INTO subscription_entitlements
                VALUES (?, ?, ?, ?, NULL, CURRENT_TIMESTAMP)""",
                (USER, PRODUCT, ORIGINAL, self.old.isoformat()))

    def deleted(self):
        with sqlite3.connect(self.path) as db:
            setup_recovery(db)
            for i in range(2):
                db.execute("""INSERT INTO paid_account_recovery
                    (identity_hash, user_id, original_transaction_id,
                     created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)""",
                    (f"hash-{i}", USER, ORIGINAL,
                     "2026-01-01T00:00:00+00:00", self.old.isoformat()))

    def test_active_subscription_renews_and_stale_event_does_not_shorten(self):
        self.active()
        self.assertEqual(
            self.apply(self.notification("DID_RENEW"), self.transaction()),
            "renewed"
        )
        self.assertEqual(
            self.apply(self.notification("DID_RENEW"),
                       self.transaction(self.old)),
            "already_current"
        )
        with sqlite3.connect(self.path) as db:
            expiry = db.execute(
                "SELECT expires_at FROM subscription_entitlements"
            ).fetchone()[0]
        self.assertAlmostEqual(
            datetime.fromisoformat(expiry).timestamp(),
            self.new.timestamp(), delta=0.01
        )

    def test_active_matching_refund_revokes_access(self):
        self.active()
        result = self.apply(
            self.notification("REFUND"),
            self.transaction(self.old, revoked=datetime.now(timezone.utc))
        )
        self.assertEqual(result, "revoked")
        with sqlite3.connect(self.path) as db:
            self.assertIsNotNone(db.execute(
                "SELECT revoked_at FROM subscription_entitlements"
            ).fetchone()[0])

    def test_old_refund_does_not_revoke_newer_paid_period(self):
        self.active()
        self.apply(self.notification("DID_RENEW"), self.transaction())
        self.assertEqual(
            self.apply(
                self.notification("REFUND"),
                self.transaction(self.old, revoked=datetime.now(timezone.utc))
            ), "older_transaction"
        )

    def test_active_binding_mismatch_is_rejected(self):
        self.active()
        with self.assertRaises(ValueError):
            self.apply(self.notification("DID_RENEW"),
                       self.transaction(token="token-attacker"))

    def test_deleted_account_renewal_updates_both_recovery_aliases(self):
        self.deleted()
        self.assertEqual(
            self.apply(self.notification("DID_RENEW"), self.transaction()),
            "recovery_renewed"
        )
        self.assertEqual(
            self.apply(self.notification("DID_RENEW"), self.transaction()),
            "already_current"
        )
        with sqlite3.connect(self.path) as db:
            expiries = db.execute(
                "SELECT expires_at FROM paid_account_recovery"
            ).fetchall()
            self.assertEqual(len(expiries), 2)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM subscription_entitlements"
            ).fetchone()[0], 0)
        for expiry, in expiries:
            self.assertAlmostEqual(
                datetime.fromisoformat(expiry).timestamp(),
                self.new.timestamp(), delta=0.01
            )

    def test_deleted_account_refund_removes_recovery_but_not_others(self):
        self.deleted()
        self.assertEqual(
            self.apply(
                self.notification("REFUND"),
                self.transaction(self.old, revoked=datetime.now(timezone.utc))
            ), "recovery_revoked"
        )
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM paid_account_recovery"
            ).fetchone()[0], 0)

    def test_deleted_account_older_refund_does_not_remove_renewed_recovery(self):
        self.deleted()
        self.apply(self.notification("DID_RENEW"), self.transaction())
        self.assertEqual(
            self.apply(
                self.notification("REFUND"),
                self.transaction(self.old, revoked=datetime.now(timezone.utc))
            ), "older_transaction"
        )
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM paid_account_recovery"
            ).fetchone()[0], 2)

    def test_deleted_account_binding_mismatch_is_rejected(self):
        self.deleted()
        with self.assertRaises(ValueError):
            self.apply(self.notification("DID_RENEW"),
                       self.transaction(token="token-attacker"))

    def test_unrelated_purchase_is_not_claimed(self):
        self.assertEqual(
            self.apply(self.notification("DID_RENEW"), self.transaction()),
            "unlinked"
        )


if __name__ == "__main__":
    unittest.main()
