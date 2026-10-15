"""Billing is never sold to a guest-only account."""
import sqlite3
import unittest

from billing_identity import has_verified_identity


class BillingIdentityTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)

    def test_guest_cannot_purchase_without_identity_tables(self):
        self.assertFalse(has_verified_identity(self.db, "guest-1"))

    def test_apple_identity_allows_purchase_only_for_its_owner(self):
        self.db.execute(
            "CREATE TABLE apple_identities (apple_sub TEXT, user_id TEXT)"
        )
        self.db.execute(
            "INSERT INTO apple_identities VALUES (?, ?)",
            ("verified-sub", "apple-owner"),
        )
        self.assertTrue(has_verified_identity(self.db, "apple-owner"))
        self.assertFalse(has_verified_identity(self.db, "other-user"))

    def test_verified_email_allows_purchase(self):
        self.db.execute(
            "CREATE TABLE email_identities (email TEXT, user_id TEXT)"
        )
        self.db.execute(
            "INSERT INTO email_identities VALUES (?, ?)",
            ("verified@example.test", "email-owner"),
        )
        self.assertTrue(has_verified_identity(self.db, "email-owner"))
        self.assertFalse(has_verified_identity(self.db, "guest-1"))

    def test_missing_user_is_never_eligible(self):
        self.assertFalse(has_verified_identity(self.db, ""))


if __name__ == "__main__":
    unittest.main()
