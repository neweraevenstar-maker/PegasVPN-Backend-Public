"""Authoritative Apple status must be signed and account-bound."""
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS
from unittest.mock import patch
from appstoreserverlibrary.models.Status import Status
from apple_reconcile import decision


class Verifier:
    def __init__(self, transaction, renewal=None):
        self.transaction = transaction
        self.renewal = renewal

    def verify_and_decode_signed_transaction(self, signed):
        assert signed == "signed"
        return self.transaction

    def verify_and_decode_renewal_info(self, signed):
        assert signed == "signed-renewal"
        return self.renewal


class AppleReconcileTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 14, tzinfo=timezone.utc)
        self.original = "original-apple-1"
        self.txn = NS(
            originalTransactionId=self.original,
            productId="com.pegasvpn.subscription.monthly",
            appAccountToken="owner-token",
            revocationDate=None,
            isUpgraded=False,
            expiresDate=int(
                (self.now + timedelta(days=25)).timestamp() * 1000
            ),
        )

    def response(self, status, renewal=None):
        item = NS(
            originalTransactionId=self.original,
            signedTransactionInfo="signed",
            signedRenewalInfo="signed-renewal" if renewal else None,
            status=status,
        )
        return NS(
            bundleId="com.pegasvpn.app",
            data=[NS(lastTransactions=[item])],
        )

    def test_active_signed_renewal_extends_entitlement(self):
        with patch("apple_reconcile.account_token", return_value="owner-token"):
            active, product, expiry = decision(
                self.response(Status.ACTIVE), Verifier(self.txn),
                self.original, "user", self.now
            )
        self.assertTrue(active)
        self.assertEqual(product, self.txn.productId)
        self.assertGreater(expiry, self.now)

    def test_refund_cannot_remain_active(self):
        self.txn.revocationDate = int(self.now.timestamp() * 1000)
        with patch("apple_reconcile.account_token", return_value="owner-token"):
            active, _, _ = decision(
                self.response(Status.REVOKED), Verifier(self.txn),
                self.original, "user", self.now
            )
        self.assertFalse(active)

    def test_mismatched_account_token_never_grants_access(self):
        with patch("apple_reconcile.account_token", return_value="different"):
            with self.assertRaises(ValueError):
                decision(
                    self.response(Status.ACTIVE), Verifier(self.txn),
                    self.original, "user", self.now
                )

    def test_grace_period_requires_signed_renewal(self):
        renewal = NS(
            originalTransactionId=self.original,
            gracePeriodExpiresDate=int(
                (self.now + timedelta(days=3)).timestamp() * 1000
            ),
        )
        with patch("apple_reconcile.account_token", return_value="owner-token"):
            active, _, _ = decision(
                self.response(Status.BILLING_GRACE_PERIOD, renewal),
                Verifier(self.txn, renewal),
                self.original, "user", self.now
            )
            self.assertTrue(active)
            with self.assertRaises(ValueError):
                decision(
                    self.response(Status.BILLING_GRACE_PERIOD),
                    Verifier(self.txn), self.original, "user", self.now
                )


if __name__ == "__main__":
    unittest.main()
