"""Recover missed App Store notifications using Apple's current status API.

Only Apple-signed transaction/renewal JWS can change an entitlement.
This module does not run or make network requests on import.
"""
import hmac
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from billing_account import account_token
from subscription_entitlements import DB

PRODUCTS = {
    "com.pegasvpn.subscription.monthly",
    "com.pegasvpn.subscription.yearly",
}


def apple_clients():
    from appstoreserverlibrary.api_client import AppStoreServerAPIClient
    from appstoreserverlibrary.models.Environment import Environment
    from appstoreserverlibrary.signed_data_verifier import SignedDataVerifier
    from apple_verification_config import verification_target
    from apple_receipts import BUNDLE, ROOTS

    target, app_id = verification_target()
    env = Environment.SANDBOX if target == "sandbox" else Environment.PRODUCTION
    key_file = Path(os.environ["PEGASVPN_APPSTORE_KEY_PATH"])
    if key_file.is_symlink() or key_file.stat().st_mode & 0o077:
        raise RuntimeError("App Store API signing key must be private (0600)")
    key = key_file.read_bytes()
    key_id = os.environ["PEGASVPN_APPSTORE_KEY_ID"]
    issuer = os.environ["PEGASVPN_APPSTORE_ISSUER_ID"]
    roots = [p.read_bytes() for p in sorted(ROOTS.glob("*.cer"))]
    if len(roots) != 3:
        raise RuntimeError("Apple trust roots missing")
    return (
        AppStoreServerAPIClient(key, key_id, issuer, BUNDLE, env),
        SignedDataVerifier(roots, True, env, BUNDLE, app_id),
    )


def decision(response, verifier, original, user_id, now=None):
    """Return (active, product, expiration) or raise without changing DB."""
    from apple_receipts import BUNDLE
    from appstoreserverlibrary.models.Status import Status

    if response.bundleId != BUNDLE:
        raise ValueError("Apple status response bundle mismatch")
    current = now or datetime.now(timezone.utc)
    if not response.data:
        raise ValueError("Apple returned no subscription groups")

    matches = []
    for group in response.data:
        for item in group.lastTransactions or ():
            if str(item.originalTransactionId or "") != original:
                continue
            if not item.signedTransactionInfo:
                raise ValueError("Missing Apple signed transaction")
            txn = verifier.verify_and_decode_signed_transaction(
                item.signedTransactionInfo
            )
            if (
                str(txn.originalTransactionId or "") != original
                or txn.productId not in PRODUCTS
                or not hmac.compare_digest(
                    str(txn.appAccountToken or ""), account_token(user_id)
                )
            ):
                raise ValueError("Subscription ownership mismatch")
            status = item.status
            if status not in (
                Status.ACTIVE, Status.EXPIRED, Status.BILLING_RETRY,
                Status.BILLING_GRACE_PERIOD, Status.REVOKED
            ):
                raise ValueError("Unknown Apple subscription status")
            expiration_ms = txn.expiresDate
            if not expiration_ms:
                raise ValueError("Apple transaction missing expiration")
            expiration = datetime.fromtimestamp(
                expiration_ms / 1000, tz=timezone.utc
            )
            active = (
                status == Status.ACTIVE
                and txn.revocationDate is None
                and txn.isUpgraded is not True
                and expiration > current
            )
            if status == Status.BILLING_GRACE_PERIOD:
                if not item.signedRenewalInfo:
                    raise ValueError("Unsigned Apple billing grace period")
                renewal = verifier.verify_and_decode_renewal_info(
                    item.signedRenewalInfo
                )
                if str(renewal.originalTransactionId or "") != original:
                    raise ValueError("Renewal ownership mismatch")
                grace_ms = renewal.gracePeriodExpiresDate
                if (grace_ms and txn.revocationDate is None
                        and txn.isUpgraded is not True):
                    grace = datetime.fromtimestamp(
                        grace_ms / 1000, tz=timezone.utc
                    )
                    if grace > current:
                        active, expiration = True, grace
            matches.append((active, txn.productId, expiration))

    if not matches:
        # Never revoke an account based on an incomplete API response.
        raise ValueError("Original transaction absent from Apple status")
    # A group may contain several historical products. Prefer the most
    # recent active entitlement; otherwise choose the latest expiration.
    return max(matches, key=lambda item: (item[0], item[2]))


def apply_decision(user_id, original, state, now=None):
    active, product, expiration = state
    current = now or datetime.now(timezone.utc)
    with closing(sqlite3.connect(DB, timeout=20)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            """SELECT user_id FROM subscription_entitlements
               WHERE original_transaction_id=?""", (original,)
        ).fetchone()
        if not row or row[0] != user_id:
            return False
        user = db.execute(
            "SELECT is_active FROM users WHERE id=?", (user_id,)
        ).fetchone()
        if not user or not user[0]:
            return False
        db.execute(
            """UPDATE subscription_entitlements SET
               product_id=?, expires_at=?, revoked_at=?,
               verified_at=CURRENT_TIMESTAMP
               WHERE user_id=? AND original_transaction_id=?""",
            (product, expiration.isoformat(),
             None if active else current.isoformat(), user_id, original),
        )
        return True


def reconcile_all(limit=100):
    if os.getenv("PEGASVPN_ENABLE_APPLE_RECONCILIATION") != "1":
        raise RuntimeError("Apple status reconciliation is not enabled")
    if not 1 <= limit <= 1000:
        raise ValueError("Invalid reconciliation batch size")
    client, verifier = apple_clients()
    with closing(sqlite3.connect(DB, timeout=20)) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS apple_reconcile_attempts (
            original_transaction_id TEXT PRIMARY KEY,
            attempted_at TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0
        )""")
        rows = db.execute(
            """SELECT e.user_id, e.original_transaction_id
               FROM subscription_entitlements e
               LEFT JOIN apple_reconcile_attempts a
               ON a.original_transaction_id=e.original_transaction_id
               ORDER BY COALESCE(a.attempted_at, '') ASC
               LIMIT ?""", (limit,)
        ).fetchall()
    succeeded = 0
    failed = 0
    for user_id, original in rows:
        verified = False
        try:
            response = client.get_all_subscription_statuses(original)
            state = decision(response, verifier, original, user_id)
            if apply_decision(user_id, original, state):
                succeeded += 1
            verified = True
        except Exception as exc:
            # Never revoke or grant access on Apple API failure.
            failed += 1
            print("Apple status unavailable:", type(exc).__name__)
        finally:
            with closing(sqlite3.connect(DB, timeout=20)) as db, db:
                db.execute(
                    """INSERT INTO apple_reconcile_attempts
                       (original_transaction_id,attempted_at,failures)
                       VALUES (?,CURRENT_TIMESTAMP,?)
                       ON CONFLICT(original_transaction_id) DO UPDATE SET
                       attempted_at=CURRENT_TIMESTAMP,
                       failures=CASE WHEN excluded.failures=0 THEN 0
                                     ELSE failures+1 END""",
                    (original, 0 if verified else 1),
                )
    return {"reconciled": succeeded, "failed": failed}


if __name__ == "__main__":
    print(reconcile_all())
