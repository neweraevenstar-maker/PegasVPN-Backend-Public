import hmac
import os
from contextlib import closing
import sqlite3

from apple_receipts import verify_transaction
from billing_account import account_token
from billing_identity import has_verified_identity
from subscription_entitlements import DB, parse_date

def claim(user_id, signed_transaction):
    from apple_verification_config import verification_target
    verification_target()

    receipt = verify_transaction(signed_transaction)

    expected = account_token(user_id)
    actual = receipt["app_account_token"]

    if not hmac.compare_digest(expected, actual):
        raise ValueError("Purchase belongs to another user")

    original = receipt["original_transaction_id"]
    product = receipt["product_id"]
    expiry = receipt["expires_at"]

    with closing(sqlite3.connect(DB, timeout=15)) as db, db:
        db.execute("BEGIN IMMEDIATE")

        user = db.execute(
            "SELECT is_active FROM users WHERE id=?",
            (user_id,)
        ).fetchone()

        if not user or not user[0]:
            raise ValueError("User is inactive")
        if not has_verified_identity(db, user_id):
            raise ValueError("Verified Apple or email identity required")

        owner = db.execute(
            """SELECT user_id FROM subscription_entitlements
               WHERE original_transaction_id=?""",
            (original,)
        ).fetchone()

        if owner and owner[0] != user_id:
            raise ValueError("Purchase already assigned")

        previous = db.execute(
            """SELECT original_transaction_id, expires_at,
                      revoked_at
               FROM subscription_entitlements
               WHERE user_id=?""",
            (user_id,)
        ).fetchone()

        if previous:
            old_original, old_expiry, revoked = previous

            if revoked:
                raise ValueError("Revoked purchase requires review")

            if old_original != original:
                raise ValueError(
                    "Different subscription requires reconciliation"
                )

            if parse_date(old_expiry) > parse_date(expiry):
                expiry = old_expiry

        db.execute(
            """INSERT INTO subscription_entitlements
               (user_id, product_id, original_transaction_id,
                expires_at, revoked_at, verified_at)
               VALUES (?, ?, ?, ?, NULL, datetime('now'))
               ON CONFLICT(user_id) DO UPDATE SET
                 product_id=excluded.product_id,
                 expires_at=excluded.expires_at,
                 verified_at=excluded.verified_at""",
            (user_id, product, original, expiry)
        )

    return {
        "verified": True,
        "subscription_active": True,
        "expires_at": expiry
    }
