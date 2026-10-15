import hmac
from contextlib import closing
import sqlite3
from datetime import datetime, timezone

from billing_account import account_token
from subscription_entitlements import DB, parse_date

PRODUCTS = {
    "com.pegasvpn.subscription.monthly",
    "com.pegasvpn.subscription.yearly",
}

def event_name(value):
    return str(getattr(value, "value", value) or "")

def apple_date(milliseconds):
    return datetime.fromtimestamp(
        milliseconds / 1000,
        tz=timezone.utc
    )

def apply_verified_event(notification, transaction):
    if transaction is None:
        return "no_transaction"

    original = transaction.originalTransactionId
    product = transaction.productId

    if not original or product not in PRODUCTS:
        return "ignored"

    event = event_name(notification.notificationType)

    with closing(sqlite3.connect(DB, timeout=15)) as db, db:
        db.execute("BEGIN IMMEDIATE")

        row = db.execute("""
            SELECT user_id, expires_at, revoked_at
            FROM subscription_entitlements
            WHERE original_transaction_id=?
        """, (original,)).fetchone()

        if not row:
            # A subscriber may delete their PegasVPN account while Apple's
            # auto-renewing subscription continues. Keep the minimal recovery
            # bridge current, but NEVER recreate VPN access on notification.
            table = db.execute(
                """SELECT 1 FROM sqlite_master
                   WHERE type='table' AND name='paid_account_recovery'"""
            ).fetchone()
            if not table:
                return "unlinked"
            recovery = db.execute(
                """SELECT user_id, expires_at FROM paid_account_recovery
                   WHERE original_transaction_id=? LIMIT 1""",
                (original,),
            ).fetchone()
            if not recovery:
                return "unlinked"

            recovery_user, recovery_expiry = recovery
            if not hmac.compare_digest(
                account_token(recovery_user),
                str(transaction.appAccountToken or ""),
            ):
                raise ValueError("Apple recovery binding mismatch")

            expiration = transaction.expiresDate
            if not expiration:
                return "no_expiry"
            new_expiry = apple_date(expiration)
            current_expiry = parse_date(recovery_expiry)

            if event in ("DID_RENEW", "SUBSCRIBED"):
                if transaction.revocationDate is not None:
                    return "revoked_transaction"
                if new_expiry <= datetime.now(timezone.utc):
                    return "expired_transaction"
                if new_expiry <= current_expiry:
                    return "already_current"
                db.execute(
                    """UPDATE paid_account_recovery SET expires_at=?
                       WHERE original_transaction_id=?""",
                    (new_expiry.isoformat(), original),
                )
                return "recovery_renewed"

            if event in ("REFUND", "REVOKE"):
                if transaction.revocationDate is None:
                    return "revocation_unconfirmed"
                if abs(
                    (new_expiry - current_expiry).total_seconds()
                ) > 1:
                    return "older_transaction"
                db.execute(
                    """DELETE FROM paid_account_recovery
                       WHERE original_transaction_id=?""",
                    (original,),
                )
                return "recovery_revoked"

            return "recovery_recorded_only"

        user_id, old_expiry, revoked = row

        expected = account_token(user_id)
        actual = str(transaction.appAccountToken or "")

        if not hmac.compare_digest(expected, actual):
            raise ValueError("Apple account binding mismatch")

        expiration = transaction.expiresDate
        if not expiration:
            return "no_expiry"

        new_expiry = apple_date(expiration)
        current_expiry = parse_date(old_expiry)

        if event in ("DID_RENEW", "SUBSCRIBED"):
            if transaction.revocationDate is not None:
                return "revoked_transaction"

            if new_expiry <= datetime.now(timezone.utc):
                return "expired_transaction"

            if new_expiry <= current_expiry:
                return "already_current"

            db.execute("""
                UPDATE subscription_entitlements
                SET product_id=?,
                    expires_at=?,
                    revoked_at=NULL,
                    verified_at=CURRENT_TIMESTAMP
                WHERE user_id=?
            """, (
                product,
                new_expiry.isoformat(),
                user_id
            ))
            return "renewed"

        if event in ("REFUND", "REVOKE"):
            if transaction.revocationDate is None:
                return "revocation_unconfirmed"

            # Never revoke a newer renewal because an
            # earlier subscription period was refunded.
            if abs(
                (new_expiry - current_expiry).total_seconds()
            ) > 1:
                return "older_transaction"

            if revoked:
                return "already_revoked"

            db.execute("""
                UPDATE subscription_entitlements
                SET revoked_at=?,
                    verified_at=CURRENT_TIMESTAMP
                WHERE user_id=?
            """, (
                apple_date(
                    transaction.revocationDate
                ).isoformat(),
                user_id
            ))
            return "revoked"

        return "recorded_only"
