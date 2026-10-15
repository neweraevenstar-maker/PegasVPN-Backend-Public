"""Minimal, pseudonymous purchase-recovery bridge for deleted accounts.

Only previously verified Apple/email identities can reclaim the old billing UUID.
No sessions, IPs, VPN keys, or plaintext identity are retained here.
Deployment requires an approved privacy notice and retention policy.
"""
import hashlib
import hmac
from datetime import datetime, timezone


def identity_hash(secret, kind, identity):
    if kind not in ("apple", "email") or not identity:
        raise ValueError("Unsupported recovery identity")
    payload = ("pegasvpn-paid-recovery-v1:" + kind + ":" + identity).encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def setup(db):
    db.execute("""CREATE TABLE IF NOT EXISTS paid_account_recovery (
        identity_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        original_transaction_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        deleted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("""CREATE INDEX IF NOT EXISTS idx_paid_recovery_user
        ON paid_account_recovery(user_id)""")
    db.execute("""CREATE INDEX IF NOT EXISTS idx_paid_recovery_original
        ON paid_account_recovery(original_transaction_id)""")


def preserve(db, user_id, secret):
    """Call within the account-deletion transaction, before deleting identities."""
    tables = {r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    if "subscription_entitlements" not in tables:
        return False
    row = db.execute("""SELECT original_transaction_id, expires_at, revoked_at
        FROM subscription_entitlements WHERE user_id=?""", (user_id,)).fetchone()
    if not row or row[2]:
        return False
    try:
        expiry = datetime.fromisoformat(row[1].replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            return False
    except (ValueError, TypeError, AttributeError):
        return False

    owner = db.execute(
        "SELECT created_at FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if not owner:
        raise ValueError("Missing account for paid recovery")

    identities = []
    for kind, table, column in (
        ("apple", "apple_identities", "apple_sub"),
        ("email", "email_identities", "email"),
    ):
        if table in tables:
            identities.extend(
                (kind, r[0]) for r in db.execute(
                    f"SELECT {column} FROM {table} WHERE user_id=?",
                    (user_id,),
                )
            )
    if not identities:
        # Guest-only purchases have no independently verified identity.
        return False

    setup(db)
    for kind, identity in identities:
        key = identity_hash(secret, kind, identity)
        prior = db.execute(
            "SELECT user_id FROM paid_account_recovery WHERE identity_hash=?",
            (key,),
        ).fetchone()
        if prior and prior[0] != user_id:
            raise ValueError("Recovery identity already belongs to another user")
        db.execute("""INSERT OR REPLACE INTO paid_account_recovery
            (identity_hash, user_id, original_transaction_id,
             created_at, expires_at, deleted_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            (key, user_id, row[0], owner[0], row[1]),
        )
    return True


def find(db, kind, identity, secret=None):
    """Look up a deleted billing UUID after fresh Apple/OTP verification."""
    setup(db)
    # New installations and ordinary logins do not need a billing secret.
    if not db.execute("SELECT 1 FROM paid_account_recovery LIMIT 1").fetchone():
        return None
    if secret is None:
        from billing_account import SECRET
        secret = SECRET.read_bytes()
    row = db.execute("""SELECT user_id, created_at
        FROM paid_account_recovery WHERE identity_hash=?""",
        (identity_hash(secret, kind, identity),),
    ).fetchone()
    if row and db.execute(
        "SELECT 1 FROM users WHERE id=?", (row[0],)
    ).fetchone():
        raise ValueError("Recovery account already active")
    return row


def consume(db, user_id):
    """Remove all aliases only after the old UUID is recreated transactionally."""
    db.execute(
        "DELETE FROM paid_account_recovery WHERE user_id=?", (user_id,)
    )
