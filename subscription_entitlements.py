from contextlib import closing
import sqlite3
from runtime_paths import db_path
from datetime import datetime, timezone

DB = str(db_path())

def parse_date(value):
    if not value:
        return None
    result = datetime.fromisoformat(
        str(value).replace("Z", "+00:00")
    )
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)

def initialize():
    with closing(sqlite3.connect(DB, timeout=15)) as db, db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS subscription_entitlements (
                user_id TEXT PRIMARY KEY,
                product_id TEXT NOT NULL,
                original_transaction_id TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                verified_at TEXT NOT NULL
            )
        """)

def paid_status(user_id):
    with closing(sqlite3.connect(DB, timeout=15)) as db, db:
        row = db.execute("""
            SELECT product_id, expires_at, revoked_at
            FROM subscription_entitlements
            WHERE user_id=?
        """, (user_id,)).fetchone()

    if not row:
        return False, None

    product_id, expires_at, revoked_at = row

    if revoked_at:
        return False, expires_at

    try:
        expiry = parse_date(expires_at)
        active = expiry > datetime.now(timezone.utc)
        return active, expires_at
    except (TypeError, ValueError):
        return False, None

initialize()
