"""Idempotent, transactional migrations for existing PegasVPN SQLite databases.

Never run on import. A consistent SQLite backup is required before apply.
Existing user/session tables must already exist; we do not recreate users.
"""
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

REQUIRED = {
    "users": {"id", "account_type", "created_at", "is_active"},
    "sessions": {"id", "user_id", "token_hash", "expires_at", "revoked_at"},
}


def _columns(db, table):
    return {r[1] for r in db.execute(f"PRAGMA table_info({table})")}


def migrate(db):
    """Apply additive migrations inside one caller-owned transaction."""
    for table, required in REQUIRED.items():
        missing = required - _columns(db, table)
        if missing:
            raise RuntimeError(
                f"Existing {table} schema lacks: {', '.join(sorted(missing))}"
            )
    db.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
        migration_id TEXT PRIMARY KEY, applied_at TEXT NOT NULL
    )""")
    if db.execute(
        "SELECT 1 FROM schema_migrations WHERE migration_id='001_release'"
    ).fetchone():
        return False

    db.execute("""CREATE TABLE IF NOT EXISTS guest_refresh_tokens (
        token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )""")
    columns = db.execute(
        "PRAGMA table_info(guest_refresh_tokens)"
    ).fetchall()
    pk = [r[1] for r in columns if r[5] > 0]
    if pk == ["user_id"]:
        db.execute("""CREATE TABLE guest_refresh_tokens_migration (
            token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )""")
        db.execute("""INSERT INTO guest_refresh_tokens_migration
            (token_hash, user_id, expires_at)
            SELECT token_hash, user_id, expires_at FROM guest_refresh_tokens
        """)
        db.execute("DROP TABLE guest_refresh_tokens")
        db.execute("""ALTER TABLE guest_refresh_tokens_migration
            RENAME TO guest_refresh_tokens""")
    elif pk != ["token_hash"]:
        raise RuntimeError("Unknown refresh-token schema; migration stopped")
    db.execute("""CREATE INDEX IF NOT EXISTS idx_guest_refresh_user
        ON guest_refresh_tokens(user_id)""")
    db.execute("""CREATE TABLE IF NOT EXISTS apple_identities (
        apple_sub TEXT PRIMARY KEY,
        user_id TEXT NOT NULL UNIQUE REFERENCES users(id)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS email_identities (
        email TEXT PRIMARY KEY,
        user_id TEXT NOT NULL UNIQUE REFERENCES users(id)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS email_codes (
        email TEXT PRIMARY KEY, code_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL,
        last_sent INTEGER NOT NULL
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS subscription_entitlements (
        user_id TEXT PRIMARY KEY, product_id TEXT NOT NULL,
        original_transaction_id TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL, revoked_at TEXT,
        verified_at TEXT NOT NULL
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS apple_notifications (
        notification_id TEXT PRIMARY KEY, event_type TEXT NOT NULL,
        event_subtype TEXT, original_transaction_id TEXT,
        transaction_id TEXT, signed_at INTEGER,
        received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("""CREATE INDEX IF NOT EXISTS idx_apple_original
        ON apple_notifications(original_transaction_id)""")
    db.execute("""CREATE TABLE IF NOT EXISTS vpn_provision_limits (
        user_id TEXT PRIMARY KEY, ip_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )""")
    db.execute("""CREATE INDEX IF NOT EXISTS idx_provision_time
        ON vpn_provision_limits(created_at)""")
    db.execute("""CREATE TABLE IF NOT EXISTS guest_rate_limits (
        client_hash TEXT NOT NULL, window_start INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(client_hash, window_start)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS paid_account_recovery (
        identity_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        original_transaction_id TEXT NOT NULL,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
        deleted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("""CREATE INDEX IF NOT EXISTS idx_paid_recovery_user
        ON paid_account_recovery(user_id)""")
    db.execute("""CREATE INDEX IF NOT EXISTS idx_paid_recovery_original
        ON paid_account_recovery(original_transaction_id)""")
    db.execute("""CREATE TABLE IF NOT EXISTS email_request_limits (
        email_hash TEXT NOT NULL, window_start INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(email_hash, window_start)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS apple_reconcile_attempts (
        original_transaction_id TEXT PRIMARY KEY,
        attempted_at TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0
    )""")
    db.execute("""INSERT INTO schema_migrations(migration_id, applied_at)
        VALUES ('001_release', ?)""",
        (datetime.now(timezone.utc).isoformat(),))
    return True


def apply(database):
    """Use an immediate transaction so a failed migration leaves no changes."""
    with closing(sqlite3.connect(database, timeout=30)) as db:
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("BEGIN IMMEDIATE")
        try:
            changed = migrate(db)
            db.commit()
            return changed
        except BaseException:
            db.rollback()
            raise
