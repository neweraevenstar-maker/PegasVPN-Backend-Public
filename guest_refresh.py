"""Per-device refresh sessions with atomic legacy SQLite migration."""
import hashlib
import os
import secrets
import sqlite3
from contextlib import closing
import uuid
from datetime import datetime, timedelta, timezone
from runtime_paths import db_path

DB = str(db_path())
MAX_SESSIONS_PER_USER = 10


def now():
    return datetime.now(timezone.utc)


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def initialize():
    with closing(sqlite3.connect(DB, timeout=15)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("""
            CREATE TABLE IF NOT EXISTS guest_refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)

        # Older releases used user_id as PRIMARY KEY and silently
        # invalidated other devices whenever a user signed in.
        columns = db.execute(
            "PRAGMA table_info(guest_refresh_tokens)"
        ).fetchall()
        primary_key = [
            col[1] for col in columns if col[5] > 0
        ]
        if primary_key == ["user_id"]:
            db.execute("""
                CREATE TABLE guest_refresh_tokens_v2 (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
            """)
            db.execute("""
                INSERT INTO guest_refresh_tokens_v2
                    (token_hash, user_id, expires_at)
                SELECT token_hash, user_id, expires_at
                FROM guest_refresh_tokens
            """)
            db.execute("DROP TABLE guest_refresh_tokens")
            db.execute("""
                ALTER TABLE guest_refresh_tokens_v2
                RENAME TO guest_refresh_tokens
            """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_guest_refresh_user
            ON guest_refresh_tokens(user_id)
        """)


def store(db, user_id, token, expiry):
    """Store one device's refresh token without invalidating other devices."""
    db.execute(
        "DELETE FROM guest_refresh_tokens WHERE expires_at <= ?",
        (now().isoformat(),)
    )
    db.execute("""
        INSERT INTO guest_refresh_tokens
            (token_hash, user_id, expires_at)
        VALUES (?, ?, ?)
    """, (digest(token), user_id, expiry))

    # Bound per-account storage; revoke only oldest excess sessions.
    db.execute("""
        DELETE FROM guest_refresh_tokens
        WHERE user_id=?
          AND rowid NOT IN (
              SELECT rowid FROM guest_refresh_tokens
              WHERE user_id=? ORDER BY rowid DESC LIMIT ?
          )
    """, (user_id, user_id, MAX_SESSIONS_PER_USER))


def mint(user_id):
    token = secrets.token_urlsafe(48)
    expiry = (now() + timedelta(days=365)).isoformat()

    with closing(sqlite3.connect(DB, timeout=15)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        # /auth/enroll must not create an unlimited number of
        # refresh sessions from a single cached access token.
        exists = db.execute("""
            SELECT 1 FROM guest_refresh_tokens
            WHERE user_id=? AND expires_at > ? LIMIT 1
        """, (user_id, now().isoformat())).fetchone()
        if exists:
            raise sqlite3.IntegrityError("Already enrolled")
        store(db, user_id, token, expiry)

    return token


def rotate(old_token):
    if not old_token or len(old_token) > 256:
        raise ValueError("Invalid refresh token")

    new_access = secrets.token_urlsafe(48)
    new_refresh = secrets.token_urlsafe(48)
    current = now()

    with closing(sqlite3.connect(DB, timeout=15)) as db, db:
        db.execute("BEGIN IMMEDIATE")

        row = db.execute("""
            SELECT r.user_id, r.expires_at, u.is_active
            FROM guest_refresh_tokens r
            JOIN users u ON u.id = r.user_id
            WHERE r.token_hash = ?
        """, (digest(old_token),)).fetchone()

        if not row or not row[2]:
            raise ValueError("Invalid refresh token")

        user_id, expiry, _ = row

        expires = datetime.fromisoformat(
            expiry.replace("Z", "+00:00")
        )

        if expires <= current:
            raise ValueError("Refresh token expired")

        db.execute("""
            UPDATE guest_refresh_tokens
            SET token_hash=?, expires_at=?
            WHERE token_hash=?
        """, (
            digest(new_refresh),
            (current + timedelta(days=365)).isoformat(),
            digest(old_token)
        ))

        db.execute("""
            INSERT INTO sessions
            (id, user_id, token_hash, expires_at, revoked_at)
            VALUES (?, ?, ?, ?, NULL)
        """, (
            str(uuid.uuid4()),
            user_id,
            digest(new_access),
            (current + timedelta(hours=24)).isoformat()
        ))

    return {
        "user_id": user_id,
        "access_token": new_access,
        "refresh_token": new_refresh
    }


initialize()
