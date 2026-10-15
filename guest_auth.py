import hashlib
import secrets
from contextlib import closing
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from runtime_paths import db_path

DB_PATH = db_path()
SESSION_HOURS = 24

def database():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn

def create_guest_session():
    user_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = (
        datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    ).isoformat()

    with closing(database()) as conn, conn:
        conn.execute(
            "INSERT INTO users(id, account_type) VALUES (?, 'guest')",
            (user_id,)
        )
        conn.execute(
            """
            INSERT INTO sessions(id, user_id, token_hash, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (session_id, user_id, token_hash, expires)
        )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires,
        "user_id": user_id
    }

def validate_session(token):
    if not isinstance(token, str) or not token:
        return None

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    with closing(database()) as conn, conn:
        row = conn.execute(
            """
            SELECT s.user_id
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
              AND s.revoked_at IS NULL
              AND s.expires_at > ?
              AND u.is_active = 1
            """,
            (token_hash, datetime.now(timezone.utc).isoformat())
        ).fetchone()

    return row[0] if row else None
