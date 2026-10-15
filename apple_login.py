"""Verified Sign in with Apple and optional guest-account upgrade."""
import hashlib
import hmac
import secrets
import sqlite3
from contextlib import closing
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from jwt import PyJWKClient

from guest_auth import DB_PATH, validate_session
from guest_refresh import store as store_refresh

BUNDLE = "com.pegasvpn.app"
APPLE_KEYS = PyJWKClient(
    "https://appleid.apple.com/auth/keys", cache_keys=True, timeout=5
)


class AccountConflict(ValueError):
    pass


def verify_identity(identity_token, nonce):
    if not isinstance(identity_token, str) or not 50 < len(identity_token) < 10000:
        raise ValueError("Invalid Apple identity token")
    if not isinstance(nonce, str) or not 16 <= len(nonce) <= 128:
        raise ValueError("Invalid Apple nonce")
    try:
        key = APPLE_KEYS.get_signing_key_from_jwt(identity_token)
        claims = jwt.decode(
            identity_token, key.key, algorithms=["RS256"],
            audience=BUNDLE, issuer="https://appleid.apple.com",
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
            leeway=30,
        )
    except jwt.PyJWKClientConnectionError as exc:
        raise RuntimeError("Apple identity provider unavailable") from exc
    except (jwt.PyJWTError, ValueError) as exc:
        raise ValueError("Apple identity verification failed") from exc
    expected = hashlib.sha256(nonce.encode()).hexdigest()
    actual = claims.get("nonce")
    if not isinstance(actual, str) or not hmac.compare_digest(actual, expected):
        raise ValueError("Apple nonce mismatch")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not 1 <= len(sub) <= 255:
        raise ValueError("Invalid Apple subject")
    return sub


def login(identity_token, nonce, guest_access_token=None):
    apple_sub = verify_identity(identity_token, nonce)
    guest_id = None
    if guest_access_token is not None:
        guest_id = validate_session(guest_access_token)
        if not guest_id:
            raise ValueError("Guest session invalid")

    now = datetime.now(timezone.utc)
    access = secrets.token_urlsafe(48)
    refresh = secrets.token_urlsafe(48)
    access_exp = (now + timedelta(hours=24)).isoformat()
    refresh_exp = (now + timedelta(days=365)).isoformat()

    with closing(sqlite3.connect(DB_PATH, timeout=15)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("""CREATE TABLE IF NOT EXISTS apple_identities (
            apple_sub TEXT PRIMARY KEY,
            user_id TEXT NOT NULL UNIQUE REFERENCES users(id)
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS guest_refresh_tokens (
            user_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL
        )""")
        row = db.execute(
            "SELECT user_id FROM apple_identities WHERE apple_sub=?",
            (apple_sub,),
        ).fetchone()
        if row:
            # Existing Apple identity takes precedence over a fresh device guest.
            user_id = row[0]
        else:
            # Only a newly verified Apple identity can reclaim a deleted
            # paid account. Reusing the billing UUID preserves the original
            # Apple appAccountToken without transferring purchases.
            from paid_account_recovery import find, consume
            recovery = find(db, "apple", apple_sub)
            if recovery:
                user_id, original_created_at = recovery
                db.execute(
                    """INSERT INTO users(id, account_type, created_at)
                       VALUES (?, 'guest', ?)""",
                    (user_id, original_created_at),
                )
                consume(db, user_id)
            elif guest_id:
                if db.execute(
                    "SELECT 1 FROM apple_identities WHERE user_id=?",
                    (guest_id,),
                ).fetchone():
                    raise AccountConflict("Guest account already linked")
                user_id = guest_id
            else:
                user_id = str(uuid.uuid4())
                db.execute(
                    "INSERT INTO users(id, account_type) VALUES (?, 'guest')",
                    (user_id,),
                )
            db.execute(
                "INSERT INTO apple_identities(apple_sub,user_id) VALUES (?,?)",
                (apple_sub, user_id),
            )
        active = db.execute(
            "SELECT is_active FROM users WHERE id=?", (user_id,)
        ).fetchone()
        if not active or not active[0]:
            raise ValueError("Account inactive")
        db.execute("""INSERT INTO sessions(id,user_id,token_hash,expires_at)
            VALUES (?,?,?,?)""", (
            str(uuid.uuid4()), user_id,
            hashlib.sha256(access.encode()).hexdigest(), access_exp,
        ))
        store_refresh(db, user_id, refresh, refresh_exp)

    return {
        "user_id": user_id, "access_token": access,
        "refresh_token": refresh, "token_type": "bearer",
        "expires_at": access_exp,
    }
