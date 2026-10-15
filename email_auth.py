import hashlib
import hmac
import os
import secrets
import smtplib
from contextlib import closing
import sqlite3
import ssl
import time
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

from email_validator import validate_email, EmailNotValidError
from guest_auth import DB_PATH, validate_session
from guest_rate_limit import allow_request
from guest_refresh import store as store_refresh
from runtime_paths import data_dir
from rate_limit_identity import keyed_ip, keyed_email

SECRET_PATH = data_dir() / ".email_auth_secret"

class AccountConflict(ValueError):
    pass

def canonical(email):
    try:
        return validate_email(
            email, check_deliverability=False
        ).normalized.lower()
    except (EmailNotValidError, TypeError):
        raise ValueError("Invalid email address")

def secret():
    if SECRET_PATH.is_symlink():
        raise RuntimeError("Email OTP secret must not be a symlink")
    try:
        fd = os.open(
            SECRET_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
            f.flush()
            os.fsync(f.fileno())
    for attempt in range(20):
        if SECRET_PATH.is_symlink():
            raise RuntimeError("Email OTP secret must not be a symlink")
        value = SECRET_PATH.read_bytes()
        if len(value) == 32:
            SECRET_PATH.chmod(0o600)
            return value
        if attempt < 19:
            time.sleep(0.05)
    raise RuntimeError("Email OTP secret is missing or incomplete")

def digest(email, code):
    return hmac.new(
        secret(), f"{email}:{code}".encode(), hashlib.sha256
    ).hexdigest()

def setup(db):
    db.execute("""CREATE TABLE IF NOT EXISTS email_codes (
        email TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        attempts INTEGER NOT NULL,
        last_sent INTEGER NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS email_identities (
        email TEXT PRIMARY KEY,
        user_id TEXT NOT NULL UNIQUE REFERENCES users(id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS guest_refresh_tokens (
        user_id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS email_request_limits (
        email_hash TEXT NOT NULL, window_start INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(email_hash, window_start)
    )""")

def mail_config():
    keys = (
        "PEGASVPN_SMTP_HOST", "PEGASVPN_SMTP_USER",
        "PEGASVPN_SMTP_PASSWORD", "PEGASVPN_SMTP_FROM"
    )
    values = [os.environ.get(k) for k in keys]
    if not all(values):
        raise RuntimeError("Email delivery not configured")
    return values

def send_code(email, code, cfg):
    host, user, password, sender = cfg
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = email
    msg["Subject"] = "PegasVPN sign-in code"
    msg.set_content(
        f"Your PegasVPN code: {code}\nExpires in 10 minutes.\n"
    )
    security = os.getenv("PEGASVPN_SMTP_SECURITY", "starttls").lower()
    if security not in ("starttls", "ssl"):
        raise RuntimeError("Encrypted SMTP transport required")
    port = int(os.getenv(
        "PEGASVPN_SMTP_PORT", "465" if security == "ssl" else "587"
    ))
    for attempt in range(2):
        try:
            if security == "ssl":
                with smtplib.SMTP_SSL(
                    host, port, timeout=10, context=ssl.create_default_context()
                ) as smtp:
                    smtp.login(user, password)
                    smtp.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=10) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=ssl.create_default_context())
                    smtp.ehlo()
                    smtp.login(user, password)
                    smtp.send_message(msg)
            return
        except (OSError, smtplib.SMTPException):
            if attempt == 1:
                raise
            time.sleep(0.25)

def request_code(email, client_ip):
    email = canonical(email)
    cfg = mail_config()
    if not client_ip:
        raise ValueError("Missing client IP")
    ip_key = keyed_ip(client_ip, "email")
    if not allow_request(ip_key, limit=5, window_seconds=3600):
        raise ValueError("Too many requests")

    now = int(time.time())
    code = f"{secrets.randbelow(1000000):06d}"
    code_hash = digest(email, code)

    with closing(sqlite3.connect(DB_PATH, timeout=15)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        setup(db)
        row = db.execute(
            "SELECT last_sent FROM email_codes WHERE email=?",
            (email,)
        ).fetchone()
        if row and now - row[0] < 60:
            return {"sent": True}

        email_hash = keyed_email(email)
        window = now // 3600
        db.execute(
            "DELETE FROM email_request_limits WHERE window_start < ?",
            (window - 1,),
        )
        used = db.execute(
            """SELECT attempts FROM email_request_limits
               WHERE email_hash=? AND window_start=?""",
            (email_hash, window),
        ).fetchone()
        if used and used[0] >= 5:
            raise ValueError("Too many requests for this email")
        db.execute("""INSERT INTO email_request_limits
            (email_hash,window_start,attempts) VALUES (?,?,1)
            ON CONFLICT(email_hash,window_start)
            DO UPDATE SET attempts=attempts+1""",
            (email_hash, window),
        )
        db.execute("""INSERT INTO email_codes VALUES (?,?,?,?,?)
            ON CONFLICT(email) DO UPDATE SET
            code_hash=excluded.code_hash,
            expires_at=excluded.expires_at,
            attempts=0,
            last_sent=excluded.last_sent""",
            (email, code_hash, now + 600, 0, now))

    try:
        send_code(email, code, cfg)
    except (OSError, smtplib.SMTPException, ValueError) as exc:
        with closing(sqlite3.connect(DB_PATH, timeout=15)) as db, db:
            db.execute(
                "DELETE FROM email_codes WHERE email=? AND code_hash=?",
                (email, code_hash)
            )
        raise RuntimeError("Email delivery failed") from exc

    return {"sent": True}

def verify_code(email, code, guest_token=None):
    email = canonical(email)
    if (
        not isinstance(code, str)
        or len(code) != 6
        or not code.isascii()
        or not code.isdecimal()
    ):
        raise ValueError("Invalid code")

    guest_id = None
    if guest_token is not None:
        guest_id = validate_session(guest_token)
        if not guest_id:
            raise ValueError("Invalid guest session")

    now = int(time.time())
    access = secrets.token_urlsafe(48)
    refresh = secrets.token_urlsafe(48)
    expiry = (
        datetime.now(timezone.utc) + timedelta(hours=24)
    ).isoformat()
    refresh_exp = (
        datetime.now(timezone.utc) + timedelta(days=365)
    ).isoformat()

    with closing(sqlite3.connect(DB_PATH, timeout=15)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        setup(db)
        row = db.execute(
            """SELECT code_hash, expires_at, attempts
               FROM email_codes WHERE email=?""",
            (email,)
        ).fetchone()

        if not row or row[1] <= now or row[2] >= 5:
            raise ValueError("Code expired or invalid")

        if not hmac.compare_digest(row[0], digest(email, code)):
            db.execute(
                """UPDATE email_codes SET attempts=attempts+1
                   WHERE email=?""",
                (email,)
            )
            db.commit()
            raise ValueError("Invalid code")

        linked = db.execute(
            "SELECT user_id FROM email_identities WHERE email=?",
            (email,)
        ).fetchone()

        if linked:
            user_id = linked[0]
            if guest_id and guest_id != user_id:
                raise AccountConflict("Email belongs to another account")
        else:
            # A fresh, successfully verified email OTP may recover a
            # previously deleted paid account without restoring its PII.
            from paid_account_recovery import find, consume
            recovery = find(db, "email", email)
            if recovery:
                user_id, original_created_at = recovery
                db.execute(
                    """INSERT INTO users(id, account_type, created_at)
                       VALUES (?, 'guest', ?)""",
                    (user_id, original_created_at),
                )
                consume(db, user_id)
            elif guest_id:
                user_id = guest_id
                existing = db.execute(
                    "SELECT 1 FROM email_identities WHERE user_id=?",
                    (user_id,)
                ).fetchone()
                if existing:
                    raise AccountConflict("Account already linked to email")
            else:
                user_id = str(uuid.uuid4())
                db.execute(
                    "INSERT INTO users(id,account_type) VALUES (?, 'guest')",
                    (user_id,)
                )
            db.execute(
                "INSERT INTO email_identities VALUES (?,?)",
                (email, user_id)
            )

        active = db.execute(
            "SELECT is_active FROM users WHERE id=?",
            (user_id,)
        ).fetchone()
        if not active or not active[0]:
            raise ValueError("Account inactive")

        db.execute("DELETE FROM email_codes WHERE email=?", (email,))
        db.execute(
            """INSERT INTO sessions
               (id,user_id,token_hash,expires_at)
               VALUES (?,?,?,?)""",
            (
                str(uuid.uuid4()), user_id,
                hashlib.sha256(access.encode()).hexdigest(),
                expiry
            )
        )
        store_refresh(db, user_id, refresh, refresh_exp)

    return {
        "user_id": user_id,
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_at": expiry
    }
