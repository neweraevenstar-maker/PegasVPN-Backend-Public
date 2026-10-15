import hashlib
import hmac
from contextlib import closing
import sqlite3
import time
from pathlib import Path
from runtime_paths import data_dir, db_path

DATA = data_dir()
DB = db_path()
SALT = DATA / ".provision_salt"
MAX_IP = 3
MAX_TOTAL = 50

def initialize():
    with closing(sqlite3.connect(DB, timeout=15)) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS vpn_provision_limits (
            user_id TEXT PRIMARY KEY,
            ip_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL)""")
        db.execute("""CREATE INDEX IF NOT EXISTS idx_provision_time
            ON vpn_provision_limits(created_at)""")

def reserve(user_id, ip):
    if (DATA / f"{user_id}.json").is_file():
        return True
    now = int(time.time())
    cutoff = now - 86400
    digest = hmac.new(
        SALT.read_bytes(), ip.encode(), hashlib.sha256
    ).hexdigest()
    with closing(sqlite3.connect(DB, timeout=15)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute(
            "SELECT 1 FROM vpn_provision_limits WHERE user_id=?",
            (user_id,)
        ).fetchone():
            return True
        total = db.execute(
            "SELECT COUNT(*) FROM vpn_provision_limits WHERE created_at>=?",
            (cutoff,)
        ).fetchone()[0]
        per_ip = db.execute(
            """SELECT COUNT(*) FROM vpn_provision_limits
               WHERE ip_hash=? AND created_at>=?""",
            (digest, cutoff)
        ).fetchone()[0]
        if total >= MAX_TOTAL or per_ip >= MAX_IP:
            return False
        db.execute(
            "INSERT INTO vpn_provision_limits VALUES (?,?,?)",
            (user_id, digest, now)
        )
        return True

initialize()
