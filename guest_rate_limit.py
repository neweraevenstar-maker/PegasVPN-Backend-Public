from contextlib import closing
import sqlite3
import time
from pathlib import Path

from runtime_paths import db_path

DB = db_path()

def initialize():
    with closing(sqlite3.connect(DB, timeout=10)) as conn, conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS guest_rate_limits (
                client_hash TEXT NOT NULL,
                window_start INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(client_hash, window_start)
            )
        """)

def allow_request(client_hash, limit=5, window_seconds=3600):
    now = int(time.time())
    window = now // window_seconds

    with closing(sqlite3.connect(DB, timeout=10)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "DELETE FROM guest_rate_limits WHERE window_start < ?",
            (window - 1,)
        )
        row = conn.execute(
            "SELECT attempts FROM guest_rate_limits WHERE client_hash=? AND window_start=?",
            (client_hash, window)
        ).fetchone()

        if row and row[0] >= limit:
            return False

        conn.execute("""
            INSERT INTO guest_rate_limits(client_hash,window_start,attempts)
            VALUES(?,?,1)
            ON CONFLICT(client_hash,window_start)
            DO UPDATE SET attempts=attempts+1
        """, (client_hash, window))
        return True

initialize()
