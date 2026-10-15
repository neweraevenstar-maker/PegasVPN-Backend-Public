"""Offline SQLite regression tests; never touches a production database."""
import hashlib
import importlib
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


class MultiDeviceRefreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = str(Path(self.tmp.name) / "test.db")
        os.environ["PEGASVPN_DB_PATH"] = self.db_path
        self.addCleanup(os.environ.pop, "PEGASVPN_DB_PATH", None)

        expiry = (
            datetime.now(timezone.utc) + timedelta(days=30)
        ).isoformat()
        with sqlite3.connect(self.db_path) as db:
            db.execute("""
                CREATE TABLE users (
                    id TEXT PRIMARY KEY, is_active INTEGER NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT
                )
            """)
            db.execute("INSERT INTO users VALUES ('alice', 1)")
            db.execute("INSERT INTO users VALUES ('bob', 1)")
            db.execute("""
                CREATE TABLE guest_refresh_tokens (
                    user_id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    expires_at TEXT NOT NULL
                )
            """)
            db.execute(
                "INSERT INTO guest_refresh_tokens VALUES (?,?,?)",
                ("alice", hashlib.sha256(b"legacy").hexdigest(), expiry)
            )

        sys.modules.pop("guest_refresh", None)
        self.refresh = importlib.import_module("guest_refresh")

    def test_migration_preserves_existing_session(self):
        with sqlite3.connect(self.db_path) as db:
            columns = db.execute(
                "PRAGMA table_info(guest_refresh_tokens)"
            ).fetchall()
            pk = [col[1] for col in columns if col[5]]
        self.assertEqual(pk, ["token_hash"])
        result = self.refresh.rotate("legacy")
        self.assertEqual(result["user_id"], "alice")

    def test_two_devices_refresh_independently(self):
        expiry = (
            datetime.now(timezone.utc) + timedelta(days=30)
        ).isoformat()
        with sqlite3.connect(self.db_path) as db:
            self.refresh.store(db, "alice", "device-two", expiry)

        first = self.refresh.rotate("legacy")
        second = self.refresh.rotate("device-two")
        self.assertEqual(first["user_id"], "alice")
        self.assertEqual(second["user_id"], "alice")
        self.assertNotEqual(first["refresh_token"], second["refresh_token"])
        with self.assertRaises(ValueError):
            self.refresh.rotate("legacy")
        self.assertEqual(
            self.refresh.rotate(first["refresh_token"])["user_id"],
            "alice"
        )

    def test_enroll_rejects_duplicate_session(self):
        self.refresh.mint("bob")
        with self.assertRaises(sqlite3.IntegrityError):
            self.refresh.mint("bob")

    def test_revoked_user_cannot_refresh(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE users SET is_active=0 WHERE id='alice'")
        with self.assertRaises(ValueError):
            self.refresh.rotate("legacy")

    def test_delete_all_device_sessions(self):
        expiry = (
            datetime.now(timezone.utc) + timedelta(days=30)
        ).isoformat()
        with sqlite3.connect(self.db_path) as db:
            self.refresh.store(db, "alice", "device-two", expiry)
            db.execute(
                "DELETE FROM guest_refresh_tokens WHERE user_id='alice'"
            )
        for token in ("legacy", "device-two"):
            with self.assertRaises(ValueError):
                self.refresh.rotate(token)


if __name__ == "__main__":
    unittest.main()
