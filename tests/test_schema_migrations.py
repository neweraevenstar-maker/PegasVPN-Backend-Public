"""Atomic migration preserves existing user and refresh-token records."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from db_migrations import apply


class SchemaMigrationTests(unittest.TestCase):
    def test_preserves_legacy_users_sessions_and_refresh_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.sqlite"
            with sqlite3.connect(path) as db:
                db.executescript("""
                    CREATE TABLE users (
                        id TEXT PRIMARY KEY, account_type TEXT NOT NULL,
                        created_at TEXT NOT NULL, is_active INTEGER DEFAULT 1
                    );
                    CREATE TABLE sessions (
                        id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                        token_hash TEXT NOT NULL, expires_at TEXT NOT NULL,
                        revoked_at TEXT
                    );
                    CREATE TABLE guest_refresh_tokens (
                        user_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
                        expires_at TEXT NOT NULL
                    );
                    INSERT INTO users VALUES ('user1','guest','2026-01-01',1);
                    INSERT INTO sessions VALUES ('s1','user1','token','2099-01-01',NULL);
                    INSERT INTO guest_refresh_tokens
                        VALUES ('user1','refresh','2099-01-01');
                """)
            self.assertTrue(apply(path))
            self.assertFalse(apply(path))
            with sqlite3.connect(path) as db:
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1
                )
                self.assertEqual(
                    db.execute("SELECT token_hash FROM sessions").fetchone()[0],
                    "token",
                )
                self.assertEqual(
                    db.execute(
                        "SELECT user_id,token_hash FROM guest_refresh_tokens"
                    ).fetchone(), ("user1", "refresh")
                )
                self.assertEqual(
                    [r[1] for r in db.execute(
                        "PRAGMA table_info(guest_refresh_tokens)"
                    ) if r[5] > 0], ["token_hash"]
                )
                self.assertIn("paid_account_recovery", {
                    r[0] for r in db.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                })

    def test_unknown_schema_rolls_back_without_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.sqlite"
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE users(id TEXT PRIMARY KEY)")
            with self.assertRaises(RuntimeError):
                apply(path)
            with sqlite3.connect(path) as db:
                self.assertIsNone(db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='schema_migrations'"
                ).fetchone())


if __name__ == "__main__":
    unittest.main()
