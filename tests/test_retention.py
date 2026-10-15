"""Retention removes expired operational rows, never live recovery data."""
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
import retention


class RetentionTests(unittest.TestCase):
    def test_cleanup_and_policy_gated_paid_recovery(self):
        now = datetime(2026, 10, 14, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "retention.sqlite")
            with sqlite3.connect(db_path) as db:
                db.executescript("""
                    CREATE TABLE sessions (
                        token_hash TEXT, expires_at TEXT, revoked_at TEXT
                    );
                    CREATE TABLE guest_refresh_tokens(expires_at TEXT);
                    CREATE TABLE email_codes(expires_at INTEGER);
                    CREATE TABLE guest_rate_limits(window_start INTEGER);
                    CREATE TABLE vpn_provision_limits(created_at INTEGER);
                    CREATE TABLE paid_account_recovery(
                        deleted_at TEXT, expires_at TEXT
                    );
                """)
                db.execute(
                    "INSERT INTO sessions VALUES (?, ?, NULL)",
                    ("old", (now - timedelta(days=1)).isoformat()),
                )
                db.execute(
                    "INSERT INTO sessions VALUES (?, ?, NULL)",
                    ("current", (now + timedelta(days=1)).isoformat()),
                )
                db.execute(
                    "INSERT INTO email_codes VALUES (?)", (int(now.timestamp()) - 1,)
                )
                db.execute(
                    "INSERT INTO paid_account_recovery VALUES (?, ?)",
                    ("2026-01-01", "2026-02-01"),
                )
            with patch.object(retention, "DB", db_path):
                with patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("PEGASVPN_PAID_RECOVERY_RETENTION_DAYS", None)
                    result = retention.purge(now)
                self.assertEqual(result["sessions"], 1)
                self.assertEqual(result["email_codes"], 1)
                self.assertEqual(
                    result["paid_account_recovery"],
                    "not_purged_policy_pending",
                )
                with patch.dict(os.environ, {
                    "PEGASVPN_PAID_RECOVERY_RETENTION_DAYS": "30"
                }):
                    result = retention.purge(now)
                self.assertEqual(result["paid_account_recovery"], 1)
            with sqlite3.connect(db_path) as db:
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 1
                )


if __name__ == "__main__":
    unittest.main()
