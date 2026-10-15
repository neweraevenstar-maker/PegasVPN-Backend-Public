"""Isolated end-to-end email OTP tests: no real SMTP, VPN or production data."""
import hashlib
import os
from pathlib import Path
import smtplib
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import db_migrations
import email_auth
import guest_rate_limit
import rate_limit_identity


class EmailOtpFlowTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.path = root / "isolated.sqlite"
        with sqlite3.connect(self.path) as db:
            db.executescript("""
                CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    account_type TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    is_active INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT
                );
            """)
        db_migrations.apply(self.path)

        for target, attr, value in (
            (email_auth, "DB_PATH", self.path),
            (email_auth, "SECRET_PATH", root / "otp_secret"),
            (guest_rate_limit, "DB", self.path),
            (rate_limit_identity, "SECRET", root / "rate_secret"),
        ):
            p = patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)

        env = patch.dict(os.environ, {
            "PEGASVPN_SMTP_HOST": "smtp-relay.brevo.com",
            "PEGASVPN_SMTP_PORT": "587",
            "PEGASVPN_SMTP_SECURITY": "starttls",
            "PEGASVPN_SMTP_USER": "fixture@smtp-brevo.com",
            "PEGASVPN_SMTP_PASSWORD": "FAKE-TEST-ONLY",
            "PEGASVPN_SMTP_FROM": "noreply@vimvitae.net",
        })
        env.start()
        self.addCleanup(env.stop)
        self.sent = []
        sender = patch.object(
            email_auth, "send_code",
            side_effect=lambda address, code, cfg: self.sent.append(
                (address, code, cfg[0], cfg[3])
            ),
        )
        self.sender = sender.start()
        self.addCleanup(sender.stop)

    def request(self, email="user@example.com", ip="203.0.113.5"):
        return email_auth.request_code(email, ip)

    def code(self):
        return self.sent[-1][1]

    def test_request_and_verify_create_account_and_consume_code(self):
        self.assertEqual(self.request("USER@example.com"), {"sent": True})
        self.assertEqual(len(self.sent), 1)
        address, code, host, sender = self.sent[0]
        self.assertEqual(address, "user@example.com")
        self.assertEqual(host, "smtp-relay.brevo.com")
        self.assertEqual(sender, "noreply@vimvitae.net")
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isascii() and code.isdecimal())

        auth = email_auth.verify_code("USER@example.com", code)
        self.assertTrue(auth["access_token"])
        self.assertTrue(auth["refresh_token"])
        with sqlite3.connect(self.path) as db:
            identity = db.execute(
                "SELECT user_id FROM email_identities WHERE email=?",
                ("user@example.com",),
            ).fetchone()
            self.assertEqual(identity, (auth["user_id"],))
            self.assertIsNone(db.execute(
                "SELECT 1 FROM email_codes WHERE email=?",
                ("user@example.com",),
            ).fetchone())
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id=? AND token_hash=?",
                (auth["user_id"], hashlib.sha256(
                    auth["access_token"].encode()
                ).hexdigest()),
            ).fetchone()[0], 1)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM guest_refresh_tokens WHERE user_id=?",
                (auth["user_id"],),
            ).fetchone()[0], 1)
        with self.assertRaises(ValueError):
            email_auth.verify_code("user@example.com", code)

    def test_four_digit_code_is_rejected(self):
        self.request()
        with self.assertRaisesRegex(ValueError, "Invalid code"):
            email_auth.verify_code("user@example.com", "1234")

    def test_wrong_code_locks_after_five_attempts(self):
        self.request()
        correct = self.code()
        wrong = "000000" if correct != "000000" else "111111"
        for _ in range(5):
            with self.assertRaisesRegex(ValueError, "Invalid code"):
                email_auth.verify_code("user@example.com", wrong)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute(
                "SELECT attempts FROM email_codes WHERE email=?",
                ("user@example.com",),
            ).fetchone()[0], 5)
        with self.assertRaisesRegex(ValueError, "Code expired or invalid"):
            email_auth.verify_code("user@example.com", correct)

    def test_expired_code_is_rejected(self):
        self.request()
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE email_codes SET expires_at=0 WHERE email=?",
                ("user@example.com",),
            )
        with self.assertRaisesRegex(ValueError, "Code expired or invalid"):
            email_auth.verify_code("user@example.com", self.code())

    def test_resend_cooldown_does_not_send_another_email(self):
        self.request()
        self.assertEqual(self.request(), {"sent": True})
        self.assertEqual(len(self.sent), 1)

    def test_sixth_request_from_same_ip_is_rate_limited(self):
        for i in range(5):
            self.request(f"person{i}@example.com")
        with self.assertRaisesRegex(ValueError, "Too many requests"):
            self.request("person6@example.com")
        self.assertEqual(len(self.sent), 5)

    def test_delivery_failure_removes_unusable_code(self):
        self.sender.side_effect = smtplib.SMTPException("simulated failure")
        with self.assertRaisesRegex(RuntimeError, "Email delivery failed"):
            self.request()
        with sqlite3.connect(self.path) as db:
            self.assertIsNone(db.execute(
                "SELECT 1 FROM email_codes WHERE email=?",
                ("user@example.com",),
            ).fetchone())


if __name__ == "__main__":
    unittest.main()
