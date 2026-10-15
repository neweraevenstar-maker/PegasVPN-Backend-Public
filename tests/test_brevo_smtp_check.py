"""Offline Brevo SMTP integration checks; no real mail or credentials."""
import importlib.util
import io
import os
from contextlib import redirect_stdout
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

import email_auth

PATH = Path(__file__).resolve().parents[1] / "scripts" / "brevo_smtp_check.py"
SPEC = importlib.util.spec_from_file_location("brevo_smtp_check", PATH)
brevo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(brevo)

ENV = {
    "PEGASVPN_SMTP_HOST": "smtp-relay.brevo.com",
    "PEGASVPN_SMTP_PORT": "465",
    "PEGASVPN_SMTP_SECURITY": "ssl",
    "PEGASVPN_SMTP_USER": "test-user@smtp-brevo.com",
    "PEGASVPN_SMTP_PASSWORD": "TEST-SECRET-NEVER-PRINT",
    "PEGASVPN_SMTP_FROM": "noreply@vimvitae.net",
}


class BrevoSmtpTests(unittest.TestCase):
    def test_ssl_465_configuration(self):
        cfg = brevo.config(ENV)
        self.assertEqual((cfg["host"], cfg["port"], cfg["mode"]),
                         ("smtp-relay.brevo.com", 465, "ssl"))

    def test_starttls_587_configuration(self):
        cfg = brevo.config(dict(ENV, PEGASVPN_SMTP_PORT="587",
                                PEGASVPN_SMTP_SECURITY="starttls"))
        self.assertEqual((cfg["port"], cfg["mode"]), (587, "starttls"))

    def test_reject_missing_smtp_key(self):
        env = dict(ENV)
        del env["PEGASVPN_SMTP_PASSWORD"]
        with self.assertRaises(brevo.ConfigError):
            brevo.config(env)

    def test_reject_plaintext_and_mismatched_ports(self):
        for mode, port in (("none", "587"), ("ssl", "587"),
                           ("starttls", "465")):
            with self.subTest(mode=mode, port=port):
                with self.assertRaises(brevo.ConfigError):
                    brevo.config(dict(ENV, PEGASVPN_SMTP_SECURITY=mode,
                                      PEGASVPN_SMTP_PORT=port))

    def test_reject_unexpected_host_or_sender(self):
        for change in ({"PEGASVPN_SMTP_HOST": "other.example.org"},
                       {"PEGASVPN_SMTP_FROM": "admin@elsewhere.test"}):
            with self.assertRaises(brevo.ConfigError):
                brevo.config(dict(ENV, **change))

    def test_default_mode_never_connects_or_prints_secret(self):
        output = io.StringIO()
        with (
            patch.dict(os.environ, ENV, clear=True),
            patch.object(brevo.smtplib, "SMTP_SSL") as smtp,
            redirect_stdout(output),
        ):
            self.assertEqual(brevo.main([]), 0)
        smtp.assert_not_called()
        self.assertNotIn(ENV["PEGASVPN_SMTP_PASSWORD"], output.getvalue())

    def test_explicit_ssl_test_uses_tls_and_sends_no_code(self):
        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        with (
            patch.object(brevo.smtplib, "SMTP_SSL", return_value=smtp) as secure,
            patch.object(brevo.smtplib, "SMTP") as plaintext,
        ):
            brevo.send_test(brevo.config(ENV), "admin@vimvitae.net")
        secure.assert_called_once()
        plaintext.assert_not_called()
        smtp.login.assert_called_once_with(
            ENV["PEGASVPN_SMTP_USER"], ENV["PEGASVPN_SMTP_PASSWORD"]
        )
        message = smtp.send_message.call_args.args[0]
        self.assertEqual(message["To"], "admin@vimvitae.net")
        self.assertIn("NOT a login code", message.get_content())

    def test_reject_header_injection(self):
        with self.assertRaises(brevo.ConfigError):
            brevo.send_test(brevo.config(ENV), "a@b.test\nBcc:other@c.test")

    def test_existing_otp_backend_accepts_brevo_configuration(self):
        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        with (
            patch.dict(os.environ, ENV, clear=True),
            patch.object(email_auth.smtplib, "SMTP_SSL", return_value=smtp),
            patch.object(email_auth.smtplib, "SMTP") as plaintext,
        ):
            email_auth.send_code(
                "user@example.org", "123456",
                [ENV["PEGASVPN_SMTP_HOST"], ENV["PEGASVPN_SMTP_USER"],
                 ENV["PEGASVPN_SMTP_PASSWORD"], ENV["PEGASVPN_SMTP_FROM"]],
            )
        plaintext.assert_not_called()
        msg = smtp.send_message.call_args.args[0]
        self.assertIn("123456", msg.get_content())
        self.assertEqual(msg["From"], "noreply@vimvitae.net")


if __name__ == "__main__":
    unittest.main()
