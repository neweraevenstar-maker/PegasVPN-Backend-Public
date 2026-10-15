"""Email OTP never downgrades to plaintext SMTP."""
import os
import unittest
from unittest.mock import MagicMock, patch
import email_auth


class EmailDeliveryTests(unittest.TestCase):
    def test_starttls_login_and_send(self):
        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        with (
            patch("email_auth.smtplib.SMTP", return_value=smtp),
            patch.dict(os.environ, {
                "PEGASVPN_SMTP_SECURITY": "starttls",
                "PEGASVPN_SMTP_PORT": "587",
            }),
        ):
            email_auth.send_code(
                "recipient@example.test", "123456",
                ["smtp.example.test", "sender", "password",
                 "noreply@example.test"],
            )
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("sender", "password")
        smtp.send_message.assert_called_once()

    def test_ssl_mode_uses_smtp_ssl_not_plain_smtp(self):
        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        with (
            patch("email_auth.smtplib.SMTP_SSL", return_value=smtp),
            patch("email_auth.smtplib.SMTP") as plaintext,
            patch.dict(os.environ, {
                "PEGASVPN_SMTP_SECURITY": "ssl",
                "PEGASVPN_SMTP_PORT": "465",
            }),
        ):
            email_auth.send_code(
                "recipient@example.test", "123456",
                ["smtp.example.test", "sender", "password",
                 "noreply@example.test"],
            )
        plaintext.assert_not_called()
        smtp.login.assert_called_once()

    def test_plaintext_mode_rejected(self):
        with patch.dict(os.environ, {
            "PEGASVPN_SMTP_SECURITY": "none"
        }):
            with self.assertRaises(RuntimeError):
                email_auth.send_code(
                    "recipient@example.test", "123456",
                    ["smtp.example.test", "sender", "password",
                     "noreply@example.test"],
                )


if __name__ == "__main__":
    unittest.main()
