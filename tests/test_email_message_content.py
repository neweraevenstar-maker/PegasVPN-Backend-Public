"""Offline OTP email content regression test; never contacts SMTP."""
import os
import unittest
from unittest.mock import MagicMock, patch

import email_auth


class EmailMessageContentTests(unittest.TestCase):
    def test_code_recipient_and_expiration(self):
        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        with patch("email_auth.smtplib.SMTP_SSL", return_value=smtp), patch.dict(
            os.environ, {"PEGASVPN_SMTP_SECURITY": "ssl", "PEGASVPN_SMTP_PORT": "465"}
        ):
            email_auth.send_code("recipient@example.test", "012345", [
                "smtp.example.test", "sender", "TEST-ONLY", "noreply@example.test"
            ])
        message = smtp.send_message.call_args.args[0]
        self.assertEqual(message["To"], "recipient@example.test")
        self.assertEqual(message["From"], "noreply@example.test")
        self.assertIn("012345", message.get_content())
        self.assertIn("10 minutes", message.get_content())


if __name__ == "__main__":
    unittest.main()
