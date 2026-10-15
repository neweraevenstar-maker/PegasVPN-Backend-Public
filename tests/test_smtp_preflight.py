import contextlib
import io
import json
import smtplib
import ssl
import unittest
from unittest.mock import MagicMock, patch
from scripts import smtp_preflight as module


class SMTPPreflightTests(unittest.TestCase):
    def client(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.ehlo.return_value = (250, b'OK')
        client.has_extn.return_value = True
        client.sock.version.return_value = 'TLSv1.3'
        return client

    def test_starttls_verifies_certificate_without_login_or_mail(self):
        client = self.client()
        with patch.object(module.smtplib, 'SMTP', return_value=client):
            result = module.probe('smtp.example.test')
        ctx = client.starttls.call_args.kwargs['context']
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(client.ehlo.call_count, 2)
        client.login.assert_not_called()
        client.send_message.assert_not_called()
        self.assertFalse(result['email_sent'])

    def test_implicit_tls_never_opens_plaintext_connection(self):
        client = self.client()
        with patch.object(module.smtplib, 'SMTP_SSL', return_value=client) as tls, patch.object(module.smtplib, 'SMTP') as plain:
            module.probe('smtp.example.test', security='ssl')
        plain.assert_not_called()
        self.assertEqual(tls.call_args.args[1], 465)
        self.assertTrue(tls.call_args.kwargs['context'].check_hostname)
        client.starttls.assert_not_called()
        client.login.assert_not_called()

    def test_missing_starttls_fails_closed(self):
        client = self.client()
        client.has_extn.return_value = False
        with patch.object(module.smtplib, 'SMTP', return_value=client):
            with self.assertRaises(smtplib.SMTPNotSupportedError):
                module.probe('smtp.example.test')
        client.login.assert_not_called()

    def test_certificate_failure_not_retried_without_tls(self):
        client = self.client()
        client.starttls.side_effect = ssl.SSLCertVerificationError('private diagnostic')
        with patch.object(module.smtplib, 'SMTP', return_value=client) as connect:
            with self.assertRaises(ssl.SSLCertVerificationError):
                module.probe('smtp.example.test')
        self.assertEqual(connect.call_count, 1)
        client.login.assert_not_called()

    def test_failure_report_omits_server_details(self):
        output = io.StringIO()
        with patch.object(module, 'probe', side_effect=smtplib.SMTPException('secret@example.test')), contextlib.redirect_stdout(output):
            self.assertEqual(module.main(['--host', 'smtp.example.test']), 1)
        self.assertNotIn('secret', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['transport'], 'failed')

    def test_bad_input_rejected_before_network(self):
        with patch.object(module.smtplib, 'SMTP') as connect:
            for kwargs in ({'security': 'none'}, {'port': 0}, {'port': 65536}):
                with self.assertRaises(ValueError):
                    module.probe('smtp.example.test', **kwargs)
            with self.assertRaises(ValueError):
                module.probe('user:password@smtp.example.test')
        connect.assert_not_called()

    def test_bad_ehlo_and_old_tls_rejected(self):
        for stage in ('ehlo', 'tls'):
            client = self.client()
            if stage == 'ehlo':
                client.ehlo.return_value = (500, b'No')
            else:
                client.sock.version.return_value = 'TLSv1'
            with patch.object(module.smtplib, 'SMTP', return_value=client):
                with self.assertRaises((smtplib.SMTPException, ssl.SSLError)):
                    module.probe('smtp.example.test')
