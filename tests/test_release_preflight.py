"""Paid-launch preflight must fail closed and remain read-only."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class ReleasePreflightTests(unittest.TestCase):
    def setUp(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "scripts" / "release_preflight.py"
        )
        spec = importlib.util.spec_from_file_location(
            "isolated_release_preflight", source
        )
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_unset_environment_blocks_release(self):
        with patch.dict(os.environ, {
            "PEGASVPN_DEPLOYMENT": "",
            "PEGASVPN_BILLING_ENV": "",
        }):
            errors, _ = self.module.inspect()
        self.assertTrue(errors)

    def test_staging_without_directory_is_rejected(self):
        with patch.dict(os.environ, {
            "PEGASVPN_DEPLOYMENT": "staging",
            "PEGASVPN_BILLING_ENV": "sandbox",
            "PEGASVPN_REQUIRE_APPLE_SUBSCRIPTION": "1",
            "PEGASVPN_STAGING_DATA_DIR": "",
        }):
            errors, _ = self.module.inspect()
        self.assertTrue(any("STAGING_DATA_DIR" in e for e in errors))

    def test_staging_does_not_pass_with_server_trial_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {
                "PEGASVPN_DEPLOYMENT": "staging",
                "PEGASVPN_BILLING_ENV": "sandbox",
                "PEGASVPN_REQUIRE_APPLE_SUBSCRIPTION": "0",
                "PEGASVPN_STAGING_DATA_DIR": tmp,
            }):
                errors, _ = self.module.inspect()
        self.assertTrue(any("Apple-only" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
