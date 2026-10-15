"""Explicit deployment mode prevents offline tests from touching production."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import runtime_paths as paths


class RuntimePathsTests(unittest.TestCase):
    def test_no_mode_never_assumes_production(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                paths.data_dir()
            with self.assertRaises(RuntimeError):
                paths.db_path()
            with self.assertRaises(RuntimeError):
                paths.require_live_wireguard()

    def test_tests_mode_uses_only_temporary_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {
                "PEGASVPN_DEPLOYMENT": "tests",
                "PEGASVPN_TEST_DATA_DIR": tmp,
            }):
                self.assertEqual(paths.data_dir(), Path(tmp))
                self.assertEqual(paths.db_path(), Path(tmp) / "pegasvpn.db")
                with self.assertRaises(RuntimeError):
                    paths.require_live_wireguard()

    def test_test_db_override_must_not_point_to_live_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {
                "PEGASVPN_DEPLOYMENT": "tests",
                "PEGASVPN_TEST_DATA_DIR": tmp,
                "PEGASVPN_DB_PATH": "/opt/onetapvpn-api/data/pegasvpn.db",
            }):
                with self.assertRaises(RuntimeError):
                    paths.db_path()

    def test_staging_ignores_database_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {
                "PEGASVPN_DEPLOYMENT": "staging",
                "PEGASVPN_STAGING_DATA_DIR": tmp,
                "PEGASVPN_DB_PATH": "/opt/onetapvpn-api/data/pegasvpn.db",
            }):
                self.assertEqual(paths.db_path(), Path(tmp) / "pegasvpn.db")

    def test_staging_cannot_use_parent_of_live_data(self):
        with patch.dict(os.environ, {
            "PEGASVPN_DEPLOYMENT": "staging",
            "PEGASVPN_STAGING_DATA_DIR": "/opt/onetapvpn-api",
        }):
            with self.assertRaises(RuntimeError):
                paths.data_dir()

    def test_production_requires_explicit_mode(self):
        with patch.dict(os.environ, {
            "PEGASVPN_DEPLOYMENT": "production",
        }):
            self.assertEqual(paths.data_dir(), paths.LIVE_DATA)
            self.assertIsNone(paths.require_live_wireguard())


if __name__ == "__main__":
    unittest.main()
