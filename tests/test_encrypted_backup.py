"""Real GnuPG round trip and hostile/accidentally damaged backup rejection."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "encrypted_backup", Path(__file__).parents[1] / "scripts/encrypted_backup.py")
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class EncryptedBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.snapshot = self.root / "snapshot"
        self.snapshot.mkdir(mode=0o700)
        with sqlite3.connect(self.snapshot / "pegasvpn.db") as db:
            db.execute("CREATE TABLE users(id TEXT)")
            db.execute("INSERT INTO users VALUES ('test-user')")
        for name in ("wg0.conf", "wg0-runtime.conf"):
            (self.snapshot / name).write_text("[Interface]\n# fixture only\n")
        self.entries = {}
        for path in self.snapshot.iterdir():
            path.chmod(0o600)
            self.entries[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write_manifest(self.entries)

    def write_manifest(self, entries):
        path = self.snapshot / "manifest.json"
        path.write_text(json.dumps(entries))
        path.chmod(0o600)

    @unittest.skipUnless(shutil.which("gpg") and os.name == "posix", "GnuPG/POSIX required")
    def test_real_round_trip_wrong_passphrase_tamper_and_no_overwrite(self):
        output = self.root / "backup.gpg"
        password = "test fixture passphrase only"
        original = (self.snapshot / "pegasvpn.db").read_bytes()
        receipt = backup.encrypt(self.snapshot, output, password)
        self.assertEqual(receipt["verified_files"], 3)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(backup.verify(output, password, receipt["sha256"]), receipt)
        with self.assertRaises(ValueError):
            backup.verify(output, "different fixture passphrase")
        with self.assertRaises(ValueError):
            backup.verify(output, password, "0" * 64)
        with self.assertRaises(FileExistsError):
            backup.encrypt(self.snapshot, output, password)
        damaged = self.root / "damaged.gpg"
        data = bytearray(output.read_bytes())
        data[len(data) // 2] ^= 0x01
        damaged.write_bytes(data)
        damaged.chmod(0o600)
        with self.assertRaises(ValueError):
            backup.verify(damaged, password)
        self.assertEqual((self.snapshot / "pegasvpn.db").read_bytes(), original)
        self.assertFalse(any(p.name.startswith(".pegas-encrypt-") for p in self.root.iterdir()))

    def test_rejects_changed_snapshot_before_encryption(self):
        (self.snapshot / "wg0.conf").write_text("changed")
        with self.assertRaises(ValueError):
            backup.check_snapshot(self.snapshot)

    def test_rejects_symlink_and_public_permissions(self):
        path = self.snapshot / "wg0.conf"
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            backup.check_snapshot(self.snapshot)
        path.unlink()
        path.symlink_to(self.snapshot / "wg0-runtime.conf")
        with self.assertRaises(ValueError):
            backup.check_snapshot(self.snapshot)

    def test_rejects_manifest_traversal_and_duplicate_keys(self):
        for name in ("../escape", "/absolute", "a/../../escape", "a\\escape", "a//b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                backup.manifest(json.dumps(dict(self.entries, **{name: "0" * 64})))
        raw = json.dumps(self.entries)[:-1] + ',"pegasvpn.db":"' + "0" * 64 + '"}'
        with self.assertRaises(ValueError):
            backup.manifest(raw)

    def test_rejects_archive_links_and_unexpected_entries(self):
        for name, kind in (("wg0.conf", tarfile.SYMTYPE), ("../escape", tarfile.REGTYPE)):
            archive = self.root / "hostile.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                raw = json.dumps(self.entries).encode()
                info = tarfile.TarInfo("manifest.json")
                info.mode, info.size = 0o600, len(raw)
                tar.addfile(info, io.BytesIO(raw))
                info = tarfile.TarInfo(name)
                info.mode, info.type, info.linkname = 0o600, kind, "/etc/passwd"
                tar.addfile(info)
            with self.assertRaises(ValueError):
                backup.check_tar(archive, self.root)
            self.assertFalse((self.root.parent / "escape").exists())

    def test_rejects_empty_short_or_line_break_passphrase(self):
        for value in ("", "short", "long enough\nbut split"):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                backup.validate_passphrase(value)


if __name__ == "__main__":
    unittest.main()
