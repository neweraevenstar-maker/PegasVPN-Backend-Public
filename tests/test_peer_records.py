"""Pure path-layout tests for legacy and per-device VPN peers."""
import json
import tempfile
import unittest
import uuid
from pathlib import Path

from peer_records import (
    MAX_DEVICES, all_records, canonical_device_id,
    matches_record_path, record_path, user_records,
)


class PeerRecordsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = Path(self.tmp.name)
        self.user = str(uuid.uuid4())
        self.device = str(uuid.uuid4())

    def test_distinct_device_paths_and_legacy_compatibility(self):
        old = record_path(self.data, self.user)
        new = record_path(self.data, self.user, self.device)
        self.assertEqual(old, self.data / (self.user + ".json"))
        self.assertEqual(
            new, self.data / "peers" / self.user / (self.device + ".json")
        )
        self.assertNotEqual(old, new)
        new.parent.mkdir(parents=True)
        old.write_text(json.dumps({"user_id": self.user}))
        new.write_text(json.dumps({
            "user_id": self.user, "device_id": self.device
        }))
        self.assertEqual(set(user_records(self.data, self.user)), {old, new})
        self.assertEqual(set(all_records(self.data)), {old, new})
        self.assertTrue(matches_record_path(old, {"user_id": self.user}))
        self.assertTrue(matches_record_path(new, {
            "user_id": self.user, "device_id": self.device
        }))

    def test_invalid_device_and_user_ids_cannot_escape_data_root(self):
        for value in ("../other", "invalid", "", "/tmp/escape"):
            with self.assertRaises(ValueError):
                canonical_device_id(value)
        with self.assertRaises(ValueError):
            record_path(self.data, "../outside", self.device)
        with self.assertRaises(ValueError):
            record_path(self.data, "bad/user", self.device)

    def test_mismatched_owner_or_device_is_rejected(self):
        path = record_path(self.data, self.user, self.device)
        self.assertFalse(matches_record_path(path, {
            "user_id": str(uuid.uuid4()), "device_id": self.device
        }))
        self.assertFalse(matches_record_path(path, {
            "user_id": self.user, "device_id": str(uuid.uuid4())
        }))
        self.assertFalse(matches_record_path(path, {"user_id": self.user}))

    def test_device_limit_is_five(self):
        self.assertEqual(MAX_DEVICES, 5)


if __name__ == "__main__":
    unittest.main()
