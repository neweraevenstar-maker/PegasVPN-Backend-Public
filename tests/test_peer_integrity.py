"""Orphan detection must not delete unmanaged peers by default."""
import unittest
from peer_integrity import config_peers, managed_ip


class PeerIntegrityTests(unittest.TestCase):
    def test_reserved_ipv4_pool_only(self):
        self.assertTrue(managed_ip("10.66.66.10/32"))
        self.assertTrue(managed_ip("10.66.66.249/32"))
        self.assertFalse(managed_ip("10.66.66.9/32"))
        self.assertFalse(managed_ip("10.66.66.250/32"))
        self.assertFalse(managed_ip("192.168.1.1/32"))
        self.assertFalse(managed_ip("10.66.66.0/24"))

    def test_only_managed_peers_parsed(self):
        conf = """[Interface]
PrivateKey = dummy
[Peer]
PublicKey = managedkey
AllowedIPs = 10.66.66.11/32
[Peer]
PublicKey = otherkey
AllowedIPs = 172.16.1.1/32
"""
        self.assertEqual(
            config_peers(conf), {"managedkey": "10.66.66.11/32"}
        )

    def test_duplicate_managed_key_is_rejected(self):
        conf = (
            "[Peer]\nPublicKey = key\nAllowedIPs = 10.66.66.10/32\n"
            "[Peer]\nPublicKey = key\nAllowedIPs = 10.66.66.11/32\n"
        )
        with self.assertRaises(RuntimeError):
            config_peers(conf)


if __name__ == "__main__":
    unittest.main()
