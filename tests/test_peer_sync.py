"""Periodic peer reconciliation is ordered and cannot bypass deployment guard."""
import sys
import types
import unittest
from unittest.mock import patch

import sync_peers


class PeerSyncTests(unittest.TestCase):
    def test_expired_peers_revoked_before_paid_peers_restored(self):
        order = []
        reaper = types.ModuleType("trial_reaper")
        reaper.run = lambda: order.append("revoke")
        restore = types.ModuleType("restore_paid")
        restore.restore = lambda: order.append("restore")
        integrity = types.ModuleType("peer_integrity")
        integrity.reconcile_orphans = lambda: order.append("integrity")
        with (
            patch.object(sync_peers, "require_live_wireguard"),
            patch.dict(sys.modules, {
                "trial_reaper": reaper, "restore_paid": restore,
                "peer_integrity": integrity
            }),
        ):
            sync_peers.run()
        self.assertEqual(order, ["revoke", "restore", "integrity"])

    def test_nonproduction_guard_blocks_all_peer_operations(self):
        with patch.object(
            sync_peers, "require_live_wireguard",
            side_effect=RuntimeError("Blocked"),
        ):
            with self.assertRaises(RuntimeError):
                sync_peers.run()


if __name__ == "__main__":
    unittest.main()
