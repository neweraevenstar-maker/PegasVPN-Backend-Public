"""Only actually deployed VPN exits are exposed to clients."""
import unittest

from vpn_regions import (
    REGIONS, VIRTUAL_MODES, active_regions, eu_candidates, public_catalog,
)


class VPNRegionTests(unittest.TestCase):
    def test_only_germany_is_currently_live(self):
        self.assertEqual([r.id for r in active_regions()], ["germany"])
        self.assertEqual(
            public_catalog(),
            [{
                "id": "germany",
                "name": "Germany",
                "countryCode": "DE",
                "endpoint": "https://api.vimvitae.net/vpn/provision",
                "isAvailable": True,
            }],
        )

    def test_planned_countries_not_advertised_as_available(self):
        planned = {
            "netherlands", "sweden", "lithuania", "switzerland", "russia"
        }
        self.assertEqual(
            {r.id for r in REGIONS if r.state == "planned"},
            planned,
        )
        self.assertTrue(planned.isdisjoint(
            {entry["id"] for entry in public_catalog()}
        ))

    def test_eu_auto_never_routes_to_planned_or_non_eu_servers(self):
        self.assertEqual([r.id for r in eu_candidates()], ["germany"])
        self.assertIn("eu-auto", VIRTUAL_MODES)
        self.assertNotIn("eu-auto", [r.id for r in REGIONS])

    def test_russia_whitelist_is_a_mode_not_a_fake_exit(self):
        self.assertIn("russia-whitelist", VIRTUAL_MODES)
        self.assertNotIn("russia-whitelist", [r.id for r in REGIONS])


if __name__ == "__main__":
    unittest.main()
