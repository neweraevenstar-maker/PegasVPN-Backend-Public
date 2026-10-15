"""PegasVPN country inventory.

A planned country is NOT a working VPN exit. Only a verified, deployed
location may be published by the /vpn/locations API. No new server is
provisioned by this module.
"""
from dataclasses import dataclass

PROVISIONING_API = "https://api.vimvitae.net/vpn/provision"


@dataclass(frozen=True)
class Region:
    id: str
    name: str
    country_code: str
    state: str
    eu_member: bool


REGIONS = (
    Region("germany", "Germany", "DE", "live", True),
    Region("netherlands", "Netherlands", "NL", "planned", True),
    Region("sweden", "Sweden", "SE", "planned", True),
    Region("lithuania", "Lithuania", "LT", "planned", True),
    Region("switzerland", "Switzerland", "CH", "planned", False),
    Region("russia", "Russia", "RU", "planned", False),
)

# Virtual policy, not a geographic country or a dedicated physical server.
VIRTUAL_MODES = (
    "eu-auto",
    "russia-whitelist",
)


def active_regions():
    return tuple(region for region in REGIONS if region.state == "live")


def public_catalog():
    """Return only actually deployed exits; never advertise planned nodes."""
    return [
        {
            "id": region.id,
            "name": region.name,
            "countryCode": region.country_code,
            "endpoint": PROVISIONING_API,
            "isAvailable": True,
        }
        for region in active_regions()
    ]


def eu_candidates():
    """A future EU-auto selector can use only deployed EU members."""
    return tuple(
        region for region in active_regions() if region.eu_member
    )
