"""Synchronize live WireGuard peers with verified Apple entitlement state.

Run only as a separately configured production systemd job AFTER staged
testing and backup. Importing this module does not change WireGuard.
"""
from runtime_paths import require_live_wireguard


def run():
    require_live_wireguard()
    # First revoke every expired/refunded peer, then re-enable paid peers
    # that were previously removed while awaiting a verified renewal.
    from trial_reaper import run as revoke_expired
    from restore_paid import restore as restore_paid
    revoke_expired()
    restore_paid()
    # Detect unmanaged peers in the reserved VPN address pool after a
    # crash/restart. Removal requires explicit operator authorization.
    from peer_integrity import reconcile_orphans
    reconcile_orphans()


if __name__ == "__main__":
    run()
