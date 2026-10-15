"""Detect and optionally remove orphaned PegasVPN WireGuard peers.

Unknown peers are never deleted by default. Explicit opt-in is required
because an existing operator-managed peer might share the interface.
"""
import fcntl
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path

from peer_records import all_records
from runtime_paths import data_dir, require_live_wireguard
from trial_reaper import remove_block, save_config, valid_peer_record
from trial_access import trial_status

DATA = data_dir()
WG = Path("/etc/wireguard/wg0.conf")
NETWORK = ipaddress.ip_network("10.66.66.0/24")


def managed_ip(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return (
            net.version == 4 and net.prefixlen == 32
            and net.network_address in NETWORK
            and 10 <= int(str(net.network_address).split(".")[-1]) < 250
        )
    except ValueError:
        return False


def known_peers():
    known = {}
    for path in all_records(DATA):
        record = json.loads(path.read_text())
        if not valid_peer_record(path, record):
            raise RuntimeError("Malformed managed peer record")
        key, ip = record["public_key"], record["ip"] + "/32"
        if key in known:
            raise RuntimeError("Duplicate peer key in managed records")
        known[key] = ip
    return known


def config_peers(content):
    entries = {}
    for block in re.split(r"(?=^\[Peer\][ \t]*$)", content, flags=re.M):
        if not block.lstrip().startswith("[Peer]"):
            continue
        props = {}
        for line in block.splitlines()[1:]:
            if "=" in line:
                k, v = line.split("=", 1)
                props[k.strip().lower()] = v.strip()
        key, ips = props.get("publickey"), props.get("allowedips")
        if key and ips and managed_ip(ips):
            if key in entries:
                raise RuntimeError("Duplicate managed peer in wg0.conf")
            entries[key] = ips
    return entries


def reconcile_orphans():
    require_live_wireguard()
    with (DATA / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        records = known_peers()
        # All known peers with expired access are already removed by
        # trial_reaper; this pass catches stale/orphan runtime entries.
        content = WG.read_text()
        configured = config_peers(content)
        output = subprocess.check_output(
            ["wg", "show", "wg0", "allowed-ips"], text=True
        )
        runtime = {}
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                managed = [ip for ip in parts[1:] if managed_ip(ip)]
                if managed:
                    runtime[parts[0]] = managed[0]

        orphans = {}
        for source in (configured, runtime):
            for key, ip in source.items():
                if key not in records:
                    if key in orphans and orphans[key] != ip:
                        raise RuntimeError("Orphan peer IP collision")
                    orphans[key] = ip
                elif records[key] != ip:
                    raise RuntimeError("Managed peer IP collision")
        if not orphans:
            return {"orphans": 0, "removed": 0}
        if os.getenv("PEGASVPN_REMOVE_ORPHAN_PEERS") != "1":
            raise RuntimeError(
                f"{len(orphans)} unmanaged WireGuard peers in reserved pool; "
                "explicit operator approval required"
            )

        updated = content
        for key, ip in orphans.items():
            updated, _ = remove_block(updated, key, ip.split("/")[0])
        if updated != content:
            save_config(updated, config_path=WG)
        for key in orphans:
            if key in runtime:
                subprocess.run(
                    ["wg", "set", "wg0", "peer", key, "remove"], check=True
                )
        return {"orphans": len(orphans), "removed": len(orphans)}


if __name__ == "__main__":
    print(reconcile_orphans())
