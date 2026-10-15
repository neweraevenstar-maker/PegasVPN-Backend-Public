import base64
import fcntl
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path
from subscription_entitlements import paid_status
from runtime_paths import data_dir, require_live_wireguard
from trial_reaper import save_config, valid_peer_record
from peer_records import all_records

DATA = data_dir()
WG = Path("/etc/wireguard/wg0.conf")
LOCK = DATA / ".lock"

def valid_key(value):
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except Exception:
        return False

def restore():
    require_live_wireguard()
    restored = 0
    failures = 0

    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)

        for path in all_records(DATA):
            try:
                record = json.loads(path.read_text())
                user = record["user_id"]
                key = record["public_key"]
                ip = record["ip"]

                if not valid_peer_record(path, record):
                    continue

                paid, _ = paid_status(user)
                if not paid:
                    continue

                current = WG.read_text()
                blocks = re.split(
                    r'(?=^\[Peer\][ \t]*$)',
                    current,
                    flags=re.M
                )
                found = False

                for block in blocks:
                    if not block.startswith("[Peer]"):
                        continue
                    values = {}
                    for line in block.splitlines()[1:]:
                        if "=" in line:
                            k, v = line.split("=", 1)
                            values[k.strip().lower()] = v.strip()
                    if values.get("publickey") == key:
                        if values.get("allowedips") != ip + "/32":
                            raise RuntimeError("Peer IP mismatch")
                        found = True
                    elif values.get("allowedips") == ip + "/32":
                        raise RuntimeError("IP already assigned in config")

                allowed = subprocess.check_output(
                    ["wg", "show", "wg0", "allowed-ips"],
                    text=True
                )

                for line in allowed.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] != key:
                        if ip + "/32" in parts[1:]:
                            raise RuntimeError("IP already assigned")

                subprocess.run(
                    ["wg", "set", "wg0", "peer", key,
                     "allowed-ips", ip + "/32"],
                    check=True
                )

                if not found:
                    save_config(
                        current
                        + "\n[Peer]\n"
                        + f"PublicKey = {key}\n"
                        + f"AllowedIPs = {ip}/32\n",
                        config_path=WG,
                    )

                restored += 1

            except Exception as error:
                failures += 1
                print("Paid peer restore failed:", path.name, type(error).__name__)

    print("Eligible paid peers synchronized:", restored)
    if failures:
        raise RuntimeError(f"{failures} paid peer restorations failed")

if __name__ == "__main__":
    restore()
