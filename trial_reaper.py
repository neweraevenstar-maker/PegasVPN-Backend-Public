import base64
import fcntl
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from trial_access import trial_status
from runtime_paths import data_dir, require_live_wireguard
from peer_records import all_records, matches_record_path

DATA = data_dir()
WG = Path("/etc/wireguard/wg0.conf")
LOCK = DATA / ".lock"
MAX_CONFIG_BACKUPS = 10

def valid_peer_record(path, record):
    """Never remove a peer based on an unexpected or malformed JSON file."""
    if path.is_symlink() or not isinstance(record, dict):
        return False
    key = record.get("public_key")
    ip = record.get("ip")
    if (
        not matches_record_path(path, record)
        or not isinstance(key, str)
        or not isinstance(ip, str)
        or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", key)
    ):
        return False
    try:
        if len(base64.b64decode(key, validate=True)) != 32:
            return False
        address = ipaddress.ip_address(ip)
        return (
            address.version == 4
            and address in ipaddress.ip_network("10.66.66.0/24")
        )
    except (ValueError, TypeError):
        return False


def remove_block(text, key, ip):
    parts = re.split(r'(?=^\[Peer\][ \t]*$)', text, flags=re.M)
    keep = []
    removed = 0

    for part in parts:
        lines = part.splitlines()
        if not lines or lines[0].strip() != "[Peer]":
            keep.append(part)
            continue

        values = {}
        for line in lines[1:]:
            if "=" in line:
                k, v = line.split("=", 1)
                values[k.strip().lower()] = v.strip()

        if values.get("publickey") == key:
            if values.get("allowedips") != ip + "/32":
                raise RuntimeError("Peer IP mismatch")
            removed += 1
        else:
            keep.append(part)

    if removed > 1:
        raise RuntimeError("Duplicate WireGuard peer")
    return "".join(keep), removed

def save_config(text, config_path=None):
    require_live_wireguard()
    target = Path(config_path) if config_path is not None else WG
    backup = str(target) + ".peer-backup-" + datetime.now().strftime(
        "%Y%m%d-%H%M%S-%f"
    )
    shutil.copy2(target, backup)
    os.chmod(backup, 0o600)
    fd, temp = tempfile.mkstemp(dir=str(target.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, target)
        # The backup and current config both contain the server's
        # private key. Bound local backup retention after success.
        backups = sorted(
            path for path in target.parent.glob(
                target.name + ".peer-backup-*"
            )
            if path.is_file() and not path.is_symlink()
        )
        for old in backups[:-MAX_CONFIG_BACKUPS]:
            old.unlink()
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

def run():
    require_live_wireguard()
    revoked = 0
    failures = 0
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)

        for path in all_records(DATA):
            try:
                record = json.loads(path.read_text())
                if not valid_peer_record(path, record):
                    continue
                user = record["user_id"]
                key = record["public_key"]
                ip = record["ip"]
                if trial_status(user)["has_access"]:
                    continue

                current = WG.read_text()
                updated, removed = remove_block(current, key, ip)

                if removed:
                    save_config(updated)

                active = subprocess.check_output(
                    ["wg", "show", "wg0", "peers"], text=True
                ).split()

                if key in active:
                    subprocess.run(
                        ["wg", "set", "wg0", "peer", key, "remove"],
                        check=True
                    )
                    revoked += 1
            except Exception as e:
                failures += 1
                print("Peer revocation failed:", path.name, type(e).__name__)

    print("Expired active peers removed:", revoked)
    if failures:
        raise RuntimeError(f"{failures} peer revocations failed")

if __name__ == "__main__":
    run()
