"""Account deletion and immediate VPN access revocation."""
import base64
import fcntl
import ipaddress
import json
import re
from contextlib import closing
import sqlite3
import subprocess
from pathlib import Path

from guest_auth import DB_PATH
from paid_account_recovery import preserve
from trial_reaper import remove_block, save_config, valid_peer_record
from peer_records import user_records
from runtime_paths import data_dir, require_live_wireguard

DATA = data_dir()
WG = Path("/etc/wireguard/wg0.conf")

def erase_account(user_id):
    require_live_wireguard()
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", user_id):
        raise ValueError("Invalid account")

    with (DATA / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)

        with closing(sqlite3.connect(DB_PATH, timeout=15)) as db, db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")

            row = db.execute(
                "SELECT is_active FROM users WHERE id=?",
                (user_id,)
            ).fetchone()

            if not row or not row[0]:
                raise ValueError("Account unavailable")

            # Revoke every device peer, including the old single-peer layout.
            records = list(user_records(DATA, user_id))
            for record_path in records:
                record = json.loads(record_path.read_text())
                if not valid_peer_record(record_path, record):
                    raise RuntimeError("Invalid VPN peer record")
                key = record["public_key"]
                ip = record["ip"]

                updated, count = remove_block(WG.read_text(), key, ip)
                active = subprocess.check_output(
                    ["wg", "show", "wg0", "peers"],
                    text=True,
                ).split()

                if count:
                    save_config(updated, config_path=WG)

                if key in active:
                    subprocess.run(
                        ["wg", "set", "wg0", "peer", key, "remove"],
                        check=True,
                    )

            tables = {
                row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }

            # Keep only an HMAC identity and the original billing UUID
            # for an active paid subscriber. Do not retain access tokens,
            # plaintext email, Apple subject, or WireGuard configuration.
            paid_recovery_saved = False
            if "subscription_entitlements" in tables:
                from billing_account import SECRET
                paid_recovery_saved = preserve(
                    db, user_id, SECRET.read_bytes()
                )

            if (
                "email_identities" in tables
                and "email_codes" in tables
            ):
                db.execute(
                    """DELETE FROM email_codes WHERE email IN
                       (SELECT email FROM email_identities
                        WHERE user_id=?)""",
                    (user_id,)
                )

            for table in (
                "sessions",
                "guest_refresh_tokens",
                "apple_identities",
                "email_identities",
                "subscription_entitlements",
                "vpn_provision_limits",
            ):
                if table in tables:
                    db.execute(
                        f"DELETE FROM {table} WHERE user_id=?",
                        (user_id,)
                    )

            db.execute(
                "DELETE FROM users WHERE id=?",
                (user_id,)
            )

            for record_path in records:
                record_path.unlink()
            peer_folder = DATA / "peers" / user_id
            if peer_folder.is_dir() and not peer_folder.is_symlink():
                try:
                    peer_folder.rmdir()
                except OSError:
                    # Unrelated files must not be removed by account deletion.
                    pass

    return {"deleted": True, "paid_recovery_saved": paid_recovery_saved}
