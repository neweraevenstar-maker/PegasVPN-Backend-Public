#!/usr/bin/env python3
"""Read-only PegasVPN paid-release preflight. Never deploys or changes VPN."""
import os
import shutil
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime_paths import data_dir, db_path

REQUIRED_TABLES = {
    "users", "sessions", "guest_refresh_tokens", "apple_identities",
    "email_identities", "subscription_entitlements",
    "apple_notifications", "vpn_provision_limits",
}


def inspect():
    errors = []
    warnings = []
    deployment = os.getenv("PEGASVPN_DEPLOYMENT", "").lower()
    billing = os.getenv("PEGASVPN_BILLING_ENV", "").lower()
    if deployment not in ("production", "staging"):
        errors.append("Explicit PEGASVPN_DEPLOYMENT=production|staging required")
        return errors, warnings
    if billing != ("sandbox" if deployment == "staging" else "production"):
        errors.append("Apple billing environment does not match deployment")
    if os.getenv("PEGASVPN_REQUIRE_APPLE_SUBSCRIPTION") != "1":
        errors.append("Server guest trial still enabled; Apple-only access required")

    try:
        data = data_dir()
        database = db_path()
    except RuntimeError as exc:
        errors.append(str(exc))
        return errors, warnings

    if not data.is_dir():
        errors.append("VPN data directory is missing")
    elif data.stat().st_mode & 0o077:
        errors.append("VPN data directory is accessible to other users")

    if not database.is_file():
        errors.append("VPN database is missing")
    else:
        try:
            # Read-only SQLite: never create/migrate or modify the database.
            with sqlite3.connect(
                database.resolve().as_uri() + "?mode=ro", uri=True
            ) as db:
                tables = {
                    row[0] for row in db.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
            missing = REQUIRED_TABLES - tables
            if missing:
                errors.append(
                    "Missing database tables: " + ", ".join(sorted(missing))
                )
        except sqlite3.Error:
            errors.append("Cannot read VPN database schema")

    if deployment == "production":
        app_id = os.getenv("PEGASVPN_APP_APPLE_ID", "")
        if not app_id.isdecimal() or int(app_id) == 0:
            errors.append("Apple App ID is not configured")
        roots = Path("/etc/onetapvpn/apple-roots")
        if len(list(roots.glob("*.cer"))) != 3:
            errors.append("Exactly three Apple root certificates are required")
        for name in (
            "PEGASVPN_SMTP_HOST", "PEGASVPN_SMTP_USER",
            "PEGASVPN_SMTP_PASSWORD", "PEGASVPN_SMTP_FROM",
        ):
            if not os.getenv(name):
                errors.append(name + " is not configured")
        if not (data / ".billing_secret").is_file():
            errors.append("Billing identity secret is missing")
        if not (data / ".provision_salt").is_file():
            errors.append("Provisioning rate-limit salt is missing")
        if not Path("/etc/wireguard/wg0.conf").is_file():
            errors.append("Live WireGuard configuration is missing")
        if not shutil.which("wg"):
            errors.append("WireGuard command is missing")
    else:
        warnings.append(
            "Staging must use mocked WireGuard operations; live peer mutation is disabled"
        )

    warnings.append(
        "Confirm scheduled peer expiry/revocation and backup/rollback manually"
    )
    warnings.append(
        "Confirm legal privacy notice, recovery-data retention, and Apple terms"
    )
    return errors, warnings


if __name__ == "__main__":
    errors, warnings = inspect()
    for message in errors:
        print("FAIL:", message)
    for message in warnings:
        print("NOTE:", message)
    print("Preflight:", "PASS" if not errors else "BLOCKED")
    raise SystemExit(0 if not errors else 1)
