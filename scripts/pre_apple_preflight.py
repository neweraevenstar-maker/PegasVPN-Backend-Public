#!/usr/bin/env python3
"""Read-only pre-Apple production readiness report. Never deploys or edits."""
import os
import shutil
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime_paths import deployment, data_dir, db_path

REQUIRED = {"users", "sessions", "guest_refresh_tokens"}
SMTP = ("PEGASVPN_SMTP_HOST", "PEGASVPN_SMTP_USER",
        "PEGASVPN_SMTP_PASSWORD", "PEGASVPN_SMTP_FROM")


def check():
    blockers, warnings = [], []
    if deployment() != "production":
        blockers.append("Production deployment mode is not configured")
        return blockers, warnings
    if os.getenv("PEGASVPN_BILLING_ENV") == "sandbox":
        blockers.append("Sandbox Apple billing forbidden on production")
    if os.getenv("PEGASVPN_REQUIRE_APPLE_SUBSCRIPTION") == "1":
        blockers.append("Apple-only policy cannot start before App Store approval")
    if not os.getenv("ONETAPVPN_ADMIN_TOKEN"):
        blockers.append("Internal provisioning admin token is missing")

    try:
        folder = data_dir()
        db_file = db_path()
        if not folder.is_dir() or folder.stat().st_mode & 0o077:
            blockers.append("Production data folder missing or not private")
        if not db_file.is_file() or db_file.is_symlink():
            blockers.append("Production database missing or unsafe")
        else:
            with sqlite3.connect(
                db_file.resolve().as_uri() + "?mode=ro", uri=True
            ) as db:
                names = {
                    row[0] for row in db.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                missing = REQUIRED - names
                if missing:
                    blockers.append(
                        "Database migration needed: " + ",".join(sorted(missing))
                    )
                if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    blockers.append("Database quick_check failed")
    except (OSError, sqlite3.Error, RuntimeError) as exc:
        blockers.append("Database readiness: " + type(exc).__name__)

    if not shutil.which("wg"):
        blockers.append("WireGuard command not installed")
    if not Path("/etc/wireguard/wg0.conf").is_file():
        blockers.append("WireGuard config missing")
    missing_smtp = [k for k in SMTP if not os.getenv(k)]
    if missing_smtp:
        blockers.append("SMTP credentials missing: " + ", ".join(missing_smtp))
    if os.getenv("PEGASVPN_SMTP_SECURITY", "starttls") not in ("ssl", "starttls"):
        blockers.append("Encrypted SMTP transport not configured")
    if not Path("/etc/onetapvpn/pegasvpn.env").is_file():
        blockers.append("Private service environment file missing")
    if not os.getenv("PEGASVPN_CONFIRM_CLIENT_KEY_V2_ROLLOUT"):
        warnings.append("Do not deploy client-key-v2 backend until compatible iOS client is available")
    if not os.getenv("PEGASVPN_PAID_RECOVERY_RETENTION_DAYS"):
        warnings.append("Paid-account recovery retention requires policy approval")
    if not os.getenv("PEGASVPN_LOCAL_LOG_RETENTION_DAYS"):
        warnings.append("App-owned log retention is not configured")
    warnings.append("Nginx/journald/hosting logs and backups require separate retention configuration")
    return blockers, warnings


if __name__ == "__main__":
    blockers, warnings = check()
    for item in blockers:
        print("BLOCKED:", item)
    for item in warnings:
        print("NOTE:", item)
    print("PRE-APPLE:", "READY" if not blockers else "NOT READY")
    raise SystemExit(0 if not blockers else 1)
