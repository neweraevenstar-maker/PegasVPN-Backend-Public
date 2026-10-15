"""Bounded deletion of expired operational data, without touching VPN peers.

Paid account-recovery data requires an approved explicit retention policy.
Importing this module does not mutate the database.
"""
import os
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from runtime_paths import db_path, data_dir

DB = db_path()


def purge(now=None):
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("Timezone-aware time required")
    timestamp = int(current.timestamp())
    iso = current.isoformat()
    seven_days_ago = (current - timedelta(days=7)).isoformat()
    report = {}

    with closing(sqlite3.connect(DB, timeout=30)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        tables = {
            r[0] for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

        def remove(table, where, params):
            if table in tables:
                count = db.execute(
                    f"DELETE FROM {table} WHERE {where}", params
                ).rowcount
                report[table] = count

        remove("sessions",
               "expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)",
               (iso, seven_days_ago))
        remove("guest_refresh_tokens", "expires_at < ?", (iso,))
        remove("email_codes", "expires_at < ?", (timestamp,))
        remove("guest_rate_limits", "window_start < ?",
               (timestamp // 3600 - 2,))
        remove("email_request_limits", "window_start < ?",
               (timestamp // 3600 - 2,))
        remove("vpn_provision_limits", "created_at < ?",
               (timestamp - 86400,))
        if (
            "apple_reconcile_attempts" in tables
            and "subscription_entitlements" in tables
        ):
            report["apple_reconcile_attempts"] = db.execute(
                """DELETE FROM apple_reconcile_attempts
                   WHERE original_transaction_id NOT IN (
                       SELECT original_transaction_id
                       FROM subscription_entitlements
                   )"""
            ).rowcount

        days_raw = os.getenv("PEGASVPN_PAID_RECOVERY_RETENTION_DAYS")
        if days_raw:
            if not days_raw.isdecimal() or not 1 <= int(days_raw) <= 400:
                raise RuntimeError("Invalid approved recovery retention days")
            # Never purge a still-current Apple entitlement solely because
            # the user deleted their PegasVPN account some time ago.
            cutoff = (current - timedelta(days=int(days_raw))).isoformat()
            remove(
                "paid_account_recovery",
                "julianday(deleted_at) < julianday(?) AND "
                "julianday(expires_at) < julianday(?)",
                (cutoff, iso),
            )
        else:
            report["paid_account_recovery"] = "not_purged_policy_pending"

        notifications = os.getenv("PEGASVPN_NOTIFICATION_RETENTION_DAYS")
        if notifications:
            if not notifications.isdecimal() or not 180 <= int(notifications) <= 730:
                raise RuntimeError("Invalid Apple notification retention policy")
            cutoff = (current - timedelta(days=int(notifications))).isoformat()
            remove("apple_notifications",
                   "julianday(received_at) < julianday(?)", (cutoff,))

    log_days = os.getenv("PEGASVPN_LOCAL_LOG_RETENTION_DAYS")
    if log_days:
        if not log_days.isdecimal() or not 1 <= int(log_days) <= 90:
            raise RuntimeError("Invalid local log retention policy")
        folder = data_dir() / "logs"
        if folder.is_symlink():
            raise RuntimeError("Unsafe log directory")
        removed = 0
        if folder.is_dir():
            cutoff_seconds = timestamp - int(log_days) * 86400
            for path in folder.glob("*.log"):
                if path.is_file() and not path.is_symlink():
                    if path.stat().st_mtime < cutoff_seconds:
                        path.unlink()
                        removed += 1
        report["local_logs"] = removed
    return report


if __name__ == "__main__":
    print(purge())
