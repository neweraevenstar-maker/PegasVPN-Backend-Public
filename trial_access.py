import os
from contextlib import closing
import sqlite3
from datetime import datetime, timedelta, timezone
from subscription_entitlements import paid_status, parse_date
from runtime_paths import db_path

DB = str(db_path())
TRIAL_DAYS = 7

def trial_status(user_id):
    with closing(sqlite3.connect(DB, timeout=15)) as db, db:
        row = db.execute(
            "SELECT created_at, is_active FROM users WHERE id=?",
            (user_id,)
        ).fetchone()

    result = {
        "has_access": False,
        "trial_active": False,
        "subscription_active": False,
        "trial_ends_at": None,
        "subscription_ends_at": None
    }

    if not row or not row[1]:
        return result

    if os.getenv("PEGASVPN_REQUIRE_APPLE_SUBSCRIPTION") != "1":
        try:
            created = parse_date(row[0])
            expires = created + timedelta(days=TRIAL_DAYS)
            result["trial_ends_at"] = expires.isoformat()
            result["trial_active"] = (
                datetime.now(timezone.utc) < expires
            )
        except (TypeError, ValueError):
            pass

    paid, paid_until = paid_status(user_id)
    result["subscription_active"] = paid
    result["subscription_ends_at"] = paid_until
    result["has_access"] = result["trial_active"] or paid

    return result
