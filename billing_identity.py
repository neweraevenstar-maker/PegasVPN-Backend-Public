"""Require an independently verified Apple/email identity for new purchases.

Guest VPN access remains supported, but guest-only accounts cannot buy
an auto-renewing subscription whose ownership they could not later prove.
"""


def has_verified_identity(db, user_id):
    if not user_id:
        return False
    tables = {
        row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    for table in ("apple_identities", "email_identities"):
        if table not in tables:
            continue
        if db.execute(
            f"SELECT 1 FROM {table} WHERE user_id=? LIMIT 1",
            (user_id,),
        ).fetchone():
            return True
    return False
