import os
from contextlib import closing
import sqlite3
from pathlib import Path
from runtime_paths import db_path

from appstoreserverlibrary.models.Environment import Environment
from appstoreserverlibrary.signed_data_verifier import (
    SignedDataVerifier,
    VerificationException,
)

DB = str(db_path())
ROOTS = Path("/etc/onetapvpn/apple-roots")
BUNDLE = "com.pegasvpn.app"

def initialize():
    with closing(sqlite3.connect(DB, timeout=15)) as db, db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS apple_notifications (
                notification_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                event_subtype TEXT,
                original_transaction_id TEXT,
                transaction_id TEXT,
                signed_at INTEGER,
                received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_apple_original
            ON apple_notifications(original_transaction_id)
        """)

def receive(signed_payload):
    from apple_verification_config import verification_target
    target, app_id = verification_target()

    if not isinstance(signed_payload, str):
        raise ValueError("Invalid notification")
    if len(signed_payload) > 100000:
        raise ValueError("Notification too large")

    roots = [
        p.read_bytes()
        for p in sorted(ROOTS.glob("*.cer"))
    ]
    if len(roots) != 3:
        raise RuntimeError("Apple certificates unavailable")

    verifier = SignedDataVerifier(
        roots,
        True,
        Environment.SANDBOX if target == "sandbox"
        else Environment.PRODUCTION,
        BUNDLE,
        app_id
    )

    try:
        notification = verifier.verify_and_decode_notification(
            signed_payload
        )

        data = notification.data
        transaction = None

        if data and data.signedTransactionInfo:
            transaction = verifier.verify_and_decode_signed_transaction(
                data.signedTransactionInfo
            )

    except VerificationException:
        raise ValueError("Invalid Apple signature")

    notification_id = str(notification.notificationUUID or "")
    if not notification_id:
        raise ValueError("Missing notification ID")

    event_type = getattr(
        notification.notificationType,
        "value",
        notification.notificationType
    )
    subtype = getattr(
        notification.subtype,
        "value",
        notification.subtype
    )

    from apple_event_apply import apply_verified_event
    apply_verified_event(notification, transaction)

    with closing(sqlite3.connect(DB, timeout=15)) as db, db:
        db.execute("""
            INSERT OR IGNORE INTO apple_notifications
            (notification_id, event_type, event_subtype,
             original_transaction_id, transaction_id, signed_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            notification_id,
            str(event_type),
            str(subtype) if subtype else None,
            transaction.originalTransactionId if transaction else None,
            transaction.transactionId if transaction else None,
            notification.signedDate
        ))

    return {"received": True}

initialize()
