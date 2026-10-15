import os
import time
from datetime import datetime, timezone
from pathlib import Path

from appstoreserverlibrary.models.Environment import Environment
from appstoreserverlibrary.signed_data_verifier import (
    SignedDataVerifier,
    VerificationException,
)

ROOTS = Path("/etc/onetapvpn/apple-roots")
BUNDLE = "com.pegasvpn.app"
PRODUCTS = {
    "com.pegasvpn.subscription.monthly",
    "com.pegasvpn.subscription.yearly",
}

def verify_transaction(signed_transaction):
    if not isinstance(signed_transaction, str):
        raise ValueError("Invalid transaction")
    if len(signed_transaction) > 32768:
        raise ValueError("Transaction too large")

    roots = [
        p.read_bytes() for p in sorted(ROOTS.glob("*.cer"))
    ]
    if len(roots) != 3:
        raise RuntimeError("Apple certificates missing")

    from apple_verification_config import verification_target
    target, app_id = verification_target()
    environment = (
        Environment.SANDBOX if target == "sandbox"
        else Environment.PRODUCTION
    )
    verifier = SignedDataVerifier(
        roots, True, environment, BUNDLE, app_id
    )
    try:
        transaction = verifier.verify_and_decode_signed_transaction(
            signed_transaction
        )
    except VerificationException as exc:
        raise ValueError("Apple signature not verified") from exc

    if transaction.productId not in PRODUCTS:
        raise ValueError("Unknown subscription product")

    if not transaction.originalTransactionId:
        raise ValueError("Missing transaction identity")

    if transaction.revocationDate is not None:
        raise ValueError("Purchase revoked")

    if transaction.isUpgraded is True:
        raise ValueError("Subscription upgraded")

    expiration = transaction.expiresDate
    if not expiration or expiration <= int(time.time() * 1000):
        raise ValueError("Subscription expired")

    if not transaction.appAccountToken:
        raise ValueError("Account binding missing")

    expires_at = datetime.fromtimestamp(
        expiration / 1000, tz=timezone.utc
    ).isoformat()

    return {
        "product_id": transaction.productId,
        "original_transaction_id": transaction.originalTransactionId,
        "app_account_token": str(transaction.appAccountToken),
        "expires_at": expires_at,
    }
