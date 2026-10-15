"""Stable per-installation Apple appAccountToken binding secret."""
import hashlib
import hmac
import os
import time
import uuid

from runtime_paths import data_dir

DATA = data_dir()
SECRET = DATA / ".billing_secret"


def _initialize_secret():
    if SECRET.is_symlink():
        raise RuntimeError("Billing secret must not be a symlink")
    try:
        fd = os.open(
            SECRET,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError:
        # Concurrent workers must share the same durable secret.
        pass
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(os.urandom(32))
            stream.flush()
            os.fsync(stream.fileno())

    for attempt in range(20):
        if SECRET.is_symlink():
            raise RuntimeError("Billing secret must not be a symlink")
        secret = SECRET.read_bytes()
        if len(secret) == 32:
            SECRET.chmod(0o600)
            return
        if attempt < 19:
            time.sleep(0.05)
    raise RuntimeError("Billing secret is missing or incomplete")


_initialize_secret()


def account_token(user_id):
    if not isinstance(user_id, str) or not user_id:
        raise ValueError("Invalid account identifier")
    digest = hmac.new(
        SECRET.read_bytes(),
        user_id.encode(),
        hashlib.sha256,
    ).digest()
    return str(uuid.UUID(bytes=digest[:16], version=4))
