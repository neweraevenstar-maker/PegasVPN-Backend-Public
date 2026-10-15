"""Pseudonymize client IPs before storing abuse-prevention counters.

A raw SHA-256 of an IPv4 address is guessable by exhaustive enumeration.
Use a separate, random installation secret and purpose-separated HMAC.
"""
import hashlib
import hmac
import os
import time

from runtime_paths import data_dir

SECRET = data_dir() / ".rate_limit_secret"


def _secret():
    if SECRET.is_symlink():
        raise RuntimeError("Unsafe rate-limit secret")
    try:
        fd = os.open(
            SECRET, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(os.urandom(32))
            stream.flush()
            os.fsync(stream.fileno())
    for attempt in range(20):
        if SECRET.is_symlink():
            raise RuntimeError("Unsafe rate-limit secret")
        value = SECRET.read_bytes()
        if len(value) == 32:
            SECRET.chmod(0o600)
            return value
        if attempt < 19:
            time.sleep(0.05)
    raise RuntimeError("Rate-limit secret is incomplete")


def keyed_ip(ip, purpose):
    if not isinstance(ip, str) or not ip or len(ip) > 128:
        raise ValueError("Invalid client address")
    if purpose not in ("guest", "email"):
        raise ValueError("Invalid rate-limit purpose")
    return hmac.new(
        _secret(),
        ("pegasvpn-rate-v1:" + purpose + ":" + ip).encode(),
        hashlib.sha256,
    ).hexdigest()


def keyed_email(email):
    """Purpose-separated keyed email identity for delivery abuse counters."""
    if not isinstance(email, str) or not email or len(email) > 320:
        raise ValueError("Invalid email")
    return hmac.new(
        _secret(),
        ("pegasvpn-rate-v1:email-address:" + email).encode(),
        hashlib.sha256,
    ).hexdigest()
