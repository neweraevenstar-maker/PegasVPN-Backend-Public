"""Separate production, staging and offline-test state.

Never fall back to production paths for staging or tests. Importing a
module in offline-test mode must not create anything under /opt or /etc.
"""
import os
from pathlib import Path

LIVE_DATA = Path("/opt/onetapvpn-api/data")
LIVE_WIREGUARD = Path("/etc/wireguard")
FORBIDDEN_ROOTS = (LIVE_DATA, LIVE_WIREGUARD, Path("/etc/onetapvpn"))


def deployment():
    return os.getenv("PEGASVPN_DEPLOYMENT", "").strip().lower()


def is_staging():
    return deployment() == "staging"


def _isolated_dir(variable):
    raw = os.getenv(variable)
    if not raw:
        raise RuntimeError(variable + " is required")
    path = Path(raw).expanduser().resolve()
    if path == Path("/") or any(
        path == root or root in path.parents or path in root.parents
        for root in FORBIDDEN_ROOTS
    ):
        raise RuntimeError("Refusing unsafe isolated data directory")
    return path


def data_dir():
    mode = deployment()
    if mode == "staging":
        return _isolated_dir("PEGASVPN_STAGING_DATA_DIR")
    if mode == "tests":
        return _isolated_dir("PEGASVPN_TEST_DATA_DIR")
    if mode == "production":
        return LIVE_DATA
    raise RuntimeError("PEGASVPN_DEPLOYMENT must be explicitly set")


def db_path():
    mode = deployment()
    if mode == "staging":
        return data_dir() / "pegasvpn.db"
    if mode == "tests":
        # A separate database per unit test can override the test-only path.
        override = os.getenv("PEGASVPN_DB_PATH")
        if override:
            target = Path(override).expanduser().resolve()
            if target == Path("/") or any(
                target == root or root in target.parents
                for root in FORBIDDEN_ROOTS
            ):
                raise RuntimeError("Unsafe offline test database path")
            return target
        return data_dir() / "pegasvpn.db"
    if mode == "production":
        # Retain the existing deployment's optional database override.
        override = os.getenv("PEGASVPN_DB_PATH")
        return Path(override) if override else LIVE_DATA / "pegasvpn.db"
    raise RuntimeError("PEGASVPN_DEPLOYMENT must be explicitly set")


def require_live_wireguard():
    if deployment() != "production":
        raise RuntimeError(
            "Live WireGuard mutation requires explicit production deployment"
        )
