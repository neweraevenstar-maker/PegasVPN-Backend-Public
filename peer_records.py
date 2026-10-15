"""Per-device WireGuard record layout, backwards-compatible with legacy peers.

Legacy: DATA/<user_id>.json
Current: DATA/peers/<user_id>/<device_uuid>.json
All IDs used as path components are validated before access.
"""
import re
import uuid
from pathlib import Path

MAX_DEVICES = 5
USER_ID = re.compile(r"[A-Za-z0-9_-]{1,100}\Z")


def canonical_device_id(device_id):
    if device_id is None:
        return None
    if not isinstance(device_id, str):
        raise ValueError("Invalid device identifier")
    try:
        return str(uuid.UUID(device_id))
    except (ValueError, AttributeError) as exc:
        raise ValueError("Invalid device identifier") from exc


def record_path(data, user_id, device_id=None):
    if not isinstance(user_id, str) or not USER_ID.fullmatch(user_id):
        raise ValueError("Invalid account identifier")
    root = Path(data)
    device = canonical_device_id(device_id)
    if device is None:
        return root / (user_id + ".json")
    return root / "peers" / user_id / (device + ".json")


def user_records(data, user_id):
    legacy = record_path(data, user_id)
    if legacy.is_file() and not legacy.is_symlink():
        yield legacy
    peers_root = Path(data) / "peers"
    if peers_root.is_symlink():
        return
    folder = peers_root / user_id
    if folder.is_dir() and not folder.is_symlink():
        for path in sorted(folder.glob("*.json")):
            if path.is_file() and not path.is_symlink():
                yield path


def all_records(data):
    root = Path(data)
    for path in sorted(root.glob("*.json")):
        if path.is_file() and not path.is_symlink():
            yield path
    parent = root / "peers"
    if parent.is_dir() and not parent.is_symlink():
        for folder in sorted(parent.iterdir()):
            if folder.is_symlink() or not folder.is_dir():
                continue
            for path in sorted(folder.glob("*.json")):
                if path.is_file() and not path.is_symlink():
                    yield path


def matches_record_path(path, record):
    if not isinstance(record, dict):
        return False
    user_id = record.get("user_id")
    if not isinstance(user_id, str) or not USER_ID.fullmatch(user_id):
        return False
    device = record.get("device_id")
    try:
        return Path(path) == record_path(
            Path(path).parent.parent.parent if device is not None
            else Path(path).parent,
            user_id, device,
        )
    except ValueError:
        return False
