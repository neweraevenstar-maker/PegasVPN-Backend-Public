#!/usr/bin/env python3
"""Explicit, backup-first database migration. Never runs automatically."""
import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime_paths import db_path, deployment
from db_migrations import apply


def backup_sqlite(source, destination):
    source = Path(source)
    destination = Path(destination)
    if not source.is_file() or source.is_symlink():
        raise RuntimeError("Source SQLite file missing or symlinked")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.parent.stat().st_mode & 0o077:
        raise RuntimeError("Backup directory must be private (0700)")
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        with sqlite3.connect(
            source.resolve().as_uri() + "?mode=ro", uri=True
        ) as src, sqlite3.connect(destination) as dst:
            src.backup(dst)
            result = dst.execute("PRAGMA integrity_check").fetchone()
            if result != ("ok",):
                raise RuntimeError("SQLite backup integrity check failed")
        with destination.open("rb") as stream:
            os.fsync(stream.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return destination


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-mode", choices=("staging", "production"),
                        required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.apply or deployment() != args.expected_mode:
        raise SystemExit("Explicit --apply and matching deployment required")
    if args.expected_mode == "production" and os.getenv(
        "PEGASVPN_CONFIRM_PRODUCTION_MIGRATION"
    ) != "I_HAVE_STOPPED_API_AND_BACKED_UP_WIREGUARD":
        raise SystemExit("Production migration requires explicit approval")
    source = db_path()
    directory = args.backup_dir.expanduser().resolve()
    if directory == source.parent.resolve():
        raise SystemExit("Keep database backups in a separate private folder")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = directory / ("pegasvpn-before-migration-" + stamp + ".sqlite")
    backup_sqlite(source, destination)
    print("SQLite backup:", destination)
    print("Migration applied:", apply(source))


if __name__ == "__main__":
    main()
