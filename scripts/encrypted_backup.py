#!/usr/bin/env python3
"""Encrypt a verified snapshot, or rehearse recovery in a private temporary folder.

Never reads live VPN paths, uploads data, restores production or restarts services.
Passphrases are entered on a TTY and sent to GnuPG through an anonymous pipe.
"""
import argparse
import contextlib
import getpass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import warnings

REQUIRED = {"pegasvpn.db", "wg0.conf", "wg0-runtime.conf"}
MAX_MANIFEST = 1024 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024**3


def digest(file):
    h = hashlib.sha256()
    for block in iter(lambda: file.read(1024 * 1024), b""):
        h.update(block)
    return h.hexdigest()


def manifest(raw):
    if len(raw) > MAX_MANIFEST:
        raise ValueError("Manifest too large")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate manifest entry")
            result[key] = value
        return result
    entries = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(entries, dict) or not REQUIRED <= entries.keys():
        raise ValueError("Required snapshot files missing")
    for name, sha in entries.items():
        p = PurePosixPath(name)
        if (not name or p.is_absolute() or ".." in p.parts
                or str(p) != name or "\\" in name or name == "manifest.json"
                or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha)):
            raise ValueError("Unsafe manifest entry")
    return entries


def private(path, directory=False):
    s = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected(s.st_mode) or s.st_mode & 0o077
            or s.st_uid != os.geteuid()):
        raise ValueError("Snapshot and output paths must be private and owned by the caller")


def sqlite_check(path):
    with contextlib.closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("SQLite integrity check failed")


def check_snapshot(folder):
    private(folder, directory=True)
    private(folder / "manifest.json")
    entries = manifest((folder / "manifest.json").read_bytes())
    for name, sha in entries.items():
        path = folder
        for component in PurePosixPath(name).parts[:-1]:
            path /= component
            private(path, directory=True)
        path = folder / name
        private(path)
        with path.open("rb") as f:
            if digest(f) != sha:
                raise ValueError("Snapshot hash mismatch")
    sqlite_check(folder / "pegasvpn.db")
    return entries


def check_tar(archive, work):
    """Validate every entry without extractall; write only the fixed SQLite name."""
    with tarfile.open(archive, "r:gz") as tar:
        seen = {}
        total = 0
        for item in tar:
            total += item.size
            if (not item.isfile() or item.name in seen or item.size < 0
                    or total > MAX_ARCHIVE_BYTES or item.mode & 0o077):
                raise ValueError("Unsafe archive member")
            seen[item.name] = item
        if "manifest.json" not in seen or seen["manifest.json"].size > MAX_MANIFEST:
            raise ValueError("Missing or oversized archive manifest")
        with tar.extractfile(seen["manifest.json"]) as f:
            entries = manifest(f.read(MAX_MANIFEST + 1))
        if set(seen) != set(entries) | {"manifest.json"}:
            raise ValueError("Unexpected archive members")
        for name, sha in entries.items():
            with tar.extractfile(seen[name]) as f:
                if digest(f) != sha:
                    raise ValueError("Archive hash mismatch")
        restored = work / "restore-check.db"
        with tar.extractfile(seen["pegasvpn.db"]) as source:
            with restored.open("xb") as target:
                os.chmod(restored, 0o600)
                shutil.copyfileobj(source, target)
        sqlite_check(restored)
    return len(entries)


def validate_passphrase(value):
    if len(value) < 12 or len(value.encode()) > 1000 or "\n" in value or "\r" in value:
        raise ValueError("Use a nonempty passphrase of at least 12 characters")


@contextlib.contextmanager
def gpg_home():
    with tempfile.TemporaryDirectory(prefix="pegas-gpg-") as name:
        home = Path(name)
        try:
            yield home
        finally:
            if shutil.which("gpgconf"):
                subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def gpg(home, passphrase, args, output):
    validate_passphrase(passphrase)
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, passphrase.encode() + b"\n")
        os.close(write_fd)
        write_fd = None
        command = ["gpg", "--no-options", "--homedir", str(home), "--batch",
                   "--pinentry-mode", "loopback", "--no-symkey-cache",
                   "--passphrase-fd", str(read_fd), "--output", "-"] + args
        result = subprocess.run(command, pass_fds=(read_fd,), stdout=output,
                                stderr=subprocess.PIPE)
        if result.returncode:
            raise ValueError("GnuPG failed: wrong passphrase, corrupt data or unavailable GnuPG")
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)


def verify(encrypted, passphrase, expected_sha=None):
    private(encrypted)
    with encrypted.open("rb") as f:
        actual = digest(f)
    if expected_sha is not None and actual != expected_sha:
        raise ValueError("Encrypted file SHA-256 mismatch")
    with tempfile.TemporaryDirectory(prefix="pegas-restore-") as name, gpg_home() as home:
        work = Path(name)
        plain = work / "snapshot.tar.gz"
        with plain.open("xb") as f:
            os.chmod(plain, 0o600)
            gpg(home, passphrase, ["--decrypt", "--", str(encrypted.resolve())], f)
        count = check_tar(plain, work)
    return {"sha256": actual, "verified_files": count, "sqlite_restore": "ok"}


def encrypt(folder, output, passphrase):
    validate_passphrase(passphrase)
    entries = check_snapshot(folder)
    private(output.parent, directory=True)
    if output.exists() or output.is_symlink():
        raise FileExistsError("Output already exists; refusing to replace it")
    with tempfile.TemporaryDirectory(prefix=".pegas-encrypt-", dir=output.parent) as name:
        work = Path(name)
        plain, encrypted = work / "snapshot.tar.gz", work / "snapshot.gpg"
        with plain.open("xb") as f:
            os.chmod(plain, 0o600)
            with tarfile.open(fileobj=f, mode="w:gz") as tar:
                for relative in ["manifest.json"] + sorted(entries):
                    tar.add(folder / relative, arcname=relative, recursive=False)
        check_tar(plain, work)
        with gpg_home() as home, encrypted.open("xb") as f:
            os.chmod(encrypted, 0o600)
            gpg(home, passphrase, ["--symmetric", "--cipher-algo", "AES256",
                "--s2k-mode", "3", "--s2k-digest-algo", "SHA512",
                "--s2k-count", "65011712", "--", str(plain)], f)
            f.flush()
            os.fsync(f.fileno())
        receipt = verify(encrypted, passphrase)
        os.link(encrypted, output)  # Atomic publication, fails if destination exists.
        fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return receipt


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    enc = sub.add_parser("encrypt")
    enc.add_argument("snapshot", type=Path)
    enc.add_argument("output", type=Path)
    dec = sub.add_parser("verify")
    dec.add_argument("encrypted", type=Path)
    dec.add_argument("--sha256", required=True)
    args = parser.parse_args()
    if not sys.stdin.isatty():
        parser.error("An interactive terminal is required; never supply the passphrase in arguments or environment")
    warnings.filterwarnings("error", category=getpass.GetPassWarning)
    phrase = getpass.getpass("Backup passphrase (at least 12 characters): ")
    validate_passphrase(phrase)
    if args.command == "encrypt":
        if phrase != getpass.getpass("Repeat backup passphrase: "):
            parser.error("Passphrases differ; nothing encrypted")
        receipt = encrypt(args.snapshot, args.output, phrase)
    else:
        receipt = verify(args.encrypted, phrase, args.sha256)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, sqlite3.Error, tarfile.TarError) as error:
        print("BACKUP FAILED:", str(error), file=sys.stderr)
        raise SystemExit(1)
