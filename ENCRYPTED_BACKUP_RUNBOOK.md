# Encrypted off-host backups

This procedure packages an existing, immutable, verified snapshot. It does not
read the live database, change WireGuard, deploy code, start a timer or restart
a service. No automated schedule or deletion policy is enabled by this change.

## Required decisions

- The owner approves the off-host destination and any temporary SSH access.
- The owner keeps the backup passphrase in their password manager, separately
  from the server, Codespace, archive and repository. Use at least 12 characters.
  This is a separate backup secret; the tool cannot recover a forgotten phrase.
- The off-host destination must preserve private access. An archive stored only
  on the server is not an off-host backup. A Codespace alone is not the durable
  recovery location because it can be deleted.
- Keep the verified snapshot until off-host download and recovery pass. Do not
  delete existing backups or set retention periods without the owner's decision.

## Preconditions

Python 3.11+ and GnuPG 2.2+ are required on the machine performing the operation.
Check `python3 --version` and `gpg --version`. Installing software on production
requires separate approval; do not install it implicitly.

The input snapshot directory must be owned by the current user, have no group
or world permissions, and contain a `manifest.json` mapping relative filenames
to SHA-256 hashes. The manifest must include `pegasvpn.db`, `wg0.conf` and
`wg0-runtime.conf`. Snapshot files must be regular, private files; symlinks and
unsafe relative paths are rejected. Only files listed in the manifest, plus the
manifest itself, are packaged. Unlisted restore rehearsals are not included.

## Encrypt on the source machine

Use an interactive terminal. Substitute the approved snapshot and output paths;
the output's parent must be a private directory owned by the current user.

```bash
python3 scripts/encrypted_backup.py encrypt /PRIVATE/SNAPSHOT /PRIVATE/backup.tar.gz.gpg
```

Enter the backup passphrase twice at the hidden prompts. Do not put it in a
command, environment variable, GitHub secret, CI job, chat message or text file.
The CLI refuses noninteractive input and empty/short passphrases. GnuPG receives
the phrase through an anonymous pipe, with symmetric-key caching disabled.

The tool verifies source hashes and SQLite integrity, packages the snapshot,
encrypts using GnuPG AES-256, then independently decrypts it into a private
temporary directory and checks archive hashes and SQLite integrity. Temporary
plaintext files are removed on normal completion or handled errors. Abrupt OS
termination may leave private temporary directories; inspect them privately
after a crash. No claim of forensic secure erasure is made.

The destination is published only after validation succeeds. Existing output
files are never replaced. The final JSON receipt contains ciphertext SHA-256,
the number of verified files and SQLite restoration status. Record this receipt
privately, separately from the archive transfer. Passphrases and backup contents
are not printed. This symmetric format does not provide a sender signature;
the separately recorded expected SHA-256 is required for transfer verification.

## Transfer only ciphertext

After approval, copy only `backup.tar.gz.gpg` to the agreed private off-host
destination. Never transfer the raw snapshot, temporary plaintext, SSH identity
or backup passphrase into the public repository, Actions artifacts or logs.
Confirm the received encrypted file's SHA-256 against the recorded receipt.

## Rehearse off-host recovery

Use a separate machine or isolated environment and an independently downloaded
copy of the encrypted archive. The encrypted file must be private (`chmod 600`).

```bash
python3 scripts/encrypted_backup.py verify /PRIVATE/backup.tar.gz.gpg --sha256 EXPECTED_CIPHERTEXT_SHA256
```

Enter the passphrase through the hidden prompt. The tool checks the expected
ciphertext hash before decryption, verifies every archive entry and hash, and
opens a restored SQLite file read-only in a private temporary directory.
Traversal paths, links, duplicate names, unexpected files and corrupt SQLite
are rejected. It never extracts files into production or applies a migration.

Success means the downloaded snapshot is decryptable and its SQLite backup is
readable. It is not a full application failover test. Actual deployment,
restoration to production, WireGuard key activation, service restart and backup
pruning each retain their separate approval gates.

## Finish

Record the off-host location, archive SHA-256 and successful independent check
privately. Revoke temporary SSH access and verify that a new login is denied.
Confirm API PID/start time and WireGuard availability did not change. An
approved retention schedule, recurring backup credentials and a full recovery
drill are still required before calling disaster recovery complete.

GnuPG options reference: https://www.gnupg.org/documentation/manuals/gnupg/GPG-Esoteric-Options.html
