# Pre-Apple execution plan

## Verified baseline

Offline test fixture from private PR #2 is included. Consistent SQLite and disk/runtime WireGuard backups were prepared and verified on the existing server: integrity checks, file hashes, restrictive permissions and service availability passed. The backup is currently on the same disk, so off-host recovery is not yet established. No production service was restarted and no peer was changed.

Private Actions previously failed before obtaining a runner because GitHub reported failed account payments or a spending limit. Public Actions run 38693341515 completed successfully; no billing settings were changed.

SSH login from the existing Codespace was verified with strict host-key checking. Temporary public-key access was explicitly revoked after diagnostics, and a subsequent login was denied. Future access requires a protected identity and explicit reauthorization.

A fresh snapshot passed independent hash/permission checks and a separate SQLite restore matched its full SQL content. Migration on the restored duplicate passed integrity, idempotency and legacy-record preservation checks. Both WireGuard peer sets matched. Production API PID and activation time stayed unchanged. Encrypted off-host backup and off-host recovery remain unfinished.

## Order and approval gates

1. Backend: obtain SSH authentication through the secure interface, verify the host fingerprint independently and confirm a second session. Review PR #2, run public offline CI and stage the backend. Check the current installed iOS build as well as source contracts. Obtain separate approval before deployment or any production service restart.
2. SQLite: create an encrypted off-host backup, verify hashes and restoration, use the already successful duplicate migration rehearsal as evidence, and verify rollback behavior. Obtain separate approval before any live migration.
3. SMTP and email authentication: select the actual provider, enter credentials privately, check SPF/DKIM/DMARC and real OTP delivery. Obtain separate approval before production configuration changes.
4. Retention: agree retention periods, enumerate deletion candidates read-only and test cleanup on a duplicate. Obtain separate approval before deleting production data or enabling timers.
5. WireGuard: inspect managed peers without changing them, test expiry/revocation and paid recovery with mocks. Obtain separate approval before peer changes, key installation/rotation or enabling automatic revocation.
6. Data policy and recovery: reconcile actual storage/provider logs, define encrypted backup retention and rehearse isolated restoration. Off-host backup and a completed recovery drill remain release blockers. Live recovery requires separate approval.

Never create a new server, change active VPN connections or enable production timers without the relevant explicit authorization. Keep all operational details and backups outside this public repository.
