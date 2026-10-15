# Pre-Apple execution plan

## Verified baseline

Offline test fixture from private PR #2 is included. Consistent SQLite and disk/runtime WireGuard backups were prepared and verified on the existing server: integrity checks, file hashes, restrictive permissions and service availability passed. The backup is currently on the same disk, so off-host recovery is not yet established. No production service was restarted and no peer was changed.

Private Actions previously failed before obtaining a runner because GitHub reported failed account payments or a spending limit. Public CI must be checked independently; no billing changes are authorized.

Existing Codespace workspace trust is confirmed. SSH port 22 is reachable from that Codespace. A known_hosts entry exists, but no private SSH identity or active agent was found. SSH authentication remains blocked pending secure user action.

## Order and approval gates

1. Backend: obtain SSH authentication through the secure interface, verify the host fingerprint independently and confirm a second session. Review PR #2, run public offline CI and stage the backend. Check the current installed iOS build as well as source contracts. Obtain separate approval before deployment or any production service restart.
2. SQLite: create an encrypted off-host backup, verify hashes and restoration, then rehearse migration on a duplicate database. Compare legacy records and rollback behavior. Obtain separate approval before any live migration.
3. SMTP and email authentication: select the actual provider, enter credentials privately, check SPF/DKIM/DMARC and real OTP delivery. Obtain separate approval before production configuration changes.
4. Retention: agree retention periods, enumerate deletion candidates read-only and test cleanup on a duplicate. Obtain separate approval before deleting production data or enabling timers.
5. WireGuard: inspect managed peers without changing them, test expiry/revocation and paid recovery with mocks. Obtain separate approval before peer changes, key installation/rotation or enabling automatic revocation.
6. Data policy and recovery: reconcile actual storage/provider logs, define encrypted backup retention and rehearse isolated restoration. Off-host backup and a completed recovery drill remain release blockers. Live recovery requires separate approval.

Never create a new server, change active VPN connections or enable production timers without the relevant explicit authorization. Keep all operational details and backups outside this public repository.
