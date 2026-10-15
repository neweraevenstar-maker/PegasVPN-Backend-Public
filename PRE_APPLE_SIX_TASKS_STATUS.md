# Pre-Apple six tasks: verified status

Public development continues in this repository. Imported source is from private PR #2 at a94c30697942ff4068b72eae55155704bdbdcc19. Operational reports and private history remain private.

## Validation

- All 74 offline tests passed locally in an isolated test environment.
- Public GitHub Actions run 38693341515 succeeded on commit 6d48689130d10d451e710cc489e5c193e872ff5d. The previous private-repository billing gate did not prevent this public run. No payment or spending setting was changed.
- Source was checked for common private-key/token patterns before publication; runtime data and operational backups are excluded.
- SSH authentication from the existing Codespace succeeded with strict host-key checking. A temporary restricted public key was installed with an expiry, then explicitly revoked after diagnostics. A subsequent login was denied. Existing SSH key entries were preserved; no production service was restarted.
- A fresh SQLite/disk-and-runtime WireGuard snapshot was created over SSH. All 7 file hashes and restrictive permissions passed an independent verification. SQLite was restored to a separate file; integrity and full SQL content matched.
- The new migration was rehearsed on that restored duplicate: first apply succeeded, second apply made no changes, and users/sessions/devices/allocations/subscription records were unchanged. Original snapshot bytes stayed unchanged.
- Disk/runtime WireGuard peer sets matched (2 peers). API PID and activation time were unchanged after the work.

| Task | Actual state | Remaining gate |
| --- | --- | --- |
| Backend | PR #2 test fix included; public CI green; iOS source contract checked | Protect and reauthorize temporary SSH identity when next needed; installed iOS build verification; coordinated rollout approval |
| SQLite and backups | Fresh SQLite and WireGuard snapshot verified; restore content matched; migration on restored duplicate passed | Encrypted off-host copy and off-host restore drill; live migration approval |
| SMTP and email | Offline auth/delivery tests passed | Actual provider and private credentials; DNS and real OTP test; production approval |
| Retention | Offline tests passed; policy requires review | Read-only candidate inventory; retention agreement; production cleanup/timer approval |
| WireGuard and expiry | Client-key source contract and mocked tests passed | Installed-client compatibility; explicit approval for any peer/timer changes |
| Data policy and recovery | Sequential execution plan documented | Provider/log retention verification; encrypted off-host retention and isolated disaster recovery drill |

No source from this repository has been deployed. No production VPN connection, service or timer was changed. Current iOS source requires client-generated keys and a placeholder that the live older backend does not provide; release requires coordinated compatibility verification.

See PRE_APPLE_EXECUTION_PLAN.md for ordered work and approval gates.
