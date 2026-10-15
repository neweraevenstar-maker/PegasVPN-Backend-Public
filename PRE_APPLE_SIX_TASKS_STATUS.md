# Pre-Apple six tasks: verified status

Public development continues in this repository. Imported source is from private PR #2 at a94c30697942ff4068b72eae55155704bdbdcc19. Operational reports and private history remain private.

## Validation

- All 74 offline tests passed locally in an isolated test environment.
- Public GitHub Actions run 38693341515 succeeded on commit 6d48689130d10d451e710cc489e5c193e872ff5d. The previous private-repository billing gate did not prevent this public run. No payment or spending setting was changed.
- Source was checked for common private-key/token patterns before publication; runtime data and operational backups are excluded.
- Existing Codespace can reach the server's SSH service and validates its existing known_hosts entry. Batch authentication failed with Permission denied because no usable private identity or SSH agent is present. No new access has been installed.

| Task | Actual state | Remaining gate |
| --- | --- | --- |
| Backend | PR #2 test fix included; public CI green; iOS source contract checked | SSH identity; installed iOS build verification; coordinated rollout approval |
| SQLite and backups | Consistent SQLite plus disk/runtime WireGuard copies verified on existing server | Encrypted off-host copy; restore and migration rehearsal on duplicate; live migration approval |
| SMTP and email | Offline auth/delivery tests passed | Actual provider and private credentials; DNS and real OTP test; production approval |
| Retention | Offline tests passed; policy requires review | Read-only candidate inventory; retention agreement; production cleanup/timer approval |
| WireGuard and expiry | Client-key source contract and mocked tests passed | Live peer inventory; installed-client compatibility; explicit approval for any peer/timer changes |
| Data policy and recovery | Sequential execution plan documented | Provider/log retention verification; encrypted off-host retention and isolated disaster recovery drill |

No source from this repository has been deployed. No production VPN connection, service or timer was changed. Current iOS source requires client-generated keys and a placeholder that the live older backend does not provide; release requires coordinated compatibility verification.

See PRE_APPLE_EXECUTION_PLAN.md for ordered work and approval gates.
