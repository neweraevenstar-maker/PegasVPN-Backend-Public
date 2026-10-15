# PegasVPN Backend

Public development repository for PegasVPN backend and offline CI. Imported source matches private backend PR #2 at a94c30697942ff4068b72eae55155704bdbdcc19, including the account deletion test fixture fix. Private history, operational reports, production databases, WireGuard configurations, credentials and backups are excluded.

## Offline checks

Use Python 3.11 or newer, install requirements-auth.txt in a virtual environment, then run scripts/run_offline_tests.sh. Tests use isolated temporary data and mocked WireGuard commands. GitHub Actions runs offline checks only; it does not deploy.

## Production status

This source has not been deployed. Existing server configuration and VPN connections remain unchanged. Current iOS source expects client-generated WireGuard keys and the __PEGASVPN_LOCAL_KEY__ placeholder; the existing production backend still generates keys on the server. Coordinate deployment and client verification before release.

See PRE_APPLE_EXECUTION_PLAN.md for remaining release work. Do not commit .env files, SSH keys, database copies, logs or WireGuard configs.
