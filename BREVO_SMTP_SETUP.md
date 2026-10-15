# Brevo SMTP for PegasVPN email registration

**Status: Brevo sending domain authenticated, sender verified, and an actual
non-OTP SMTP test message was delivered to the corporate mailbox from the
owner's Windows PC. The SMTP key is held by the owner; it is not installed
on the backend. No production deployment or service changes have occurred.**

## Architecture and limits

PegasVPN retains **email registration** with a six-digit, 10-minute one-time
code. Existing endpoints are `POST /auth/email/request` and
`POST /auth/email/verify` in `main.py`. Existing `email_auth.py` supports
SMTP over SSL/TLS; no Brevo-specific SDK, account password, or API key is
needed. Keep Sign in with Apple and guest mode as separate login options.

**Sender:** `noreply@vimvitae.net`. The existing inbound Cloudflare Email
Routing rules for `admin@vimvitae.net` and `info@vimvitae.net` forwarding
to Gmail must remain unchanged.

Brevo's free plan currently permits **300 emails/day**, including
transactional messages. Once the limit is reached, transactional messages
may be delayed/queued; do not rely on that queue for time-sensitive OTPs.
Track sending volume and upgrade before approaching the limit. A 6-digit
code costs the same email quota as a 4-digit code.

## User sign-in required — Brevo

1. In a protected cloud-browser session, the account owner signs up or
   signs in at https://app.brevo.com/ (prefer the existing corporate email).
   Never send passwords, verification codes, or SMTP keys through chat.
2. Add sending domain `vimvitae.net` in Brevo's Domains settings.
   Select **manual DNS authentication**, not a bulk automatic DNS rewrite,
   to protect existing Cloudflare Email Routing settings.
3. In Brevo, copy the **actual account-specific** verification TXT,
   DKIM (TXT or CNAME) and DMARC values. In Cloudflare DNS, add the
   missing records. Review existing records before any edit:
   - **Do not delete/replace root MX records.** They receive company mail.
   - **Do not create a second SPF TXT record** at the same name.
   - **Do not overwrite an existing `_dmarc` record.** Merge a required
     change only after reviewing the existing DMARC policy.
   - For DKIM CNAME records, use DNS-only (not proxied); avoid CNAME
     flattening for those selectors.
   - Brevo says SPF/MX changes are **not required** for ordinary shared-IP
     domain authentication; do not add them without an explicit reason.
4. Wait until Brevo shows the sending domain authenticated. Configure
   `noreply@vimvitae.net` as the verified sender if necessary.
5. Go to **Settings > SMTP & API > SMTP**. Note the account's **SMTP
   login**, which may differ from the Brevo account email. Generate a
   dedicated **SMTP key** for PegasVPN. **An SMTP key is not an API key.**
   Save it privately when first displayed; Brevo may not show it again.
   If Brevo requires transactional SMTP activation/verification, complete
   that step inside the provider account.

## Runtime configuration (private only)

Use the existing protected backend environment configuration. **Do not
create a second public environment file, commit secrets or replace other
production settings.** Add these settings only after authorized rollout:

```ini
PEGASVPN_SMTP_HOST=smtp-relay.brevo.com
PEGASVPN_SMTP_PORT=587
PEGASVPN_SMTP_SECURITY=starttls
PEGASVPN_SMTP_FROM=noreply@vimvitae.net
PEGASVPN_SMTP_USER=<SMTP LOGIN SHOWN IN BREVO>
PEGASVPN_SMTP_PASSWORD=<DEDICATED SECRET SMTP KEY>
```

Brevo's SMTP settings page for this account advertises port 587; use
STARTTLS, not plaintext. The offline probe also supports SSL on 465,
but do not switch ports without checking the account's current settings.

The production file location is `/etc/onetapvpn/pegasvpn.env`; verify
ownership, restrictive permissions and service environment loading
before any changes. The SMTP key must never be entered into the
public repository, a Codespace commit, GitHub Actions or chat.

## Test Brevo delivery yourself on Windows (no Work, no server)

This test **does not activate registration on production**. It sends one
non-OTP test message directly from your own Windows PC to the existing
corporate mailbox. You do **not** need Python, Codespaces, Work or SSH.

1. Open [the PowerShell test script](scripts/brevo_smtp_windows.ps1) in
   GitHub. Review it and download the **Raw** file as
   `brevo_smtp_windows.ps1` into Windows Downloads.
2. In **Windows PowerShell** run:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\Downloads\brevo_smtp_windows.ps1" -Send
   ```

   This policy flag applies to this child PowerShell process only; it does
   not change system policy. Do not run an unreviewed or modified script.
3. At the first prompt enter the **SMTP Login** shown on Brevo's SMTP
   settings page (not your normal account email). At the second prompt
   enter the **SMTP key**. The key input is hidden and is never written
   to a file, chat, repository or command-line argument.
4. Check the existing Gmail inbox receiving `admin@vimvitae.net` and
   Brevo's transactional email events. SMTP acceptance does not guarantee
   actual delivery.

The script defaults to **offline/no send** unless `-Send` is specified.
It connects to `smtp-relay.brevo.com:587` using STARTTLS, and sends only
from the verified `noreply@vimvitae.net` sender. No production services,
databases or VPN peers are touched.

If the test fails, report only **"test failed"**, not the SMTP key or
raw server exception. Verify that Brevo has activated transactional SMTP
sending, and check that the local network permits port 587.

## Checks (no live VPN modifications)

`scripts/brevo_smtp_check.py` uses only Python's standard library.
With the above variables supplied through a secure environment:

```sh
python scripts/brevo_smtp_check.py
```

This is a **configuration-only check**: no network connection, no
message, no DB write, no service restart.

Only after Brevo verifies the domain, and the owner approves one test
message, run:

```sh
python scripts/brevo_smtp_check.py --send-to admin@vimvitae.net
```

This sends **one clearly labelled non-OTP test message**. Confirm its
arrival in the existing Gmail destination and inspect Brevo delivery
events. SMTP acceptance alone is not proof of delivery. Then test the
actual `/auth/email/request` and `/auth/email/verify` flow against an
isolated test environment (wrong code, expiry, cooldown, rate limits,
account linking). Check delivery to target-market mail providers.

Run the offline checks in the public repository:

```sh
python -m unittest discover -s tests -v
```

**Do not deploy or restart the production API or WireGuard** to
complete this setup without explicit authorization. Production changes
also require iOS client/backend compatibility and a verified off-host
backup/rollback plan.

## Current checklist

- [x] Brevo selected; official SMTP host and TLS parameters verified.
- [x] Existing email OTP implementation supports Brevo SMTP.
- [x] Added safe configuration check and opt-in test-mail utility.
- [x] Added offline unit tests; public GitHub Actions to verify.
- [x] Owner registered in Brevo.
- [x] `vimvitae.net` authenticated; `noreply@vimvitae.net` sender verified with DKIM/DMARC.
- [x] Dedicated SMTP key generated and retained privately by owner.
- [ ] SMTP login/key configured in a protected environment (not in repository).
- [x] One real non-OTP SMTP test email delivered to `admin@vimvitae.net` (owner confirmed receipt).
- [ ] Real OTP request/verify tested end-to-end in isolated environment with private credentials.
- [x] Offline mocked request/verify tests added (code expiry, replay, abuse limits, failed delivery).
- [ ] Separate production deployment approval.

Official references:
- https://help.brevo.com/hc/en-us/articles/7924908994450-Send-transactional-emails-using-Brevo-SMTP
- https://help.brevo.com/hc/en-us/articles/7959631848850-Create-and-manage-your-SMTP-keys
- https://help.brevo.com/hc/en-us/articles/12163873383186-Authenticate-your-domain-with-Brevo-Brevo-code-DKIM-DMARC
- https://help.brevo.com/hc/en-us/articles/208589409-About-Brevo-s-pricing-plans
