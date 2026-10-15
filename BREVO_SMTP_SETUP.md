# Brevo SMTP for PegasVPN email registration

**Status: source and offline tests prepared. Not configured with Brevo, not
deployed to the live Germany server. No production service changes.**

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
PEGASVPN_SMTP_PORT=465
PEGASVPN_SMTP_SECURITY=ssl
PEGASVPN_SMTP_FROM=noreply@vimvitae.net
PEGASVPN_SMTP_USER=<SMTP LOGIN SHOWN IN BREVO>
PEGASVPN_SMTP_PASSWORD=<DEDICATED SECRET SMTP KEY>
```

The production file location is `/etc/onetapvpn/pegasvpn.env`; verify
ownership, restrictive permissions and service environment loading
before any changes. The SMTP key must never be entered into the
public repository, a Codespace commit, GitHub Actions or chat.

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
- [ ] Owner signs into Brevo in protected browser.
- [ ] Brevo sending domain and sender authenticated in Cloudflare DNS.
- [ ] Dedicated SMTP login/key stored privately (not in repository).
- [ ] Real SMTP test email and end-to-end OTP tested.
- [ ] Separate production deployment approval.

Official references:
- https://help.brevo.com/hc/en-us/articles/7924908994450-Send-transactional-emails-using-Brevo-SMTP
- https://help.brevo.com/hc/en-us/articles/7959631848850-Create-and-manage-your-SMTP-keys
- https://help.brevo.com/hc/en-us/articles/12163873383186-Authenticate-your-domain-with-Brevo-Brevo-code-DKIM-DMARC
- https://help.brevo.com/hc/en-us/articles/208589409-About-Brevo-s-pricing-plans
