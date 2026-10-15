# SMTP activation gates

The transport probe is ready; SMTP delivery is not activated. No provider,
credentials, DNS change, test recipient or production deployment is implied.

1. Select a transactional email provider and obtain its documented SMTP host,
   port and TLS mode from the provider account. Confirm sender-domain control.
2. From the existing Germany host run the standalone probe (Python standard
   library only). It sends EHLO/STARTTLS/QUIT only, with no AUTH or email:

   ```sh
   python3 scripts/smtp_preflight.py --host PROVIDER_HOST --security starttls --port 587
   ```

   For implicit TLS use `--security ssl --port 465`. Certificate validation and
   hostname verification are mandatory. A passing report verifies transport
   from that machine only, not credentials or message delivery. Run neither
   backend imports nor production migrations for this check.
3. Obtain provider-specific SPF/DKIM records and review the existing DNS before
   changes. Preserve existing mailbox delivery. Verify DNS and sender status
   in the provider account. Set a reviewed DMARC policy.
4. Enter SMTP credentials through the secure operator interface into the
   existing private service environment, only after production approval.
   Required settings: PEGASVPN_SMTP_HOST, PEGASVPN_SMTP_PORT,
   PEGASVPN_SMTP_SECURITY, PEGASVPN_SMTP_USER, PEGASVPN_SMTP_PASSWORD,
   PEGASVPN_SMTP_FROM. Never place values in GitHub, CLI arguments or reports.
5. After a verified off-host backup and coordinated backend rollout approval,
   activate the settings and test a real OTP only to an explicitly authorized
   recipient. Verify arrival, expiry, one-time use and throttling; never record
   the OTP or the recipient's address in a public report.
6. Record delivery success and provider retention settings without secrets.
   Keep email registration enabled alongside Apple login and guest access.

## Validation

Seven isolated tests cover STARTTLS, implicit TLS, certificate failure,
missing STARTTLS, invalid input, EHLO/TLS failure and redacted errors. They do
not contact a mail provider. The probe never logs in or sends a message, and
never modifies files, services, database rows or WireGuard peers.
