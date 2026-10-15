#!/usr/bin/env python3
"""Read-only Brevo SMTP config check; sends one test mail ONLY with --send-to.

This script does not modify PegasVPN, the database, WireGuard, or systemd.
Secrets must be supplied through a protected environment, never GitHub.
"""
import argparse
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from email.utils import parseaddr

HOST = "smtp-relay.brevo.com"
SENDER = "noreply@vimvitae.net"
REQUIRED = (
    "PEGASVPN_SMTP_HOST", "PEGASVPN_SMTP_PORT",
    "PEGASVPN_SMTP_SECURITY", "PEGASVPN_SMTP_USER",
    "PEGASVPN_SMTP_PASSWORD", "PEGASVPN_SMTP_FROM",
)


class ConfigError(ValueError):
    pass


def email_address(value):
    if not isinstance(value, str) or "\r" in value or "\n" in value:
        raise ConfigError("Invalid email address")
    parsed = parseaddr(value)[1]
    if parsed != value or parsed.count("@") != 1 or not parsed.split("@")[1]:
        raise ConfigError("Invalid email address")
    return parsed


def config(env=None):
    env = os.environ if env is None else env
    missing = [name for name in REQUIRED if not env.get(name)]
    if missing:
        raise ConfigError("Missing configuration: " + ", ".join(missing))
    if env["PEGASVPN_SMTP_HOST"] != HOST:
        raise ConfigError("Expected Brevo SMTP relay hostname")
    mode = env["PEGASVPN_SMTP_SECURITY"].lower()
    if mode not in ("ssl", "starttls"):
        raise ConfigError("Encrypted SMTP transport required")
    try:
        port = int(env["PEGASVPN_SMTP_PORT"])
    except ValueError as exc:
        raise ConfigError("Invalid SMTP port") from exc
    if (mode, port) not in (("ssl", 465), ("starttls", 587)):
        raise ConfigError("Use SSL/465 or STARTTLS/587 for Brevo")
    sender = email_address(env["PEGASVPN_SMTP_FROM"])
    if sender.lower() != SENDER:
        raise ConfigError("Unexpected sender address")
    return {
        "host": HOST,
        "port": port,
        "mode": mode,
        "user": env["PEGASVPN_SMTP_USER"],
        "password": env["PEGASVPN_SMTP_PASSWORD"],
        "sender": sender,
    }


def send_test(cfg, recipient):
    recipient = email_address(recipient)
    message = EmailMessage()
    message["From"] = cfg["sender"]
    message["To"] = recipient
    message["Subject"] = "PegasVPN: SMTP test (not a login code)"
    message.set_content(
        "This is a test of the PegasVPN email delivery service.\n"
        "This message is NOT a login code. No action is required.\n"
    )
    context = ssl.create_default_context()
    if cfg["mode"] == "ssl":
        with smtplib.SMTP_SSL(
            cfg["host"], cfg["port"], timeout=10, context=context
        ) as smtp:
            smtp.login(cfg["user"], cfg["password"])
            smtp.send_message(message)
    else:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(cfg["user"], cfg["password"])
            smtp.send_message(message)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--send-to", metavar="EMAIL",
        help="opt in to sending ONE test email to this address"
    )
    args = parser.parse_args(argv)
    try:
        cfg = config()
        print("Brevo configuration valid: SSL/TLS enabled; sender", cfg["sender"])
        print("Credentials not displayed. No database/VPN changes.")
        if args.send_to:
            send_test(cfg, args.send_to)
            print("SMTP accepted one test message. Check actual inbox delivery.")
        else:
            print("Offline check only: no SMTP connection and no email sent.")
    except (ConfigError, OSError, smtplib.SMTPException) as exc:
        # SMTP exception strings can include server responses: do not log them.
        print("Brevo SMTP check failed:", type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
