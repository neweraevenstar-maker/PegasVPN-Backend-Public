#!/usr/bin/env python3
"""Check SMTP TLS without credentials, messages, or application imports."""
import argparse
import json
import smtplib
import ssl


def probe(host, port=None, security='starttls'):
    if security not in ('ssl', 'starttls'):
        raise ValueError('TLS is required')
    if not host or any(c.isspace() for c in host) or any(c in host for c in '/@'):
        raise ValueError('Provide a hostname, not a URL or credentials')
    port = port if port is not None else (465 if security == 'ssl' else 587)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('Invalid port')
    context = ssl.create_default_context()
    client = smtplib.SMTP_SSL if security == 'ssl' else smtplib.SMTP
    kwargs = {'timeout': 10, 'local_hostname': '[127.0.0.1]'}
    if security == 'ssl':
        kwargs['context'] = context
    with client(host, port, **kwargs) as smtp:
        if smtp.ehlo()[0] != 250:
            raise smtplib.SMTPException('EHLO failed')
        if security == 'starttls':
            if not smtp.has_extn('starttls'):
                raise smtplib.SMTPNotSupportedError('STARTTLS unavailable')
            smtp.starttls(context=context)
            if smtp.ehlo()[0] != 250:
                raise smtplib.SMTPException('TLS EHLO failed')
        tls_version = smtp.sock.version()
        if tls_version not in ('TLSv1.2', 'TLSv1.3'):
            raise ssl.SSLError('TLS version unsupported')
        return {'transport': 'verified', 'tls': tls_version,
                'auth_advertised': smtp.has_extn('auth'),
                'credentials_tested': False, 'email_sent': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int)
    parser.add_argument('--security', choices=('starttls', 'ssl'), default='starttls')
    args = parser.parse_args(argv)
    try:
        result = probe(args.host, args.port, args.security)
    except (OSError, ValueError, smtplib.SMTPException) as exc:
        # Server replies can contain addresses and identifiers: never print them.
        print(json.dumps({'transport': 'failed', 'error_type': type(exc).__name__,
                          'credentials_tested': False, 'email_sent': False}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
