from fastapi import Request
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import subprocess
import ipaddress
import os
import fcntl
import json
import secrets
import tempfile
import base64
import binascii
import re
from pathlib import Path
from peer_records import (
    MAX_DEVICES, USER_ID, all_records, user_records,
    record_path as peer_record_path, canonical_device_id,
)
from runtime_paths import data_dir, require_live_wireguard

app = FastAPI(
    title="PegasVPN API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

DATA_DIR = data_dir()
DATA_DIR.mkdir(mode=0o700, exist_ok=True)
os.chmod(DATA_DIR, 0o700)

SERVER_PUBLIC_KEY = "iK1lXr0LcPETWLMb7gDvf2pMqNa7eSbtNtdkI1Y7BjQ="
SERVER_ENDPOINT = "2.31.30.143:51820"
WIREGUARD_CONFIG = Path("/etc/wireguard/wg0.conf")

class ProvisionRequest(BaseModel):
    user_id: str
    device_id: str | None = None
    public_key: str | None = None

def run(command, input_text=None):
    return subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=True
    ).stdout.strip()

def rotate_device_key(record_path, record, new_key):
    """Rotate a legacy or lost device key without exposing private keys.

    Called only under the same global peer lock as provisioning. The
    authenticated caller must own the device record.
    """
    from trial_reaper import remove_block, save_config
    old_key, ip = record["public_key"], record["ip"]
    for other_path in all_records(DATA_DIR):
        if other_path == record_path:
            continue
        other = json.loads(other_path.read_text())
        if other.get("public_key") == new_key:
            raise HTTPException(409, "WireGuard public key already registered")

    old_config = WIREGUARD_CONFIG.read_text()
    updated, removed = remove_block(old_config, old_key, ip)
    if removed != 1:
        raise HTTPException(409, "Old peer is not present in configuration")
    new_block = (
        "\n[Peer]\nPublicKey = " + new_key
        + "\nAllowedIPs = " + ip + "/32\n"
    )
    new_wg_config = updated + new_block
    new_client_config = f"""[Interface]
PrivateKey = __PEGASVPN_LOCAL_KEY__
Address = {ip}/32
DNS = 1.1.1.1

[Peer]
PublicKey = {SERVER_PUBLIC_KEY}
Endpoint = {SERVER_ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    previous_runtime = old_key in run(["wg", "show", "wg0", "peers"]).split()
    changed = dict(record)
    changed["public_key"] = new_key
    changed["configuration"] = new_client_config
    changed["key_version"] = 2
    temp_path = None
    try:
        save_config(new_wg_config, config_path=WIREGUARD_CONFIG)
        run(["wg", "set", "wg0", "peer", new_key,
             "allowed-ips", ip + "/32"])
        run(["wg", "set", "wg0", "peer", old_key, "remove"])
        fd, temp_path = tempfile.mkstemp(
            prefix=".peer-rekey-", dir=str(record_path.parent)
        )
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(json.dumps(changed))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, record_path)
    except Exception:
        # Fail closed and attempt to restore the last durable record.
        try:
            save_config(old_config, config_path=WIREGUARD_CONFIG)
            run(["wg", "set", "wg0", "peer", new_key, "remove"])
            if previous_runtime:
                run(["wg", "set", "wg0", "peer", old_key,
                     "allowed-ips", ip + "/32"])
        except Exception:
            raise RuntimeError("Peer rekey rollback failed")
        raise
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
    return new_client_config


@app.get("/health")
def health():
    return {"status": "ok", "service": "PegasVPN"}


@app.get("/vpn/locations")
def vpn_locations():
    # The client expects a JSON array of VPNRemoteServer objects.
    # Planned locations and virtual routing modes are never selectable.
    from vpn_regions import public_catalog
    return public_catalog()


@app.post("/internal/provision")
def provision(
    request: ProvisionRequest,
    x_api_key: str | None = Header(default=None)
):
    require_live_wireguard()
    expected = os.environ.get("ONETAPVPN_ADMIN_TOKEN")
    if not expected or not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(401, "Unauthorized")
    if not request.user_id or len(request.user_id) > 100:
        raise HTTPException(400, "Invalid user ID")

    if not USER_ID.fullmatch(request.user_id):
        raise HTTPException(400, "Invalid user ID")
    try:
        device_id = canonical_device_id(request.device_id)
    except ValueError:
        raise HTTPException(400, "Invalid device ID")

    # Only the iPhone generates device private keys.
    client_key = request.public_key
    if client_key is None:
        raise HTTPException(400, "Client WireGuard public key required")
    if client_key is not None:
        try:
            decoded = base64.b64decode(client_key, validate=True)
            if (len(decoded) != 32 or decoded == bytes(32)
                    or base64.b64encode(decoded).decode() != client_key):
                raise ValueError("Invalid public key")
        except (ValueError, TypeError, binascii.Error):
            raise HTTPException(400, "Invalid WireGuard public key")

    lock_path = DATA_DIR / ".lock"

    with open(lock_path, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)

        record_path = peer_record_path(
            DATA_DIR, request.user_id, device_id
        )
        if record_path.is_symlink():
            raise HTTPException(409, "Invalid peer record")
        if record_path.exists():
            record = json.loads(record_path.read_text())
            from trial_reaper import valid_peer_record
            if (
                not valid_peer_record(record_path, record)
                or record.get("user_id") != request.user_id
                or record.get("device_id") != device_id
            ):
                raise HTTPException(409, "VPN peer ownership mismatch")
            if client_key is not None:
                if record["public_key"] != client_key:
                    return {"configuration": rotate_device_key(
                        record_path, record, client_key
                    )}
                if "__PEGASVPN_LOCAL_KEY__" not in record["configuration"]:
                    raise HTTPException(409, "Generate a new client device key")
            return {"configuration": record["configuration"]}

        if len(list(user_records(DATA_DIR, request.user_id))) >= MAX_DEVICES:
            raise HTTPException(429, "Maximum registered devices reached")

        if device_id is not None:
            peers_root = DATA_DIR / "peers"
            if peers_root.is_symlink() or record_path.parent.is_symlink():
                raise HTTPException(409, "Invalid peer directory")
            record_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            os.chmod(record_path.parent, 0o700)

        used = set()

        for path in all_records(DATA_DIR):
            record = json.loads(path.read_text())
            if record.get("public_key") == client_key:
                raise HTTPException(409, "Device public key already registered")
            used.add(record["ip"])

        active = run(["wg", "show", "wg0", "allowed-ips"])
        for line in active.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                for cidr in parts[1:]:
                    try:
                        used.add(str(ipaddress.ip_interface(cidr).ip))
                    except ValueError:
                        pass

        for n in range(10, 250):
            ip = f"10.66.66.{n}"
            if ip not in used:
                break
        else:
            raise HTTPException(503, "No available IP addresses")

        public_key = client_key
        interface_key = "__PEGASVPN_LOCAL_KEY__"

        configuration = f"""[Interface]
PrivateKey = {interface_key}
Address = {ip}/32
DNS = 1.1.1.1

[Peer]
PublicKey = {SERVER_PUBLIC_KEY}
Endpoint = {SERVER_ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

        run([
            "wg", "set", "wg0",
            "peer", public_key,
            "allowed-ips", f"{ip}/32"
        ])

        record = {
            "user_id": request.user_id,
            "device_id": device_id,
            "ip": ip,
            "public_key": public_key,
            "configuration": configuration
        }

        try:
            # Persist the new peer atomically, with a backup of wg0.conf.
            from trial_reaper import save_config
            peer_block = (
                "\n[Peer]\n"
                + f"PublicKey = {public_key}\n"
                + f"AllowedIPs = {ip}/32\n"
            )
            save_config(
                WIREGUARD_CONFIG.read_text() + peer_block,
                config_path=WIREGUARD_CONFIG,
            )
    
            fd, temp_path = tempfile.mkstemp(
                prefix=".peer-", dir=str(record_path.parent)
            )
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w") as record_file:
                    record_file.write(json.dumps(record))
                    record_file.flush()
                    os.fsync(record_file.fileno())
                os.replace(temp_path, record_path)
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
        except Exception:
            # Never leave an untracked live peer when disk persistence fails.
            try:
                from trial_reaper import remove_block
                current = WIREGUARD_CONFIG.read_text()
                updated, removed = remove_block(current, public_key, ip)
                if removed:
                    save_config(updated, config_path=WIREGUARD_CONFIG)
            except Exception:
                # Preserve the original failure; operations are auditable
                # in the server logs and must be reviewed before release.
                pass
            try:
                run(["wg", "set", "wg0", "peer", public_key, "remove"])
            except Exception:
                pass
            raise

        return {"configuration": configuration}


# PEGASVPN GUEST AUTH ROUTES
from guest_auth import create_guest_session, validate_session

@app.post("/auth/guest")
def guest_login(request: Request):
    from guest_rate_limit import allow_request
    from rate_limit_identity import keyed_ip

    client_ip = request.client.host if request.client else None
    if not client_ip:
        raise HTTPException(status_code=400, detail="Missing client address")
    client_hash = keyed_ip(client_ip, "guest")

    if not allow_request(client_hash):
        raise HTTPException(
            status_code=429,
            detail="Too many guest registrations"
        )

    session = create_guest_session()
    from guest_refresh import mint
    session["refresh_token"] = mint(session["user_id"])
    return session

@app.get("/auth/me")
def guest_me(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")

    token = authorization.removeprefix("Bearer ").strip()
    user_id = validate_session(token)

    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return {"user_id": user_id, "authenticated": True}


# PEGASVPN AUTHENTICATED PROVISIONING
@app.post("/vpn/provision")
def guest_provision(
    request: Request,
    authorization: str | None = Header(default=None),
    x_pegasvpn_device_id: str | None = Header(default=None),
    x_pegasvpn_public_key: str | None = Header(default=None)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")

    token = authorization.removeprefix("Bearer ").strip()
    user_id = validate_session(token)

    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")

    from trial_access import trial_status
    if not trial_status(user_id)["has_access"]:
        raise HTTPException(403, "No active VPN subscription or trial")

    from provision_guard import reserve
    ip = request.client.host if request.client else None
    if not ip:
        raise HTTPException(400, "Missing client IP")
    if not reserve(user_id, ip):
        raise HTTPException(429, "Provisioning limit reached")
    return provision(
        ProvisionRequest(
            user_id=user_id,
            device_id=x_pegasvpn_device_id,
            public_key=x_pegasvpn_public_key,
        ),
        x_api_key=os.environ.get("ONETAPVPN_ADMIN_TOKEN")
    )


@app.get("/access/status")
def access_status(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    user_id = validate_session(
        authorization.removeprefix("Bearer ").strip()
    )
    if not user_id:
        raise HTTPException(401, "Unauthorized")
    from trial_access import trial_status
    return trial_status(user_id)


# PEGASVPN BILLING API
class BillingVerifyRequest(BaseModel):
    signed_transaction: str

def authenticated_billing_user(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")

    user_id = validate_session(authorization[7:].strip())
    if not user_id:
        raise HTTPException(401, "Unauthorized")

    return user_id

def verified_billing_user(authorization):
    import sqlite3
    from contextlib import closing
    from guest_auth import DB_PATH
    from billing_identity import has_verified_identity

    user_id = authenticated_billing_user(authorization)
    with closing(sqlite3.connect(DB_PATH, timeout=15)) as db, db:
        if not has_verified_identity(db, user_id):
            raise HTTPException(
                403, "Sign in with Apple or email before subscribing"
            )
    return user_id

@app.get("/billing/account")
def get_billing_account(
    authorization: str | None = Header(default=None)
):
    from billing_account import account_token
    user_id = verified_billing_user(authorization)
    return {"app_account_token": account_token(user_id)}

@app.post("/billing/verify")
def verify_billing(
    body: BillingVerifyRequest,
    authorization: str | None = Header(default=None)
):
    user_id = verified_billing_user(authorization)

    if len(body.signed_transaction) > 32768:
        raise HTTPException(413, "Transaction too large")

    from apple_verification_config import verification_target
    try:
        verification_target()
    except RuntimeError:
        raise HTTPException(503, "Apple billing not activated")

    from billing_claim import claim

    try:
        return claim(user_id, body.signed_transaction)
    except (ValueError, TypeError):
        raise HTTPException(400, "Invalid Apple transaction")


# PERSISTENT GUEST SESSIONS
class GuestRefreshBody(BaseModel):
    refresh_token: str

@app.post("/auth/refresh")
def refresh_guest(body: GuestRefreshBody):
    from guest_refresh import rotate
    try:
        return rotate(body.refresh_token)
    except ValueError:
        raise HTTPException(401, "Invalid refresh token")

@app.post("/auth/enroll")
def enroll_guest(
    authorization: str | None = Header(default=None)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")

    user_id = validate_session(authorization[7:].strip())
    if not user_id:
        raise HTTPException(401, "Unauthorized")

    from guest_refresh import mint
    import sqlite3

    try:
        token = mint(user_id)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Already enrolled")

    return {"refresh_token": token}


# APP STORE SERVER NOTIFICATIONS V2
class AppleNotificationBody(BaseModel):
    signedPayload: str

@app.post("/apple/notifications")
def apple_notification(body: AppleNotificationBody):
    from apple_notifications import receive
    try:
        return receive(body.signedPayload)
    except ValueError:
        raise HTTPException(400, "Invalid Apple notification")
    except RuntimeError:
        raise HTTPException(503, "Apple verification unavailable")

# VERIFIED SIGN IN WITH APPLE
class AppleLoginBody(BaseModel):
    identity_token: str
    nonce: str

@app.post("/auth/apple")
def apple_sign_in(
    body: AppleLoginBody,
    authorization: str | None = Header(default=None)
):
    from apple_login import login, AccountConflict

    guest_token = None
    if authorization:
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "Invalid authorization")
        guest_token = authorization[7:].strip()

    try:
        return login(body.identity_token, body.nonce, guest_token)
    except AccountConflict as exc:
        raise HTTPException(409, str(exc))
    except ValueError:
        raise HTTPException(401, "Invalid Apple login")
    except RuntimeError:
        raise HTTPException(503, "Apple login unavailable")

# EMAIL ONE-TIME CODE AUTHENTICATION
class EmailRequestBody(BaseModel):
    email: str

class EmailVerifyBody(BaseModel):
    email: str
    code: str

@app.post("/auth/email/request")
def email_request(body: EmailRequestBody, request: Request):
    from email_auth import request_code
    ip = request.client.host if request.client else None
    try:
        return request_code(body.email, ip)
    except ValueError as exc:
        if str(exc) in (
            "Too many requests",
            "Too many requests for this email",
        ):
            raise HTTPException(429, "Too many requests")
        raise HTTPException(400, str(exc))
    except RuntimeError:
        raise HTTPException(503, "Email delivery unavailable")

@app.post("/auth/email/verify")
def email_verify(
    body: EmailVerifyBody,
    authorization: str | None = Header(default=None)
):
    from email_auth import verify_code, AccountConflict
    guest_token = None
    if authorization:
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "Invalid authorization")
        guest_token = authorization[7:].strip()
    try:
        return verify_code(body.email, body.code, guest_token)
    except AccountConflict as exc:
        raise HTTPException(409, str(exc))
    except ValueError:
        raise HTTPException(401, "Invalid email verification")

# SELF-SERVICE ACCOUNT DELETION
@app.delete("/auth/account")
def delete_account(
    authorization: str | None = Header(default=None)
):
    from account_delete import erase_account

    user_id = authenticated_billing_user(authorization)

    try:
        return erase_account(user_id)
    except ValueError:
        raise HTTPException(400, "Account unavailable")
    except (
        RuntimeError,
        OSError,
        subprocess.SubprocessError
    ):
        raise HTTPException(503, "Account deletion unavailable")
