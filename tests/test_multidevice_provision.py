"""End-to-end source-level per-device provisioning in a temporary staging dir.

All wg commands and WireGuard writes are mocked; no live server is accessed.
"""
import os
import subprocess
import sys
import tempfile
import unittest


class MultiDeviceProvisionTests(unittest.TestCase):
    def test_two_devices_have_distinct_keys_and_device_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.update({
                "PEGASVPN_DEPLOYMENT": "staging",
                "PEGASVPN_STAGING_DATA_DIR": tmp,
                "ONETAPVPN_ADMIN_TOKEN": "isolated-test-admin-token",
            })
            script = r"""
import base64
import hashlib
import itertools
import pathlib
import uuid
import unittest.mock as mock
import main
import trial_reaper
from fastapi import HTTPException

root = pathlib.Path(__import__("os").environ["PEGASVPN_STAGING_DATA_DIR"])
main.WIREGUARD_CONFIG = root / "wg0.conf"
main.WIREGUARD_CONFIG.write_text("[Interface]\nPrivateKey = test\n")
counter = itertools.count(1)

def fake_wg(command, input_text=None):
    if command[:3] == ["wg", "show", "wg0"]:
        return ""
    if command[:2] == ["wg", "genkey"]:
        return base64.b64encode(bytes([next(counter)]) * 32).decode()
    if command[:2] == ["wg", "pubkey"]:
        return base64.b64encode(
            hashlib.sha256(input_text.encode()).digest()
        ).decode()
    if command[:2] == ["wg", "set"]:
        return ""
    raise AssertionError(command)

user = str(uuid.uuid4())
devices = [str(uuid.uuid4()) for _ in range(6)]
with (
    mock.patch.object(main, "require_live_wireguard"),
    mock.patch.object(trial_reaper, "require_live_wireguard"),
    mock.patch.object(main, "run", side_effect=fake_wg),
):
    one = main.provision(
        main.ProvisionRequest(user_id=user, device_id=devices[0], public_key=base64.b64encode(bytes([1])*32).decode()),
        x_api_key="isolated-test-admin-token",
    )["configuration"]
    two = main.provision(
        main.ProvisionRequest(user_id=user, device_id=devices[1], public_key=base64.b64encode(bytes([2])*32).decode()),
        x_api_key="isolated-test-admin-token",
    )["configuration"]
    assert one != two
    assert "PrivateKey = __PEGASVPN_LOCAL_KEY__" in one
    assert "Address = 10.66.66.10/32" in one
    assert "Address = 10.66.66.11/32" in two
    repeat = main.provision(
        main.ProvisionRequest(user_id=user, device_id=devices[0], public_key=base64.b64encode(bytes([1])*32).decode()),
        x_api_key="isolated-test-admin-token",
    )["configuration"]
    assert repeat == one
    for device in devices[2:5]:
        main.provision(
            main.ProvisionRequest(user_id=user, device_id=device, public_key=base64.b64encode(bytes([devices.index(device)+1])*32).decode()),
            x_api_key="isolated-test-admin-token",
        )
    try:
        main.provision(
            main.ProvisionRequest(user_id=user, device_id=devices[5], public_key=base64.b64encode(bytes([6])*32).decode()),
            x_api_key="isolated-test-admin-token",
        )
    except HTTPException as exc:
        assert exc.status_code == 429
    else:
        raise AssertionError("Sixth device must be rejected")

records = list((root / "peers" / user).glob("*.json"))
assert len(records) == 5
assert all("PrivateKey = __PEGASVPN_LOCAL_KEY__" in p.read_text() for p in records)
assert main.WIREGUARD_CONFIG.read_text().count("[Peer]") == 5
print("MULTI_DEVICE_PROVISION_OK")
"""
            proc = subprocess.run(
                [sys.executable, "-c", script],
                env=env, capture_output=True, text=True, timeout=25
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("MULTI_DEVICE_PROVISION_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
