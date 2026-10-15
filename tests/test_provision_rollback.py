"""A failed peer record write must not leave an untracked WireGuard peer."""
import os
import subprocess
import sys
import tempfile
import unittest


class ProvisionRollbackTests(unittest.TestCase):
    def test_disk_failure_removes_live_peer_and_no_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.update({
                "PEGASVPN_DEPLOYMENT": "staging",
                "PEGASVPN_STAGING_DATA_DIR": tmp,
                "ONETAPVPN_ADMIN_TOKEN": "test-admin",
            })
            script = r"""
import base64
import pathlib
import uuid
import unittest.mock as mock
import main
import trial_reaper

root = pathlib.Path(__import__("os").environ["PEGASVPN_STAGING_DATA_DIR"])
main.WIREGUARD_CONFIG = root / "wg0.conf"
main.WIREGUARD_CONFIG.write_text("[Interface]\nPrivateKey = test\n")
user, device = str(uuid.uuid4()), str(uuid.uuid4())
key = base64.b64encode(b"a" * 32).decode()
commands = []

def fake_wg(command, input_text=None):
    commands.append(command)
    if command[:3] == ["wg", "show", "wg0"]:
        return ""
    if command[:2] in (["wg", "genkey"], ["wg", "pubkey"]):
        return key
    if command[:2] == ["wg", "set"]:
        return ""
    raise AssertionError(command)

with (
    mock.patch.object(main, "require_live_wireguard"),
    mock.patch.object(main, "run", side_effect=fake_wg),
    mock.patch.object(trial_reaper, "save_config",
                      side_effect=OSError("disk full")),
):
    try:
        main.provision(
            main.ProvisionRequest(user_id=user, device_id=device, public_key=key),
            x_api_key="test-admin",
        )
    except OSError:
        pass
    else:
        raise AssertionError("Expected persistence failure")

assert any(cmd[:4] == ["wg", "set", "wg0", "peer"]
           and cmd[-1] == "remove" for cmd in commands)
assert not list((root / "peers" / user).glob("*.json"))
print("PROVISION_ROLLBACK_OK")
"""
            proc = subprocess.run(
                [sys.executable, "-c", script],
                env=env, capture_output=True, text=True, timeout=20
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("PROVISION_ROLLBACK_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
