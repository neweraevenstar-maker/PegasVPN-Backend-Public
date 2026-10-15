"""New VPN device records never contain a client private key."""
import os
import subprocess
import sys
import tempfile
import unittest


class ClientKeyProvisionTests(unittest.TestCase):
    def test_client_public_key_only_and_atomic_device_rekey(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.update({
                "PEGASVPN_DEPLOYMENT": "staging",
                "PEGASVPN_STAGING_DATA_DIR": tmp,
                "ONETAPVPN_ADMIN_TOKEN": "offline-admin",
            })
            script = r"""
import base64, json, pathlib, uuid
import unittest.mock as mock
import main, trial_reaper

root = pathlib.Path(__import__("os").environ["PEGASVPN_STAGING_DATA_DIR"])
main.WIREGUARD_CONFIG = root / "wg0.conf"
main.WIREGUARD_CONFIG.write_text("[Interface]\nPrivateKey = test-server\n")
user, device = str(uuid.uuid4()), str(uuid.uuid4())
first = base64.b64encode(b"a" * 32).decode()
second = base64.b64encode(b"b" * 32).decode()
active = {}

def fake_wg(cmd, input_text=None):
    if cmd[:3] == ["wg", "show", "wg0"]:
        if cmd[-1] == "peers":
            return "\n".join(active)
        return "\n".join(k + " " + v for k, v in active.items())
    if cmd[:4] == ["wg", "set", "wg0", "peer"]:
        if cmd[-1] == "remove":
            active.pop(cmd[4], None)
        else:
            active[cmd[4]] = cmd[-1]
        return ""
    raise AssertionError(cmd)

def safe_write(text, config_path=None):
    pathlib.Path(config_path).write_text(text)

with (
    mock.patch.object(main, "require_live_wireguard"),
    mock.patch.object(main, "run", side_effect=fake_wg),
    mock.patch.object(trial_reaper, "save_config", side_effect=safe_write),
):
    one = main.provision(
        main.ProvisionRequest(user_id=user, device_id=device,
                              public_key=first),
        x_api_key="offline-admin",
    )["configuration"]
    assert "PrivateKey = __PEGASVPN_LOCAL_KEY__" in one
    assert "test-server" not in one
    record_path = root / "peers" / user / (device + ".json")
    assert first in record_path.read_text()
    assert "PrivateKey = __PEGASVPN_LOCAL_KEY__" in record_path.read_text()
    two = main.provision(
        main.ProvisionRequest(user_id=user, device_id=device,
                              public_key=second),
        x_api_key="offline-admin",
    )["configuration"]
    assert two == one
    record = json.loads(record_path.read_text())
    assert record["public_key"] == second
    assert first not in main.WIREGUARD_CONFIG.read_text()
    assert second in main.WIREGUARD_CONFIG.read_text()
    assert list(active) == [second]
print("CLIENT_SIDE_KEY_ONLY_OK")
"""
            proc = subprocess.run(
                [sys.executable, "-c", script],
                env=env, capture_output=True, text=True, timeout=25,
            )
            self.assertEqual(
                proc.returncode, 0, proc.stdout + proc.stderr
            )
            self.assertIn("CLIENT_SIDE_KEY_ONLY_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
