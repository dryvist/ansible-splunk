"""Identity selection in scripts/run-ansible.sh.

curl and ansible-playbook are stubbed on PATH so each test sees which login
and sign URL the runner sends; ssh-keygen and jq are the real tools.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

RUNNER = Path(__file__).resolve().parents[2] / "scripts" / "run-ansible.sh"

FAKE_CURL = """
#!/usr/bin/env bash
url="${@: -1}"
body=""
prev=""
for a in "$@"; do
  if [[ "$prev" == "--data" && "$a" == "@-" ]]; then body=$(cat); fi
  prev="$a"
done
printf 'URL=%s BODY=%s\\n' "$url" "$body" >> "$FAKE_CURL_LOG"
if [[ "$url" == *"/auth/approle/login" ]]; then
  printf '{"auth":{"client_token":"fake-token"}}\\n'
elif [[ "$url" == *"/sign/"* ]]; then
  printf '{"data":{"signed_key":"fake-cert-body"}}\\n'
fi
exit 0
"""

FAKE_PLAYBOOK = """
#!/usr/bin/env bash
printf 'called: %s\\n' "$*" >> "$FAKE_CALLED_LOG"
exit 0
"""

GENERIC = {
    "SECRET_STORE_ADDR": "https://store.example.invalid",
    "SSH_SIGNER_ROLE_ID": "gen-role",
    "SSH_SIGNER_SECRET_ID": "gen-secret",
    "SSH_CA_MOUNT": "gen-mount",
    "SSH_SIGNER_ROLE": "gen-sign",
}

LEGACY = {
    "BAO_ADDR": "https://bao.example.invalid",
    "OPENBAO_APPROLE_SEMAPHORE_ROLE_ID": "sem-role",
    "OPENBAO_APPROLE_SEMAPHORE_SECRET_ID": "sem-secret",
}

CLEARED = (
    "BAO_ADDR",
    "BAO_TOKEN",
    "PROXMOX_SSH_KEY_PATH",
    "OPENBAO_APPROLE_SEMAPHORE_ROLE_ID",
    "OPENBAO_APPROLE_SEMAPHORE_SECRET_ID",
    "OPENBAO_APPROLE_ANSIBLE_ROLE_ID",
    "OPENBAO_APPROLE_ANSIBLE_SECRET_ID",
    *GENERIC,
)


class RunAnsibleIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.bin = root / "bin"
        self.bin.mkdir()
        self.curl_log = root / "curl.log"
        self.called_log = root / "called.log"
        for name, body in (("curl", FAKE_CURL), ("ansible-playbook", FAKE_PLAYBOOK)):
            path = self.bin / name
            path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
            path.chmod(0o700)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, extra):
        env = {k: v for k, v in os.environ.items() if k not in CLEARED}
        env["PATH"] = f"{self.bin}{os.pathsep}{env['PATH']}"
        env["TMPDIR"] = self.tmp.name
        env["FAKE_CURL_LOG"] = str(self.curl_log)
        env["FAKE_CALLED_LOG"] = str(self.called_log)
        env.update(extra)
        return subprocess.run(
            ["bash", str(RUNNER), "playbooks/site.yml"],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def _curl_log(self):
        return self.curl_log.read_text(encoding="utf-8")

    def test_legacy_names_alone_keep_current_behaviour(self):
        result = self._run(LEGACY)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("authenticated as: semaphore", result.stdout)
        log = self._curl_log()
        self.assertIn("https://bao.example.invalid/v1/ssh-client-ca/sign/automation-semaphore", log)
        self.assertIn('"role_id":"sem-role"', log)

    def test_generic_names_alone_sign_with_supplied_mount_and_role(self):
        result = self._run(GENERIC)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("authenticated as: signer", result.stdout)
        log = self._curl_log()
        self.assertIn("https://store.example.invalid/v1/gen-mount/sign/gen-sign", log)
        self.assertIn('"role_id":"gen-role"', log)

    def test_generic_names_win_over_legacy_names(self):
        result = self._run({**LEGACY, **GENERIC})
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self._curl_log()
        self.assertIn("https://store.example.invalid/v1/gen-mount/sign/gen-sign", log)
        self.assertNotIn("sem-role", log)
        self.assertNotIn("bao.example.invalid", log)

    def test_generic_names_without_mount_refuse(self):
        env = dict(GENERIC)
        del env["SSH_CA_MOUNT"]
        result = self._run(env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SSH_CA_MOUNT or SSH_SIGNER_ROLE is not", result.stderr)
        self.assertFalse(self.curl_log.exists())
        self.assertFalse(self.called_log.exists())


if __name__ == "__main__":
    unittest.main()
