"""Contract for the repo-local shim to the shared Ansible runner."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run-ansible.sh"
RUNNER_OPTIONS = (
    "RUN_ANSIBLE_IDENTITIES",
    "RUN_ANSIBLE_FALLBACK_ON_ERROR",
    "RUN_ANSIBLE_STATIC_KEY_FALLBACK",
    "RUN_ANSIBLE_REVOKE_ATTEMPTS",
    "RUN_ANSIBLE_RETIRING_IDENTITIES",
)
DEFAULTS = {
    "RUN_ANSIBLE_IDENTITIES": "signer,semaphore?,ansible",
    "RUN_ANSIBLE_FALLBACK_ON_ERROR": "1",
    "RUN_ANSIBLE_STATIC_KEY_FALLBACK": "1",
    "RUN_ANSIBLE_REVOKE_ATTEMPTS": "3",
    "RUN_ANSIBLE_RETIRING_IDENTITIES": "ansible",
}


class RunAnsibleRunnerShim(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.capture = self.root / "nix.json"
        fake_nix = self.bin_dir / "nix"
        fake_nix.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import json
                import os
                import sys

                names = (
                    "RUN_ANSIBLE_IDENTITIES",
                    "RUN_ANSIBLE_FALLBACK_ON_ERROR",
                    "RUN_ANSIBLE_STATIC_KEY_FALLBACK",
                    "RUN_ANSIBLE_REVOKE_ATTEMPTS",
                    "RUN_ANSIBLE_RETIRING_IDENTITIES",
                )
                with open(os.environ["RUNNER_CAPTURE"], "w", encoding="utf-8") as stream:
                    json.dump(
                        {
                            "argv": sys.argv[1:],
                            "env": {name: os.environ.get(name) for name in names},
                        },
                        stream,
                    )
                """
            ),
            encoding="utf-8",
        )
        fake_nix.chmod(0o700)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _run(self, args, overrides=None):
        env = os.environ.copy()
        for name in RUNNER_OPTIONS:
            env.pop(name, None)
        env.update(
            {
                "PATH": f"{self.bin_dir}{os.pathsep}{env['PATH']}",
                "RUNNER_CAPTURE": str(self.capture),
            }
        )
        env.update(overrides or {})
        return subprocess.run(
            [str(RUNNER), *args],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def _capture(self):
        return json.loads(self.capture.read_text(encoding="utf-8"))

    def test_execs_pinned_runner_with_repo_defaults_and_all_arguments(self):
        args = ("playbooks/site.yml", "--limit", "splunk-vm", "--tags", "configure")
        result = self._run(args)

        self.assertEqual(result.returncode, 0, result.stderr)
        captured = self._capture()
        self.assertEqual(
            captured["argv"],
            [
                "run",
                "github:dryvist/homelab-contracts/v5.31.0#run-ansible",
                "--",
                *args,
            ],
        )
        self.assertEqual(captured["env"], DEFAULTS)

    def test_preserves_caller_overrides(self):
        overrides = {
            "RUN_ANSIBLE_IDENTITIES": "signer,ansible",
            "RUN_ANSIBLE_REVOKE_ATTEMPTS": "2",
        }
        result = self._run(("playbooks/site.yml",), overrides)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self._capture()["env"],
            {**DEFAULTS, **overrides},
        )


if __name__ == "__main__":
    unittest.main()
