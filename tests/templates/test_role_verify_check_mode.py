#!/usr/bin/env python3
"""Role Reconcile, Verify and Assert skip only in check mode for a role that does not exist yet.

In check mode "Create Splunk role" is skipped, so a role the lookup reported as
404 is still absent and its Verify GET returns 404. Reconcile, Verify and Assert
must skip exactly that case and run in every other one, real runs included:
Reconcile after a create is what sets a new role to exactly the declared grants.
"""

import sys
from pathlib import Path

import jinja2
import yaml

ROOT = Path(__file__).resolve().parents[2]
FILE = ROOT / "roles/splunk_docker/tasks/manage_one_role.yml"
GUARDED = ("Reconcile Splunk role", "Verify Splunk role", "Assert Splunk role")


def runs(when, check_mode, status):
    """Evaluate a task's `when` the way Ansible does (a bare Jinja expression)."""
    env = jinja2.Environment()
    ctx = {"ansible_check_mode": check_mode, "splunk_docker_role_lookup": {"status": status}}
    return env.compile_expression(when)(**ctx) is True


def main():
    tasks = yaml.safe_load(FILE.read_text())
    bad = []
    for prefix in GUARDED:
        task = next((t for t in tasks if t.get("name", "").startswith(prefix)), None)
        if task is None or "when" not in task:
            bad.append(f"{prefix}: task or its when is missing")
            continue
        for check_mode in (False, True):
            for status in (200, 404):
                want = not (check_mode and status == 404)
                if runs(task["when"], check_mode, status) != want:
                    bad.append(f"{prefix}: check_mode={check_mode} status={status} runs != {want}")
    assert not runs("not (ansible_check_mode and splunk_docker_role_lookup.status == 404)", True, 404)
    if bad:
        print("\n".join(bad))
        return 1
    print("role Reconcile/Verify/Assert check-mode guard OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
