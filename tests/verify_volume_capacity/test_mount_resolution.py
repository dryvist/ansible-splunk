#!/usr/bin/env python3
"""
Test the volume-to-mount resolution in roles/splunk_docker/tasks/resolve_volume_mounts.yml.

Renders the real set_fact expressions verbatim out of the task file against
fixture mount tables, so a change to the real expressions is what this test
exercises. The nested case matters: hot_warm sits on a disk mounted under its
parent mount, and the parent must not win.

Run from repo root:
  uv run -q --with jinja2 --with pyyaml python3 tests/verify_volume_capacity/test_mount_resolution.py
"""

import sys
from pathlib import Path

try:
    import yaml
    from jinja2 import Environment
except ImportError:
    print("ERROR: pyyaml/jinja2 not installed. Run: pip install pyyaml jinja2")
    sys.exit(1)

TASK_FILE = (
    Path(__file__).parent.parent.parent
    / "roles/splunk_docker/tasks/resolve_volume_mounts.yml"
)

TASKS = yaml.safe_load(TASK_FILE.read_text())


def facts_of(task):
    return task["ansible.builtin.set_fact"]


def task_with_key(predicate):
    return next(t for t in TASKS if any(predicate(k) for k in facts_of(t)))


DATA_PATHS = facts_of(task_with_key(lambda k: k == "splunk_docker_volume_data_paths"))[
    "splunk_docker_volume_data_paths"
]

MOUNT_TASK = task_with_key(lambda k: k.startswith("splunk_docker_mount_point_"))
MOUNT_KEY = next(k for k in facts_of(MOUNT_TASK))
MOUNT_EXPR = facts_of(MOUNT_TASK)[MOUNT_KEY]
SELECT_EXPR = facts_of(task_with_key(lambda k: k == "splunk_docker_volume_mounts"))[
    "splunk_docker_volume_mounts"
]

env = Environment()


def resolve(var_dir, cold_dir, mounts):
    data_paths = {
        key: env.from_string(template).render(
            splunk_docker_var_dir=var_dir, splunk_docker_cold_dir=cold_dir
        ).strip()
        for key, template in DATA_PATHS.items()
    }
    points = {
        key: env.from_string(MOUNT_EXPR).render(
            item={"key": key, "value": path}, ansible_facts={"mounts": mounts}
        ).strip()
        for key, path in data_paths.items()
    }
    selected = env.from_string(SELECT_EXPR).render(
        ansible_facts={"mounts": mounts},
        splunk_docker_mount_point_hot_warm=points["hot_warm"],
        splunk_docker_mount_point_cold=points["cold"],
    )
    return data_paths, points["hot_warm"], points["cold"], selected


def m(mount, device):
    return {"mount": mount, "device": device, "size_available": 1}


VAR = "/opt/splunk/var"
COLD = "/opt/splunk/cold"

# Substring traps: "/var" appears inside "/opt/splunk/var/lib/splunk/", so a
# substring match would pick it. "/opt/splunk/var/lib/spl" is a string prefix of
# the data path but not an ancestor at a path-component boundary.
NESTED = [
    m("/", "/dev/sda1"),
    m("/var", "/dev/sdb1"),
    m("/opt", "/dev/sda2"),
    m("/opt/splunk/var", "/dev/sdc1"),
    m("/opt/splunk/var/lib/spl", "/dev/sdf1"),
    m("/opt/splunk/var/lib/splunk", "/dev/sdd1"),
    m("/opt/splunk/cold", "/dev/sde1"),
]

errors = []


def check(label, got, want):
    if got != want:
        errors.append(f"FAIL: {label}: got {got!r}, want {want!r}")
    else:
        print(f"PASS: {label} -> {got}")


# --- nested: hot_warm resolves to the nested disk, not the parent ------
paths, hot_warm, cold, selected = resolve(VAR, COLD, NESTED)
check("data path hot_warm is var_dir/lib/splunk", paths["hot_warm"], "/opt/splunk/var/lib/splunk")
check("nested hot_warm mount wins over parent", hot_warm, "/opt/splunk/var/lib/splunk")
check("cold resolves to its own mount", cold, "/opt/splunk/cold")
check("selected hot_warm facts are the nested disk", "/dev/sdd1" in selected, True)

# --- parent only: nested disk not mounted, parent is the longest prefix -
_, hot_warm, _, _ = resolve(VAR, COLD, [m("/", "/dev/sda1"), m("/opt/splunk/var", "/dev/sdc1")])
check("parent-only hot_warm falls back to /opt/splunk/var", hot_warm, "/opt/splunk/var")

# --- no covering mount: unknown capacity, not zero ----------------------
_, hot_warm, cold, _ = resolve(VAR, COLD, [m("/var", "/dev/sdb1")])
check("no covering mount gives empty hot_warm", hot_warm, "")
check("no covering mount gives empty cold", cold, "")

if errors:
    print()
    for err in errors:
        print(err)
    sys.exit(1)

print("\nAll tests passed.")
