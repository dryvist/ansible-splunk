#!/usr/bin/env python3
"""
Test the volume-to-mount resolution in verify_volume_capacity.yml.

Renders the resolution expressions verbatim out of the task file against
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
    / "roles/splunk_docker/tasks/verify_volume_capacity.yml"
)

tasks = yaml.safe_load(TASK_FILE.read_text())


def set_fact_value(task_name, key):
    task = next(t for t in tasks if t.get("name") == task_name)
    return task["ansible.builtin.set_fact"][key]


DATA_PATHS = set_fact_value("Resolve the host data path of each Splunk volume", "splunk_docker_volume_data_paths")
HOT_WARM_MOUNT = set_fact_value("Resolve the mount backing the hot_warm data path", "splunk_docker_hot_warm_mount_point")
COLD_MOUNT = set_fact_value("Resolve the mount backing the cold data path", "splunk_docker_cold_mount_point")

env = Environment()


def resolve(var_dir, cold_dir, mounts):
    data_paths = {
        key: env.from_string(template).render(
            splunk_docker_var_dir=var_dir, splunk_docker_cold_dir=cold_dir
        ).strip()
        for key, template in DATA_PATHS.items()
    }
    ctx = {"ansible_facts": {"mounts": mounts}, "splunk_docker_volume_data_paths": data_paths}
    hot_warm = env.from_string(HOT_WARM_MOUNT).render(**ctx).strip()
    cold_ctx = dict(ctx, splunk_docker_hot_warm_mount_point=hot_warm)
    cold = env.from_string(COLD_MOUNT).render(**cold_ctx).strip()
    return data_paths, hot_warm, cold


def m(mount, device):
    return {"mount": mount, "device": device, "size_available": 1}


VAR = "/opt/splunk/var"
COLD = "/opt/splunk/cold"

# Substring traps: "/var" appears inside "/opt/splunk/var/lib/splunk/", so a
# substring match would pick it. "/opt/splunk/var/lib/spl" is a string prefix
# of the data path but not an ancestor at a path-component boundary.
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
paths, hot_warm, cold = resolve(VAR, COLD, NESTED)
check("data path hot_warm is var_dir/lib/splunk", paths["hot_warm"], "/opt/splunk/var/lib/splunk")
check("nested hot_warm mount wins over parent", hot_warm, "/opt/splunk/var/lib/splunk")
check("cold resolves to its own mount", cold, "/opt/splunk/cold")

# --- parent only: nested disk not mounted, parent is the longest prefix -
_, hot_warm, _ = resolve(VAR, COLD, [m("/", "/dev/sda1"), m("/opt/splunk/var", "/dev/sdc1")])
check("parent-only hot_warm falls back to /opt/splunk/var", hot_warm, "/opt/splunk/var")

# --- no covering mount: unknown capacity, not zero ----------------------
_, hot_warm, cold = resolve(VAR, COLD, [m("/var", "/dev/sdb1")])
check("no covering mount gives empty hot_warm", hot_warm, "")
check("no covering mount gives empty cold", cold, "")

if errors:
    print()
    for err in errors:
        print(err)
    sys.exit(1)

print("\nAll tests passed.")
