#!/usr/bin/env python3
"""Read-only probes whose output a later task asserts on must run in check mode.

THE DEFECT THIS EXISTS TO CATCH
-------------------------------
`ansible-playbook --check` skips `command` tasks and `uri` calls unless the
task sets `check_mode: false`. A probe that is skipped registers no output, so
the assert or `until` that reads it fails: the object-storage versioning
assert, the NTP synchronization wait and the HEC completeness check each
aborted a whole-site `--check` for that reason alone, on a healthy host.

FALSIFIABILITY
--------------
`_selftest` runs the same check against a copy with the key removed and must
see it fail before the real files are trusted.
"""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]

# file -> task names that only read state and feed a later assertion
PROBES = {
    "playbooks/tasks/sync-splunkbase/preflight.yml": [
        "Look for the object-storage client",
        "Query object-storage bucket versioning",
    ],
    "playbooks/tasks/sync-splunkbase/resolve-and-sync.yml": [
        "Resolve latest release per Splunkbase entry",
        "Query current object-storage version tag for each entry",
    ],
    "roles/splunk_docker/tasks/verify_hec_completeness.yml": [
        "Query live HEC input stanzas from Splunk",
    ],
}


def _tasks(node):
    """Yield every task dict in a playbook or task file, at any depth."""
    if isinstance(node, list):
        for item in node:
            yield from _tasks(item)
    elif isinstance(node, dict):
        if "name" in node:
            yield node
        for key in ("tasks", "pre_tasks", "post_tasks", "block", "rescue", "always"):
            yield from _tasks(node.get(key))


def missing(files):
    """Return 'file: task' for each named probe lacking `check_mode: false`."""
    found = []
    for rel, names in files.items():
        tasks = {t["name"]: t for t in _tasks(yaml.safe_load((ROOT / rel).read_text()))}
        for name in names:
            if tasks.get(name, {}).get("check_mode") is not False:
                found.append(f"{rel}: {name}")
    return found


def _selftest():
    """The checker must flag a probe that lacks the key."""
    original = (ROOT / "playbooks/tasks/sync-splunkbase/preflight.yml").read_text()
    stripped = "\n".join(line for line in original.splitlines() if "check_mode: false" not in line)
    tasks = {t["name"]: t for t in _tasks(yaml.safe_load(stripped))}
    assert tasks["Look for the object-storage client"].get("check_mode") is not False


def main():
    _selftest()
    ntp = [t for t in _tasks(yaml.safe_load((ROOT / "playbooks/site.yml").read_text()))
           if t["name"] == "Wait for the clock to synchronize via systemd-timesyncd"]
    bad = missing(PROBES) + [
        f"playbooks/site.yml: {t['name']}" for t in ntp if t.get("check_mode") is not False
    ]
    if not ntp:
        bad.append("playbooks/site.yml: NTP wait task not found")
    if bad:
        print("probes skipped in --check mode:\n  " + "\n  ".join(bad))
        return 1
    print("ok: every read-only probe sets check_mode: false")
    return 0


if __name__ == "__main__":
    sys.exit(main())
