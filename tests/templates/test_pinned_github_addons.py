#!/usr/bin/env python3
"""
Guard the pinned GitHub-release add-on install.

A GitHub-release add-on without a pin is installed from releases/latest behind
a `creates:` guard, so it is installed once and never upgraded: the directory
exists, the task skips, and every later release stays out of Splunk with no
error anywhere. An entry with `pin_version` is installed from that tag and
installed again when the tag changes, tracked by a marker file named for the tag.

Run from repo root:
  python3 tests/templates/test_pinned_github_addons.py
"""

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent.parent
REGISTRY = ROOT / "roles/splunk_docker/vars/addons.yml"
TASKS = ROOT / "roles/splunk_docker/tasks/apps.yml"

errors = []

registry_text = REGISTRY.read_text()
entry = next(
    (e for e in yaml.safe_load(registry_text)["splunk_docker_addons"] if e["app_dir"] == "splunk-homelab-alerts"),
    None,
)
if entry is None:
    print("FAIL: splunk-homelab-alerts is not in the add-on registry")
    sys.exit(1)

if not re.fullmatch(r"v\d+\.\d+\.\d+", str(entry.get("pin_version", ""))):
    errors.append(f"FAIL: splunk-homelab-alerts needs a pin_version release tag (found {entry.get('pin_version')!r})")

# Renovate reads the pin from the annotation on the line directly above it.
annotation = "# renovate: datasource=github-releases depName=dryvist/splunk-homelab-alerts"
if not re.search(rf"^\s*{re.escape(annotation)}\n\s*pin_version:", registry_text, re.M):
    errors.append("FAIL: pin_version lacks the Renovate annotation on the line above it")

tasks = {t["name"]: t for t in yaml.safe_load(TASKS.read_text())}

latest = tasks["Install Splunk add-ons from GitHub Releases"]
if "rejectattr('pin_version', 'defined')" not in latest["loop"]:
    errors.append("FAIL: the releases/latest install still takes pinned entries")

pinned = tasks["Install pinned GitHub-release add-ons"]
if "releases/download/{{ item.pin_version }}/" not in pinned["ansible.builtin.unarchive"]["src"]:
    errors.append("FAIL: the pinned install does not download the pinned tag")
if "creates" in pinned["ansible.builtin.unarchive"]:
    errors.append("FAIL: the pinned install has a creates guard, so a new tag would never install")

check = tasks["Check the release marker of pinned GitHub-release add-ons"]
if ".release-{{ item.pin_version }}" not in check["ansible.builtin.stat"]["path"]:
    errors.append("FAIL: the marker path does not name the pinned tag")
if "rejectattr('stat.exists')" not in pinned["loop"]:
    errors.append("FAIL: the pinned install runs for entries whose marker already exists")

marker = tasks["Record the release marker of pinned GitHub-release add-ons"]
if "rejectattr('failed')" not in marker["loop"]:
    errors.append("FAIL: a failed download would record a marker and never retry")

if errors:
    print("\n".join(errors))
    sys.exit(1)
print("OK: pinned GitHub-release add-on install")
