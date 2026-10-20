#!/usr/bin/env python3
"""Keep empty Splunkbase resolution plans safe for both sync policies."""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "playbooks/tasks/sync-splunkbase/resolve-and-sync.yml"
PLAYBOOK = ROOT / "playbooks/sync-splunkbase.yml"

tasks = yaml.safe_load(TASKS.read_text())
by_name = {task["name"]: task for task in tasks}
errors = []

initialize = by_name["Initialize resolved release versions"]
if initialize["ansible.builtin.set_fact"].get("splunkbase_desired_all") != []:
    errors.append("FAIL: an empty selection must initialize resolved versions as an empty list")

compute = by_name["Compute every resolved release's desired version"]["ansible.builtin.set_fact"]["splunkbase_desired_all"]
if "splunkbase_desired_all | default" in compute:
    errors.append("FAIL: resolution accumulation must use its explicit initialization")

filtered = by_name["Keep only resolvable entries"]["ansible.builtin.set_fact"]["splunkbase_desired"]
if "splunkbase_desired_all | default" in filtered:
    errors.append("FAIL: filtering must derive an empty list from initialized resolution results")

plan = by_name["Initialize sync plan from resolvable entries"]["ansible.builtin.set_fact"]["splunkbase_plan"]
if plan != "{{ splunkbase_desired }}":
    errors.append("FAIL: the plan must start from the filtered resolvable entries")

compute_plan = by_name["Compute sync decisions (bucket tag vs resolved latest)"]["ansible.builtin.set_fact"]["splunkbase_plan"]
if "splunkbase_plan | default" in compute_plan:
    errors.append("FAIL: sync decisions must append to the explicitly initialized plan")

closed = by_name["Fail closed when no configured Splunkbase version resolves"]
condition = closed["ansible.builtin.assert"]["that"]
if closed.get("when") != "not (splunkbase_sync_fail_open | default(true) | bool)":
    errors.append("FAIL: the zero-resolution assertion must run only in fail-closed mode")
if not any("splunkbase_entries | length == 0" in item for item in condition):
    errors.append("FAIL: an empty selected set must remain a clean no-op")
if not any("splunkbase_desired | length > 0" in item for item in condition):
    errors.append("FAIL: fail-closed mode must reject zero resolved entries")
if "release API status" not in closed["ansible.builtin.assert"]["fail_msg"] or "resolution" not in closed["ansible.builtin.assert"]["fail_msg"]:
    errors.append("FAIL: the fail-closed message must identify resolution as the cause")

for name in ("Write manifest to controller tmpdir", "Publish manifest.json to object storage"):
    publish = by_name[name]
    if publish.get("when") != "splunkbase_plan | length > 0":
        errors.append(f"FAIL: an empty plan must not write or publish the manifest ({name})")

empty = by_name["Report empty Splunkbase plan"]
if empty.get("when") != "splunkbase_plan | length == 0" or "Nothing to sync" not in empty["ansible.builtin.debug"]["msg"]:
    errors.append("FAIL: an empty plan must report a clean no-op")

verify = next(task for task in yaml.safe_load(PLAYBOOK.read_text()) if task["name"] == "Mirror latest Splunkbase add-ons into object storage")
verify = next(task for task in verify["tasks"] if task["name"] == "Verify published object-storage tags and manifest")
if "splunkbase_plan | length > 0" not in verify.get("when", ""):
    errors.append("FAIL: empty plans must skip post-sync manifest verification")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("OK: empty resolution plans preserve the manifest and honor fail-closed mode")
