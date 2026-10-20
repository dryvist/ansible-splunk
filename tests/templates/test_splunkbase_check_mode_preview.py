#!/usr/bin/env python3
"""Check mode prints sync decisions and ends before Splunkbase mutations."""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "playbooks/tasks/sync-splunkbase/resolve-and-sync.yml"
PLAYBOOK = ROOT / "playbooks/sync-splunkbase.yml"
SITE = ROOT / "playbooks/site.yml"

tasks = yaml.safe_load(TASKS.read_text())
by_name = {task["name"]: (index, task) for index, task in enumerate(tasks)}
errors = []

decision_index, _ = by_name["Show sync decisions"]
end_index, end_task = by_name["End Splunkbase sync play after the check-mode preview"]
login_index, _ = by_name["Authenticate to Splunkbase (only when something needs downloading)"]
if not decision_index < end_index < login_index:
    errors.append("FAIL: check mode must end after decisions and before authentication")
if end_task.get("ansible.builtin.meta") != "end_play" or end_task.get("when") != "ansible_check_mode":
    errors.append("FAIL: check mode must end only the current play after its preview")

site_plays = yaml.safe_load(SITE.read_text())
sync_index = next(
    (index for index, play in enumerate(site_plays)
     if play.get("ansible.builtin.import_playbook") == "sync-splunkbase.yml"),
    None,
)
if sync_index is None or sync_index == len(site_plays) - 1:
    errors.append("FAIL: site.yml must retain later plays after importing the sync playbook")

sync_play = next(
    play for play in yaml.safe_load(PLAYBOOK.read_text())
    if play.get("name") == "Mirror latest Splunkbase add-ons into object storage"
)
if sync_play.get("hosts") != "localhost":
    errors.append("FAIL: the check-mode end task must remain scoped to the sync play")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("OK: check mode shows decisions, ends before authentication, and leaves later site plays intact")
