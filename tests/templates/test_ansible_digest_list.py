#!/usr/bin/env python3
"""
Guard the per-row list on the ansible pipeline-staleness digests.

Each listed search sends a Slack digest (digest_mode = 1). The webhook action
sends only the first result row, so every row must carry the full list of its
per-row values. Each search must hold eventstats values(<key>) as <list field>,
then an mvjoin of that list after the eventstats, and its table clause must keep
the list field so it reaches the payload.

Asserts on the RENDERED savedsearches.conf, not the template source, so a
variable that never reaches the template shows up here instead of at converge.

Run from repo root:
  python3 tests/templates/test_ansible_digest_list.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)
TEMPLATE = ansible_env(ROOT / "roles/splunk_docker/templates").get_template("savedsearches.conf.j2")

# Each entry is (per-row field, list field) for one digested search.
AGGREGATES = {
    "ansible_stale_converge": ("host", "hosts"),
    "ansible_converge_host_count": ("playbook", "playbooks"),
    "ansible_orphan_host": ("host", "hosts"),
    "ansible_apply_owed": ("host", "hosts"),
}


def search_text(body):
    # A search may continue onto following lines through a trailing backslash.
    match = re.search(r"^search = ((?:.*\\\n)*.*)$", body, re.M)
    return match.group(1) if match else ""


context = {**DEFAULTS, "splunk_docker_alert_ntfy_url": None}
stanzas = {m.group(1): m.group(2) for m in STANZA_RE.finditer(TEMPLATE.render(**context))}

errors = []
checks = 0
for name, (key, alias) in AGGREGATES.items():
    body = stanzas.get(name)
    checks += 1
    if body is None:
        errors.append(f"FAIL: [{name}] was not rendered")
        continue
    search = search_text(body)
    aggregate = re.search(rf"eventstats\b[^|]*\bvalues\({key}\) as {alias}\b", search)
    join = re.search(rf'\b{alias} ?= ?mvjoin\(mvsort\({alias}\), ?","\)', search)
    checks += 1
    if aggregate is None:
        errors.append(f"FAIL: [{name}] search lacks eventstats values({key}) as {alias}")
    checks += 1
    if join is None or aggregate is None or join.start() < aggregate.start():
        errors.append(f"FAIL: [{name}] search does not join {alias} with mvjoin(mvsort({alias}), \",\") after the eventstats")
    checks += 1
    if "| table" not in search or not re.search(rf"\b{alias}\b", search.rsplit("| table", 1)[-1]):
        errors.append(f"FAIL: [{name}] table clause drops {alias}, so the list never reaches the payload")

failed = len(errors)
for err in errors:
    print(err)
print(f"{checks - failed} passed, {failed} failed, {checks} checks across {len(AGGREGATES)} saved searches")
if errors:
    sys.exit(1)
print("PASS: every ansible digest search carries its per-row list through eventstats, mvjoin and table")
