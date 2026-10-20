#!/usr/bin/env python3
"""Guard boolean normalization in saved-search REST comparisons."""

import ast
from pathlib import Path

import yaml

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
TASK_FILE = ROOT / "roles/splunk_docker/tasks/apply_saved_search_override.yml"
TASKS = yaml.safe_load(TASK_FILE.read_text())
DELTA_TEMPLATE = next(
    task["ansible.builtin.set_fact"]["splunk_docker_saved_search_delta"]
    for task in TASKS
    if task.get("name", "").startswith("Work out which settings differ")
)
ENV = ansible_env(ROOT / "roles/splunk_docker/templates")
ENV.filters["string"] = str


def delta(live, wanted):
    rendered = ENV.from_string(DELTA_TEMPLATE).render(
        splunk_docker_saved_search_current={"json": {"entry": [{"content": live}]}},
        splunk_docker_saved_search_wanted=wanted,
    )
    return ast.literal_eval(rendered)


live = {
    "disabled": True,
    "enableSched": "true",
    "action.email": "FALSE",
    "label": "CaseSensitive",
}
wanted = {
    "disabled": 1,
    "enableSched": 1,
    "action.email": 0,
    "label": "CaseSensitive",
}
if result := delta(live, wanted):
    raise SystemExit(f"FAIL: equivalent boolean values produced a delta: {result}")

if result := delta({"disabled": "false"}, {"disabled": 1}):
    if result != {"disabled": 1}:
        raise SystemExit(f"FAIL: changed boolean produced the wrong delta: {result}")
else:
    raise SystemExit("FAIL: a differing boolean did not produce a delta")

if result := delta({"label": "casesensitive"}, {"label": "CaseSensitive"}):
    if result != {"label": "CaseSensitive"}:
        raise SystemExit(f"FAIL: case-sensitive setting produced the wrong delta: {result}")
else:
    raise SystemExit("FAIL: case-sensitive values were compared without their case")

print("PASS: REST boolean forms compare idempotently while other strings remain case-sensitive")
