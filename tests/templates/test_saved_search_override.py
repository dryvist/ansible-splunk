#!/usr/bin/env python3
"""Guard the saved-search REST API enablement and readback contract."""

import ast
import sys
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined

from _defaults_loader import load_defaults

ROOT = Path(__file__).parent.parent.parent
TASK_FILE = ROOT / "roles/splunk_docker/tasks/apply_saved_search_override.yml"
DEFAULTS = load_defaults(ROOT)
DELIVERY = DEFAULTS["splunk_docker_saved_search_delivery_ntfy"]
TASKS = yaml.safe_load(TASK_FILE.read_text())
DELTA_SOURCE = next(
    task["ansible.builtin.set_fact"]["splunk_docker_saved_search_delta"]
    for task in TASKS
    if task.get("name", "").startswith("Work out which settings differ")
)
DUMMY_URL = "https://example.invalid/dmc-webhook"
WANTED = {"disabled": 0, "alert.track": 1, **DELIVERY}
WANTED["action.webhook.param.url"] = DUMMY_URL


def delta(content: dict) -> dict:
    """Render the task's Jinja comparison against one REST API response."""
    rendered = Environment(undefined=StrictUndefined).from_string(DELTA_SOURCE).render(
        splunk_docker_saved_search_current={"json": {"entry": [{"content": content}]}},
        splunk_docker_saved_search_wanted=WANTED,
    )
    return ast.literal_eval(rendered)


errors = []
if DELIVERY.get("actions") != "webhook" or "action.webhook" in DELIVERY:
    errors.append("FAIL: REST delivery must enable the webhook through actions=webhook")

legacy_post_readback = {
    "disabled": "0",
    "alert.track": "1",
    "action.webhook": "0",
    "actions": "",
    "action.webhook.param.url": DUMMY_URL,
}
if delta(legacy_post_readback) != {"actions": "webhook"}:
    errors.append("FAIL: the old readback must request only the REST actions enablement field")

enabled_readback = {
    "disabled": "0",
    "alert.track": "1",
    "action.webhook": "1",
    "actions": "webhook",
    "action.webhook.param.url": DUMMY_URL,
}
if delta(enabled_readback):
    errors.append("FAIL: the enabled webhook readback must produce an empty delta")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: saved-search webhook enablement uses `actions`, and its REST readback converges cleanly")
