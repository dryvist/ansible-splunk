#!/usr/bin/env python3
"""Guard the Zammad alert-action configuration and credential delivery path."""

import sys
from pathlib import Path

import yaml

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
TASK_FILE = ROOT / "roles/splunk_docker/tasks/zammad_alert_action.yml"
MAIN_FILE = ROOT / "roles/splunk_docker/tasks/main.yml"
TEMPLATES = ROOT / "roles/splunk_docker/templates"
TEST_URL = "https://zammad.example.invalid/api/v1"
TEST_TOKEN = "placeholder-" + "token"

errors = []

expected_defaults = {
    "splunk_docker_zammad_url_openbao_key": "SPLUNK_ZAMMAD_URL",
    "splunk_docker_zammad_token_openbao_key": "SPLUNK_ZAMMAD_TOKEN",
}
for name, expected in expected_defaults.items():
    if DEFAULTS.get(name) != expected:
        errors.append(f"FAIL: {name} expected {expected!r}, got {DEFAULTS.get(name)!r}")

rendered = ansible_env(TEMPLATES).get_template("zammad_alert_actions.conf.j2").render(
    splunk_docker_zammad_url_openbao_key="SPLUNK_ZAMMAD_URL",
    splunk_docker_zammad_bao_secret={
        "json": {
            "data": {
                "data": {
                    "SPLUNK_ZAMMAD_URL": TEST_URL,
                    "SPLUNK_ZAMMAD_TOKEN": TEST_TOKEN,
                }
            }
        }
    },
)
if rendered.splitlines() != ["[zammad]", f"param.url = {TEST_URL}"]:
    errors.append(f"FAIL: unexpected alert_actions.conf output: {rendered!r}")
if TEST_TOKEN in rendered:
    errors.append("FAIL: rendered alert_actions.conf contains the placeholder credential")

tasks = yaml.safe_load(TASK_FILE.read_text())
if not isinstance(tasks, list):
    errors.append("FAIL: zammad_alert_action.yml is not a YAML task list")
    tasks = []

secret_markers = (
    "SPLUNK_ZAMMAD_TOKEN",
    "splunk_docker_zammad_token_openbao_key",
    "splunk_docker_token_openbao_token",
    "splunk_docker_zammad_bao_secret",
    "clear_password",
    "password",
)


def scalars(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from scalars(key)
            yield from scalars(child)
    elif isinstance(value, list):
        for child in value:
            yield from scalars(child)
    elif isinstance(value, str):
        yield value


for task in tasks:
    # A quiet assert prints its fail_msg and the unexpanded expression only, so its
    # message stays visible; every other task touching the credential must hide output.
    if (task.get("ansible.builtin.assert") or {}).get("quiet") is True:
        continue
    text = " ".join(scalars(task))
    if any(marker in text for marker in secret_markers) and task.get("no_log") is not True:
        errors.append(f"FAIL: sensitive task lacks no_log: {task.get('name', '<unnamed task>')}")

main_tasks = yaml.safe_load(MAIN_FILE.read_text())
apps_index = next(
    (i for i, task in enumerate(main_tasks) if task.get("ansible.builtin.include_tasks") == "apps.yml"),
    None,
)
saved_search_index = next(
    (i for i, task in enumerate(main_tasks) if task.get("name") == "Apply saved-search overrides through the REST API"),
    None,
)
zammad_include_index = next(
    (
        i
        for i, task in enumerate(main_tasks)
        if isinstance(task.get("ansible.builtin.include_tasks"), dict)
        and task["ansible.builtin.include_tasks"].get("file") == "zammad_alert_action.yml"
    ),
    None,
)
if apps_index is None:
    errors.append("FAIL: main.yml has no apps.yml include")
if saved_search_index is None:
    errors.append("FAIL: main.yml has no saved-search override include")
if zammad_include_index is None:
    errors.append("FAIL: main.yml has no Zammad alert-action include")
else:
    zammad_tags = main_tasks[zammad_include_index].get("tags", [])
    apply_tags = (
        main_tasks[zammad_include_index]["ansible.builtin.include_tasks"]
        .get("apply", {})
        .get("tags", [])
    )
    if "alerting" not in zammad_tags or "alerting" not in apply_tags:
        errors.append("FAIL: Zammad include and included tasks must carry the alerting tag")
    if saved_search_index is not None and saved_search_index >= zammad_include_index:
        errors.append("FAIL: Zammad include must follow the saved-search override include")
if apps_index is not None and zammad_include_index is not None and apps_index >= zammad_include_index:
    errors.append("FAIL: Zammad include must follow the apps.yml include")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: Zammad URL rendering, secret logging, defaults and alerting include contract")
