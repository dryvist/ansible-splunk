#!/usr/bin/env python3
"""
Test the container-state and log-tail tasks in playbooks/tasks/validate/01-docker-container.yml.

Renders the real redaction expression out of the task file against fixture log
lines, and checks that no task prints the registered container info whole.

Run from repo root:
  uv run -q --with jinja2 --with pyyaml python3 tests/validate_container_state/test_container_state_output.py
"""

import re
from pathlib import Path

import yaml
from jinja2.nativetypes import NativeEnvironment

TASK_FILE = Path(__file__).parent.parent.parent / "playbooks/tasks/validate/01-docker-container.yml"
TASKS = {t["name"]: t for t in yaml.safe_load(TASK_FILE.read_text())}

state = TASKS["Show Splunk container state"]
read = TASKS["Read the tail of the Splunk container log"]
show = TASKS["Show the Splunk container log tail without secret-bearing lines"]

# The registered info holds Config.Env; only named fields may be printed.
for task in (state, show):
    text = yaml.safe_dump(task["ansible.builtin.debug"])
    assert "Env" not in text and "HostConfig" not in text and "Mounts" not in text, task["name"]
    assert not re.search(r"\{\{\s*splunk_container(\.container)?\s*\}\}", text), task["name"]

assert read["no_log"] is True and read["check_mode"] is False and read["changed_when"] is False
assert read["ansible.builtin.command"]["argv"][:2] == ["docker", "logs"]

env = NativeEnvironment()
env.tests["search"] = lambda value, pattern, ignorecase=False: bool(
    re.search(pattern, value, re.IGNORECASE if ignorecase else 0)
)
# Fixture lines are built from parts so no secret-shaped literal sits in the repository.
SECRET_LINES = [
    "splunk start -auth admin:" + "example",
    "SPLUNK_PASSWORD=" + "example",
    "Authorization: Bearer " + "example",
    "hec TOKEN " + "example",
    "pass4SymmKey = " + "example",
    "-" * 5 + "BEGIN EXAMPLE" + "-" * 5,
    "api_key=" + "example",
]
PLAIN_LINES = ["PLAY RECAP ***", "fatal: [localhost]: FAILED! => migration failed", "splunkd is not running"]
log = {"stdout_lines": SECRET_LINES[:4] + PLAIN_LINES, "stderr_lines": SECRET_LINES[4:] + ["plain stderr line"]}
ctx = {
    "splunk_container_log": log,
    "_splunk_log_redact": show["vars"]["_splunk_log_redact"],
    "_splunk_log_failure": show["vars"]["_splunk_log_failure"],
}
for name in ("_splunk_stdout_safe", "_splunk_stderr_safe"):
    ctx[name] = env.from_string(show["vars"][name]).render(**ctx)
out = {key: env.from_string(expr).render(**ctx) for key, expr in show["ansible.builtin.debug"]["msg"].items()}

printed = out["failure_lines"] + out["stdout_tail"] + out["stderr_tail"]
for line in SECRET_LINES:
    assert line not in printed, line
assert out["stdout_tail"] == PLAIN_LINES
assert out["stderr_tail"] == ["plain stderr line"]
# Recap and failure lines surface even when they are not the newest lines.
assert out["failure_lines"] == PLAIN_LINES[:2]

print("ok")
