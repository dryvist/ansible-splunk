#!/usr/bin/env python3
"""Container diagnostics print state and log tail without ever leaking secrets.

THE DEFECT THIS EXISTS TO CATCH
-------------------------------
The validate play registers the full `docker_container_info` result, and that
result carries the Splunk admin password inside the container's environment
list. A debug that renders the registered variable whole — or any whole
sub-dict of it — prints the admin password into playbook output the first time
someone runs validate verbosely. The diagnostics file must render a strict
allow-list of state fields only, and every container-log line matching a
secret-like term must be dropped before the log tail is printed.

FALSIFIABILITY
--------------
`_selftest` runs the same checks against mutated inputs (an unlisted
`splunk_container` path in the state print, a redaction term removed) and must
see both get flagged before the real file is trusted.
"""

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DIAGNOSTICS = ROOT / "playbooks/tasks/validate/01-docker-container-diagnostics.yml"
ENTRY = ROOT / "playbooks/validate.yml"

# Every splunk_container.* path the diagnostics file may render, and nothing else.
ALLOWED_PATHS = {
    "splunk_container.container.State.Status",
    "splunk_container.container.State.Running",
    "splunk_container.container.State.Restarting",
    "splunk_container.container.State.OOMKilled",
    "splunk_container.container.State.ExitCode",
    "splunk_container.container.State.Error",
    "splunk_container.container.State.StartedAt",
    "splunk_container.container.State.FinishedAt",
    "splunk_container.container.State.Health.Status",
    "splunk_container.container.RestartCount",
    "splunk_container.container.Config.Image",
}

# The redaction filter must list every one of these terms.
SECRET_TERMS = [
    "password",
    "passwd",
    "secret",
    "token",
    "pass4symmkey",
    "hec_token",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "-----BEGIN",
]

# Whole sub-dicts that hold secrets must never be referenced at all.
FORBIDDEN_SNIPPETS = ["Config.Env", "HostConfig", "Mounts"]


def strings_in(node):
    """Collect every string value (and key) in a parsed YAML structure."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from strings_in(key)
            yield from strings_in(value)
    elif isinstance(node, list):
        for item in node:
            yield from strings_in(item)


def unlisted_refs(strings):
    """Return splunk_container references that are not whole allow-listed paths.

    Allow-listed paths are removed first, so any leftover bare or partially
    qualified reference — the registered variable whole, `splunk_container`
    passed to debug var:, or a whole sub-dict like the container state — shows
    up here. `splunk_container_log` is a distinct token and does not match.
    """
    refs = []
    for text in strings:
        remaining = text
        for path in ALLOWED_PATHS:
            remaining = remaining.replace(path, "")
        refs.extend(re.findall(r"\bsplunk_container\b[\w.]*", remaining))
    return refs


def missing_terms(text):
    """Return redaction terms absent from the file text."""
    return [term for term in SECRET_TERMS if term not in text]


def _selftest():
    """The checks must flag a leaked path and a thinned redaction list."""
    assert unlisted_refs(["{{ splunk_container }}"]) == ["splunk_container"]
    assert unlisted_refs(["{{ splunk_container.container }}"]) == ["splunk_container.container"]
    assert unlisted_refs(["{{ splunk_container.container.Env }}"]) == [
        "splunk_container.container.Env"
    ]
    assert unlisted_refs(ALLOWED_PATHS) == []
    assert missing_terms("password|secret|-----BEGIN") == [
        "passwd",
        "token",
        "pass4symmkey",
        "hec_token",
        "api_key",
        "apikey",
        "authorization",
        "bearer",
    ]


def main():
    _selftest()
    errors = []
    if not DIAGNOSTICS.exists():
        print(f"FAIL: {DIAGNOSTICS} is missing")
        return 1

    raw = DIAGNOSTICS.read_text()
    tasks = yaml.safe_load(raw)
    strings = list(strings_in(tasks))

    for snippet in FORBIDDEN_SNIPPETS:
        if snippet in raw:
            errors.append(f"the file references {snippet}, which holds secrets")

    refs = unlisted_refs(strings)
    if refs:
        errors.append(
            "renders unlisted splunk_container paths (whole-result or sub-dict leak): "
            + ", ".join(sorted(set(refs)))
        )

    log_tasks = [t for t in tasks if "ansible.builtin.command" in t]
    if len(log_tasks) != 1:
        errors.append(f"expected exactly one command task, found {len(log_tasks)}")
    else:
        log_task = log_tasks[0]
        if log_task["ansible.builtin.command"] != {"cmd": "docker logs --tail 120 splunk"}:
            errors.append("the command task must read exactly: docker logs --tail 120 splunk")
        for key in ("changed_when", "check_mode", "failed_when"):
            if log_task.get(key) is not False:
                errors.append(f"the command task must set {key}: false")
        if log_task.get("no_log") is not True:
            errors.append("the command task must set no_log: true")
        if log_task.get("register") != "splunk_container_log":
            errors.append("the command task must register splunk_container_log")

    for text in strings:
        if "splunk_container_log" in text and "reject('search'" not in text:
            if text == "splunk_container_log":
                continue  # the register key itself
            errors.append("the log output is referenced outside the redaction reject() filter")

    if "reject('search', splunk_log_secret_terms, 'ignorecase')" not in raw:
        errors.append("the redaction must use reject('search', ..., 'ignorecase')")
    missing = missing_terms(raw)
    if missing:
        errors.append("redaction pattern list is missing terms: " + ", ".join(missing))

    debug_tasks = [t for t in tasks if "ansible.builtin.debug" in t]
    if len(debug_tasks) != 2:
        errors.append(f"expected exactly two debug tasks, found {len(debug_tasks)}")
    for debug in debug_tasks:
        if "var" in debug["ansible.builtin.debug"]:
            errors.append("a debug task prints a whole variable via var:")
        if "when" in debug:
            errors.append("a diagnostic print is conditional; both must run always")

    if any("ansible.builtin.set_fact" in t for t in tasks):
        errors.append("diagnostics must not set facts; they cannot change check results")

    play = next(p for p in yaml.safe_load(ENTRY.read_text()) if p.get("hosts") == "splunk")
    includes = [
        t["ansible.builtin.include_tasks"]
        for t in play["tasks"]
        if "ansible.builtin.include_tasks" in t
    ]
    if "tasks/validate/01-docker-container-diagnostics.yml" not in includes:
        errors.append("the validate entry point does not include the diagnostics file")
    elif not (
        includes.index("tasks/validate/01-docker-container.yml")
        < includes.index("tasks/validate/01-docker-container-diagnostics.yml")
        < includes.index("tasks/validate/02-ports-and-hec.yml")
    ):
        errors.append("the diagnostics include must sit next to the docker-container tasks")

    if errors:
        print("container diagnostics would leak or misredact:\n  " + "\n  ".join(errors))
        return 1
    print("ok: diagnostics print an explicit state allow-list and a redacted log tail")
    return 0


if __name__ == "__main__":
    sys.exit(main())