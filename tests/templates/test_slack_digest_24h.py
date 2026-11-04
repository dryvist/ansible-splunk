#!/usr/bin/env python3
"""
Guard the Slack digest on the saved searches that notify Slack.

Each listed search sends at most one notification per 24 hours, and that
notification lists every hit (digest_mode = 1). The suppression carries no
per-key field, so the digest is not split per host, request or index.

Asserts on the RENDERED savedsearches.conf, not the template source, so a
variable that never reaches the template shows up here instead of at converge.

Run from repo root:
  python3 tests/templates/test_slack_digest_24h.py
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

DIGESTED = (
    "os_silence_detector",
    "index_gap_detector",
    "llm_pipeline_silence_detector",
    "llm_router_silence_detector",
    "offbox_sync_job_unhealthy",
    "mac_windowserver_synchronize_timeout",
    "pve_swap_active",
)


def value(body, key):
    match = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return match.group(1) if match else None


def is_24h(period):
    # os_silence_detector renders its period from minutes, so 1440m is the same 24 hours.
    return period in ("24h", "1440m")


context = {**DEFAULTS, "splunk_docker_alert_ntfy_url": None}
stanzas = {m.group(1): m.group(2) for m in STANZA_RE.finditer(TEMPLATE.render(**context))}

errors = []
checks = 0
for name in DIGESTED:
    body = stanzas.get(name)
    if body is None:
        checks += 1
        errors.append(f"FAIL: [{name}] was not rendered")
        continue
    expectations = {
        "alert.digest_mode": "1",
        "alert.suppress": "1",
    }
    for key, want in expectations.items():
        checks += 1
        if value(body, key) != want:
            errors.append(f"FAIL: [{name}] {key} is {value(body, key)!r}, want {want!r}")
    checks += 1
    if not is_24h(value(body, "alert.suppress.period") or ""):
        errors.append(f"FAIL: [{name}] alert.suppress.period is {value(body, 'alert.suppress.period')!r}, want 24h")
    checks += 1
    if value(body, "alert.suppress.fields") is not None:
        errors.append(f"FAIL: [{name}] still sets alert.suppress.fields")

failed = len(errors)
for err in errors:
    print(err)
print(f"{checks - failed} passed, {failed} failed, {checks} checks across {len(DIGESTED)} saved searches")
if errors:
    sys.exit(1)
print("PASS: every Slack-notifying saved search sends one digest per 24 hours")
