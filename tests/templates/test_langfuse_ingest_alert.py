#!/usr/bin/env python3
"""Guard the rendered Langfuse ingestion failure-signature alert contract."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
TEMPLATES = ROOT / "roles/splunk_docker/templates"
NTFY = "https://ntfy.example.test/keystone"
STANZA = "langfuse_ingest_failure_signature"

render_values = {**DEFAULTS, "splunk_docker_alert_ntfy_url": NTFY}
rendered = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(**render_values)
match = re.search(rf"^\[{STANZA}\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
errors = []

if not match:
    errors.append(f"FAIL: [{STANZA}] was not rendered")
else:
    body = match.group(1)

    def value(key):
        found = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
        return found.group(1) if found else None

    search = value("search") or ""
    expected = {
        "dispatch.earliest_time": f"-{DEFAULTS['splunk_docker_langfuse_ingest_lookback_minutes']}m",
        "dispatch.latest_time": "now",
        "cron_schedule": "*/5 * * * *",
        "disabled": "0",
        "alert.severity": "4",
        "alert.suppress": "1",
        "alert.suppress.period": "24h",
        "action.webhook": "1",
    }
    for key, expected_value in expected.items():
        if value(key) != expected_value:
            errors.append(f"FAIL: {key} expected {expected_value!r}, got {value(key)!r}")

    for fragment in (
        'index=langfuse sourcetype="langfuse:app"',
        '"could not renew lock"',
        '"Maximum call stack size exceeded"',
        '"Redis ping timeout"',
        f"lock_renew >= {DEFAULTS['splunk_docker_langfuse_ingest_lock_renew_failures']}",
        f"stack_overflow >= {DEFAULTS['splunk_docker_langfuse_ingest_stack_overflows']}",
        f"redis_ping >= {DEFAULTS['splunk_docker_langfuse_ingest_redis_ping_timeouts']}",
        'eval alert_text="Langfuse ingestion at risk: "',
    ):
        if fragment not in search:
            errors.append(f"FAIL: search is missing {fragment!r}")
    if "{{" in search or "}}" in search:
        errors.append("FAIL: search contains an unrendered placeholder")
    if value("description") is None:
        errors.append("FAIL: alert has no description")
    if not (value("action.webhook.param.url") or "").startswith(NTFY):
        errors.append("FAIL: alert does not use the rendered notification destination")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: rendered Langfuse ingestion alert has its three signatures, thresholds, schedule, throttle and destination")
