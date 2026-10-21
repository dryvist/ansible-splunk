#!/usr/bin/env python3
"""Guard the rendered LiteLLM request-volume alert contract."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
TEMPLATES = ROOT / "roles/splunk_docker/templates"
NTFY = "https://ntfy.example.test/keystone"

render_values = {**DEFAULTS, "splunk_docker_alert_ntfy_url": NTFY}
rendered = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(**render_values)
match = re.search(r"^\[litellm_request_volume_drop\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
errors = []

if not match:
    errors.append("FAIL: [litellm_request_volume_drop] was not rendered")
else:
    body = match.group(1)

    def value(key):
        found = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
        return found.group(1) if found else None

    search = value("search") or ""
    expected = {
        "dispatch.earliest_time": f"-{DEFAULTS['splunk_docker_litellm_request_dispatch_days']}d@h",
        "dispatch.latest_time": "now",
        "cron_schedule": "5 * * * *",
        "disabled": "0",
        "alert.severity": "4",
        "alert.suppress": "1",
        "alert.suppress.period": "60m",
        "action.webhook": "1",
    }
    for key, expected_value in expected.items():
        if value(key) != expected_value:
            errors.append(f"FAIL: {key} expected {expected_value!r}, got {value(key)!r}")

    for fragment in (
        "index=llm",
        'sourcetype="litellm:proxy"',
        "fields _time message",
        "path=event output=event",
        'event="llm_request"',
        "message",
        "timechart span=1h",
        "makecontinuous _time span=1h",
        "eventstats median(baseline_requests) as baseline by hour",
        f"relative_time(target_hour, \"-{DEFAULTS['splunk_docker_litellm_request_baseline_days']}d\")",
        f"baseline >= {DEFAULTS['splunk_docker_litellm_request_min_baseline_per_hour']} AND requests < baseline * {DEFAULTS['splunk_docker_litellm_request_drop_ratio']}",
        'relative_time(info_max_time, "-1h@h")',
    ):
        if fragment not in search:
            errors.append(f"FAIL: search is missing {fragment!r}")
    if "{{" in search or "}}" in search:
        errors.append("FAIL: search contains an unrendered placeholder")
    if value("description") is None:
        errors.append("FAIL: alert has no description")
    if not value("action.webhook.param.url").startswith(NTFY):
        errors.append("FAIL: alert does not use the rendered notification destination")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: rendered request-volume alert has its source fields, hourly baseline, schedule, throttle and notification destination")
