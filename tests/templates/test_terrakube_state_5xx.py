#!/usr/bin/env python3
"""Guard the rendered Terrakube state-version HTTP 5xx alert contract."""

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
match = re.search(r"^\[terrakube_state_version_5xx\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
errors = []

if not match:
    errors.append("FAIL: [terrakube_state_version_5xx] was not rendered")
else:
    body = match.group(1)

    def value(key):
        found = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
        return found.group(1) if found else None

    search = value("search") or ""
    for key, expected in {
        "dispatch.earliest_time": f"-{DEFAULTS['splunk_docker_terrakube_state_5xx_lookback_minutes']}m",
        "dispatch.latest_time": "now",
        "cron_schedule": "*/5 * * * *",
        "disabled": "0",
        "alert.severity": "4",
        "alert.suppress": "1",
        "alert.suppress.period": "60m",
        "alert.suppress.fields": "host",
        "action.webhook": "1",
    }.items():
        if value(key) != expected:
            errors.append(f"FAIL: {key} expected {expected!r}, got {value(key)!r}")

    for fragment in (
        "index=proxy",
        "sourcetype=traefik:syslog",
        "current-state-version",
        "state-version",
        "message",
        "status_5xx",
        "host",
        f"where status_5xx >= {DEFAULTS['splunk_docker_terrakube_state_5xx_min_events']}",
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

print("PASS: rendered state-version 5xx alert has its source fields, threshold, cadence, throttle and notification destination")
