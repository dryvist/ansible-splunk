#!/usr/bin/env python3
"""Guard the Hermes missing Slack delivery-route alert."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
TEMPLATES = ROOT / "roles/splunk_docker/templates"
NTFY = "https://ntfy.example.test/keystone"
DEFAULTS = load_defaults(ROOT)
rendered = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(
    **{**DEFAULTS, "splunk_docker_alert_ntfy_url": NTFY}
)
match = re.search(
    r"^\[hermes_slack_delivery_route_missing\]$(.*?)(?=^\[|\Z)",
    rendered,
    re.M | re.S,
)
errors = []

if not match:
    errors.append("FAIL: missing Hermes Slack delivery-route alert")
else:
    body = match.group(1)

    def value(key):
        found = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
        return found.group(1) if found else None

    search = value("search") or ""
    expected = {
        "dispatch.earliest_time": "-15m",
        "dispatch.latest_time": "now",
        "cron_schedule": "*/5 * * * *",
        "disabled": "0",
        "alert.suppress": "1",
        "alert.suppress.period": "24h",
        "alert.suppress.fields": "host,source",
        "action.webhook": "1",
    }
    for key, expected_value in expected.items():
        if value(key) != expected_value:
            errors.append(f"FAIL: {key} expected {expected_value!r}, got {value(key)!r}")

    for fragment in (
        "index=hermes",
        "platform 'slack' not configured",
        "stats count AS failure_count by host source",
        "where failure_count > 0",
    ):
        if fragment not in search:
            errors.append(f"FAIL: search is missing {fragment!r}")
    if value("action.webhook.param.url") != NTFY + DEFAULTS["splunk_docker_alert_ntfy_query"]:
        errors.append("FAIL: alert does not use the rendered alert_delivery destination")

ticker = re.search(r"^\[hermes_cron_ticker_silent\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
if not ticker:
    errors.append("FAIL: missing Hermes cron ticker silence alert")
else:
    tbody = ticker.group(1)

    def tvalue(key):
        found = re.search(rf"^{re.escape(key)} = (.*)$", tbody, re.M)
        return found.group(1) if found else None

    for key, expected_value in {
        "dispatch.earliest_time": "-75m",
        "cron_schedule": "*/15 * * * *",
        "disabled": "0",
        "alert.suppress.period": "24h",
        "action.webhook.param.url": NTFY + DEFAULTS["splunk_docker_alert_ntfy_query"],
    }.items():
        if tvalue(key) != expected_value:
            errors.append(f"FAIL: ticker {key} expected {expected_value!r}, got {tvalue(key)!r}")
    tsearch = tvalue("search") or ""
    for fragment in ('index=hermes host=hermes-agent "cron.scheduler"', "where scheduler_events = 0"):
        if fragment not in tsearch:
            errors.append(f"FAIL: ticker search is missing {fragment!r}")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: rendered Hermes Slack delivery alert searches 15 minutes, throttles by host/source and uses alert_delivery")
