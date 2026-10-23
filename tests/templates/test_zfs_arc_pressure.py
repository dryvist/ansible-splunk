#!/usr/bin/env python3
"""Guard the rendered ZFS ARC pressure alert contract."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
TEMPLATES = ROOT / "roles/splunk_docker/templates"
NTFY = "https://ntfy.example.test/keystone"

render_values = dict(DEFAULTS)
render_values["splunk_docker_alert_ntfy_url"] = NTFY
rendered = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(**render_values)
match = re.search(r"^\[zfs_arc_pressure\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
body = match.group(1) if match else ""


def value(key):
    found = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return found.group(1) if found else None


errors = []
expected = {
    "dispatch.earliest_time": "-15m",
    "dispatch.latest_time": "now",
    "cron_schedule": f"*/{ALERT_DEFAULTS['span_minutes']} * * * *",
    "enableSched": "1",
    "is_visible": "1",
    "disabled": "0",
    "alert.severity": "5",
    "alert.suppress": "1",
    "alert.suppress.period": "60m",
    "alert.suppress.fields": "host",
    "alert.track": "1",
    "counttype": "number of events",
    "relation": "greater than",
    "quantity": "0",
}
for key, expected_value in expected.items():
    if value(key) != expected_value:
        errors.append(f"FAIL: {key} expected {expected_value!r}, got {value(key)!r}")

search = " ".join(body.splitlines())
for fragment in (
    "latest(node_zfs_arc_memory_available_bytes) as available",
    "latest(node_zfs_arc_memory_all_bytes) as total",
    "WHERE index=host_metrics span=5m BY host",
    "| eval available_pct=round(100*available/total,1)",
    "| where available_pct < 10",
    "| stats count AS pressured_samples min(available_pct) AS lowest_available_pct by host",
):
    if fragment not in search:
        errors.append(f"FAIL: search is missing {fragment!r}")
if value("action.webhook") != "1" or not value("action.webhook.param.url"):
    errors.append("FAIL: alert has no rendered alert delivery")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: rendered ZFS ARC pressure alert has the expected metric, threshold and delivery")
