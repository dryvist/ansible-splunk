#!/usr/bin/env python3
"""Guard the rendered router database-failure digest contract."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
TEMPLATES = ROOT / "roles/splunk_docker/templates"
NTFY = "https://ntfy.example.test/keystone"
ALERT_DEFAULTS = DEFAULTS["splunk_docker_llm_router_db_unreachable"]

render_values = dict(DEFAULTS)
render_values["splunk_docker_alert_ntfy_url"] = NTFY
rendered = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(**render_values)
match = re.search(r"^\[llm_router_db_unreachable\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
body = match.group(1) if match else ""


def value(key):
    found = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return found.group(1) if found else None


errors = []
expected = {
    "dispatch.earliest_time": "-15m",
    "dispatch.latest_time": "now",
    "cron_schedule": f"*/{ALERT_DEFAULTS['window_minutes']} * * * *",
    "enableSched": "1",
    "is_visible": "1",
    "disabled": "0",
    "alert.severity": "4",
    "alert.suppress": "1",
    "alert.suppress.period": "30m",
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
    "index=os_ai sourcetype=syslog",
    "match(lower(_raw),\"router\")",
    "match(lower(_raw),\"database|postgresql|postgres|sqlalchemy|psycopg|mysql|redis\")",
    "match(lower(_raw),\"connect|connection|refused|unreachable|timeout\")",
    "match(lower(_raw),\"error|failed|refused|unreachable|timeout|exception|failure\")",
    "bin _time span=5m",
    "stats count AS failure_count dc(host) AS affected_router_count by _time",
    "where failure_count >= 1",
):
    if fragment not in search:
        errors.append(f"FAIL: search is missing {fragment!r}")
if value("action.webhook") != "1" or not value("action.webhook.param.url"):
    errors.append("FAIL: alert has no rendered alert delivery")
if "host=llm-router" in search:
    errors.append("FAIL: search includes a literal router host pattern")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: rendered router database-failure alert has the expected digest and delivery")
