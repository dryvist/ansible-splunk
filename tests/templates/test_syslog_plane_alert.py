#!/usr/bin/env python3
"""Guard the fleet syslog silence summary alert contract."""

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
stanzas = {
    match.group(1): match.group(2)
    for match in re.finditer(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
}

body = stanzas.get("syslog_plane_down")
errors = []
if body is None:
    print("FAIL: [syslog_plane_down] was not rendered")
    sys.exit(1)


def value(key):
    match = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return match.group(1) if match else None


config = DEFAULTS["splunk_docker_syslog_plane_down"]
expected = {
    "dispatch.earliest_time": f"-{config['reporting_window_minutes'] + config['silence_minutes']}m",
    "dispatch.latest_time": "now",
    "cron_schedule": config["cron"],
    "enableSched": "1",
    "is_visible": "1",
    "alert.severity": "5",
    "alert.suppress": "1",
    "alert.suppress.period": f"{config['suppress_minutes']}m",
    "alert.track": "1",
    "counttype": "number of events",
    "relation": "greater than",
    "quantity": "0",
    "action.webhook": "1",
}
for key, expected_value in expected.items():
    if value(key) != expected_value:
        errors.append(
            f"FAIL: [syslog_plane_down] {key} expected {expected_value!r}, got {value(key)!r}"
        )

url = value("action.webhook.param.url")
if not url or not url.startswith(NTFY + "?priority=high&tpl=yes"):
    errors.append(f"FAIL: [syslog_plane_down] has no rendered alert hub destination: {url!r}")

search = value("search") or ""
required = (
    f"index={config['index']}",
    f"sourcetype={config['sourcetype']}",
    f"timechart cont=true span={config['silence_minutes']}m dc(host) as active_hosts",
    "fillnull value=0 active_hosts",
    f"streamstats current=f window={config['reporting_window_minutes'] // config['silence_minutes']} max(active_hosts) as reporting_hosts",
    "silent_host_count=reporting_hosts-active_hosts",
    f"silent_host_count >= {config['minimum_silent_hosts']}",
    'strftime(_time, "%Y-%m-%dT%H:%M:%SZ")',
    "table silent_host_count earliest_silent",
)
for fragment in required:
    if fragment not in search:
        errors.append(f"FAIL: [syslog_plane_down] search is missing {fragment!r}")
if "{{" in search or "{%" in search:
    errors.append("FAIL: [syslog_plane_down] search contains an unrendered template expression")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: rendered syslog plane summary includes count, earliest-silent field, schedule, suppression and alert delivery")
