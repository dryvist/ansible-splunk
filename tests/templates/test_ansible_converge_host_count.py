#!/usr/bin/env python3
"""Guard the rendered Ansible converge host-count alert contract."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
TEMPLATES = ROOT / "roles/splunk_docker/templates"
NTFY = "https://ntfy.example.test/keystone"
ALERT_DEFAULTS = DEFAULTS["splunk_docker_ansible_converge_host_count"]

render_values = dict(DEFAULTS)
render_values["splunk_docker_alert_ntfy_url"] = NTFY
rendered = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(**render_values)

stanzas = {
    match.group(1): match.group(2)
    for match in re.finditer(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
}


def value(body, key, default=None):
    match = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return match.group(1) if match else default


errors = []
body = stanzas.get("ansible_converge_host_count")
if body is None:
    errors.append("FAIL: [ansible_converge_host_count] was not rendered")
else:
    expected = {
        "dispatch.earliest_time": f"-{ALERT_DEFAULTS['history_window_days']}d@d",
        "dispatch.latest_time": "now",
        "cron_schedule": f"*/{ALERT_DEFAULTS['freshness_window_minutes']} * * * *",
        "enableSched": "1",
        "is_visible": "1",
        "disabled": "0",
        "alert.severity": "4",
        "alert.suppress": "1",
        "alert.suppress.period": "1h",
        "alert.suppress.fields": "playbook",
        "alert.track": "1",
        "counttype": "number of events",
        "relation": "greater than",
        "quantity": "0",
    }
    for key, expected_value in expected.items():
        if value(body, key) != expected_value:
            errors.append(
                f"FAIL: [ansible_converge_host_count] {key} expected "
                f"{expected_value!r}, got {value(body, key)!r}"
            )

    search = value(body, "search", "")
    for fragment in (
        "index=ansible",
        'sourcetype="ansible:converge:run"',
        f"earliest=-{ALERT_DEFAULTS['history_window_days']}d",
        "tonumber(hosts)",
        "sort 0 playbook _time",
        "streamstats current=f window=0",
        "count as history_count",
        "median(host_count) as median_hosts",
        f'_time >= relative_time(now(), "-{ALERT_DEFAULTS["freshness_window_minutes"]}m")',
        f"host_count=0 OR (history_count>={ALERT_DEFAULTS['minimum_history_runs']} AND host_count < median_hosts * {ALERT_DEFAULTS['low_host_count_ratio']})",
        "table _time, playbook, host_count, median_hosts, history_count, repo, git_sha",
    ):
        if fragment not in search:
            errors.append(f"FAIL: search is missing {fragment!r}")
    if value(body, "description") is None:
        errors.append("FAIL: alert has no one-line description")
    if "description =" in search:
        errors.append("FAIL: rendered search includes the next stanza setting")
    freshness_filter = f'_time >= relative_time(now(), "-{ALERT_DEFAULTS["freshness_window_minutes"]}m")'
    if search.find(freshness_filter) < search.find("streamstats current=f window=0"):
        errors.append("FAIL: freshness filter runs before the historical median is computed")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: rendered Ansible converge host-count alert has history guard and run-level search")
