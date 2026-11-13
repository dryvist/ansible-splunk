#!/usr/bin/env python3
"""Guard the 24-hour repeat budget for high-priority saved-search alerts."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
TEMPLATES = ROOT / "roles/splunk_docker/templates"
DEFAULTS = load_defaults(ROOT)
NTFY = "https://ntfy.example.test/keystone"

# A changed state key pages immediately, and WAN-down keeps its documented
# four-hour reminder while the link remains down.
REPEAT_EXCEPTIONS = {
    "hardware_smart_failure": "A changed failing-set key pages as a new fault state.",
    "openbao_raft_quorum": "A changed quorum-state key pages each state transition.",
    "unifi_wan_down": "A four-hour repeat is documented while a WAN remains down.",
}

render_values = dict(DEFAULTS)
render_values["splunk_docker_alert_ntfy_url"] = NTFY
rendered = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(**render_values)
stanzas = {
    match.group(1): match.group(2)
    for match in re.finditer(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
}


def value(body, key):
    """Return the effective final setting in a rendered stanza."""
    matches = re.findall(rf"^{re.escape(key)}\s*=\s*(.*)$", body, re.M)
    return matches[-1].strip() if matches else None


def seconds(period):
    match = re.fullmatch(r"(\d+)([smhd])", period or "")
    if not match:
        return None
    amount, unit = int(match.group(1)), match.group(2)
    return amount * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


errors = []
high_priority_rules = set()
for name, body in stanzas.items():
    if value(body, "enableSched") != "1" or value(body, "disabled") != "0":
        continue
    if value(body, "action.webhook") != "1":
        continue
    url = value(body, "action.webhook.param.url") or ""
    if "priority=high" not in url:
        continue

    high_priority_rules.add(name)
    period = value(body, "alert.suppress.period")
    duration = seconds(period)
    if value(body, "alert.suppress") != "1":
        errors.append(f"FAIL: [{name}] has no enabled alert suppression")
    if duration is None:
        errors.append(f"FAIL: [{name}] has missing or invalid suppression period {period!r}")
    elif duration < 86400 and name not in REPEAT_EXCEPTIONS:
        errors.append(f"FAIL: [{name}] suppression period is {period!r}, below 24 hours")

if not high_priority_rules:
    errors.append("FAIL: no enabled high-priority saved-search alerts were rendered")
for name in REPEAT_EXCEPTIONS:
    if name not in high_priority_rules:
        errors.append(f"FAIL: allowlisted exception [{name}] is not an enabled high-priority alert")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print(
    f"PASS: {len(high_priority_rules)} enabled high-priority alerts suppress repeats for 24 hours; "
    f"{len(REPEAT_EXCEPTIONS)} documented exceptions retain their repeat policy"
)
