#!/usr/bin/env python3
"""
Guard the mac_process_lifecycle_silence alert's search, threshold, schedule and delivery.

Asserts on the RENDERED savedsearches.conf, not the template source, so a
variable that never reaches the template, or a Jinja construct that eats a
newline, shows up here instead of at converge.

1. The search is a tstats over index=os sourcetype=macos:process:lifecycle.
2. The appendpipe guard renders, so a fully silent window still yields a row.
3. The threshold is 15 minutes, and the schedule, suppression and severity are each on their own line.
4. The shared alert_delivery webhook renders when a hub URL is set.

Run from repo root:
  python3 tests/templates/test_mac_process_lifecycle_silence_alert.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)

NAME = "mac_process_lifecycle_silence"
STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)
SEARCH_RE = re.compile(r"^search = (.*)$", re.M)
TEMPLATE = ansible_env(ROOT / "roles/splunk_docker/templates").get_template("savedsearches.conf.j2")

SOURCE = "WHERE index=os sourcetype=macos:process:lifecycle"
APPENDPIPE_GUARD = "appendpipe [ stats count as _rows | where _rows == 0 | eval last_seen = 0 | fields - _rows ]"
THRESHOLD = "| where minutes_silent > 15"

# Keys the stanza must carry verbatim, one per line.
REQUIRED_LINES = (
    "enableSched = 1",
    "disabled = 0",
    "dispatch.earliest_time = -24h",
    "cron_schedule = */5 * * * *",
    "alert.severity = 4",
    "alert.suppress = 1",
    "alert.suppress.period = 24h",
)


def render_stanza(**overrides):
    """This stanza's body from the full master template, rendered with role defaults."""
    context = {**DEFAULTS, "splunk_docker_alert_ntfy_url": None, **overrides}
    for match in STANZA_RE.finditer(TEMPLATE.render(**context)):
        if match.group(1) == NAME:
            return match.group(2)
    return None


def search_of(body):
    found = SEARCH_RE.search(body or "")
    return found.group(1) if found else ""


errors = []

body = render_stanza()
if body is None:
    print(f"FAIL: [{NAME}] not found in rendered output")
    sys.exit(1)
search = search_of(body)

# 1. The search reads only the lifecycle sourcetype from index=os.
if "tstats" not in search or SOURCE not in search:
    errors.append(f"FAIL: search does not read {SOURCE!r} through tstats: {search!r}")

# 2. The zero-row guard renders, so total silence still produces a result row.
if APPENDPIPE_GUARD not in search:
    errors.append("FAIL: search is missing the appendpipe zero-row guard")

# 3. The threshold is 15 minutes, and the schedule, suppression and severity are each on their own line.
if not search.endswith(THRESHOLD):
    errors.append(f"FAIL: search does not end with {THRESHOLD!r}")
for line in REQUIRED_LINES:
    if not re.search(rf"^{re.escape(line)}$", body, re.M):
        errors.append(f"FAIL: stanza is missing the line {line!r}")

# 4. Delivery rides the shared macro: a hub URL renders the webhook action.
hub_body = render_stanza(splunk_docker_alert_ntfy_url="https://ntfy.example.test/keystone") or ""
if "action.webhook = 1" not in hub_body:
    errors.append("FAIL: with a hub URL set, the stanza does not render the shared webhook action")

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print(
    "PASS: mac_process_lifecycle_silence runs a tstats over index=os sourcetype=macos:process:lifecycle "
    "with the appendpipe zero-row guard, fires past 15 minutes of silence, carries its schedule, "
    "suppression and severity, and delivers via the shared alert_delivery macro."
)
print("\nAll tests passed.")
