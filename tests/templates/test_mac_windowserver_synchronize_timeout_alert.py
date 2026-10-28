#!/usr/bin/env python3
"""
Guard the mac_windowserver_synchronize_timeout alert's search, schedule and delivery.

Asserts on the RENDERED savedsearches.conf, not the template source, so a
variable that never reaches the template, or a Jinja construct that eats a
newline, shows up here instead of at converge.

1. The search reads only WindowServer "synchronize timed out" unified-log lines
   and counts them by host.
2. Scheduling, suppression and severity are each on their own line.
3. The search shares no clause with mac_windowserver_watchdog_checkin_gap or
   mac_ws_monitor_freeze, and both of those still render beside this one.
4. The shared alert_delivery webhook renders when a hub URL is set.

Run from repo root:
  python3 tests/templates/test_mac_windowserver_synchronize_timeout_alert.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)

NAME = "mac_windowserver_synchronize_timeout"
NEIGHBOURS = ("mac_windowserver_watchdog_checkin_gap", "mac_ws_monitor_freeze")
STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)
SEARCH_RE = re.compile(r"^search = (.*)$", re.M)
TEMPLATE = ansible_env(ROOT / "roles/splunk_docker/templates").get_template("savedsearches.conf.j2")

EXPECTED_SEARCH = (
    'index=os sourcetype=macos:unified_log process=WindowServer "synchronize timed out"'
    " | stats count by host"
)

# Keys the stanza must carry verbatim, one per line.
REQUIRED_LINES = (
    "enableSched = 1",
    "disabled = 0",
    "dispatch.earliest_time = -10m",
    "cron_schedule = */5 * * * *",
    "alert.severity = 4",
    "alert.suppress = 1",
    "alert.suppress.period = 60m",
    "alert.suppress.fields = host",
)

# Clauses owned by the neighbouring detectors; this search must not repeat them.
NEIGHBOUR_CLAUSES = (
    "userspace watchdog timeout",
    "DiagnosticReports",
    "ws-monitor",
    "severity=FREEZE",
)


def render_stanza(name=NAME, **overrides):
    """A stanza's body from the full master template, rendered with role defaults."""
    context = {**DEFAULTS, "splunk_docker_alert_ntfy_url": None, **overrides}
    for match in STANZA_RE.finditer(TEMPLATE.render(**context)):
        if match.group(1) == name:
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

# 1. Only WindowServer synchronize-timeout lines, counted per host.
if search != EXPECTED_SEARCH:
    errors.append(f"FAIL: search is {search!r}, expected {EXPECTED_SEARCH!r}")

# 2. Schedule, suppression and severity, each on its own line (a welded key fails here).
for line in REQUIRED_LINES:
    if not re.search(rf"^{re.escape(line)}$", body, re.M):
        errors.append(f"FAIL: stanza is missing the line {line!r}")

# 3. No overlap with the neighbouring detectors, which must still render.
for clause in NEIGHBOUR_CLAUSES:
    if clause in search:
        errors.append(f"FAIL: search repeats {clause!r}, a clause a neighbouring detector owns")
for neighbour in NEIGHBOURS:
    if render_stanza(neighbour) is None:
        errors.append(f"FAIL: [{neighbour}] no longer renders beside [{NAME}]")

# 4. Delivery rides the shared macro: a hub URL renders the webhook action.
hub_body = render_stanza(splunk_docker_alert_ntfy_url="https://ntfy.example.test/keystone") or ""
if "action.webhook = 1" not in hub_body:
    errors.append("FAIL: with a hub URL set, the stanza does not render the shared webhook action")

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print(
    "PASS: mac_windowserver_synchronize_timeout counts WindowServer synchronize-timeout lines "
    "per host over ten minutes, carries its schedule, suppression and severity, shares no clause "
    "with its neighbouring Mac detectors, and delivers via the shared alert_delivery macro."
)
print("\nAll tests passed.")
