#!/usr/bin/env python3
"""
Guard the mac_notificationcenter_runaway alert's search, schedule and delivery.

Asserts on the RENDERED savedsearches.conf, not the template source, so a
variable that never reaches the template, or a Jinja construct that eats a
newline, shows up here instead of at converge.

1. The search expands the ws-monitor top-5 CPU entries in index=mac_perf and
   keeps only the NotificationCenter executable.
2. Scheduling, suppression and severity are each on their own line.
3. The search repeats none of the clauses the neighbouring Mac detectors own,
   and those detectors still render beside this one.
4. The shared alert_delivery webhook renders when a hub URL is set.

Run from repo root:
  python3 tests/templates/test_mac_notificationcenter_runaway_alert.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)

NAME = "mac_notificationcenter_runaway"
NEIGHBOURS = ("mac_ws_monitor_freeze", "mac_windowserver_synchronize_timeout", "mac_windowserver_watchdog_checkin_gap")
STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)
SEARCH_RE = re.compile(r"^search = (.*)$", re.M)
TEMPLATE = ansible_env(ROOT / "roles/splunk_docker/templates").get_template("savedsearches.conf.j2")

EXPECTED_SEARCH = (
    "index=mac_perf sourcetype=ws-monitor host=jevans-mbp*"
    " | eventstats count AS samples BY host"
    " | eval procs = 'top_processes{}'"
    " | mvexpand procs"
    r' | rex field=procs "^\s*\d+\s+(?<pcpu>[\d.]+)\s+\d+\s+(?<command>\S.*?)\s*$"'
    ' | where match(command, "/NotificationCenter$")'
    " | eval pcpu = tonumber(pcpu)"
    " | stats count AS appearances avg(pcpu) AS mean_cpu max(samples) AS samples BY host"
    " | where appearances >= 0.5 * samples AND mean_cpu >= 40"
)

# Keys the stanza must carry verbatim, one per line.
REQUIRED_LINES = (
    "enableSched = 1",
    "disabled = 0",
    "dispatch.earliest_time = -30m",
    "cron_schedule = */5 * * * *",
    "alert.severity = 4",
    "alert.suppress = 1",
    "alert.suppress.period = 24h",
    "alert.suppress.fields = host",
)

# Clauses owned by the neighbouring detectors; this search must not repeat them.
NEIGHBOUR_CLAUSES = (
    "severity=FREEZE",
    "DiagnosticReports",
    "userspace watchdog timeout",
    "synchronize timed out",
    "WindowServer",
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

# 1. Only NotificationCenter entries of the ws-monitor top-5 lists are counted.
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
    "PASS: mac_notificationcenter_runaway expands ws-monitor top-5 CPU entries in index=mac_perf "
    "and keeps NotificationCenter, carries its schedule, suppression and severity, shares no clause "
    "with its neighbouring Mac detectors, and delivers via the shared alert_delivery macro."
)
print("\nAll tests passed.")
