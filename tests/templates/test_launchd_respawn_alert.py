#!/usr/bin/env python3
"""
Guard the mac_launchd_respawn_loop alert's threshold, exemptions and delivery.

Asserts on the RENDERED savedsearches.conf, not the template source, so a
variable that never reaches the template, or a Jinja construct that eats a
newline, shows up here instead of at converge.

1. The spawn threshold comes from splunk_docker_launchd_respawn_threshold: an
   override changes the rendered where clause and the default value is gone.
2. The NOT in() exemption clause renders only when the list is non-empty.
3. Scheduling, suppression and severity follow the watchdog stanza, and the
   shared alert_delivery webhook renders when a hub URL is set.

Run from repo root:
  python3 tests/templates/test_launchd_respawn_alert.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)

NAME = "mac_launchd_respawn_loop"
STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)
SEARCH_RE = re.compile(r"^search = (.*)$", re.M)
TEMPLATE = ansible_env(ROOT / "roles/splunk_docker/templates").get_template("savedsearches.conf.j2")

# Keys the stanza must carry verbatim, one per line.
REQUIRED_LINES = (
    "enableSched = 1",
    "dispatch.earliest_time = -10m",
    "cron_schedule = */5 * * * *",
    "alert.severity = 5",
    "alert.suppress = 1",
    "alert.suppress.period = 60m",
    "alert.suppress.fields = host,label",
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

# 1. The threshold is the variable's value, not a literal in the template.
threshold = DEFAULTS["splunk_docker_launchd_respawn_threshold"]
if not re.search(rf"where spawns >= {threshold}\s*\|", search):
    errors.append(f"FAIL: default threshold {threshold} is not in the rendered where clause")
tuned = threshold + 1
tuned_search = search_of(render_stanza(splunk_docker_launchd_respawn_threshold=tuned))
if not re.search(rf"where spawns >= {tuned}\s*\|", tuned_search):
    errors.append(f"FAIL: overriding the threshold to {tuned} did not change the rendered where clause")
if re.search(rf"where spawns >= {threshold}\s*\|", tuned_search):
    errors.append("FAIL: the default threshold survives an override, so the template hard-codes it")

# 2. The exemption clause is absent for the empty default and present when set.
if DEFAULTS["splunk_docker_launchd_respawn_exemptions"] != []:
    errors.append("FAIL: splunk_docker_launchd_respawn_exemptions must default to an empty list")
if "NOT in(label" in search:
    errors.append("FAIL: the exemption clause renders with the empty default list")
exempt_search = search_of(
    render_stanza(splunk_docker_launchd_respawn_exemptions=["com.example.alpha", "com.example.beta"])
)
if 'NOT in(label, "com.example.alpha", "com.example.beta")' not in exempt_search:
    errors.append("FAIL: a non-empty exemption list does not render as a NOT in() clause on label")

# 3. Search shape: the base filter, both label sources, and the output fields.
for needle in (
    'index=os sourcetype=macos:unified_log process=launchd "Successfully spawned"',
    "rex field=subsystem",
    "rex field=eventMessage",
    "table host label spawns first_seen last_seen",
):
    if needle not in search:
        errors.append(f"FAIL: search is missing {needle!r}")

# 4. Schedule, suppression and severity, each on its own line (a welded key fails here).
for line in REQUIRED_LINES:
    if not re.search(rf"^{re.escape(line)}$", body, re.M):
        errors.append(f"FAIL: stanza is missing the line {line!r}")

# 5. Delivery rides the shared macro: a hub URL renders the webhook action.
if "action.webhook = 1" not in (render_stanza(splunk_docker_alert_ntfy_url="https://ntfy.example.test/keystone") or ""):
    errors.append("FAIL: with a hub URL set, the stanza does not render the shared webhook action")

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print(
    "PASS: mac_launchd_respawn_loop takes its spawn threshold from the defaults, "
    "renders the NOT in() exemption clause only when the list is non-empty, "
    "carries the watchdog stanza's schedule, suppression and severity, and "
    "delivers via the shared alert_delivery macro."
)
print("\nAll tests passed.")
