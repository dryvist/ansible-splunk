#!/usr/bin/env python3
"""
Guard the gpu_utilization_report status-topic report (savedsearches/27-gpu-utilization.j2).

GPU utilization is published to the hub's status topic every 30 minutes as a
standard metrics report on the regular ntfy pipeline: the same delivery shape
as the other status-topic stanzas -- status_delivery only, severity 1, no
suppression, firing when the search returns at least one row -- so nothing
pages and no help-desk ticket opens.

1. The stanza renders exactly once, and the 30-minute cron plus the
   house allow_skew setting sit on their own lines.
2. Delivery rides status_delivery alone: one webhook URL, on the status
   topic, never the alert topic, and no suppression that would drop runs.
3. The search reads both raw utilization series with mstats, one window
   each (last 30 minutes, last 4 hours), per host, folded into a single
   multi-line message field.
4. The template carries no literal host name (pve-, jevans, or a dotted
   domain) and no channel name: hosts come from the metric data, and the
   delivery URL comes from the shared status_delivery macro, not this file.

Run from repo root:
  python3 tests/templates/test_gpu_utilization_report.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
TEMPLATE = ROOT / "roles/splunk_docker/templates/savedsearches/27-gpu-utilization.j2"
NTFY = "https://ntfy.example.test/keystone"

STANZA_NAME = "gpu_utilization_report"
STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)
# A dotted domain: three dot-separated labels, the last one alphabetic.
# Applied to the search and description values, where a literal host could
# hide; the fixed conf keys (alert.suppress.period and friends) carry dots
# of their own, so the raw file is not scanned.
DOMAIN_RE = re.compile(r"\b[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9-]*\.[a-z]{2,6}\b")

env = ansible_env(ROOT / "roles/splunk_docker/templates")
env.filters["regex_escape"] = re.escape
env.filters["comment"] = lambda text: f"# {text}"


def render_master(**overrides):
    """The full rendered savedsearches.conf, from role defaults."""
    context = {**DEFAULTS, "splunk_docker_alert_ntfy_url": None, **overrides}
    return env.get_template("savedsearches.conf.j2").render(**context)


def stanza_body(master, name=STANZA_NAME):
    for match in STANZA_RE.finditer(master):
        if match.group(1) == name:
            return match.group(2)
    return None


def line_of(body, key):
    m = re.search(rf"^{re.escape(key)} = (.*)$", body or "", re.M)
    return m.group(1) if m else None


errors = []

plain_master = render_master()
plain = stanza_body(plain_master)
if plain is None:
    print(f"FAIL: [{STANZA_NAME}] not found in the rendered savedsearches.conf")
    sys.exit(1)

# 1. exactly once, 30-minute schedule, skew in effect
occurrences = len(re.findall(rf"^\[{STANZA_NAME}\]$", plain_master, re.M))
if occurrences != 1:
    errors.append(f"FAIL: [{STANZA_NAME}] appears {occurrences} times in the rendered output; expected exactly once")

REQUIRED_LINES = (
    "cron_schedule = */30 * * * *",
    "allow_skew = 5m",
    "dispatch.earliest_time = -4h",
    "dispatch.latest_time = now",
    "enableSched = 1",
    "is_visible = 1",
    "disabled = 0",
    "alert.severity = 1",
    # fires when the search returns at least one row -- same trigger as the
    # other status-topic report -- so every run publishes the report
    "counttype = number of events",
    "relation = greater than",
    "quantity = 0",
)
for line in REQUIRED_LINES:
    if re.search(rf"^{re.escape(line)}$", plain, re.M) is None:
        errors.append(f"FAIL: [{STANZA_NAME}] is missing '{line}' on its own line")

# 2. delivery: status topic only, low-priority override
hub_master = render_master(splunk_docker_alert_ntfy_url=NTFY)
hub = stanza_body(hub_master) or ""
urls = re.findall(r"^action\.webhook\.param\.url = (.*)$", hub, re.M)
# A second url line would win over status_delivery (last key wins in a stanza).
if len(urls) != 1 or not urls[0].startswith("https://ntfy.example.test/status?priority=default"):
    errors.append(f"FAIL: [{STANZA_NAME}] must carry exactly one webhook URL, on the status topic; URLs: {urls}")
if "alert.suppress" in hub:
    errors.append(f"FAIL: [{STANZA_NAME}] suppresses runs; a report publishes every run")
if "priority=high" in hub:
    errors.append(f"FAIL: [{STANZA_NAME}] carries paging (keystone) delivery; it must use status_delivery only")

# 3. search shape: two mstats windows, both metrics, per host, one message field
search = line_of(plain, "search") or ""
required_search = (
    "| mstats",
    "node_gpu_utilization_gpu_percent_all",
    "macmon_gpu_active_ratio",
    "WHERE index=*",
    "earliest=-30m",
    "earliest=-4h",
    "by host",
    "* 100",
    "round(",
    '"no data"',
    '"GPU utilization"',
    'mvjoin(lines, urldecode("%0A"))',
    "| sort 0 host | stats list(line) as lines",
    "| table message",
)
for fragment in required_search:
    if fragment not in search:
        errors.append(f"FAIL: the search is missing {fragment!r}")
# eval has printf, not sprintf; a call to it fails the whole search
if "sprintf(" in search:
    errors.append("FAIL: the search calls sprintf(), which is not an eval function")
for mark in ("🟢", "🟡", "🔴"):
    if mark not in search:
        errors.append(f"FAIL: the search is missing the {mark} mark")

# 4. no literal hosts, no channel names, no address
text = TEMPLATE.read_text()
if "pve-" in text:
    errors.append("FAIL: the template names a Proxmox host by pattern (pve-); hosts must come from the data")
if "jevans" in text.lower():
    errors.append("FAIL: the template carries a personal name; it must stay deployment-agnostic")
for label, value in (("search", search), ("description", line_of(plain, "description") or "")):
    for hit in DOMAIN_RE.findall(value):
        errors.append(f"FAIL: the {label} carries a dotted-domain literal: {hit}")
if "http" in text.lower():
    errors.append("FAIL: the template carries a literal URL; the delivery URL must come from the status_delivery macro")
if "keystone" in text.lower():
    errors.append("FAIL: the template names the alert topic; this report stays on the status topic")

# the dotted-domain guard must catch real hosts and not conf-style content
if not DOMAIN_RE.search("pve-gpu01.internal.lan"):
    errors.append("FAIL: the dotted-domain guard no longer catches a literal host name")
if DOMAIN_RE.search("round(x, 0) */30 * * * *"):
    errors.append("FAIL: the dotted-domain guard false-positives on search content")

if errors:
    for error in errors:
        print(error)
    sys.exit(1)

print("PASS: gpu_utilization_report renders once, on a 30-minute schedule with skew in effect,")
print("     delivered to the status topic alone with no suppression, and its search")
print("     reads both GPU utilization series per host with no literal hosts or channels.")
print("All tests passed.")
