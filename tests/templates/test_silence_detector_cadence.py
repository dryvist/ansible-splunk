#!/usr/bin/env python3
"""
Guard the two generic silence-detector bugs fixed here:

1. Lookback bug: dispatch.earliest_time was a flat -7d shared by every
   detector regardless of its threshold_minutes. A host silent longer than
   the window has no row for tstats to return at all, so a host silent
   longer than 7 days was invisible to its own detector — exactly the case
   it exists to catch. Fixed by deriving the lookback from each detector's
   own threshold_minutes (guards against it silently reverting to any flat
   constant, not just the old one). Applies to by_host entries, which still
   render their own stanza.

2. Flat-threshold bug: a by_host detector applied ONE threshold_minutes to
   every host on the index regardless of that host's normal logging cadence,
   so a naturally-quiet host fires continuously. Fixed by deriving each
   host's effective threshold from its own observed average inter-event gap
   (floored at threshold_minutes), with a host_overrides escape hatch.

A non-by_host entry no longer renders its own stanza (Zammad 17191 --
index_gap_detector replaces the flat per-index stanzas with one report); this
test checks instead that its threshold_minutes reaches index_gap_detector's
case() expression unchanged, so a bad merge or a typo'd index name in that
expression is still caught here rather than only by a full render diff.

Run from repo root:
  python3 tests/templates/test_silence_detector_cadence.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("ERROR: jinja2 not installed. Run: pip install jinja2")
    sys.exit(1)

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
DETECTORS = DEFAULTS["splunk_docker_silence_detectors"]
MULTIPLIER = DEFAULTS["splunk_docker_silence_lookback_multiplier"]

env = ansible_env(ROOT / "roles/splunk_docker/templates")
rendered = env.get_template("savedsearches.conf.j2").render(
    splunk_docker_silence_detectors=DETECTORS,
    splunk_docker_silence_lookback_multiplier=MULTIPLIER,
    splunk_docker_indexes_core=DEFAULTS["splunk_docker_indexes_core"],
    splunk_docker_indexes_extra=DEFAULTS["splunk_docker_indexes_extra"],
    splunk_docker_alert_ntfy_url=None,
    splunk_docker_alert_slack_webhook=None,
)

errors = []
by_name = {}
for stanza in re.finditer(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S):
    by_name[stanza.group(1)] = stanza.group(2)

gap_detector_body = by_name.get("index_gap_detector")
if gap_detector_body is None:
    errors.append("FAIL: [index_gap_detector] not found in rendered output")
gap_detector_search = (re.search(r"^search = (.*)$", gap_detector_body, re.M).group(1)
                        if gap_detector_body else "")

for det in DETECTORS:
    if not det.get("by_host"):
        # Non-by_host: no stanza of its own. Its threshold_minutes must
        # still reach index_gap_detector's case() expression unchanged.
        expected_branch = f'index="{det["index"]}", {det["threshold_minutes"]}'
        if expected_branch not in gap_detector_search:
            errors.append(
                f"FAIL: index_gap_detector's case() is missing "
                f"{expected_branch!r} for splunk_docker_silence_detectors "
                f"entry '{det['name']}'"
            )
        continue

    name = f"{det['name']}_silence_detector"
    body = by_name.get(name)
    if body is None:
        errors.append(f"FAIL: [{name}] not found in rendered output")
        continue

    # 1. Lookback must derive from THIS detector's own threshold, not a flat
    # constant. Assert the exact expected value so a regression to any other
    # hardcoded number (old or new) is caught, not just the specific one fixed.
    expected_lookback = f"-{det['threshold_minutes'] * MULTIPLIER}m"
    m = re.search(r"^dispatch\.earliest_time = (\S+)$", body, re.M)
    if not m or m.group(1) != expected_lookback:
        errors.append(
            f"FAIL: [{name}] dispatch.earliest_time = {m.group(1) if m else 'MISSING'}, "
            f"expected {expected_lookback} (threshold_minutes x lookback multiplier)"
        )

    # 2. by_host detectors must compare against a computed per-host threshold,
    # not the flat threshold_minutes directly.
    if "where minutes_silent > host_threshold_minutes" not in body:
        errors.append(f"FAIL: [{name}] is by_host but does not gate on host_threshold_minutes")
    if "avg_gap_minutes" not in body:
        errors.append(f"FAIL: [{name}] is by_host but computes no per-host cadence baseline")

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

by_host_count = sum(1 for det in DETECTORS if det.get("by_host"))
print(f"PASS: {by_host_count} by_host silence detector(s) have a threshold-derived lookback and "
      f"gate on a cadence-derived per-host threshold; the remaining "
      f"{len(DETECTORS) - by_host_count} entries reach index_gap_detector's case() unchanged")
print("\nAll tests passed.")
