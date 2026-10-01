#!/usr/bin/env python3
"""
Test the Hindsight bank-DR alert contract in savedsearches.conf.j2.

Four stanzas live in one file (18-hindsight-bank-dr.j2), all literal text --
no Jinja substitution reaches any of them, so reading the file is equivalent
to rendering it and needs none of the role vars the surrounding macros want.
Same rationale as test_savedsearches_conf.py's hardware_smart_failure check.

What this guards: each stanza's `search` line carries the exact index,
sourcetype, event name, result value, and (for the two absence detectors)
the threshold that makes it detect what its description claims. Drop any of
these and the alert still exists, still runs on schedule, and still returns
zero results forever -- indistinguishable from "everything is healthy".

Run from repo root:
  python3 tests/templates/test_hindsight_bank_dr_alerts.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
TEMPLATE = ROOT / "roles/splunk_docker/templates/savedsearches/18-hindsight-bank-dr.j2"

# stanza -> phrase -> what its absence would stop detecting
REQUIRED_PHRASES = {
    "hindsight_bank_export_failed": {
        "index=hindsight": "scoping to the wrong (or no) index",
        "sourcetype=hindsight:app": "matching unrelated events sharing the index",
        'event="hindsight_bank_export"': "matching the drill's events too",
        'result="fail"': "the actual failure condition",
    },
    "hindsight_dr_drill_failed": {
        "index=hindsight": "scoping to the wrong (or no) index",
        "sourcetype=hindsight:app": "matching unrelated events sharing the index",
        'event="hindsight_dr_drill"': "matching the export's events too",
        'result="fail"': "the actual failure condition",
    },
    "hindsight_bank_export_no_pass": {
        "index=hindsight": "scoping to the wrong (or no) index",
        'event="hindsight_bank_export"': "matching the drill's pass events too",
        'result="pass"': "the absence-of-success condition",
        "hours_since_pass > 26": "the 26h dead-man's-switch window",
        "_rows == 0": "the zero-row (fully silent) blind spot guard",
    },
    "hindsight_dr_drill_no_pass": {
        "index=hindsight": "scoping to the wrong (or no) index",
        'event="hindsight_dr_drill"': "matching the export's pass events too",
        'result="pass"': "the absence-of-success condition",
        "days_since_pass > 8": "the 8-day dead-man's-switch window",
        "_rows == 0": "the zero-row (fully silent) blind spot guard",
    },
}

errors = []
body = TEMPLATE.read_text()

for stanza_name, phrases in REQUIRED_PHRASES.items():
    stanza = re.search(rf"^\[{re.escape(stanza_name)}\]$(.*?)(?=^\[|\Z)", body, re.M | re.S)
    if not stanza:
        errors.append(f"FAIL: [{stanza_name}] stanza not found")
        continue

    search_line = next(
        (ln for ln in stanza.group(1).splitlines() if ln.startswith("search = ")), ""
    )
    if not search_line:
        errors.append(f"FAIL: [{stanza_name}] has no search line")
        continue

    for phrase, why in phrases.items():
        if phrase not in search_line:
            errors.append(f"FAIL: [{stanza_name}] search lost {phrase!r} — stops detecting {why}")

    # Index-time bounds, not event-time: `earliest=`/`latest=` against `_time`
    # is a documented silent no-op as a bare search term, and a systemd
    # unit's own clock is exactly what DR alerting must not blindly trust.
    if "_index_earliest" not in search_line or "_index_latest" not in search_line:
        errors.append(f"FAIL: [{stanza_name}] does not bound on index time (_index_earliest/_index_latest)")

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print("PASS: all four Hindsight bank-DR alert stanzas cover their fail/absence conditions and index-time bounds")
print("\nAll tests passed.")
