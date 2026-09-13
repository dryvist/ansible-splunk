#!/usr/bin/env python3
"""
Guard index_gap_detector's exempt-index boolean gate.

Split out of test_silence_detector_zero_row.py at the per-file token-budget
gate; shares that file's simulator (./_zero_row_simulator.py).

THE DEFECT THIS EXISTS TO CATCH
-------------------------------
An exempt index (splunk_docker_silence_exemptions) is never-ingested, so it
enters index_gap_detector's report through the synthetic zero-row append,
same as any other undetected index -- its age_min is roughly "since epoch"
(now() minus a 0 timestamp), tens of millions of minutes. Raising that
index's case() threshold instead of gating it boolean is therefore a no-op:
no finite threshold this codebase would ever configure comes close to
suppressing an age_min that large. Only a separate `eval exempt=if(in(index,
...), 1, 0) | where exempt=0 AND age_min > threshold_minutes` actually
excludes it. This test proves the real, rendered index_gap_detector search
gates exempt indexes this way, and a standalone fixture proves the
threshold-only mechanism it replaced would NOT have worked.

Run from repo root:
  python3 tests/templates/test_index_gap_exempt.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env
from _zero_row_simulator import simulate

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("ERROR: jinja2 not installed. Run: pip install jinja2")
    sys.exit(1)

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)

STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)
SEARCH_RE = re.compile(r"^search = (.*)$", re.M)

env = ansible_env(ROOT / "roles/splunk_docker/templates")
rendered = env.get_template("savedsearches.conf.j2").render(
    splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
    splunk_docker_silence_exemptions=DEFAULTS["splunk_docker_silence_exemptions"],
    splunk_docker_silence_lookback_multiplier=DEFAULTS[
        "splunk_docker_silence_lookback_multiplier"
    ],
    splunk_docker_indexes_core=DEFAULTS["splunk_docker_indexes_core"],
    splunk_docker_indexes_extra=DEFAULTS["splunk_docker_indexes_extra"],
    splunk_docker_alert_ntfy_url=None,
    splunk_docker_alert_slack_webhook=None,
)

errors = []

body = None
for m in STANZA_RE.finditer(rendered):
    if m.group(1) == "index_gap_detector":
        body = m.group(2)
        break
if body is None:
    print("FAIL: [index_gap_detector] not found in rendered output")
    sys.exit(1)
gap_search = SEARCH_RE.search(body).group(1)

# --- exempt indexes must never fire; a non-exempt silent index still must -
# (against the REAL rendered index_gap_detector, not a synthetic fixture) --
exempt_indexes = {
    det["index"]
    for det in DEFAULTS["splunk_docker_silence_exemptions"]
    if det.get("exempt")
}
fired_indexes = {row["index"] for row in simulate(gap_search)}
exempt_that_fired = exempt_indexes & fired_indexes
if exempt_that_fired:
    errors.append(
        f"FAIL: index_gap_detector fired on exempt index(es) {sorted(exempt_that_fired)} "
        "over a fully-silent data source -- raising a threshold does not suppress a "
        "never-ingested index (its age_min already exceeds any finite threshold), "
        "only a boolean exempt=0 gate does"
    )
if exempt_indexes and not (fired_indexes - exempt_indexes):
    errors.append(
        "FAIL: fixture assumption broken -- every fired row was exempt, so this "
        "test cannot prove a non-exempt silent index still fires"
    )

# --- standalone fixture: prove the mechanism itself, independent of the
# current roster (same technique as the other template tests: a check that
# cannot fail proves nothing). One exempt and one non-exempt index, both
# fully silent -- only the boolean gate tells them apart. ---
EXEMPT_GATE_SEARCH = (
    "| tstats max(_indextime) as last_indexed where index=* by index "
    '| append [ | makeresults | eval index="exempt_idx,real_idx" '
    '| eval index=split(index, ",") | mvexpand index | eval last_indexed=0 ] '
    "| stats max(last_indexed) as last_indexed by index "
    "| eval age_min = round((now() - last_indexed) / 60) "
    '| eval threshold_minutes = case(index="exempt_idx", 1440, index="real_idx", 1440, true(), 1440) '
    '| eval exempt = if(in(index, "exempt_idx"), 1, 0) '
    "| where exempt=0 AND age_min > threshold_minutes"
)
exempt_gate_fired = {row["index"] for row in simulate(EXEMPT_GATE_SEARCH)}
if "exempt_idx" in exempt_gate_fired:
    errors.append(
        "FAIL: regression fixture -- exempt_idx fired despite the exempt=0 gate"
    )
if "real_idx" not in exempt_gate_fired:
    errors.append(
        "FAIL: regression fixture -- real_idx (non-exempt, fully silent) did not fire"
    )

# An inverted gate (exempt=1 instead of exempt=0) suppresses every real gap
# and pages only on the exempt indexes -- the opposite of the intended
# behaviour. The simulator must read the digit out of the search text and
# apply IT, not silently keep modeling the correct exempt=0 gate regardless
# of what the search actually says (that blind spot is what let a bug this
# shape through unnoticed before).
INVERTED_GATE_SEARCH = EXEMPT_GATE_SEARCH.replace(
    "where exempt=0 AND", "where exempt=1 AND"
)
inverted_fired = {row["index"] for row in simulate(INVERTED_GATE_SEARCH)}
if "real_idx" in inverted_fired:
    errors.append(
        "FAIL: regression fixture -- an inverted exempt=1 gate should suppress the "
        "real, non-exempt gap (real_idx); the simulator did not catch the inversion"
    )
if "exempt_idx" not in inverted_fired:
    errors.append(
        "FAIL: regression fixture -- an inverted exempt=1 gate should fire only on "
        "the exempt index (exempt_idx); the simulator did not catch the inversion"
    )

# The defect this whole mechanism replaces: raising exempt_idx's threshold
# instead of gating it boolean, to 525,600 minutes (a full year -- roughly
# the most aggressive threshold this codebase would plausibly configure).
# The simulator now genuinely computes the case()-derived threshold per
# index (_parse_case_thresholds) rather than falling back to a hardcoded
# 0.0, so this proves the real comparison, not an artifact of that
# fallback: a never-ingested index's synthetic age_min (~now()/60, tens of
# millions of minutes today) still dwarfs even a 525,600-minute threshold by
# a factor of ~50-60x, so raising it is a no-op regardless of how high.
THRESHOLD_ONLY_SEARCH = EXEMPT_GATE_SEARCH.replace(
    'index="exempt_idx", 1440, index="real_idx", 1440,',
    'index="exempt_idx", 525600, index="real_idx", 1440,',
).replace(
    ' | eval exempt = if(in(index, "exempt_idx"), 1, 0) | where exempt=0 AND age_min > threshold_minutes',
    " | where age_min > threshold_minutes",
)
if "exempt_idx" not in {row["index"] for row in simulate(THRESHOLD_ONLY_SEARCH)}:
    errors.append(
        "FAIL: regression fixture -- expected a raised-threshold-only exemption to "
        "still fire on a never-ingested index against its real, computed 525,600-minute "
        "threshold (proving the mechanism this replaced was in fact a no-op); it did "
        "not, so this fixture no longer demonstrates the defect it exists to guard against"
    )

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print(
    f"PASS: index_gap_detector's exempt=0 boolean gate excludes all {len(exempt_indexes)} exempt "
    "indexes and still fires on at least one non-exempt silent index; a threshold-only "
    "exemption (the mechanism this replaces) is proven to be a no-op"
)
print("\nAll tests passed.")
