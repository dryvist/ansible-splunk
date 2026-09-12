#!/usr/bin/env python3
"""
Guard index_gap_detector's index-time requirement and index coverage.

A sourcetype whose reported _time drifts ahead of the search head's clock
makes a detector keyed on _time read a dead source as "very recently
updated" and never fire -- exactly backwards. This test fails if the
search is ever rewritten to key off _time instead of _indextime, to use
latest(_indextime) instead of max(_indextime) (latest() follows whichever
row has the greatest _time, not the largest _indextime across all rows, so
it inherits the same _time-drift blind spot this whole design avoids), or
to drop the index-time bound in the tstats clause itself.

It also checks index_gap_detector covers every index this role declares
(splunk_docker_indexes_core + splunk_docker_indexes_extra), including one not
in splunk_docker_silence_detectors at all -- the whole point of a gap
detector over per-index alerts is that a newly created index is covered from
day one, at the 1440-minute default, without anyone remembering to add an
entry for it.

Run from repo root:
  python3 tests/templates/test_gap_detector.py
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

STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)
SEARCH_RE = re.compile(r"^search = (.*)$", re.M)


def uses_index_time_only(search):
    """True iff the search ages an index by max(_indextime) and never _time
    or latest(_indextime). latest(X) returns X from the single row with the
    greatest _time, not the largest X across all rows -- on a future-dated
    _time row that row IS the "latest" row by _time, so latest(_indextime)
    would freeze at whatever _indextime that one row carries, which can be
    older than a real, more-recent write from a well-behaved row. Only
    max(_indextime), independent of any row's _time, stays correct regardless
    of what _time does."""
    return (
        "max(_indextime)" in search
        and "latest(_time)" not in search
        and "latest(_indextime)" not in search
    )


def bounds_by_index_time_in_base_search(search):
    """True iff _index_earliest/_index_latest are TERMS in the tstats clause
    itself (the first pipe segment), not appended after a later pipe -- see
    operating-core.md: appended after a pipe, they become arguments to
    whatever command is last, and the search still returns success with an
    effectively unbounded (or wrong) window."""
    base = search.split("|", 2)[1] if search.count("|") >= 1 else search
    return "_index_earliest=" in base and "_index_latest=" in base


env = ansible_env(ROOT / "roles/splunk_docker/templates")
rendered = env.get_template("savedsearches.conf.j2").render(
    splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
    splunk_docker_silence_lookback_multiplier=DEFAULTS["splunk_docker_silence_lookback_multiplier"],
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

search = SEARCH_RE.search(body).group(1)

if not uses_index_time_only(search):
    errors.append(
        "FAIL: index_gap_detector does not age indexes by max(_indextime) alone -- "
        "either _time or latest(_indextime) would let a clock-skewed or unparsed "
        "sourcetype defeat this detector"
    )
if not bounds_by_index_time_in_base_search(search):
    errors.append(
        "FAIL: index_gap_detector's tstats clause has no _index_earliest/"
        "_index_latest bound in the base search"
    )

# --- covers every declared index, not just ones with a detector entry -----
all_indexes = {
    idx["name"]
    for idx in DEFAULTS["splunk_docker_indexes_core"] + DEFAULTS["splunk_docker_indexes_extra"]
}
detector_indexes = {det["index"] for det in DEFAULTS["splunk_docker_silence_detectors"]}
undetected = all_indexes - detector_indexes
if not undetected:
    errors.append(
        "FAIL: fixture assumption broken -- every declared index already has a "
        "splunk_docker_silence_detectors entry, so this test cannot prove an "
        "index with NO entry is still covered by the 1440-minute default"
    )
else:
    sample = sorted(undetected)[0]
    roster_match = re.search(r'eval index="([^"]*)"', search)
    roster = roster_match.group(1).split(",") if roster_match else []
    if sample not in roster:
        errors.append(
            f"FAIL: '{sample}' has no splunk_docker_silence_detectors entry and is "
            "missing from index_gap_detector's expected-index roster -- an index "
            "with nobody watching it explicitly must still be covered by the "
            "gap detector, or a newly created index goes unmonitored until "
            "someone remembers to add one"
        )
    case_body = search.split("case(", 1)[-1].split(") | where", 1)[0]
    if f'index="{sample}"' in case_body:
        errors.append(
            f"FAIL: '{sample}' has its own case() branch despite having no "
            "splunk_docker_silence_detectors entry -- fixture assumption broken"
        )

# --- prove each check can fail (same technique as the other template tests:
# a check that cannot fail is indistinguishable from one that passes) ------
EVENT_TIME_REGRESSION = "| tstats latest(_time) as last_indexed where index=* _index_earliest=-1d _index_latest=now by index"
if uses_index_time_only(EVENT_TIME_REGRESSION):
    errors.append("FAIL: regression fixture -- an _time-only search was not flagged")

LATEST_INDEXTIME_REGRESSION = (
    "| tstats latest(_indextime) as last_indexed where index=* "
    "_index_earliest=-1d _index_latest=now by index"
)
if uses_index_time_only(LATEST_INDEXTIME_REGRESSION):
    errors.append("FAIL: regression fixture -- a latest(_indextime) search was not flagged")

CORRECT_FIXTURE = (
    "| tstats max(_indextime) as last_indexed where index=* "
    "_index_earliest=-1d _index_latest=now by index"
)
if not uses_index_time_only(search):
    pass  # already reported above; avoid a duplicate message
elif not uses_index_time_only(CORRECT_FIXTURE):
    errors.append("FAIL: regression fixture -- a correctly max(_indextime) search was flagged")

NO_BOUND_REGRESSION = "| tstats max(_indextime) as last_indexed where index=* by index"
if bounds_by_index_time_in_base_search(NO_BOUND_REGRESSION):
    errors.append("FAIL: regression fixture -- a tstats clause with no index-time bound was not flagged")
LATE_BOUND_REGRESSION = (
    "| tstats max(_indextime) as last_indexed where index=* by index "
    "| where _index_earliest=-1d AND _index_latest=now"
)
if bounds_by_index_time_in_base_search(LATE_BOUND_REGRESSION):
    errors.append(
        "FAIL: regression fixture -- an index-time bound appended after the first "
        "pipe (not a base-search term) was not flagged"
    )
if not bounds_by_index_time_in_base_search(CORRECT_FIXTURE):
    errors.append("FAIL: regression fixture -- a correctly base-search-bounded tstats clause was flagged")

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print(
    "PASS: index_gap_detector ages indexes by max(_indextime) (never _time or "
    "latest(_indextime)) bounded by _index_earliest/_index_latest in the base "
    "search, and covers every declared index including one with no "
    "splunk_docker_silence_detectors entry of its own"
)
print("\nAll tests passed.")
