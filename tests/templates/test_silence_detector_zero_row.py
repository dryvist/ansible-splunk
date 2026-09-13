#!/usr/bin/env python3
"""
Guard the tstats/stats zero-row blind spot in savedsearches.conf.j2.

tstats is a GENERATING command: over a lookback window with no matching
events at all, it returns ZERO result rows -- not one row with a null
last_seen -- whether or not it groups `by host`. `stats ... by <field>`
shares the same blind spot when grouped: zero input rows means zero groups,
so it also emits nothing. (An UNGROUPED `stats` aggregate like `stats count`
is exempt -- it always emits exactly one row, even over zero input rows.)
Verified live: index=llm from the router hosts and llm_pipeline emitters was
fully empty for 18 days, and both llm_router_silence_detector (which already
had coalesce(last_seen, 0)) and llm_pipeline_silence_detector never fired.
coalesce() cannot help because there is no row for eval to run it on -- the
downstream `eval minutes_silent = ... | where minutes_silent > N` guard
simply never executes.

The fix is the appendpipe sentinel-row pattern: `appendpipe [ stats count as
_rows | where _rows == 0 | eval last_seen = 0 | fields - _rows ]`. An
ungrouped `stats count` always emits exactly one result row, even over zero
input rows -- so this branch fires precisely when (and only when) the main
result set is empty, synthesizing the missing "everything is silent" row.

Coverage note: this test used to check a hardcoded list of stanza names (the
three named detectors plus the generic per-index loop's non-by_host branch),
so a new stanza with the same defect -- or the loop's by_host branch -- would
not be caught. It now DERIVES the set of checked searches from the rendered
template (see `silence_stanzas()`), the same approach test_cutover_gate.py
uses for the disabled-by-default gate.

Inclusion rule: a stanza qualifies as a silence/staleness detector -- and
therefore must survive its own aggregation returning zero rows -- when its
search performs a grouped aggregation (`tstats`, by-clause or not; or
`stats ... by`) AND computes elapsed time since a last-seen event
(`now() - coalesce(...)`). The second half excludes a spike/content-match
search (nothing to fire on when healthy is correct) and a *data-value*
threshold over a grouped aggregate, e.g. llm_serving_memory_headroom's
`stats avg(...) by host | where ... > 85` -- zero rows there means no host is
over the memory ceiling, the correct silent-when-healthy behavior, not a
blind spot.

Run from repo root:
  python3 tests/templates/test_silence_detector_zero_row.py
"""

import re
import sys
import time
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

# Same stanza-block extraction as test_cutover_gate.py's STANZA_RE.
STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)
SEARCH_RE = re.compile(r"^search = (.*)$", re.M)
# SPL command keywords are case-insensitive (`stats ... BY host` and
# `stats ... by host` are identical to Splunk's parser), so this must match
# regardless of case -- a case-sensitive version silently missed every
# grouped-stats search written in the `BY`-uppercase style.
GROUPED_AGG_RE = re.compile(r"\btstats\b|\bstats\b[^|]*\bby\b", re.I)
# Any reference to now() -- elapsed-time subtraction (now() - coalesce(...)),
# or a recency comparison (relative_time(now(), ...)) -- is this codebase's
# tell for "this search's condition is time/recency, not a data value". Kept
# broad (not anchored to the one `now() - coalesce(` idiom PR #460 happened to
# use) so a differently-worded staleness check -- e.g. `now() - last_seen`
# with no coalesce() wrapper -- is still recognized.
SILENCE_SIGNATURE_RE = re.compile(r"now\(\)")

# Real, currently-guarded stanzas that must always be swept in -- a floor so
# a selector regression that stops matching anything still fails loudly
# instead of passing vacuously with zero detectors checked.
EXPECTED_INCLUDED = {
    "macos_edge_silence_detector",
    "llm_pipeline_silence_detector",
    "llm_router_silence_detector",
    "index_gap_detector",
}
# Real grouped-aggregation stanzas that are NOT silence detectors (a
# data-value threshold or a run-count/score comparison, not elapsed time
# since a last-seen event) -- must never be swept in.
EXPECTED_EXCLUDED = {
    "model_eval_regression",
    "llm_serving_memory_headroom",
    "bench_verdict_maturity",
}


def is_silence_detector(search):
    return bool(GROUPED_AGG_RE.search(search)) and bool(SILENCE_SIGNATURE_RE.search(search))


def silence_stanzas(rendered):
    """Name -> search for every stanza whose search matches the
    grouped-aggregation-over-empty-input blind spot (see module docstring),
    derived entirely from the render -- never a maintained list."""
    found = {}
    for m in STANZA_RE.finditer(rendered):
        sm = SEARCH_RE.search(m.group(2))
        if sm and is_silence_detector(sm.group(1)):
            found[m.group(1)] = sm.group(1)
    return found


# --- minimal SPL simulator, scoped to exactly what these searches use ------
#
# A "table" is a list of dict rows. Two zero-row guard shapes are recognized:
#
# appendpipe [ stats count | where _rows == 0 | eval ... | fields - _rows ] --
# the by_host/legacy shape, one guard row synthesized only when the whole
# result set is empty.
#
# append [ | makeresults | eval <field>=<list> | eval <field>=split(...) |
# mvexpand <field> | eval <recency>=0 ] | stats max(<recency>) as <recency>
# by <field> -- index_gap_detector's shape: one sentinel row PER expected
# member of a wildcarded search (index_gap_detector's `index=*` has no
# equivalent to appendpipe's single ungrouped-count fallback, because the
# blind spot here is "this one group among many has zero rows", not "the
# whole search has zero rows"). `stats max(...)` then keeps a real tstats
# row over the 0 sentinel wherever one exists, and keeps the sentinel where
# none does.
#
# Beyond the guard itself: eval <recency> = (now() - coalesce(field, 0)) / 60
# (or, for index_gap_detector, without the /60 divide since it names its
# field in minutes already: age_min = round((now() - last_indexed) / 60)),
# and where <recency> > <threshold>. This is not a general SPL interpreter.


def run_appendpipe_zero_guard(table, search):
    guard = re.search(
        r"appendpipe \[ stats count as _rows \| where _rows == 0 \| eval (.+?) \| fields - _rows \]",
        search,
    )
    if not guard:
        return table  # no guard present -- nothing appended (the bug)
    if len(table) != 0:
        return table  # stats count as _rows > 0 here, so `where _rows == 0` drops it
    # stats on zero input rows still emits exactly one row (ungrouped count).
    row = {}
    for assignment in guard.group(1).split(", "):
        field, _, value = assignment.partition(" = ")
        row[field.strip()] = 0 if value.strip() == "0" else value.strip().strip('"')
    return table + [row]


def run_append_stats_max_guard(search):
    """index_gap_detector's guard shape (see module docstring). Returns None
    when this shape is absent so `simulate()` falls back to the appendpipe
    shape, and (sentinel table, recency field name) when it matches -- the
    fully-silent ground truth for a wildcarded, grouped search where NO real
    tstats row exists for any member, plus the field name to compute
    elapsed-time from, both derived from the search rather than assumed."""
    m = re.search(
        r"append \[ \| makeresults \| eval (\w+)=\"([^\"]*)\" \| eval \1=split\(\1, \",\"\) "
        r"\| mvexpand \1 \| eval (\w+)=0 \] \| stats max\(\3\) as \3 by \1",
        search,
    )
    if not m:
        return None
    group_field, members, recency_field = m.group(1), m.group(2), m.group(3)
    table = [{group_field: name, recency_field: 0} for name in members.split(",") if name]
    return table, recency_field


def run_eval_minutes_silent(table):
    now_minutes = time.time() / 60
    for row in table:
        last_seen = row.get("last_seen")
        last_seen = last_seen if isinstance(last_seen, (int, float)) else 0
        row["minutes_silent"] = now_minutes - last_seen / 60
    return table


def run_eval_age_min(table, recency_field):
    now_minutes = time.time() / 60
    for row in table:
        value = row.get(recency_field)
        value = value if isinstance(value, (int, float)) else 0
        row["age_min"] = round(now_minutes - value / 60)
    return table


def run_eval_exempt(table, search):
    """index_gap_detector-only: `eval exempt = if(in(index, "a", "b", ...),
    1, 0)`. Marks each row exempt=1/0 by whether its index is named in the
    boolean gate; a search with no such clause leaves every row exempt=0
    (nothing to filter, matching plain `where age_min > threshold_minutes`
    with no exempt gate at all)."""
    m = re.search(r'eval exempt = if\(in\(index((?:, "[^"]*")*)\), 1, 0\)', search)
    exempt_indexes = re.findall(r'"([^"]*)"', m.group(1)) if m else []
    for row in table:
        row["exempt"] = 1 if row.get("index") in exempt_indexes else 0
    return table


def run_where_threshold(table, search, recency_field="minutes_silent"):
    m = re.search(rf"where (?:exempt=0 AND )?{recency_field} > (\S+)", search)
    try:
        threshold = float(m.group(1)) if m else 0.0
    except ValueError:
        # Symbolic threshold (e.g. host_threshold_minutes, or
        # index_gap_detector's case()-derived threshold_minutes). A sentinel
        # row's recency field is always computed from a 0 timestamp, so its
        # elapsed-time value is ~now()/60 -- tens of millions of minutes --
        # which dwarfs any realistic bounded threshold this codebase would
        # ever configure.
        threshold = 0.0
    return [row for row in table if row.get("exempt", 0) == 0 and row[recency_field] > threshold]


def simulate(search):
    """Run a search against a fully-silent data source (a grouped
    aggregation over zero matching input rows returns zero result rows) and
    return the surviving rows -- what the alert would fire on."""
    append_guard = run_append_stats_max_guard(search)
    if append_guard is not None:
        append_table, recency_field = append_guard
        table = run_eval_age_min(append_table, recency_field)
        table = run_eval_exempt(table, search)
        return run_where_threshold(table, search, recency_field="age_min")
    table = run_appendpipe_zero_guard([], search)
    table = run_eval_minutes_silent(table)
    return run_where_threshold(table, search)


env = ansible_env(ROOT / "roles/splunk_docker/templates")
rendered = env.get_template("savedsearches.conf.j2").render(
    splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
    splunk_docker_silence_exemptions=DEFAULTS["splunk_docker_silence_exemptions"],
    splunk_docker_silence_lookback_multiplier=DEFAULTS["splunk_docker_silence_lookback_multiplier"],
    # index_gap_detector's zero-row guard covers a wildcarded search, so it
    # needs the real expected-index roster to have any members to guard --
    # without these two, its append branch has an empty list and this test
    # would validate nothing about it (see index_gap_detector's own template
    # comment for why the two default independently rather than as a pair).
    splunk_docker_indexes_core=DEFAULTS["splunk_docker_indexes_core"],
    splunk_docker_indexes_extra=DEFAULTS["splunk_docker_indexes_extra"],
    splunk_docker_alert_ntfy_url=None,
    splunk_docker_alert_slack_webhook=None,
)

detectors = silence_stanzas(rendered)
errors = []

missing_floor = EXPECTED_INCLUDED - detectors.keys()
if missing_floor:
    errors.append(
        f"FAIL: the inclusion rule stopped matching known silence detectors: "
        f"{sorted(missing_floor)} -- selector regression, this test would now pass vacuously"
    )

overreach = EXPECTED_EXCLUDED & detectors.keys()
if overreach:
    errors.append(
        f"FAIL: the inclusion rule swept in non-silence stanzas that legitimately "
        f"return nothing when healthy: {sorted(overreach)}"
    )

for name, search in detectors.items():
    if not simulate(search):
        errors.append(
            f"FAIL: [{name}] produced no result row over a fully-silent data "
            f"source -- the alert would stay quiet through total silence"
        )

# --- exempt indexes must never fire; a non-exempt silent index still must -
# (against the REAL rendered index_gap_detector, not a synthetic fixture) --
gap_search = detectors.get("index_gap_detector")
if gap_search:
    exempt_indexes = {
        det["index"] for det in DEFAULTS["splunk_docker_silence_exemptions"] if det.get("exempt")
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

# --- regression fixtures: prove the derivation catches a reintroduced bug,
# and doesn't flag a correctly-guarded search, without touching the real
# template (same technique as test_cutover_gate.py's fixture). ---
BROKEN = (
    "| tstats latest(_time) as last_seen WHERE index=fixture by host "
    "| eval minutes_silent = (now() - coalesce(last_seen, 0)) / 60 "
    "| where minutes_silent > 15"
)
FIXED = (
    "| tstats latest(_time) as last_seen WHERE index=fixture by host "
    "| appendpipe [ stats count as _rows | where _rows == 0 | eval last_seen = 0 | fields - _rows ] "
    "| eval minutes_silent = (now() - coalesce(last_seen, 0)) / 60 "
    "| where minutes_silent > 15"
)

if not is_silence_detector(BROKEN):
    errors.append("FAIL: regression fixture -- inclusion rule failed to recognize a real silence-detector shape")
elif simulate(BROKEN):
    errors.append("FAIL: regression fixture -- simulator did not catch a search missing the appendpipe guard")

if not is_silence_detector(FIXED):
    errors.append("FAIL: regression fixture -- inclusion rule rejected a properly-guarded silence detector")
elif not simulate(FIXED):
    errors.append("FAIL: regression fixture -- simulator rejected a correctly-guarded search")

# Uppercase BY regression: SPL command keywords are case-insensitive
# (`stats ... BY host` and `stats ... by host` are identical to Splunk's
# parser), so a case-sensitive GROUPED_AGG_RE silently missed every grouped
# search written in the `BY`-uppercase style -- this caught two real
# detectors (ansible_stale_converge, ansible_orphan_host) before it was
# fixed.
UPPERCASE_BY = (
    "index=fixture | stats latest(_time) as last_seen BY host "
    "| appendpipe [ stats count as _rows | where _rows == 0 | eval last_seen = 0 | fields - _rows ] "
    "| eval minutes_silent = (now() - coalesce(last_seen, 0)) / 60 "
    "| where minutes_silent > 15"
)
if not is_silence_detector(UPPERCASE_BY):
    errors.append("FAIL: regression fixture -- inclusion rule is case-sensitive to the BY keyword")

# Exempt-gate regression: a raised threshold is a no-op for a never-ingested
# index (see module docstring for why), so the fix is a boolean gate. This
# fixture reproduces index_gap_detector's shape with one exempt and one
# non-exempt index, both fully silent, and proves only the boolean gate
# tells them apart -- catching a regression back to a threshold-only
# "exemption" that fires on both.
EXEMPT_GATE_SEARCH = (
    '| tstats max(_indextime) as last_indexed where index=* by index '
    '| append [ | makeresults | eval index="exempt_idx,real_idx" '
    '| eval index=split(index, ",") | mvexpand index | eval last_indexed=0 ] '
    '| stats max(last_indexed) as last_indexed by index '
    '| eval age_min = round((now() - last_indexed) / 60) '
    '| eval threshold_minutes = case(index="exempt_idx", 1440, index="real_idx", 1440, true(), 1440) '
    '| eval exempt = if(in(index, "exempt_idx"), 1, 0) '
    '| where exempt=0 AND age_min > threshold_minutes'
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

# The defect this whole mechanism replaces: raising exempt_idx's threshold
# instead of gating it boolean. Proves the simulator (and by extension the
# real search, which uses the identical shape) would have caught it: a
# never-ingested index's age_min is effectively unbounded, so no finite
# raised threshold suppresses it.
THRESHOLD_ONLY_SEARCH = EXEMPT_GATE_SEARCH.replace(
    'index="exempt_idx", 1440, index="real_idx", 1440,', 'index="exempt_idx", 525600, index="real_idx", 1440,'
).replace(' | eval exempt = if(in(index, "exempt_idx"), 1, 0) | where exempt=0 AND age_min > threshold_minutes',
          ' | where age_min > threshold_minutes')
if "exempt_idx" not in {row["index"] for row in simulate(THRESHOLD_ONLY_SEARCH)}:
    errors.append(
        "FAIL: regression fixture -- expected a raised-threshold-only exemption to "
        "still fire on a never-ingested index (proving the mechanism this PR replaced "
        "was in fact a no-op); it did not, so this fixture no longer demonstrates the "
        "defect it exists to guard against"
    )

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print(
    f"PASS: all {len(detectors)} silence/staleness detectors derived from the render "
    f"({', '.join(sorted(detectors))}) produce a firing result row when their source "
    f"data is fully silent; the inclusion rule excludes non-silence grouped aggregations "
    f"and catches both a reintroduced missing-guard bug and its fix in fixtures"
)
print("\nAll tests passed.")
