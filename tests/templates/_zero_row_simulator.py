"""Minimal SPL simulator shared by test_silence_detector_zero_row.py and
test_index_gap_exempt.py -- split out at the per-file token-budget gate.

A "table" is a list of dict rows. Two zero-row guard shapes are recognized:

appendpipe [ stats count | where _rows == 0 | eval ... | fields - _rows ] --
the by_host/legacy shape, one guard row synthesized only when the whole
result set is empty.

append [ | makeresults | eval <field>=<list> | eval <field>=split(...) |
mvexpand <field> | eval <recency>=0 ] | stats max(<recency>) as <recency>
by <field> -- index_gap_detector's shape: one sentinel row PER expected
member of a wildcarded search (index_gap_detector's `index=*` has no
equivalent to appendpipe's single ungrouped-count fallback, because the
blind spot here is "this one group among many has zero rows", not "the
whole search has zero rows"). `stats max(...)` then keeps a real tstats
row over the 0 sentinel wherever one exists, and keeps the sentinel where
none does.

Beyond the guard itself: eval <recency> = (now() - coalesce(field, 0)) / 60
(or, for index_gap_detector, without the /60 divide since it names its
field in minutes already: age_min = round((now() - last_indexed) / 60)),
and where <recency> > <threshold>. This is not a general SPL interpreter.

These tests run as standalone scripts, not under pytest, so this is a plain
sibling module rather than a conftest -- same shape as _render_env.py.
"""

import re
import time

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


def is_silence_detector(search):
    return bool(GROUPED_AGG_RE.search(search)) and bool(SILENCE_SIGNATURE_RE.search(search))


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
