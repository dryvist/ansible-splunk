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
    return bool(GROUPED_AGG_RE.search(search)) and bool(
        SILENCE_SIGNATURE_RE.search(search)
    )


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
    table = [
        {group_field: name, recency_field: 0} for name in members.split(",") if name
    ]
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


def _parse_case_thresholds(search, field_name):
    """Parse `eval {field_name} = case(index="a", N, index="b", M, ...,
    true(), D)` into ({index: N, ...}, D). Returns None when no such eval is
    present, or when the true() fallback is not a plain number (e.g. the
    by_host cadence case()'s `max(coalesce(avg_gap_minutes, 0) * k, floor)`)
    -- in which case the caller falls back to the old always-0.0 behaviour,
    unchanged for that shape."""
    m = re.search(rf"eval {re.escape(field_name)} = case\((.*)\)", search)
    if not m:
        return None
    body = m.group(1)
    true_default = re.search(r"true\(\),\s*([\d.]+)", body)
    if not true_default:
        return None
    per_index = dict(re.findall(r'index="([^"]*)",\s*([\d.]+)', body))
    return {k: float(v) for k, v in per_index.items()}, float(true_default.group(1))


def run_where_threshold(table, search, recency_field="minutes_silent"):
    # The exempt digit is READ, not assumed: an inverted `where exempt=1 AND
    # ...` (which would suppress every real gap and page only on the exempt
    # indexes) must filter on exempt==1, not silently keep behaving like the
    # correct exempt==0 gate. Absence of any exempt clause means no exempt
    # filtering at all, matching a search that never gates on it.
    m = re.search(rf"where (?:exempt=(\d) AND )?{recency_field} > (\S+)", search)
    expected_exempt = int(m.group(1)) if m and m.group(1) is not None else None
    threshold_token = m.group(2) if m else None

    per_index_thresholds, default_threshold = None, 0.0
    if threshold_token is not None:
        try:
            default_threshold = float(threshold_token)
        except ValueError:
            # Symbolic threshold field (host_threshold_minutes, or
            # index_gap_detector's case()-derived threshold_minutes) --
            # resolve it from the case() expression that computed it rather
            # than assuming 0.0 for every row.
            parsed = _parse_case_thresholds(search, threshold_token)
            if parsed is not None:
                per_index_thresholds, default_threshold = parsed

    rows = table
    if expected_exempt is not None:
        rows = [row for row in rows if row.get("exempt", 0) == expected_exempt]

    out = []
    for row in rows:
        threshold = default_threshold
        if per_index_thresholds is not None:
            threshold = per_index_thresholds.get(row.get("index"), default_threshold)
        if row[recency_field] > threshold:
            out.append(row)
    return out


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
