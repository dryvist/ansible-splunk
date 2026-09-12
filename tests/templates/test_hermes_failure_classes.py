#!/usr/bin/env python3
"""
Guard hermes_failure_classes' five failure-class patterns and index-time
bound.

Each pattern is meant to be the literal text Hermes (or this estate's own
pinned-source patches to it, in ansible-proxmox-ai) actually logs -- see the
template header for citations. This test extracts the case() branches from
the rendered search and proves each one matches a realistic sample line for
its class and does NOT match samples for the other four classes or plain
unrelated text, so a future edit that widens or narrows a pattern is caught
here rather than only in production.

Run from repo root:
  python3 tests/templates/test_hermes_failure_classes.py
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

# One case() branch: match(_raw, "pat1") [AND|OR match(_raw, "pat2")], "class"
BRANCH_RE = re.compile(
    r'match\(_raw, "((?:[^"\\]|\\.)*)"\)'
    r'(?:\s+(AND|OR)\s+match\(_raw, "((?:[^"\\]|\\.)*)"\))?'
    r', "(\w+)"'
)

# Realistic sample lines, one per class, taken from the exact strings the
# template header cites (cron/scheduler.py's classifier, kanban-digest.py.j2,
# gateway/kanban_watchers.py, the Slack adapter's "[Slack]" prefix, and
# agent/conversation_loop.py's compaction-failure log).
SAMPLES = {
    "provider_exhausted": (
        "Cron 'nightly-wiki' failed: every fallback rung refused the request. Cause: 429"
    ),
    "cron_wall_clock_timeout": (
        "Cron 'daily-summary' failed: exceeded its aggregate wall-clock limit and was stopped."
    ),
    "kanban_block_or_stuck": ":hourglass: Stuck >6h: 2 blocked, oldest 1d.",
    "kanban_block_or_stuck_dispatcher": (
        "kanban dispatcher stuck: ready queue non-empty for 5 consecutive ticks but 0 workers spawned."
    ),
    "slack_api_error": "[Slack] Socket Mode reconnect failed: connection reset",
    "compaction_loop": "Context compression failed after 3 attempts; rebuilt request",
}
UNRELATED = "Card 'wiki-refresh' moved to review by hermes-worker-3"


def build_condition(pattern1, joiner, pattern2):
    # BRANCH_RE.findall returns "" (not None) for a non-participating
    # optional group -- re.search("", text) always matches, so treating ""
    # the same as a real second pattern silently made every single-pattern
    # branch evaluate to True via `m1 or m2`.
    def cond(text):
        m1 = bool(re.search(pattern1, text))
        if not joiner:
            return m1
        m2 = bool(re.search(pattern2, text))
        return (m1 and m2) if joiner == "AND" else (m1 or m2)

    return cond


def classify(text, branches):
    for pattern1, joiner, pattern2, cls in branches:
        if build_condition(pattern1, joiner, pattern2)(text):
            return cls
    return None


env = ansible_env(ROOT / "roles/splunk_docker/templates")
rendered = env.get_template("savedsearches.conf.j2").render(
    splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
    splunk_docker_silence_lookback_multiplier=DEFAULTS["splunk_docker_silence_lookback_multiplier"],
    splunk_docker_llm_freshness_indexes=DEFAULTS["splunk_docker_llm_freshness_indexes"],
    splunk_docker_indexes_core=DEFAULTS["splunk_docker_indexes_core"],
    splunk_docker_indexes_extra=DEFAULTS["splunk_docker_indexes_extra"],
    splunk_docker_alert_ntfy_url=None,
    splunk_docker_alert_slack_webhook=None,
)

errors = []

body = None
for m in STANZA_RE.finditer(rendered):
    if m.group(1) == "hermes_failure_classes":
        body = m.group(2)
        break

if body is None:
    print("FAIL: [hermes_failure_classes] not found in rendered output")
    sys.exit(1)

search = SEARCH_RE.search(body).group(1)

branches = BRANCH_RE.findall(search)
if len(branches) != 5:
    errors.append(
        f"FAIL: expected 5 case() branches (one per failure class), found {len(branches)} -- "
        f"either a branch was dropped or the extraction regex needs updating"
    )

expected_classes = {
    "provider_exhausted",
    "cron_wall_clock_timeout",
    "kanban_block_or_stuck",
    "slack_api_error",
    "compaction_loop",
}
found_classes = {b[3] for b in branches}
if found_classes != expected_classes:
    errors.append(
        f"FAIL: case() classes {sorted(found_classes)} do not match the expected set "
        f"{sorted(expected_classes)}"
    )

for name, sample in SAMPLES.items():
    cls = name.split("_dispatcher")[0] if name.endswith("_dispatcher") else name
    got = classify(sample, branches)
    if got != cls:
        errors.append(
            f"FAIL: sample for '{name}' ({sample!r}) classified as {got!r}, expected {cls!r}"
        )

if classify(UNRELATED, branches) is not None:
    errors.append(
        f"FAIL: unrelated text {UNRELATED!r} was classified as "
        f"{classify(UNRELATED, branches)!r} -- a pattern is too broad"
    )

# --- cross-class false-positive check: each class's sample must not also
# match a DIFFERENT class's branch (a widened pattern silently reclassifying
# another failure type is worse than a miss, since suppression and delivery
# both key on failure_class) ------------------------------------------------
for name, sample in SAMPLES.items():
    cls = name.split("_dispatcher")[0] if name.endswith("_dispatcher") else name
    for pattern1, joiner, pattern2, other_cls in branches:
        if other_cls == cls:
            continue
        if build_condition(pattern1, joiner, pattern2)(sample):
            errors.append(
                f"FAIL: '{name}' sample also matches the '{other_cls}' branch -- "
                "patterns are not mutually exclusive"
            )

# --- index-time bound in the base search -----------------------------------
base_search = search.split("|", 1)[0]
if "_index_earliest=" not in base_search or "_index_latest=" not in base_search:
    errors.append(
        "FAIL: hermes_failure_classes has no _index_earliest/_index_latest bound "
        "in the base search"
    )

# --- profile is not a confirmed field: an event lacking it must still yield
# a row (fillnull before stats), not be silently dropped by the by-clause ---
fillnull_idx = search.find('fillnull value="unknown" profile')
stats_idx = search.find("stats count by failure_class, host, profile")
if fillnull_idx == -1 or stats_idx == -1 or fillnull_idx > stats_idx:
    errors.append(
        "FAIL: hermes_failure_classes must fillnull profile to \"unknown\" "
        "before the stats by-clause, or events missing that field are dropped "
        "instead of grouped"
    )

# --- slack_api_error must not fire on the adapter's own normal-teardown
# DEBUG line (plugins/platforms/slack/adapter.py:695), which also matches
# "[Slack]" + "failed" ------------------------------------------------------
SLACK_TEARDOWN = "[Slack] Socket Mode task failed while stopping"
if classify(SLACK_TEARDOWN, branches) is not None:
    errors.append(
        f"FAIL: normal-teardown line {SLACK_TEARDOWN!r} was classified as "
        f"{classify(SLACK_TEARDOWN, branches)!r} -- slack_api_error is too broad"
    )

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print(
    "PASS: hermes_failure_classes' 5 case() branches each match their own class's real "
    "sample line, none cross-match another class or unrelated text, and the base search "
    "is bounded by index time"
)
print("\nAll tests passed.")
