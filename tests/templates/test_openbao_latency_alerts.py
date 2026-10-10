#!/usr/bin/env python3
"""
Guard the five OpenBao latency, raft-commit, heartbeat and IO-wait detectors
(savedsearches/14b-openbao-latency.j2).

Renders the real template with the shipped defaults and checks each stanza's
delivery, schedule and suppression, that every threshold default reaches its
search, that the search is one unwelded line, and that alert_text names the
node, the role and the observed value and threshold. A negative case renders
with a changed floor and proves the new value replaces the old one.

Importing check_welded runs test_search_not_welded's own checks first; they
print their PASS line before this file's output.

Run from repo root:
  python3 tests/templates/test_openbao_latency_alerts.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

from test_search_not_welded import check_welded

ROOT = Path(__file__).parent.parent.parent
TEMPLATES = ROOT / "roles/splunk_docker/templates"
DEFAULTS = load_defaults(ROOT)
NTFY = "https://ntfy.example.test/keystone"

LATENCY_KEYS = (
    "splunk_docker_openbao_latency_tail_multiplier",
    "splunk_docker_openbao_latency_tail_floor_ms",
    "splunk_docker_openbao_latency_tail_min_minutes",
    "splunk_docker_openbao_raft_commit_sustained_ms",
    "splunk_docker_openbao_raft_commit_spike_ms",
    "splunk_docker_openbao_follower_heartbeat_ms",
    "splunk_docker_openbao_leader_io_wait_s",
    "splunk_docker_openbao_voter_io_wait_s",
)

EXPECTED = {
    "openbao_request_latency_tail": {
        "earliest": "-24h@m",
        "latest": "@m",
        "suppress_fields": "host,kind",
        "search_defaults": (
            "splunk_docker_openbao_latency_tail_multiplier",
            "splunk_docker_openbao_latency_tail_floor_ms",
            "splunk_docker_openbao_latency_tail_min_minutes",
        ),
        "alert_fields": ("host", "kind", "role", "observed_ms", "threshold_ms", "ratio", "baseline_ms"),
        "alert_defaults": (),
    },
    "openbao_raft_commit_latency": {
        "earliest": "-5m@m",
        "latest": "@m",
        "suppress_fields": "host",
        "search_defaults": (
            "splunk_docker_openbao_raft_commit_sustained_ms",
            "splunk_docker_openbao_raft_commit_spike_ms",
        ),
        "alert_fields": ("host", "role", "observed_ms"),
        "alert_defaults": (
            "splunk_docker_openbao_raft_commit_sustained_ms",
            "splunk_docker_openbao_raft_commit_spike_ms",
        ),
    },
    "openbao_follower_heartbeat_lag": {
        "earliest": "-5m@m",
        "latest": "@m",
        "suppress_fields": "peer_id",
        "search_defaults": ("splunk_docker_openbao_follower_heartbeat_ms",),
        "alert_fields": ("peer_id", "role", "leader", "observed_ms"),
        "alert_defaults": ("splunk_docker_openbao_follower_heartbeat_ms",),
    },
    "openbao_leader_io_wait": {
        "earliest": "-20m@5m",
        "latest": "@5m",
        "suppress_fields": "host",
        "search_defaults": ("splunk_docker_openbao_leader_io_wait_s",),
        "alert_fields": ("host", "role", "observed_s", "pct"),
        "alert_defaults": ("splunk_docker_openbao_leader_io_wait_s",),
    },
    "openbao_voter_io_wait": {
        "earliest": "-25m@5m",
        "latest": "@5m",
        "suppress_fields": "host",
        "search_defaults": ("splunk_docker_openbao_voter_io_wait_s",),
        "alert_fields": ("host", "role", "observed_s"),
        "alert_defaults": ("splunk_docker_openbao_voter_io_wait_s",),
    },
}

COMMON_KEYS = (
    ("enableSched", "1"),
    ("is_visible", "1"),
    ("disabled", "0"),
    ("alert.severity", "4"),
    ("alert.track", "1"),
    ("counttype", "number of events"),
    ("relation", "greater than"),
    ("quantity", "0"),
)


def render(**overrides):
    values = {
        "splunk_docker_silence_detectors": DEFAULTS["splunk_docker_silence_detectors"],
        "splunk_docker_silence_exemptions": DEFAULTS["splunk_docker_silence_exemptions"],
        "splunk_docker_silence_lookback_multiplier": DEFAULTS["splunk_docker_silence_lookback_multiplier"],
        "splunk_docker_llm_freshness_indexes": DEFAULTS["splunk_docker_llm_freshness_indexes"],
        "splunk_docker_indexes_core": DEFAULTS["splunk_docker_indexes_core"],
        "splunk_docker_indexes_extra": DEFAULTS["splunk_docker_indexes_extra"],
        "splunk_docker_openbao_raft_expected_voters": DEFAULTS["splunk_docker_openbao_raft_expected_voters"],
        "splunk_docker_alert_ntfy_url": NTFY,
        "splunk_docker_alert_ntfy_query": DEFAULTS["splunk_docker_alert_ntfy_query"],
    }
    values.update({key: DEFAULTS[key] for key in LATENCY_KEYS})
    values.update(overrides)
    return ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(**values)


def stanza_bodies(text):
    return {m.group(1): m.group(2) for m in re.finditer(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", text, re.M | re.S)}


def value(body, key):
    m = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return m.group(1) if m else None


def has_token(text, token):
    """True when token appears as its own number or word, not inside a longer one."""
    return re.search(rf"(?<![\w.]){re.escape(str(token))}(?![\w.])", text) is not None


def without_literals(expr):
    """Drop SPL string literals so a field name cannot pass by appearing as prose."""
    return re.sub(r'"[^"]*"', '""', expr)


def check_stanza(name, body, spec, errors):
    def need(ok, message):
        if not ok:
            errors.append(f"FAIL: [{name}] {message}")

    need(value(body, "action.webhook") == "1", "has no action.webhook = 1 delivery")
    need("&tpl=yes&t=" in (value(body, "action.webhook.param.url") or ""), "hub URL lacks the ntfy title/message templates")
    need(value(body, "cron_schedule") == "*/5 * * * *", "cron_schedule is not */5 * * * *")
    need(value(body, "alert.suppress") == "1", "alert.suppress is not 1")
    need(value(body, "alert.suppress.period") == "1h", "alert.suppress.period is not 1h")
    need(
        value(body, "alert.suppress.fields") == spec["suppress_fields"],
        f"alert.suppress.fields is not {spec['suppress_fields']}",
    )
    need(value(body, "dispatch.earliest_time") == spec["earliest"], f"dispatch.earliest_time is not {spec['earliest']}")
    need(value(body, "dispatch.latest_time") == spec["latest"], f"dispatch.latest_time is not {spec['latest']}")
    need(value(body, "dispatch.latest_time") != "now", "dispatch.latest_time is now, which counts a partial newest bucket")
    for key, expected in COMMON_KEYS:
        need(value(body, key) == expected, f"{key} is not {expected!r}")
    need(bool(value(body, "description")), "has no description")

    search = value(body, "search") or ""
    need(bool(search), "has no search line")
    need(len(re.findall(r"^search = ", body, re.M)) == 1, "has more than one search line")
    need(not search.endswith("\\"), "search line continues onto the next line")
    need("#" not in search, "search carries a # comment")
    for key in spec["search_defaults"]:
        need(has_token(search, DEFAULTS[key]), f"search does not carry {key} = {DEFAULTS[key]}")

    # streamstats keeps one window per BY group only when rows arrive grouped,
    # and its window counts rows, so each windowed streamstats must follow a
    # sort on its own keys and check the window's time span for gaps.
    sorts = re.findall(r"\| sort 0 ([^|]+?) \|", search)
    for match in re.finditer(r"\| streamstats ([^|]*?) BY ([^|]+?) \|", search):
        args, keys = match.group(1), match.group(2).strip()
        need(f"{keys} _time" in sorts, f"streamstats BY {keys} does not follow sort 0 {keys} _time")
        if "window=" in args:
            need("earliest(_time)" in args, f"windowed streamstats BY {keys} has no time-span check")

    marker = "| eval alert_text="
    need(marker in search, "search does not end by evaluating alert_text")
    expr = without_literals(search.split(marker, 1)[1]) if marker in search else ""
    for field in spec["alert_fields"]:
        need(re.search(rf"\b{re.escape(field)}\b", expr) is not None, f"alert_text does not reference {field}")
    for key in spec["alert_defaults"]:
        need(has_token(expr, DEFAULTS[key]), f"alert_text does not carry {key} = {DEFAULTS[key]}")


rendered = render()
bodies = stanza_bodies(rendered)
errors = []

for name, spec in EXPECTED.items():
    body = bodies.get(name)
    if body is None:
        errors.append(f"FAIL: [{name}] not rendered")
        continue
    check_stanza(name, body, spec, errors)

for stanza, key, offending in check_welded(rendered):
    if stanza in EXPECTED:
        errors.append(f"FAIL: [{stanza}] {key} has a comment welded into it: ...{offending[-80:]}")

changed = stanza_bodies(render(splunk_docker_openbao_latency_tail_floor_ms=900))
changed_search = value(changed.get("openbao_request_latency_tail", ""), "search") or ""
if not has_token(changed_search, 900):
    errors.append("FAIL: floor override 900 does not reach the request-latency search")
if has_token(changed_search, 500):
    errors.append("FAIL: default floor 500 still appears in the search after the override to 900")

if errors:
    print("\n".join(errors))
    sys.exit(1)
print(
    "PASS: five OpenBao latency, raft-commit, heartbeat and IO-wait stanzas carry webhook "
    "delivery, schedule, suppression, thresholds and alert_text; a changed floor replaces the old one"
)
