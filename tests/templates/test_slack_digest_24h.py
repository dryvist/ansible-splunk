#!/usr/bin/env python3
"""
Guard the Slack digest on the listed saved searches that notify Slack.

Each listed search sends at most one notification per 24 hours, and that
notification lists every hit (digest_mode = 1). The suppression carries no
per-key field, so the digest is not split per host, request or index. Where a
search has per-row values, its search also aggregates them onto every row.

Asserts on the RENDERED savedsearches.conf, not the template source, so a
variable that never reaches the template shows up here instead of at converge.

Run from repo root:
  python3 tests/templates/test_slack_digest_24h.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)
TEMPLATE = ansible_env(ROOT / "roles/splunk_docker/templates").get_template("savedsearches.conf.j2")

DIGESTED = (
    "os_silence_detector",
    "index_gap_detector",
    "llm_pipeline_silence_detector",
    "llm_router_silence_detector",
    "offbox_sync_job_unhealthy",
    "mac_windowserver_synchronize_timeout",
    "pve_swap_active",
)

# The Slack webhook action sends only the first result row, so every row of a
# digested search must carry the full list of its per-row values. Each entry is
# (per-row field, list field): the search must hold eventstats values(<field>)
# as <list field> and an mvjoin of that list.
AGGREGATES = {
    "os_silence_detector": (("host", "silent_hosts"),),
    "index_gap_detector": (("index", "indexes"),),
    "llm_pipeline_silence_detector": (("host", "hosts"),),
    "offbox_sync_job_unhealthy": (("host", "hosts"), ("job", "jobs")),
    "mac_windowserver_synchronize_timeout": (("host", "hosts"),),
    "pve_swap_active": (("host", "hosts"),),
    "llm_router_silence_detector": (("host", "silent_hosts"),),
}

# The router takes last-seen per host, so one active router cannot hide a
# silent peer. Every name here must group its tstats by host.
PER_HOST = ("llm_router_silence_detector",)

if set(AGGREGATES) != set(DIGESTED):
    sys.exit("AGGREGATES must cover every DIGESTED search")


def value(body, key):
    match = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return match.group(1) if match else None


def search_text(body):
    # A search may continue onto following lines through a trailing backslash.
    match = re.search(r"^search = ((?:.*\\\n)*.*)$", body, re.M)
    return match.group(1) if match else ""


def is_24h(period):
    # os_silence_detector renders its period from minutes, so 1440m is the same 24 hours.
    return period in ("24h", "1440m")


context = {**DEFAULTS, "splunk_docker_alert_ntfy_url": None}
stanzas = {m.group(1): m.group(2) for m in STANZA_RE.finditer(TEMPLATE.render(**context))}

errors = []
checks = 0
for name in DIGESTED:
    body = stanzas.get(name)
    if body is None:
        checks += 1
        errors.append(f"FAIL: [{name}] was not rendered")
        continue
    expectations = {
        "alert.digest_mode": "1",
        "alert.suppress": "1",
    }
    for key, want in expectations.items():
        checks += 1
        if value(body, key) != want:
            errors.append(f"FAIL: [{name}] {key} is {value(body, key)!r}, want {want!r}")
    checks += 1
    if not is_24h(value(body, "alert.suppress.period") or ""):
        errors.append(f"FAIL: [{name}] alert.suppress.period is {value(body, 'alert.suppress.period')!r}, want 24h")
    checks += 1
    if value(body, "alert.suppress.fields") is not None:
        errors.append(f"FAIL: [{name}] still sets alert.suppress.fields")
    search = search_text(body)
    for key, alias in AGGREGATES.get(name, ()):
        aggregate = re.search(rf"eventstats\b[^|]*\bvalues\({key}\) as {alias}\b", search)
        join = re.search(rf'\b{alias} ?= ?mvjoin\(mvsort\({alias}\), ?","\)', search)
        checks += 1
        if aggregate is None:
            errors.append(f"FAIL: [{name}] search lacks eventstats values({key}) as {alias}")
        checks += 1
        if join is None or aggregate is None or join.start() < aggregate.start():
            errors.append(f"FAIL: [{name}] search does not join {alias} with mvjoin(mvsort({alias}), \",\") after the eventstats")
    if name in PER_HOST:
        checks += 1
        if not re.search(r"tstats [^|]*\bby host\b", search):
            errors.append(f"FAIL: [{name}] takes last-seen across all hosts, so one active host hides a silent one")

failed = len(errors)
for err in errors:
    print(err)
print(f"{checks - failed} passed, {failed} failed, {checks} checks across {len(DIGESTED)} saved searches")
if errors:
    sys.exit(1)
print("PASS: every listed saved search sends one digest per 24 hours and carries its per-row list")
