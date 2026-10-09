#!/usr/bin/env python3
"""
Guard openbao_privileged_use's index-time window and per-request suppression.

Audit _time is the record's own time, so a replayed backlog lands hours in
the past. The alert must bound its base search by _index_earliest/
_index_latest (alert once, on arrival) with an earliest_time wide enough to
reach those late records. A replayed copy is indexed again, so the alert
suppresses on the record's request id: the same request twice alerts once.

Run from repo root:
  python3 tests/templates/test_openbao_privileged_use.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)

rendered = ansible_env(ROOT / "roles/splunk_docker/templates").get_template(
    "savedsearches.conf.j2"
).render(
    splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
    splunk_docker_silence_lookback_multiplier=DEFAULTS["splunk_docker_silence_lookback_multiplier"],
    splunk_docker_llm_freshness_indexes=DEFAULTS["splunk_docker_llm_freshness_indexes"],
    splunk_docker_indexes_core=DEFAULTS["splunk_docker_indexes_core"],
    splunk_docker_indexes_extra=DEFAULTS["splunk_docker_indexes_extra"],
    splunk_docker_openbao_raft_expected_voters=DEFAULTS["splunk_docker_openbao_raft_expected_voters"],
    splunk_docker_alert_ntfy_url=None,
)

m = re.search(r"^\[openbao_privileged_use\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
if not m:
    print("FAIL: [openbao_privileged_use] not found in rendered output")
    sys.exit(1)
stanza = m.group(1)
search = re.search(r"^search = (.*)$", stanza, re.M)
base = search.group(1).split("|", 1)[0] if search else ""
earliest = re.search(r"^dispatch\.earliest_time = -(\d+)h$", stanza, re.M)

errors = []
if "_index_earliest=-6m" not in base or "_index_latest=now" not in base:
    errors.append("FAIL: base search is not bounded by _index_earliest=-6m/_index_latest=now")
if not earliest or int(earliest.group(1)) < 24:
    errors.append("FAIL: dispatch.earliest_time must reach at least -24h of record time")



def setting(key):
    found = re.search(rf"^{re.escape(key)} = (.*)$", stanza, re.M)
    return found.group(1) if found else None


full_search = search.group(1) if search else ""
if "eval request_id='request.id'" not in full_search:
    errors.append("FAIL: search does not derive request_id from request.id")
if "request_id" not in full_search.rsplit("| table ", 1)[-1].split():
    errors.append("FAIL: request_id is not kept in the alert's result table")
period = re.fullmatch(r"(\d+)h", setting("alert.suppress.period") or "")
if setting("alert.suppress") != "1" or not period or int(period.group(1)) < 48:
    errors.append("FAIL: suppression must be on for at least 48h")


def alerts(rows, fields, seen):
    """Splunk field suppression: a row alerts only if its key is unseen."""
    fired = 0
    for row in rows:
        key = tuple(row.get(f) for f in fields)
        if key not in seen:
            seen.add(key)
            fired += 1
    return fired


fields = (setting("alert.suppress.fields") or "").split(",")
seen = set()
first = alerts([{"request_id": "r-1"}], fields, seen)
replayed = alerts([{"request_id": "r-1"}], fields, seen)
fresh = alerts([{"request_id": "r-2"}], fields, seen)
if (first, replayed, fresh) != (1, 0, 1):
    errors.append(
        f"FAIL: suppression on {fields} gave first/replayed/fresh={first}/{replayed}/{fresh}, want 1/0/1"
    )

for err in errors:
    print(err)
if errors:
    sys.exit(1)
print("PASS: openbao_privileged_use windows on index time and alerts once per request")
