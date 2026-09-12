#!/usr/bin/env python3
"""
Guard the three new llm-serving alerts' index-time bound and match text.

llm_caller_429_rate and llm_leaked_inflight_counter are PENDING DATA (see
each stanza's own template comment): they read sourcetype=llm-serving-share,
which ships with a separate ansible-proxmox-ai PR not yet landed. This test
cannot exercise them against real data, so it checks structure only --
_index_earliest/_index_latest present, and the field names named in each
stanza's own description are the ones actually queried.

llm_watchdog_down matches two REAL strings hermes-brain-watchdog.sh already
logs today (verified against the template source, cited in this stanza's own
comment): "brain unreachable" and "brain UNSTABLE ... still flapping",
routed at index=os_ai host=hermes-agent per this repo's own
05-hermes-delivery-slo.j2. This test proves both trip the search and an
unrelated line does not, the same technique test_gap_detector.py and
test_hermes_failure_classes.py use.

Run from repo root:
  python3 tests/templates/test_llm_serving_searches.py
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

by_name = {}
for m in STANZA_RE.finditer(rendered):
    sm = SEARCH_RE.search(m.group(2))
    if sm:
        by_name[m.group(1)] = sm.group(1)

errors = []

for name in ("llm_caller_429_rate", "llm_leaked_inflight_counter", "llm_watchdog_down"):
    if name not in by_name:
        errors.append(f"FAIL: [{name}] not found in rendered output")

if errors:
    for err in errors:
        print(err)
    sys.exit(1)


def has_index_time_bound(search):
    base = search.split("|", 1)[0]
    return "_index_earliest=" in base and "_index_latest=" in base


for name in ("llm_caller_429_rate", "llm_leaked_inflight_counter", "llm_watchdog_down"):
    if not has_index_time_bound(by_name[name]):
        errors.append(
            f"FAIL: [{name}]'s base search has no _index_earliest/_index_latest bound"
        )

# --- structural checks against each stanza's own named fields -------------
caller_search = by_name["llm_caller_429_rate"]
if "caller_429_rate" not in caller_search:
    errors.append("FAIL: llm_caller_429_rate does not reference the caller_429_rate field")
if "sourcetype=llm-serving-share" not in caller_search:
    errors.append("FAIL: llm_caller_429_rate does not scope to sourcetype=llm-serving-share")

leak_search = by_name["llm_leaked_inflight_counter"]
if "status=429" not in leak_search or "duration_ms<10" not in leak_search:
    errors.append(
        "FAIL: llm_leaked_inflight_counter does not match the leaked-counter signature "
        "(status=429 AND duration_ms<10)"
    )
if "sourcetype=llm-serving-share" not in leak_search:
    errors.append("FAIL: llm_leaked_inflight_counter does not scope to sourcetype=llm-serving-share")

# --- llm_watchdog_down: prove the real strings trip it, an unrelated line
# does not (regression-fixture technique) --------------------------------
watchdog_search = by_name["llm_watchdog_down"]
if "index=os_ai" not in watchdog_search or "host=hermes-agent" not in watchdog_search:
    errors.append(
        "FAIL: llm_watchdog_down does not scope to index=os_ai host=hermes-agent"
    )
literal_match = re.search(r'\("([^"]+)" OR "([^"]+)"\)', watchdog_search)
if not literal_match:
    errors.append("FAIL: llm_watchdog_down's search has no recognizable OR'd literal match clause")
else:
    down_literal, flap_literal = literal_match.group(1), literal_match.group(2)
    DOWN_SAMPLE = (
        ":warning: hermes-brain brain unreachable (model via base_url) since "
        "2026-09-12T00:00:00Z -- pause verified succeeded=0 failed=3 desired=3"
    )
    FLAP_SAMPLE = (
        ":rotating_light: hermes-brain brain UNSTABLE for ~45 min and still "
        "flapping (6 coalesced flaps) -- model via base_url."
    )
    UNRELATED = "hermes-brain-watchdog: probe ok, no state change"
    if down_literal not in DOWN_SAMPLE:
        errors.append(
            f"FAIL: llm_watchdog_down's down-literal {down_literal!r} does not match a "
            "realistic 'brain unreachable' sample line"
        )
    if flap_literal not in FLAP_SAMPLE:
        errors.append(
            f"FAIL: llm_watchdog_down's flap-literal {flap_literal!r} does not match a "
            "realistic sustained-flap sample line"
        )
    if down_literal in UNRELATED or flap_literal in UNRELATED:
        errors.append(
            "FAIL: llm_watchdog_down's match literals also match an unrelated, healthy "
            "watchdog line -- too broad"
        )

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print(
    "PASS: llm_caller_429_rate, llm_leaked_inflight_counter and llm_watchdog_down all bound "
    "their base search by index time; the pending-data searches reference their own named "
    "fields; llm_watchdog_down scopes to index=os_ai host=hermes-agent and its match "
    "literals fire on both real watchdog transition messages and not on an unrelated "
    "healthy line"
)
print("\nAll tests passed.")
