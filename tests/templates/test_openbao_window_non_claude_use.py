"""
Guard openbao_window_non_claude_use: window requests are correlated with
Claude Code transcripts, and the alert is delivered like every other alert.

Run from repo root:
  python3 tests/templates/test_openbao_window_non_claude_use.py
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
    splunk_docker_ansible_converge_host_count=DEFAULTS["splunk_docker_ansible_converge_host_count"],
    splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
    splunk_docker_silence_lookback_multiplier=DEFAULTS["splunk_docker_silence_lookback_multiplier"],
    splunk_docker_llm_freshness_indexes=DEFAULTS["splunk_docker_llm_freshness_indexes"],
    splunk_docker_indexes_core=DEFAULTS["splunk_docker_indexes_core"],
    splunk_docker_indexes_extra=DEFAULTS["splunk_docker_indexes_extra"],
    splunk_docker_openbao_raft_expected_voters=DEFAULTS["splunk_docker_openbao_raft_expected_voters"],
    splunk_docker_openbao_latency_tail_multiplier=DEFAULTS["splunk_docker_openbao_latency_tail_multiplier"],
    splunk_docker_openbao_latency_tail_floor_ms=DEFAULTS["splunk_docker_openbao_latency_tail_floor_ms"],
    splunk_docker_openbao_latency_tail_min_minutes=DEFAULTS["splunk_docker_openbao_latency_tail_min_minutes"],
    splunk_docker_openbao_raft_commit_sustained_ms=DEFAULTS["splunk_docker_openbao_raft_commit_sustained_ms"],
    splunk_docker_openbao_raft_commit_spike_ms=DEFAULTS["splunk_docker_openbao_raft_commit_spike_ms"],
    splunk_docker_openbao_follower_heartbeat_ms=DEFAULTS["splunk_docker_openbao_follower_heartbeat_ms"],
    splunk_docker_openbao_leader_io_wait_s=DEFAULTS["splunk_docker_openbao_leader_io_wait_s"],
    splunk_docker_openbao_voter_io_wait_s=DEFAULTS["splunk_docker_openbao_voter_io_wait_s"],
    splunk_docker_alert_ntfy_url=None,
)

m = re.search(r"^\[openbao_window_non_claude_use\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
if not m:
    print("FAIL: [openbao_window_non_claude_use] not found in rendered output")
    sys.exit(1)
stanza = m.group(1)
search = re.search(r"^search = (.*)$", stanza, re.M)
full = search.group(1) if search else ""
base = full.split("|", 1)[0]

errors = []
if "_index_earliest=-6m" not in base or "_index_latest=now" not in base:
    errors.append("FAIL: base search is not bounded by _index_earliest=-6m/_index_latest=now")
if "'auth.metadata.role_name'=\"ai-admin-session\"" not in full:
    errors.append("FAIL: search does not select the ai-admin-session window")
for window in ("-20m", "-4h"):
    if f"index=claude sourcetype=claude:code _index_earliest={window}" not in full:
        errors.append(f"FAIL: no Claude Code transcript lookback of {window}")
if "where (sensitive=1 AND claude_recent=0) OR claude_session=0" not in full:
    errors.append("FAIL: alert condition does not require a Claude Code reference")
if 'like(\'request.path\', "github-enterprise-owner/%")' not in full:
    errors.append("FAIL: owner-token reads are not treated as sensitive")

# The audit record carries no caller, so alert_key separates sensitive from
# unaccounted requests. Each category pages once per 24 hours and stays on the
# result row for Splunk to key on.
def setting(key):
    found = re.search(rf"^{re.escape(key)} = (.*)$", stanza, re.M)
    return found.group(1) if found else None


period = re.fullmatch(r"24h", setting("alert.suppress.period") or "")
if setting("alert.suppress") != "1" or not period:
    errors.append("FAIL: alert suppression must be on for exactly 24h")
if setting("alert.suppress.fields") != "alert_key":
    errors.append("FAIL: alert does not throttle on alert_key")
if 'eval alert_key=if(sensitive=1, "sensitive", "unaccounted")' not in full:
    errors.append("FAIL: search does not distinguish sensitive from unaccounted requests")
table_fields = full.rsplit("| table ", 1)[-1].split()
if "paths" not in table_fields or "alert_key" not in table_fields:
    errors.append("FAIL: paths or alert_key is not kept in the alert's result table")

if errors:
    print("\n".join(errors))
    sys.exit(1)
print("PASS: openbao_window_non_claude_use correlates window use with Claude Code transcripts and throttles 24h by alert_key")
