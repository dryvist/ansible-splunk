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

if errors:
    print("\n".join(errors))
    sys.exit(1)
print("PASS: openbao_window_non_claude_use correlates window use with Claude Code transcripts")
