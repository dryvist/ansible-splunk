#!/usr/bin/env python3
"""
Guard openbao_raft_quorum's thresholds against the declared voter count.

The search pages below splunk_docker_openbao_raft_expected_voters and labels
the state "below quorum" under a majority derived from that same value, so
the two lines cannot drift apart. Renders with the shipped default and with
an override, and checks both thresholds follow.

Run from repo root:
  python3 tests/templates/test_openbao_raft_quorum.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)


def raft_search(voters):
    rendered = ansible_env(ROOT / "roles/splunk_docker/templates").get_template(
        "savedsearches.conf.j2"
    ).render(
        splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
        splunk_docker_silence_lookback_multiplier=DEFAULTS["splunk_docker_silence_lookback_multiplier"],
        splunk_docker_llm_freshness_indexes=DEFAULTS["splunk_docker_llm_freshness_indexes"],
        splunk_docker_indexes_core=DEFAULTS["splunk_docker_indexes_core"],
        splunk_docker_indexes_extra=DEFAULTS["splunk_docker_indexes_extra"],
        splunk_docker_openbao_raft_expected_voters=voters,
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
    m = re.search(r"^\[openbao_raft_quorum\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
    if not m:
        print("FAIL: [openbao_raft_quorum] not found in rendered output")
        sys.exit(1)
    search = re.search(r"^search = (.*)$", m.group(1), re.M)
    return search.group(1) if search else ""


errors = []
default = DEFAULTS["splunk_docker_openbao_raft_expected_voters"]
for voters, quorum in ((default, default // 2 + 1), (7, 4), (5, 3)):
    search = raft_search(voters)
    if f"min_voters < {voters} " not in search:
        errors.append(f"FAIL: voters={voters}: search does not page below {voters}")
    if f'min_voters < {quorum}, "below quorum' not in search:
        errors.append(f"FAIL: voters={voters}: below-quorum line is not {quorum}")
    if '"degraded voters="' not in search or '"no samples"' not in search:
        errors.append(f"FAIL: voters={voters}: quorum_state lost a state label")

if errors:
    print("\n".join(errors))
    sys.exit(1)
print("PASS: openbao_raft_quorum thresholds follow the declared voter count")
