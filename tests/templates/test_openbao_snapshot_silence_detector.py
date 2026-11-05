"""
Guard openbao_snapshot_silence_detector: one notification per 24 hours, unkeyed.

The search returns a single row per run (ungrouped stats), so there is no
per-key field to suppress on; the window alone bounds the notification rate.

Run from repo root:
  python3 tests/templates/test_openbao_snapshot_silence_detector.py
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

m = re.search(r"^\[openbao_snapshot_silence_detector\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
if not m:
    print("FAIL: [openbao_snapshot_silence_detector] not found in rendered output")
    sys.exit(1)
stanza = m.group(1)


def value(key):
    match = re.search(rf"^{re.escape(key)} = (.*)$", stanza, re.M)
    return match.group(1) if match else None


errors = []
if value("alert.suppress") != "1":
    errors.append(f"FAIL: alert.suppress is {value('alert.suppress')!r}, want '1'")
if value("alert.suppress.period") != "24h":
    errors.append(f"FAIL: alert.suppress.period is {value('alert.suppress.period')!r}, want '24h'")
if value("alert.suppress.fields") is not None:
    errors.append("FAIL: alert.suppress.fields is set; the single-row search must not be keyed")
if value("alert.digest_mode") is not None:
    errors.append("FAIL: alert.digest_mode is set; the search emits one row, digest mode is not used")

if errors:
    print("\n".join(errors))
    sys.exit(1)
print("PASS: openbao_snapshot_silence_detector notifies once per 24 hours, unkeyed")
