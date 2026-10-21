#!/usr/bin/env python3
"""Guard the rendered Ansible converge host-count alert contract."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
TEMPLATES = ROOT / "roles/splunk_docker/templates"
NTFY = "https://ntfy.example.test/keystone"

rendered = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(
    splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
    splunk_docker_silence_exemptions=DEFAULTS["splunk_docker_silence_exemptions"],
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
    splunk_docker_alert_ntfy_url=NTFY,
    splunk_docker_alert_ntfy_query=DEFAULTS["splunk_docker_alert_ntfy_query"],
)

stanzas = {
    match.group(1): match.group(2)
    for match in re.finditer(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
}


def value(body, key, default=None):
    match = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return match.group(1) if match else default


errors = []
body = stanzas.get("ansible_converge_host_count")
if body is None:
    errors.append("FAIL: [ansible_converge_host_count] was not rendered")
else:
    expected = {
        "dispatch.earliest_time": "-7d@d",
        "dispatch.latest_time": "now",
        "cron_schedule": "*/15 * * * *",
        "enableSched": "1",
        "is_visible": "1",
        "disabled": "0",
        "alert.severity": "4",
        "alert.suppress": "1",
        "alert.suppress.period": "1h",
        "alert.suppress.fields": "playbook,_time",
        "alert.track": "1",
        "counttype": "number of events",
        "relation": "greater than",
        "quantity": "0",
    }
    for key, expected_value in expected.items():
        if value(body, key) != expected_value:
            errors.append(
                f"FAIL: [ansible_converge_host_count] {key} expected "
                f"{expected_value!r}, got {value(body, key)!r}"
            )

    search = value(body, "search", "")
    for fragment in (
        "index=ansible",
        'sourcetype="ansible:converge:run"',
        "earliest=-7d",
        "tonumber(hosts)",
        "sort 0 playbook _time",
        "streamstats current=f window=0",
        "count as history_count",
        "median(host_count) as median_hosts",
        "host_count=0 OR (history_count>=3 AND host_count < median_hosts * 0.5)",
        "table _time, playbook, host_count, median_hosts, history_count, repo, git_sha",
    ):
        if fragment not in search:
            errors.append(f"FAIL: search is missing {fragment!r}")
    if value(body, "description") is None:
        errors.append("FAIL: alert has no one-line description")
    if "description =" in search:
        errors.append("FAIL: rendered search includes the next stanza setting")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: rendered Ansible converge host-count alert has history guard and run-level search")
