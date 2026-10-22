#!/usr/bin/env python3
"""Guard the rendered pool, swap and ClickHouse capacity alert contracts."""

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
    splunk_docker_ansible_converge_host_count=DEFAULTS["splunk_docker_ansible_converge_host_count"],
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


contracts = {
    "pve_zpool_fill": {
        "severity": "4",
        "fields": "host",
        "search": (
            "index=os_proxmox sourcetype=pve:health",
            r'| rex "zpool_cap_max=(?<zpool_cap_max>-?\d+)"',
            r'| rex "zpool_cap_pool=(?<zpool_cap_pool>\S+)"',
            "latest(zpool_cap_max) as zpool_cap_max",
            "by host",
            "| where zpool_cap_max >= 85",
        ),
    },
    "pve_swap_active": {
        "severity": "4",
        "fields": "host",
        "search": (
            "latest(node_memory_SwapTotal_bytes) as t",
            "latest(node_memory_SwapFree_bytes) as f",
            "WHERE index=host_metrics host=pve-* span=5m BY host",
            "| stats latest(t) as t latest(f) as f by host",
            "| eval used=t-f",
            "| where used > 2147483648",
        ),
    },
    "clickhouse_disk_fill": {
        "severity": "5",
        "fields": "host,mountpoint",
        "search": (
            "latest(node_filesystem_avail_bytes) as a",
            "latest(node_filesystem_size_bytes) as s",
            "WHERE index=host_metrics host=clickhouse fstype!=tmpfs span=5m BY host mountpoint",
            "| eval pct_used=round((1-a/s)*100,1)",
            "| where pct_used >= 85",
        ),
    },
}

errors = []
for name, contract in contracts.items():
    body = stanzas.get(name)
    if body is None:
        errors.append(f"FAIL: [{name}] was not rendered")
        continue
    expected = {
        "dispatch.earliest_time": "-15m",
        "dispatch.latest_time": "now",
        "cron_schedule": "*/5 * * * *",
        "disabled": "0",
        "alert.severity": contract["severity"],
        "alert.suppress": "1",
        "alert.suppress.period": "6h",
        "alert.suppress.fields": contract["fields"],
        "counttype": "number of events",
        "relation": "greater than",
        "quantity": "0",
    }
    for key, expected_value in expected.items():
        if value(body, key) != expected_value:
            errors.append(
                f"FAIL: [{name}] {key} expected {expected_value!r}, got {value(body, key)!r}"
            )
    search = " ".join(body.splitlines())
    for fragment in contract["search"]:
        if fragment not in search:
            errors.append(f"FAIL: [{name}] search is missing {fragment!r}")
    if value(body, "description") is None:
        errors.append(f"FAIL: [{name}] has no one-line description")
    if value(body, "action.webhook") != "1" or not value(
        body, "action.webhook.param.url"
    ):
        errors.append(f"FAIL: [{name}] has no rendered alert delivery")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print(
    "PASS: all three rendered capacity alerts have the requested search, time window, "
    "severity, suppression, count rule and delivery"
)
