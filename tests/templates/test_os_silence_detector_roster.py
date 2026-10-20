#!/usr/bin/env python3
"""Guard the inventory-backed and expiring OS silence-detector roster."""

import csv
import io
import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env


ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
TEMPLATES = ROOT / "roles/splunk_docker/templates"
ENV = ansible_env(TEMPLATES)


def render_savedsearches():
    return ENV.get_template("savedsearches.conf.j2").render(
        splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
        splunk_docker_silence_exemptions=DEFAULTS["splunk_docker_silence_exemptions"],
        splunk_docker_silence_lookback_multiplier=DEFAULTS[
            "splunk_docker_silence_lookback_multiplier"
        ],
        splunk_docker_os_emitter_roster=DEFAULTS["splunk_docker_os_emitter_roster"],
        splunk_docker_indexes_core=DEFAULTS["splunk_docker_indexes_core"],
        splunk_docker_indexes_extra=DEFAULTS["splunk_docker_indexes_extra"],
        splunk_docker_openbao_raft_expected_voters=DEFAULTS[
            "splunk_docker_openbao_raft_expected_voters"
        ],
        splunk_docker_openbao_latency_tail_multiplier=DEFAULTS[
            "splunk_docker_openbao_latency_tail_multiplier"
        ],
        splunk_docker_openbao_latency_tail_floor_ms=DEFAULTS[
            "splunk_docker_openbao_latency_tail_floor_ms"
        ],
        splunk_docker_openbao_latency_tail_min_minutes=DEFAULTS[
            "splunk_docker_openbao_latency_tail_min_minutes"
        ],
        splunk_docker_openbao_raft_commit_sustained_ms=DEFAULTS[
            "splunk_docker_openbao_raft_commit_sustained_ms"
        ],
        splunk_docker_openbao_raft_commit_spike_ms=DEFAULTS[
            "splunk_docker_openbao_raft_commit_spike_ms"
        ],
        splunk_docker_openbao_follower_heartbeat_ms=DEFAULTS[
            "splunk_docker_openbao_follower_heartbeat_ms"
        ],
        splunk_docker_openbao_leader_io_wait_s=DEFAULTS[
            "splunk_docker_openbao_leader_io_wait_s"
        ],
        splunk_docker_openbao_voter_io_wait_s=DEFAULTS[
            "splunk_docker_openbao_voter_io_wait_s"
        ],
        splunk_docker_alert_ntfy_url=None,
    )


def sections(rendered):
    return {
        match.group(1): match.group(2)
        for match in re.finditer(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
    }


def search_for(section):
    match = re.search(r"^search = (.*)$", section, re.M)
    return match.group(1) if match else ""


def main():
    inventory = {
        "nodes": {
            "node-a": {"commissioned": True},
            "node-retired": {"commissioned": False},
        },
        "containers": {
            "container-a": {"hostname": "guest-a", "vmid": 101},
            "container-stopped": {"hostname": "guest-stopped", "vmid": 102, "started": False},
        },
        "vms": {
            "vm-a": {"hostname": "vm-a", "vmid": 201, "started": True},
            "vm-stopped": {"hostname": "vm-stopped", "vmid": 202, "started": False},
        },
        "splunk_vm": {"splunk": {"hostname": "splunk-guest", "vmid": 250}},
    }
    rendered_lookup = ENV.get_template("lookups/os_pve_emitters.csv.j2").render(
        tofu_data=inventory
    )
    rows = [row for row in csv.DictReader(io.StringIO(rendered_lookup)) if row.get("host")]
    expected_rows = [
        {"host": "node-a", "kind": "node", "id": "node/node-a"},
        {"host": "guest-a", "kind": "guest", "id": "lxc/101"},
        {"host": "vm-a", "kind": "guest", "id": "qemu/201"},
        {"host": "splunk-guest", "kind": "guest", "id": "qemu/250"},
    ]
    if rows != expected_rows:
        raise AssertionError(f"PVE lookup differs from published inventory: {rows!r}")

    rendered = sections(render_savedsearches())
    detector = search_for(rendered.get("os_silence_detector", ""))
    refresh_section = rendered.get("os_silence_roster_refresh", "")
    refresh = search_for(refresh_section)

    detector_requirements = (
        "inputlookup os_expected_hosts.csv",
        "join type=left host",
        "`homelab_os_log_indexes`",
        "coalesce(last_seen, 0)",
        "silent_hosts",
    )
    for required in detector_requirements:
        if required not in detector:
            raise AssertionError(f"OS detector is missing {required!r}: {detector}")
    if "WHERE index=os" in detector:
        raise AssertionError("OS detector still reads one index directly")

    refresh_requirements = (
        "inputlookup pve_os_emitters.csv",
        "latest(pve_up)",
        'kind="node" OR isnull(pve_up) OR pve_up!=0',
        "_index_earliest=-5d",
        "in_pve_inventory",
        "outputlookup createinapp=true os_expected_hosts.csv",
    )
    for required in refresh_requirements:
        if required not in refresh:
            raise AssertionError(f"Roster refresh is missing {required!r}: {refresh}")
    if "enableSched = 1" not in refresh_section or "alert.track = 0" not in refresh_section:
        raise AssertionError("Roster refresh is not a scheduled non-alert search")

    print(
        "PASS: PVE emitters derive from published inventory; stopped guests are "
        "filtered by pve_up; recent non-PVE emitters expire after five days; "
        "OS silence checks all shared OS event indexes and preserves zero-event hosts"
    )


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, KeyError, OSError) as error:
        print(f"FAIL: {error}")
        sys.exit(1)
