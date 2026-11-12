"""Shared saved-search rendering and helpers for OpenBao alert tests."""

import re
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
TEMPLATES = ROOT / "roles/splunk_docker/templates"
DEFAULTS = load_defaults(ROOT)

render_values = {
    "splunk_docker_ansible_converge_host_count": DEFAULTS["splunk_docker_ansible_converge_host_count"],
    "splunk_docker_silence_detectors": DEFAULTS["splunk_docker_silence_detectors"],
    "splunk_docker_silence_lookback_multiplier": DEFAULTS["splunk_docker_silence_lookback_multiplier"],
    "splunk_docker_llm_freshness_indexes": DEFAULTS["splunk_docker_llm_freshness_indexes"],
    "splunk_docker_indexes_core": DEFAULTS["splunk_docker_indexes_core"],
    "splunk_docker_indexes_extra": DEFAULTS["splunk_docker_indexes_extra"],
    "splunk_docker_openbao_raft_expected_voters": DEFAULTS["splunk_docker_openbao_raft_expected_voters"],
    "splunk_docker_openbao_latency_tail_multiplier": DEFAULTS["splunk_docker_openbao_latency_tail_multiplier"],
    "splunk_docker_openbao_latency_tail_floor_ms": DEFAULTS["splunk_docker_openbao_latency_tail_floor_ms"],
    "splunk_docker_openbao_latency_tail_min_minutes": DEFAULTS["splunk_docker_openbao_latency_tail_min_minutes"],
    "splunk_docker_openbao_raft_commit_sustained_ms": DEFAULTS["splunk_docker_openbao_raft_commit_sustained_ms"],
    "splunk_docker_openbao_raft_commit_spike_ms": DEFAULTS["splunk_docker_openbao_raft_commit_spike_ms"],
    "splunk_docker_openbao_follower_heartbeat_ms": DEFAULTS["splunk_docker_openbao_follower_heartbeat_ms"],
    "splunk_docker_openbao_leader_io_wait_s": DEFAULTS["splunk_docker_openbao_leader_io_wait_s"],
    "splunk_docker_openbao_voter_io_wait_s": DEFAULTS["splunk_docker_openbao_voter_io_wait_s"],
    "splunk_docker_alert_ntfy_url": None,
}


def render_savedsearches(alert_ntfy_url=None):
    """Render saved searches with shared defaults and an optional alert URL."""
    values = dict(render_values)
    values["splunk_docker_alert_ntfy_url"] = alert_ntfy_url
    if alert_ntfy_url is not None:
        values["splunk_docker_alert_ntfy_query"] = DEFAULTS["splunk_docker_alert_ntfy_query"]
    return ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(**values)


def setting(body, key):
    """Return a rendered stanza setting, or None when it is absent."""
    found = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return found.group(1) if found else None


def search_text(body):
    """Return a rendered stanza search, or an empty string when absent."""
    found = re.search(r"^search = (.*)$", body, re.M)
    return found.group(1) if found else ""
