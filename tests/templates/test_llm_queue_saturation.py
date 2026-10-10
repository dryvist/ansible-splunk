#!/usr/bin/env python3
"""
Guard the llm_queue_saturation alert's metric series, labels, and structure.

Reads index=llm_metrics (a real metric-datatype index), fed by
ansible-proxmox-apps' mlx_metrics_normalize Cribl pipeline. Series names
(haproxy_backend_current_queue, haproxy_frontend_http_responses_total) and
the "proxy"/"code" label names are confirmed against HAProxy's own promex
exporter source (addons/promex/service-prometheus.c) and its README, not
invented. This test checks structure only -- it cannot execute real mstats
against live metric data -- same limitation test_llm_serving_searches.py
notes for its own pending-data stanzas.

Run from repo root:
  python3 tests/templates/test_llm_queue_saturation.py
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
    splunk_docker_alert_slack_webhook=None,
)

by_name = {}
for m in STANZA_RE.finditer(rendered):
    sm = SEARCH_RE.search(m.group(2))
    if sm:
        by_name[m.group(1)] = sm.group(1)

errors = []

NAME = "llm_queue_saturation"
if NAME not in by_name:
    errors.append(f"FAIL: [{NAME}] not found in rendered output")
    for err in errors:
        print(err)
    sys.exit(1)

search = by_name[NAME]

# --- both legs read the real metric index, never a different one ----------
if search.count("index=llm_metrics") < 2:
    errors.append(
        "FAIL: llm_queue_saturation must scope BOTH mstats legs to index=llm_metrics"
    )

# --- queue leg: real series name, grouped by backend, sustained threshold --
if "mstats min(haproxy_backend_current_queue)" not in search:
    errors.append(
        "FAIL: the queue leg must use min() over the window (a sustained-depth "
        "check), not an instantaneous avg/max/latest value"
    )
if "BY proxy" not in search:
    errors.append("FAIL: the queue leg must group by the 'proxy' label (backend identity)")
if "queue >= 4" not in search:
    errors.append("FAIL: the queue leg must threshold at >= 4")

# --- 503 leg: real series name, llm_wait frontend, 5xx class, counter delta
if "mstats max(haproxy_frontend_http_responses_total)" not in search:
    errors.append("FAIL: the 503 leg must read haproxy_frontend_http_responses_total")
if 'proxy="llm_wait"' not in search:
    errors.append(
        "FAIL: the 503 leg must scope to proxy=\"llm_wait\" (local-queue-cfg.nix's "
        "wait frontend, not a literal 'wait')"
    )
if 'code="5xx"' not in search:
    errors.append(
        "FAIL: the 503 leg must filter code=\"5xx\" -- HAProxy's exporter buckets "
        "by status-code CLASS, there is no per-code series"
    )
if "(hi - lo) > 0" not in search:
    errors.append(
        "FAIL: the 503 leg must check the counter INCREASED over the window "
        "(max - min > 0), not compare its absolute level"
    )

# --- both legs combined via append, not two separate stanzas ---------------
if "| append [" not in search:
    errors.append("FAIL: the two legs must be combined in one stanza via append")

# --- delivery rides the shared alert_delivery macro, never a bespoke action
# (test_savedsearch_invariants.py separately proves it actually renders
# action.webhook once splunk_docker_alert_ntfy_url is set -- this just
# checks the stanza references the shared macro, not a one-off action).
stanza_block = next(
    m.group(2) for m in STANZA_RE.finditer(rendered) if m.group(1) == NAME
)
if "{{ alert_delivery" not in Path(
    ROOT / "roles/splunk_docker/templates/savedsearches/18-llm-queue-metrics.j2"
).read_text():
    errors.append(
        "FAIL: llm_queue_saturation must render the shared alert_delivery "
        "macro, not a one-off action.* line -- every other stanza does"
    )

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print(
    "PASS: llm_queue_saturation reads index=llm_metrics on both legs, sustains "
    "haproxy_backend_current_queue >= 4 over the window grouped by backend, "
    "catches any increase in llm_wait's haproxy_frontend_http_responses_total "
    "code=5xx counter, combines both via append, and delivers via the shared "
    "alert_delivery macro."
)
print("\nAll tests passed.")
