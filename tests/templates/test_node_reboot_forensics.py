#!/usr/bin/env python3
"""Guard the rendered, on-demand post-reboot forensic saved search."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

try:
    import jinja2  # noqa: F401
except ImportError:
    print("ERROR: jinja2 not installed. Run: pip install jinja2")
    sys.exit(1)

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
NAME = "pve_node_reboot_forensics"
STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)

env = ansible_env(ROOT / "roles/splunk_docker/templates")
rendered = env.get_template("savedsearches.conf.j2").render(
    splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
    splunk_docker_silence_exemptions=DEFAULTS["splunk_docker_silence_exemptions"],
    splunk_docker_silence_lookback_multiplier=DEFAULTS[
        "splunk_docker_silence_lookback_multiplier"
    ],
    splunk_docker_indexes_core=DEFAULTS["splunk_docker_indexes_core"],
    splunk_docker_indexes_extra=DEFAULTS["splunk_docker_indexes_extra"],
)

stanzas = {
    match.group(1): match.group(2)
    for match in STANZA_RE.finditer(rendered)
}
body = stanzas.get(NAME)
errors = []

if body is None:
    errors.append(f"FAIL: [{NAME}] not rendered")
else:
    search_match = re.search(r"^search = (.*)$", body, re.M)
    search = search_match.group(1) if search_match else ""
    required = (
        "index=host_metrics sourcetype=node_exporter",
        "latest(node_boot_time_seconds) as boot_time",
        "latest(node_load5) as load_5m",
        "latest(node_memory_MemAvailable_bytes) as memory_available_bytes",
        "earliest=-90d latest=now span=1m",
        "streamstats current=f last(boot_time) as prior_boot_time BY host",
        'isnotnull(prior_boot_time) AND boot_time!=prior_boot_time, tostring(boot_time).":".tostring(prior_boot_time)',
        "eventstats values(reboot_pair) as reboot_pairs BY host",
        "mvexpand reboot_pairs",
        "window_start=floor((reboot_epoch-900)/60)*60",
        "window_end=floor(reboot_epoch/60)*60",
        "where _time >= window_start AND _time < window_end",
        "table _time host reboot_at prior_boot_at load_5m memory_available_gib",
    )
    for fragment in required:
        if fragment not in search:
            errors.append(f"FAIL: [{NAME}] search is missing {fragment!r}")

    if not re.search(r"^dispatch\.earliest_time = -90d$", body, re.M):
        errors.append(f"FAIL: [{NAME}] dispatch time range must cover retained metric history")

    if "Post-reboot forensic context" not in body or "not a reboot prediction" not in body:
        errors.append(f"FAIL: [{NAME}] does not clearly identify post-reboot context")
if errors:
    for error in errors:
        print(error)
    sys.exit(1)

print(
    "PASS: the rendered post-reboot search detects node_boot_time_seconds "
    "changes and returns 15 full pre-boot minute buckets at one-minute resolution"
)
