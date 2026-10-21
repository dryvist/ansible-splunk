#!/usr/bin/env python3
"""Guard the rendered Proxmox fencing and quorum alert contracts."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
TEMPLATES = ROOT / "roles/splunk_docker/templates"
NTFY = "https://ntfy.example.test/keystone"

render_values = dict(DEFAULTS)
render_values["splunk_docker_alert_ntfy_url"] = NTFY
rendered = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(**render_values)
stanzas = {
    match.group(1): match.group(2)
    for match in re.finditer(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
}


def value(body, key):
    match = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return match.group(1) if match else None


def check_alert(name, window_minutes, suppress_minutes):
    body = stanzas.get(name)
    if body is None:
        return [f"FAIL: [{name}] was not rendered"]
    issues = []
    expected = {
        "dispatch.earliest_time": f"-{window_minutes}m",
        "dispatch.latest_time": "now",
        "cron_schedule": DEFAULTS["splunk_docker_pve_ha_alerts"]["cron"],
        "enableSched": "1",
        "alert.severity": "5",
        "alert.suppress": "1",
        "alert.suppress.period": f"{suppress_minutes}m",
        "alert.suppress.fields": "host",
        "alert.track": "1",
        "action.webhook": "1",
    }
    for key, expected_value in expected.items():
        if value(body, key) != expected_value:
            issues.append(
                f"FAIL: [{name}] {key} expected {expected_value!r}, got {value(body, key)!r}"
            )
    url = value(body, "action.webhook.param.url")
    if not url or not url.startswith(NTFY + "?priority=high&tpl=yes"):
        issues.append(f"FAIL: [{name}] has no rendered alert hub destination: {url!r}")
    search = value(body, "search") or ""
    if "{{" in search or "{%" in search:
        issues.append(f"FAIL: [{name}] contains an unrendered template expression")
    return issues


errors = []
pve_ha = DEFAULTS["splunk_docker_pve_ha_alerts"]
fence = stanzas.get("pve_ha_fence", "")
errors.extend(
    check_alert(
        "pve_ha_fence",
        pve_ha["fence_window_minutes"],
        pve_ha["fence_suppress_minutes"],
    )
)
fence_search = value(fence, "search") or ""
for fragment in (
    "index=os_proxmox",
    '"Trying to fence node"',
    '"watchdog expired"',
    'metric_name="pve_ha_state" state="fence"',
    "sum(_value)",
    f"fence_count >= {pve_ha['fence_repeat_count']}",
    'signal_kind=case(match(lower(_raw), "trying to fence node"), "fence_attempt"',
    '"watchdog_expired")',
    "count as fence_count latest(_raw) as event_message by host signal_kind",
    "BY host",
    "table host fence_count detection_sources event_messages",
):
    if fragment not in fence_search:
        errors.append(f"FAIL: [pve_ha_fence] search is missing {fragment!r}")
if '"Successfully fenced node"' in fence_search or '"fenc*"' in fence_search:
    errors.append(
        "FAIL: [pve_ha_fence] counts one attempt plus its completion as separate fencing events"
    )

quorum = stanzas.get("pve_cluster_quorum_lost", "")
errors.extend(
    check_alert(
        "pve_cluster_quorum_lost",
        pve_ha["quorum_window_minutes"],
        pve_ha["quorum_suppress_minutes"],
    )
)
quorum_search = value(quorum, "search") or ""
for fragment in (
    'metric_name="pve_cluster_info"',
    'quorate="0"',
    "count(_value) as quorum_loss_samples",
    "quorum_loss_samples > 0",
    "BY host",
    "table host quorum_loss_samples quorum_state",
):
    if fragment not in quorum_search:
        errors.append(f"FAIL: [pve_cluster_quorum_lost] search is missing {fragment!r}")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: rendered fencing and quorum alerts include declared metrics, schedules, suppression and alert delivery")
