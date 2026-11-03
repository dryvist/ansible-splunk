#!/usr/bin/env python3
"""Guard the rendered Proxmox guest backup freshness alert contract."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
TEMPLATES = ROOT / "roles/splunk_docker/templates"
NTFY = "https://ntfy.example.test/keystone"

render_values = {**DEFAULTS, "splunk_docker_alert_ntfy_url": NTFY}
rendered = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(**render_values)
match = re.search(r"^\[guest_backup_missing\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
errors = []

if not match:
    errors.append("FAIL: [guest_backup_missing] was not rendered")
else:
    body = match.group(1)

    def value(key):
        found = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
        return found.group(1) if found else None

    hours = DEFAULTS["splunk_docker_guest_backup_max_age_hours"]
    search = value("search") or ""
    expected = {
        "dispatch.earliest_time": f"-{hours}h",
        "dispatch.latest_time": "now",
        "cron_schedule": "17 * * * *",
        "disabled": "0",
        "alert.suppress": "1",
        "alert.suppress.period": "24h",
        "alert.suppress.fields": "vmid",
        "action.webhook": "1",
    }
    for key, expected_value in expected.items():
        if value(key) != expected_value:
            errors.append(f"FAIL: {key} expected {expected_value!r}, got {value(key)!r}")
    exempt = ",".join(f'"{name}"' for name in DEFAULTS["splunk_docker_guest_backup_exempt_names"])
    for fragment in (
        "metric_name=pve_guest_info",
        'where template="0"',
        f"search NOT name IN ({exempt})",
        f"index=os_proxmox earliest=-{hours}h",
        '"Finished Backup of VM"',
        'name="(no guests reported)"',
        "where isnull(last_backup)",
    ):
        if fragment not in search:
            errors.append(f"FAIL: search is missing {fragment!r}")
    if "{{" in search or "}}" in search:
        errors.append("FAIL: search contains an unrendered placeholder")
    for name in ("postgres-apps", "openbao-21", "s3", "langfuse", "iac"):
        if name in DEFAULTS["splunk_docker_guest_backup_exempt_names"]:
            errors.append(f"FAIL: data guest {name!r} is exempt")
    if value("description") is None:
        errors.append("FAIL: alert has no description")
    if not (value("action.webhook.param.url") or "").startswith(NTFY):
        errors.append("FAIL: alert does not use the rendered notification destination")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: rendered guest backup freshness alert has its guest source, exemptions, window, sentinel and throttle")
