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
        "alert.digest_mode": "1",
        "alert.suppress": "1",
        "alert.suppress.period": "24h",
        "alert.suppress.fields": "condition",
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
        'name="(no guests to check)"',
        "where isnull(last_backup)",
    ):
        if fragment not in search:
            errors.append(f"FAIL: search is missing {fragment!r}")
    # One digest row for the whole condition: a constant condition field
    # separates the sentinel from the missing-backup list in the throttle,
    # the guest list is one sorted comma-separated field capped at 50
    # entries, and the total count stays on the row.
    digest_fragments = (
        'eval condition=if(name="(no guests to check)", "no_guests_to_check", "missing_backup")',
        'eval guest=if(condition="missing_backup", name . " (" . vmid . ")", name)',
        "stats count as missing_guests, values(guest) as guests by condition",
        'mvjoin(mvsort(mvindex(guests, 0, 49)), ",")',
        'guests . " (+ " . (missing_guests - 50) . " more)"',
        "table condition missing_guests guests",
    )
    for fragment in digest_fragments:
        if fragment not in search:
            errors.append(f"FAIL: search is missing {fragment!r}")
    if "table node vmid name" in search:
        errors.append("FAIL: search still emits one row per guest instead of one digest row")
    if "{{" in search or "}}" in search:
        errors.append("FAIL: search contains an unrendered placeholder")
    for name in ("postgres-apps", "openbao-21", "s3", "langfuse", "iac"):
        if name in DEFAULTS["splunk_docker_guest_backup_exempt_names"]:
            errors.append(f"FAIL: data guest {name!r} is exempt")
    if value("description") is None:
        errors.append("FAIL: alert has no description")
    if not (value("action.webhook.param.url") or "").startswith(NTFY):
        errors.append("FAIL: alert does not use the rendered notification destination")

    # Exempt names render verbatim in SPL quotes; only backslash and quote are escaped.
    odd_names = ["a<b&c'd", 'q"r', "x\\y"]
    odd = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(
        **{**render_values, "splunk_docker_guest_backup_exempt_names": odd_names}
    )
    odd_expected = 'search NOT name IN ("a<b&c\'d","q\\"r","x\\\\y")'
    if odd_expected not in odd:
        errors.append(f"FAIL: exempt names with special characters not rendered as {odd_expected!r}")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: rendered guest backup freshness alert has its guest source, exemptions, window, sentinel and one digest notification per 24 hours keyed on condition")
