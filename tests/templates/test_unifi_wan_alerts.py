#!/usr/bin/env python3
"""
Guard the gateway WAN alerts (savedsearches/19-unifi-wan.j2):

1. unifi_wan_transition publishes to the hub's status topic (informational,
   not the alert channel), per result, for the Down / Restored / failover CEF
   signatures, and the webhook allowlist in alert_actions.conf admits that URL
   (Splunk drops a webhook to an unlisted URL without an error).
2. unifi_wan_down escalates through the shared keystone delivery and fires
   only on a WAN whose latest Down/Restored event is Down.
3. index_gap_exempt_report (informational daily report) also goes to the
   status topic, not keystone.

Run from repo root:
  python3 tests/templates/test_unifi_wan_alerts.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
NTFY = "https://ntfy.example.test/keystone"

env = ansible_env(ROOT / "roles/splunk_docker/templates")
env.filters["regex_escape"] = re.escape
env.filters["comment"] = lambda text: f"# {text}"
rendered = env.get_template("savedsearches.conf.j2").render(
    splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
    splunk_docker_silence_exemptions=DEFAULTS["splunk_docker_silence_exemptions"],
    splunk_docker_silence_lookback_multiplier=DEFAULTS["splunk_docker_silence_lookback_multiplier"],
    splunk_docker_indexes_core=DEFAULTS["splunk_docker_indexes_core"],
    splunk_docker_indexes_extra=DEFAULTS["splunk_docker_indexes_extra"],
    splunk_docker_alert_ntfy_url=NTFY,
    splunk_docker_alert_ntfy_query=DEFAULTS["splunk_docker_alert_ntfy_query"],
    splunk_docker_alert_slack_webhook=None,
)
actions = env.get_template("alert_actions.conf.j2").render(
    ansible_managed="test",
    splunk_docker_alert_ntfy_url=NTFY,
    splunk_docker_alert_slack_webhook=None,
)
stanzas = {
    m.group(1): m.group(2)
    for m in re.finditer(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
}
allowlist = re.findall(r"^allowlist\.\S+ = (.*)$", actions, re.M)


def value(body, key):
    m = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return m.group(1) if m else None


errors = []

t = stanzas.get("unifi_wan_transition")
if t is None:
    errors.append("FAIL: [unifi_wan_transition] not rendered")
else:
    url = value(t, "action.webhook.param.url") or ""
    if not url.startswith("https://ntfy.example.test/status?priority=default&tpl=yes&t="):
        errors.append(f"FAIL: transition delivery is not the status topic: {url[:80]}")
    if not any(re.match(p, url) for p in allowlist):
        errors.append("FAIL: the status topic URL is not admitted by the webhook allowlist")
    if value(t, "alert.digest_mode") != "0":
        errors.append("FAIL: transitions must notify per event (alert.digest_mode = 0)")
    search = value(t, "search") or ""
    if "cef_id IN (100, 101, 105, 106, 107)" not in search:
        errors.append("FAIL: transition search lost its CEF signature filter")
    # Index-time bounds only scope the base search; after a pipe they are
    # plain search terms that match nothing.
    base = search.split("|", 1)[0]
    if "_index_earliest=-3m@m" not in base or "_index_latest=-1m@m" not in base:
        errors.append("FAIL: transition index-time slice is not in the base search")

d = stanzas.get("unifi_wan_down")
if d is None:
    errors.append("FAIL: [unifi_wan_down] not rendered")
else:
    url = value(d, "action.webhook.param.url") or ""
    if not url.startswith(NTFY + "?priority=high"):
        errors.append(f"FAIL: WAN-down state does not escalate to keystone: {url[:80]}")
    search = value(d, "search") or ""
    if 'latest(cef_id) as state_id' not in search or 'where state_id="100"' not in search:
        errors.append("FAIL: WAN-down state is not the latest Down/Restored event per WAN")

x = stanzas.get("index_gap_exempt_report")
if x is None:
    errors.append("FAIL: [index_gap_exempt_report] not rendered")
else:
    url = value(x, "action.webhook.param.url") or ""
    if not url.startswith("https://ntfy.example.test/status?"):
        errors.append(f"FAIL: exempt report is not on the status topic: {url[:80]}")

# The keystone URL itself must still be admitted, and nothing else.
if not any(re.match(p, NTFY + "?priority=high") for p in allowlist):
    errors.append("FAIL: the keystone URL is no longer admitted by the allowlist")
if any(re.match(p, "https://ntfy.example.test/other?x=1") for p in allowlist):
    errors.append("FAIL: the allowlist admits an unrelated topic")

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print(
    "PASS: unifi_wan_transition and index_gap_exempt_report publish to the "
    "status topic (allowlisted), and unifi_wan_down escalates the down state to keystone"
)
print("\nAll tests passed.")
