#!/usr/bin/env python3
"""
Guard the two-tier alert contract (splunk_docker_alert_two_tiers_enabled).

The tier is the severity each stanza already declares, never a name list:

1. Rendering with the switch off is byte-for-byte the pre-tier render (the
   template one commit back with the same values), so the switch is a true
   rollback.
2. Switch on: every stanza with severity >= splunk_docker_alert_page_min_severity
   keeps the keystone page (action.webhook = 1, priority=high) and its
   suppression period is at least 24 hours -- a critical alert pages at once
   and at most once per condition per day.
3. Switch on: every formerly-paging stanza whose severity is below the
   threshold loses ONLY its webhook action: the rest of the stanza is
   unchanged and it stays tracked (alert.track = 1), so each firing lands in
   index=_audit for the digest to count.
4. [alert_digest_12h] runs at cron 17 5,17 * * * (never on a quarter-hour
   minute), reads fired alerts from the audit index for the app, excludes
   exactly the paging stanzas, sends one digest_mode message over the status
   topic, and caps the listing at 40 lines.
5. The digest's schedule does not start on minute 0/15/30/45.

Run from repo root:
  python3 tests/templates/test_alert_two_tiers.py
"""

import io
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
TEMPLATES = ROOT / "roles/splunk_docker/templates"
DEFAULTS = load_defaults(ROOT)
NTFY = "https://ntfy.example.test/keystone"
PAGE_MIN = DEFAULTS["splunk_docker_alert_page_min_severity"]

STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)
BASE = {**DEFAULTS, "splunk_docker_alert_ntfy_url": NTFY}


def render(values):
    return ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(**values)


def stanzas(rendered):
    return {m.group(1): m.group(2) for m in STANZA_RE.finditer(rendered)}


def value(body, key):
    matches = re.findall(rf"^{re.escape(key)}\s*=\s*(.*)$", body, re.M)
    return matches[-1].strip() if matches else None


def seconds(period):
    match = re.fullmatch(r"(\d+)([smhd])", period or "")
    if not match:
        return None
    return int(match.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]


errors = []

# 1. Switch off: byte-for-byte the pre-tier render. The template one commit
# back predates the tiers, so rendering it with the same values (the switch
# kwarg is unknown to it and ignored) is the pre-tier document; the OFF path
# of the current template must never drift from it.
archive = subprocess.run(
    ["git", "archive", "HEAD~1", "roles/splunk_docker/templates"],
    cwd=ROOT, check=True, capture_output=True,
).stdout
with tempfile.TemporaryDirectory() as tmp:
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(tmp)
    old = ansible_env(Path(tmp) / "roles/splunk_docker/templates").get_template(
        "savedsearches.conf.j2"
    ).render(**{**BASE, "splunk_docker_alert_two_tiers_enabled": False})
off = render({**BASE, "splunk_docker_alert_two_tiers_enabled": False})
if old != off:
    errors.append("FAIL: the switch-off render is not byte-for-byte the pre-tier render")

off_stanzas = stanzas(off)
on = render(BASE)  # the role default enables the two tiers
on_stanzas = stanzas(on)

paged_off = {
    name
    for name, body in off_stanzas.items()
    if value(body, "action.webhook") == "1"
    and "priority=high" in (value(body, "action.webhook.param.url") or "")
}

# 2. Paging tier: severity >= threshold keeps the page with a >= 24h budget.
critical = set()
for name, body in on_stanzas.items():
    severity = value(body, "alert.severity")
    if severity is None:
        continue
    if int(severity) < PAGE_MIN:
        continue
    critical.add(name)
    if value(body, "action.webhook") != "1":
        errors.append(f"FAIL: [{name}] severity {severity} lost its page action")
        continue
    url = value(body, "action.webhook.param.url") or ""
    if not (url.startswith(NTFY) and "priority=high" in url):
        errors.append(f"FAIL: [{name}] no longer pages the keystone topic: {url[:80]}")
    period = seconds(value(body, "alert.suppress.period"))
    if period is None or period < 86400:
        errors.append(
            f"FAIL: [{name}] pages but its suppress period "
            f"{value(body, 'alert.suppress.period')!r} is below 24 hours"
        )

# 3. Non-paging tier: only the webhook action is removed; tracking stays on.
non_paging = set()
for name in sorted(paged_off - critical):
    body = on_stanzas.get(name)
    if body is None:
        errors.append(f"FAIL: [{name}] disappeared from the two-tier render")
        continue
    non_paging.add(name)
    if re.search(r"^action\.webhook", body, re.M):
        errors.append(f"FAIL: [{name}] is below severity {PAGE_MIN} but still carries a webhook action")
    if value(body, "alert.track") != "1":
        errors.append(f"FAIL: [{name}] lost alert.track = 1, so the digest cannot count its firings")
    stripped = "\n".join(
        line for line in off_stanzas[name].splitlines() if not line.startswith("action.webhook")
    ).strip("\n")
    if stripped != body.strip("\n"):
        errors.append(f"FAIL: [{name}] changed beyond the removed webhook action")
if not non_paging:
    errors.append(f"FAIL: no non-critical stanza was demoted; expected the severity < {PAGE_MIN} pagers")
if len(critical) != len(paged_off) - len(non_paging):
    errors.append("FAIL: the paging set in the two-tier render does not match the severity threshold")

# 4. The digest: schedule, audit source, exclusion set, one-message delivery.
digest = on_stanzas.get("alert_digest_12h")
if digest is None:
    errors.append("FAIL: [alert_digest_12h] is not rendered")
else:
    cron = value(digest, "cron_schedule")
    if cron != "17 5,17 * * *":
        errors.append(f"FAIL: [alert_digest_12h] cron is {cron!r}, want '17 5,17 * * *'")
    elif int(cron.split()[0]) in (0, 15, 30, 45):
        errors.append("FAIL: [alert_digest_12h] schedule starts on a quarter-hour minute")
    url = value(digest, "action.webhook.param.url") or ""
    if not (url.startswith(NTFY.rsplit("/", 1)[0] + "/status") and "priority=default" in url):
        errors.append(f"FAIL: [alert_digest_12h] does not use the status delivery: {url[:80]}")
    if value(digest, "alert.digest_mode") != "1":
        errors.append("FAIL: [alert_digest_12h] must send all result rows in one message (digest_mode = 1)")
    if value(digest, "dispatch.earliest_time") != "-12h":
        errors.append("FAIL: [alert_digest_12h] must read the last 12 hours of fired alerts")
    search = value(digest, "search") or ""
    if "index=_audit action=alert_fired ss_app=homelab_alerts" not in search:
        errors.append("FAIL: [alert_digest_12h] does not read fired alerts from the audit index")
    excluded = set(re.findall(r'ss_name!="([^"]+)"', search))
    if excluded != critical:
        missing = critical - excluded
        stale = excluded - critical
        errors.append(
            f"FAIL: [alert_digest_12h] exclusion set drifts from the paging stanzas "
            f"(missing {sorted(missing)}, stale {sorted(stale)})"
        )
    for fragment in ("stats count as fires by ss_name", "sort -fires", "head 40"):
        if fragment not in search:
            errors.append(f"FAIL: [alert_digest_12h] search lost {fragment!r}")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print(
    f"PASS: switch-off render is byte-identical; {len(critical)} stanzas page with a >= 24h "
    f"budget, {len(non_paging)} pagers below severity {PAGE_MIN} now only trigger and stay "
    f"tracked, and [alert_digest_12h] reports them every 12 hours on the status topic"
)
print("\nAll tests passed.")
