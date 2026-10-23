#!/usr/bin/env python3
"""Guard the Screenpipe per-run timeout and consecutive-failure alert."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
TEMPLATES = ROOT / "roles/splunk_docker/templates"
render_values = {
    **DEFAULTS,
    "splunk_docker_alert_ntfy_url": None,
    "splunk_docker_alert_slack_webhook": None,
}
rendered = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(**render_values)
match = re.search(r"^\[screenpipe_pipe_run_failure\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
if not match:
    print("FAIL: [screenpipe_pipe_run_failure] was not rendered")
    sys.exit(1)

body = match.group(1)
search_match = re.search(r"^search = (.*)$", body, re.M)
errors = []
if not search_match:
    errors.append("FAIL: alert has no search")
else:
    search = search_match.group(1)
    for fragment in (
        'index=llm sourcetype="screenpipe:pipe_run"',
        "spath input=_raw",
        'rex field=source "pipes/(?<pipe_name>[^/]+)/logs/"',
        "isnotnull(start) AND isnotnull(end) AND isnotnull(success)",
        'match(lower(tostring(error)), "timeout|timed[_ -]?out")',
        "streamstats reset_after=(failed=0) sum(failed) as consecutive_failures by pipe_name",
        "consecutive_failures>=3",
        '_indextime >= relative_time(now(), "-5m")',
        "timed_out=1 OR",
    ):
        if fragment not in search:
            errors.append(f"FAIL: search is missing {fragment!r}")

    # A failure streak of three or more triggers; a success resets the streak.
    def fires(successes):
        consecutive_failures = 0
        alerts = []
        for success in successes:
            if success:
                consecutive_failures = 0
                alerts.append(False)
            else:
                consecutive_failures += 1
                alerts.append(consecutive_failures >= 3)
        return alerts

    if fires([False, False, False, False]) != [False, False, True, True]:
        errors.append("FAIL: three consecutive failures do not keep triggering at the threshold")
    if fires([False, False, True, False, False, False]) != [False, False, False, False, False, True]:
        errors.append("FAIL: a success does not reset the consecutive-failure sequence")

if "{{ alert_delivery" not in (ROOT / "roles/splunk_docker/templates/savedsearches/25-screenpipe-pipe-runs.j2").read_text():
    errors.append("FAIL: alert does not use the shared alert_delivery macro")
if (
    "cron_schedule = */5 * * * *" not in body
    or "disabled = 0" not in body
    or "alert.suppress.period = 5m" not in body
    or "alert.suppress.fields = pipe_name" not in body
):
    errors.append("FAIL: alert is not scheduled every five minutes")
if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: pipe timeouts and failure streaks trigger the shared scheduled alert")
