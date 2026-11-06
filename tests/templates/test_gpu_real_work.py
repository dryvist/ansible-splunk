#!/usr/bin/env python3
"""Guard the rendered daily and weekly LiteLLM GPU usage reports."""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)
NTFY = "https://ntfy.example.test/keystone"
ENV = ansible_env(ROOT / "roles/splunk_docker/templates")
ENV.filters["regex_escape"] = re.escape
ENV.filters["comment"] = lambda text: f"# {text}"
VALUES = {
    **DEFAULTS,
    "splunk_docker_alert_ntfy_url": NTFY,
    "splunk_docker_alert_ntfy_query": DEFAULTS["splunk_docker_alert_ntfy_query"],
}
STANZA_RE = re.compile(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", re.M | re.S)
stanzas = {
    match.group(1): match.group(2)
    for match in STANZA_RE.finditer(ENV.get_template("savedsearches.conf.j2").render(**VALUES))
}
errors = []


def value(body, key):
    match = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return match.group(1) if match else None


search_fragments = (
    'index=llm sourcetype="litellm:proxy"',
    r'rex field=_raw "litellm\[\d+\]: (?<j>\{.*)"',
    "spath input=j",
    'fillnull value="unattributed" key_alias api_base',
    "fillnull value=0 completion_tokens prompt_tokens",
    'match(api_base, "(?i)blackwell"), "RTX 6000"',
    'match(api_base, "(?i)ada-lovelace"), "RTX 4080"',
    'match(api_base, "(?i)mac"), "Mac Studio"',
    "stats count as requests sum(completion_tokens) as generated_tokens sum(prompt_tokens) as prompt_tokens by accelerator key_alias",
    'eval report_row="No requests in report window"',
    'eval report="accelerator | caller | requests | generated tokens | prompt tokens; "',
    "stats values(report_row) as report_rows",
    "| table report",
)
expected = {
    "gpu_real_work_daily": {
        "dispatch.earliest_time": "-1d@d",
        "dispatch.latest_time": "@d",
        "cron_schedule": "19 6 * * *",
        "alert.suppress.period": "24h",
    },
    "gpu_real_work_weekly": {
        "dispatch.earliest_time": "-7d@d",
        "dispatch.latest_time": "@d",
        "cron_schedule": "39 6 * * 1",
        "alert.suppress.period": "7d",
    },
}

for name, settings in expected.items():
    body = stanzas.get(name)
    if body is None:
        errors.append(f"FAIL: [{name}] was not rendered")
        continue
    for key, wanted in {
        **settings,
        "enableSched": "1",
        "disabled": "0",
        "alert.suppress": "1",
        "alert.track": "1",
        "counttype": "number of events",
        "relation": "greater than",
        "quantity": "0",
    }.items():
        if value(body, key) != wanted:
            errors.append(f"FAIL: [{name}] {key} expected {wanted!r}, got {value(body, key)!r}")
    search = value(body, "search") or ""
    for fragment in search_fragments:
        if fragment not in search:
            errors.append(f"FAIL: [{name}] search is missing {fragment!r}")
    if value(body, "action.webhook") != "1":
        errors.append(f"FAIL: [{name}] has no webhook delivery")
    report_url = value(body, "action.webhook.param.url") or ""
    expected_url = NTFY.rsplit("/", 1)[0] + "/reports" + DEFAULTS[
        "splunk_docker_alert_ntfy_query"
    ].replace("priority=high", "priority=default")
    if report_url != expected_url:
        errors.append(f"FAIL: [{name}] is not delivered to the reports topic")

actions = ENV.get_template("alert_actions.conf.j2").render(
    ansible_managed="test",
    **VALUES,
)
allowlist = re.search(r"^allowlist\.ntfy_reports = (.*)$", actions, re.M)
reports_url = NTFY.rsplit("/", 1)[0] + "/reports?priority=default"
if allowlist is None or re.match(allowlist.group(1), reports_url) is None:
    errors.append("FAIL: reports topic URL is not admitted by the webhook allowlist")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: daily and weekly GPU reports render the attribution fields, schedules, aggregation and reports-topic delivery")
