#!/usr/bin/env python3
"""
Guard the delivery overlay for the packaged splunk-homelab-alerts app.

The app ships default/savedsearches.conf with a [default] stanza that turns
action.zammad on for all of its detectors. No Zammad alert action is
configured on this instance -- Zammad and Slack are reached only through the
ntfy hub webhook -- so as shipped those detectors deliver nowhere. The role
renders a same-app local/savedsearches.conf that switches the [default]
delivery to the hub webhook and, for the app's own scheduled reports (the
stanzas whose body sets action.zammad = 0), turns the inherited webhook back
off -- a report with no alert condition would otherwise post to the hub on
every scheduled run. The report list is parsed from the INSTALLED file at
converge time, so this test runs the same parse over a fixture that copies
the app's file shape. It also pins the task order in main.yml, because
apps.yml deletes the whole app directory on every version upgrade: an
overlay rendered before "Install apps and add-ons" would be wiped in the
same run that wrote it.

Run from repo root:
  python3 tests/templates/test_homelab_alerts_hub_delivery.py
"""

import re
import sys
from pathlib import Path

import yaml

from _defaults_loader import load_defaults
from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
TEMPLATES = ROOT / "roles/splunk_docker/templates"
# The overlay tasks are factored into their own include file to keep main.yml
# under its token limit; main.yml includes it right after the app install.
OVERLAY_TASKS = ROOT / "roles/splunk_docker/tasks/homelab_alerts_hub_delivery.yml"
TEMPLATE_FILE = "homelab_alerts_app_delivery.conf.j2"
OVERLAY_DEST_SUFFIX = "apps/splunk-homelab-alerts/local/savedsearches.conf"
NTFY = "https://ntfy.example.test/keystone"

# The overlay parses the installed app config with Ansible's regex filters;
# register Python-re equivalents so the bare-Jinja test environment renders
# the template with the same expressions Ansible will run.
env = ansible_env(TEMPLATES)
env.filters["regex_findall"] = lambda value, pattern: re.findall(pattern, value)
env.filters["regex_search"] = lambda value, pattern: re.search(pattern, value)

DEFAULTS = load_defaults(ROOT)
QUERY = DEFAULTS["splunk_docker_alert_ntfy_query"]

# Shaped like the app's default/savedsearches.conf: a [default] stanza
# enabling Zammad for everything, one detector inheriting it, and one
# scheduled report opting out with an explicit action.zammad = 0.
FIXTURE_APP_CONF = (
    "# Delivery defaults for every saved search in THIS app.\n"
    "#\n"
    "[default]\n"
    "enableSched = 1\n"
    "alert.track = 1\n"
    "action.zammad = 1\n"
    "action.zammad.param.group = Homelab Infrastructure\n"
    "action.zammad.param.correlation_key = $name$\n"
    "\n"
    "[HomelabAlert - hermes errors]\n"
    "search = index=hermes ...\n"
    "disabled = 0\n"
    "\n"
    "[hermes_cron_delivered_run_rate]\n"
    "action.zammad = 0\n"
    "cron_schedule = 5 * * * *\n"
    "disabled = 0\n"
)

errors = []


def render(url):
    return env.get_template(TEMPLATE_FILE).render(
        splunk_docker_homelab_alerts_app_conf=FIXTURE_APP_CONF,
        splunk_docker_alert_ntfy_url=url,
        splunk_docker_alert_ntfy_query=QUERY,
    )


def stanza_body(text, name):
    found = re.search(rf"^\[{re.escape(name)}\]$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    return found.group(1) if found else None


def value(body, key):
    found = re.search(rf"^{re.escape(key)} = (.*)$", body or "", re.M)
    return found.group(1) if found else None


rendered = render(NTFY)
default_body = stanza_body(rendered, "default")

# The packaged detectors must stop pointing at a Zammad action this
# instance never configured, and start delivering to the hub instead.
if value(default_body, "action.zammad") != "0":
    errors.append(f"FAIL: [default] must disable the packaged Zammad action (got {value(default_body, 'action.zammad')!r})")
if value(default_body, "action.webhook") != "1":
    errors.append(f"FAIL: [default] must enable the hub webhook (got {value(default_body, 'action.webhook')!r})")
if value(default_body, "action.webhook.param.url") != NTFY + QUERY:
    errors.append(
        "FAIL: [default] hub URL must be splunk_docker_alert_ntfy_url + "
        f"splunk_docker_alert_ntfy_query (got {value(default_body, 'action.webhook.param.url')!r})"
    )

# The scheduled report opted out of Zammad explicitly; it must not inherit
# the webhook from [default] either. The detector that never opted out gets
# no per-stanza entry at all.
report_body = stanza_body(rendered, "hermes_cron_delivered_run_rate")
if report_body is None:
    errors.append("FAIL: the fixture's action.zammad = 0 report got no overlay stanza")
elif value(report_body, "action.webhook") != "0":
    errors.append(f"FAIL: the report must disable the webhook (got {value(report_body, 'action.webhook')!r})")
if stanza_body(rendered, "HomelabAlert - hermes errors") is not None:
    errors.append("FAIL: a detector without action.zammad = 0 got a per-stanza overlay entry")

# The hub fanout replaces Zammad entirely: no direct-Zammad URL key, and no
# token anywhere in the rendered file.
if "action.zammad.param.url" in rendered:
    errors.append("FAIL: overlay renders action.zammad.param.url -- Splunk must post only to the hub")
if "token" in rendered.lower():
    errors.append("FAIL: overlay renders a token; delivery carries only the allowlisted hub URL")

# Empty URL renders no webhook at all, matching the savedsearches.conf.j2
# guard (assert_alerting_gates.yml makes the empty case unreachable in a
# real converge, but the overlay must not half-render one).
empty = render("")
if value(stanza_body(empty, "default"), "action.webhook") is not None:
    errors.append("FAIL: empty splunk_docker_alert_ntfy_url still renders webhook delivery in [default]")
if "action.webhook.param.url" in empty:
    errors.append("FAIL: empty splunk_docker_alert_ntfy_url still renders a webhook URL")
if value(stanza_body(empty, "default"), "action.zammad") != "0":
    errors.append("FAIL: empty-URL render lost the Zammad opt-out")

# The overlay must be rendered after the app install include, or the
# version-aware upgrade deletes it in the same run that wrote it.
main_tasks = yaml.safe_load((ROOT / "roles/splunk_docker/tasks/main.yml").read_text())
main_names = [t["name"] for t in main_tasks]
if "Install apps and add-ons" not in main_names:
    errors.append("FAIL: tasks/main.yml lost the 'Install apps and add-ons' task")
overlay_include = next(
    (
        t
        for t in main_tasks
        if isinstance(t.get("ansible.builtin.include_tasks"), str)
        and t["ansible.builtin.include_tasks"].endswith("homelab_alerts_hub_delivery.yml")
    ),
    None,
)
if overlay_include is None:
    errors.append("FAIL: tasks/main.yml lost the homelab_alerts_hub_delivery.yml include")
elif main_names.index(overlay_include["name"]) < main_names.index("Install apps and add-ons"):
    errors.append("FAIL: the overlay renders before 'Install apps and add-ons', whose upgrade wipes it")

tasks = yaml.safe_load(OVERLAY_TASKS.read_text())
names = [t["name"] for t in tasks]
for task in ("Read the installed splunk-homelab-alerts savedsearches.conf", "Deliver splunk-homelab-alerts detectors through the hub webhook"):
    if task not in names:
        errors.append(f"FAIL: tasks/homelab_alerts_hub_delivery.yml lost the {task!r} task")

by_name = {t["name"]: t for t in tasks}
slurp = by_name.get("Read the installed splunk-homelab-alerts savedsearches.conf")
if not slurp or "default/savedsearches.conf" not in slurp.get("ansible.builtin.slurp", {}).get("src", ""):
    errors.append("FAIL: the overlay does not read the installed app's savedsearches.conf")

overlay = by_name.get("Deliver splunk-homelab-alerts detectors through the hub webhook")
template_task = (overlay or {}).get("ansible.builtin.template", {})
if template_task.get("src") != TEMPLATE_FILE:
    errors.append(f"FAIL: the overlay task does not render {TEMPLATE_FILE}")
if not (TEMPLATES / TEMPLATE_FILE).exists():
    errors.append(f"FAIL: {TEMPLATE_FILE} does not exist")
if not template_task.get("dest", "").endswith(OVERLAY_DEST_SUFFIX):
    errors.append(f"FAIL: the overlay is not rendered to {OVERLAY_DEST_SUFFIX}")
if template_task.get("mode") != "0644":
    errors.append("FAIL: the overlay file mode is not 0644")
if "Restart Splunk container" not in (overlay or {}).get("notify", []):
    errors.append("FAIL: the overlay task does not notify Restart Splunk container")
if "alerting" not in (overlay or {}).get("tags", []):
    errors.append("FAIL: the overlay task is not tagged alerting")

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print("PASS: splunk-homelab-alerts [default] delivers to the hub webhook with the packaged "
      "Zammad action off, scheduled reports opt out per stanza, the empty-URL guard holds, "
      "and the overlay renders after the app install")
print("\nAll tests passed.")
