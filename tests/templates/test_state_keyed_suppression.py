#!/usr/bin/env python3
"""
Guard state-keyed suppression on the hardware and quorum detectors
(savedsearches/09-hardware-detectors.j2, 14-openbao.j2):

1. hardware_smart_failure and hardware_zfs_fault match a failure phrase only
   from its owning program (indexed appname) or a non-syslog event, in the
   base search. A line that quotes an alert payload must not re-fire the
   detector that sent it.
2. hardware_smart_failure suppresses on failing_set, the sorted set of
   failing lines, so a standing state pages once per period and a change
   pages at once.
3. openbao_raft_quorum suppresses on quorum_state, so a standing voter
   deficit pages once per period and a change in the count pages at once.

Run from repo root:
  python3 tests/templates/test_state_keyed_suppression.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)

env = ansible_env(ROOT / "roles/splunk_docker/templates")
env.filters["regex_escape"] = re.escape
env.filters["comment"] = lambda text: f"# {text}"
rendered = env.get_template("savedsearches.conf.j2").render(
    splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
    splunk_docker_silence_exemptions=DEFAULTS["splunk_docker_silence_exemptions"],
    splunk_docker_silence_lookback_multiplier=DEFAULTS["splunk_docker_silence_lookback_multiplier"],
    splunk_docker_indexes_core=DEFAULTS["splunk_docker_indexes_core"],
    splunk_docker_indexes_extra=DEFAULTS["splunk_docker_indexes_extra"],
    splunk_docker_alert_ntfy_url="https://ntfy.example.test/keystone",
    splunk_docker_alert_ntfy_query=DEFAULTS["splunk_docker_alert_ntfy_query"],
    splunk_docker_alert_slack_webhook=None,
)
stanzas = {
    m.group(1): m.group(2)
    for m in re.finditer(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
}


def value(body, key):
    m = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return m.group(1) if m else None


EMITTER = "(NOT sourcetype=syslog OR appname::smartd OR appname::zed OR appname::kernel)"
errors = []

for name in ("hardware_smart_failure", "hardware_zfs_fault"):
    search = value(stanzas.get(name, ""), "search") or ""
    if EMITTER not in search.split("|")[0]:
        errors.append(f"FAIL: {name} base search lacks the emitter filter")

smart = stanzas.get("hardware_smart_failure", "")
if "eventstats values(signature) as failing_set" not in (value(smart, "search") or ""):
    errors.append("FAIL: hardware_smart_failure does not compute failing_set")
if value(smart, "alert.suppress.fields") != "failing_set":
    errors.append("FAIL: hardware_smart_failure does not suppress on failing_set")

quorum = stanzas.get("openbao_raft_quorum", "")
if "eval quorum_state = " not in (value(quorum, "search") or ""):
    errors.append("FAIL: openbao_raft_quorum does not compute quorum_state")
if value(quorum, "alert.suppress.fields") != "quorum_state":
    errors.append("FAIL: openbao_raft_quorum does not suppress on quorum_state")

if errors:
    for err in errors:
        print(err)
    sys.exit(1)

print("PASS: hardware detectors filter on the emitter; SMART and quorum alerts suppress on their state")
print("\nAll tests passed.")
