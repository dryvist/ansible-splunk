#!/usr/bin/env python3
"""
Guard OpenBao privileged-use paging, its daily digest, and the in-window RBAC write detector.

Audit _time is the record's own time, so a replayed backlog lands hours in
the past. Both privileged-use stanzas classify on index time: the base
search is bounded by _index_earliest/_index_latest (classify once, on
arrival) with an earliest_time wide enough to reach those late records.

Privileged use inside the open admin window by the window's own identity
(AppRole ai-admin-session) is routine and must not page. openbao_privileged_use
keeps only privileged use under any other identity, throttled by caller and
policies for 24h (one page per identity and policy set per day), and
openbao_window_privileged_use_digest records the in-window events once a day
on the status topic. openbao_window_rbac_write separately pages on in-window
policy and AppRole role writes, throttled once per path per hour. The existing
paging and digest stanzas render one shared selection pipeline, so their
coverage can neither overlap nor skip an event.

Run from repo root:
  python3 tests/templates/test_openbao_privileged_use.py
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
DEFAULTS = load_defaults(ROOT)

render_values = {
    "splunk_docker_ansible_converge_host_count": DEFAULTS["splunk_docker_ansible_converge_host_count"],
    "splunk_docker_silence_detectors": DEFAULTS["splunk_docker_silence_detectors"],
    "splunk_docker_silence_lookback_multiplier": DEFAULTS["splunk_docker_silence_lookback_multiplier"],
    "splunk_docker_llm_freshness_indexes": DEFAULTS["splunk_docker_llm_freshness_indexes"],
    "splunk_docker_indexes_core": DEFAULTS["splunk_docker_indexes_core"],
    "splunk_docker_indexes_extra": DEFAULTS["splunk_docker_indexes_extra"],
    "splunk_docker_openbao_raft_expected_voters": DEFAULTS["splunk_docker_openbao_raft_expected_voters"],
    "splunk_docker_openbao_latency_tail_multiplier": DEFAULTS["splunk_docker_openbao_latency_tail_multiplier"],
    "splunk_docker_openbao_latency_tail_floor_ms": DEFAULTS["splunk_docker_openbao_latency_tail_floor_ms"],
    "splunk_docker_openbao_latency_tail_min_minutes": DEFAULTS["splunk_docker_openbao_latency_tail_min_minutes"],
    "splunk_docker_openbao_raft_commit_sustained_ms": DEFAULTS["splunk_docker_openbao_raft_commit_sustained_ms"],
    "splunk_docker_openbao_raft_commit_spike_ms": DEFAULTS["splunk_docker_openbao_raft_commit_spike_ms"],
    "splunk_docker_openbao_follower_heartbeat_ms": DEFAULTS["splunk_docker_openbao_follower_heartbeat_ms"],
    "splunk_docker_openbao_leader_io_wait_s": DEFAULTS["splunk_docker_openbao_leader_io_wait_s"],
    "splunk_docker_openbao_voter_io_wait_s": DEFAULTS["splunk_docker_openbao_voter_io_wait_s"],
    "splunk_docker_alert_ntfy_url": None,
}
rendered = ansible_env(ROOT / "roles/splunk_docker/templates").get_template(
    "savedsearches.conf.j2"
).render(**render_values)

WINDOW_ROLE = "ai-admin-session"
SELECTED_CLAUSE = f"| where 'auth.metadata.role_name'=\"{WINDOW_ROLE}\""
EXCLUDED_CLAUSE = f"| where NOT ('auth.metadata.role_name'=\"{WINDOW_ROLE}\")"

m = re.search(r"^\[openbao_privileged_use\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
dm = re.search(r"^\[openbao_window_privileged_use_digest\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)
wm = re.search(r"^\[openbao_window_rbac_write\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)

errors = []
if not m:
    print("FAIL: [openbao_privileged_use] not found in rendered output")
    sys.exit(1)
if not dm:
    errors.append("FAIL: [openbao_window_privileged_use_digest] not found in rendered output")
if not wm:
    errors.append("FAIL: [openbao_window_rbac_write] not found in rendered output")

stanza = m.group(1)
write_stanza = wm.group(1) if wm else ""


def setting(body, key):
    found = re.search(rf"^{re.escape(key)} = (.*)$", body, re.M)
    return found.group(1) if found else None


def action_settings(body):
    return {
        key: value
        for line in body.splitlines()
        if " = " in line
        for key, value in (line.split(" = ", 1),)
        if key.startswith("action.")
    }


def shared_pipeline(search_text):
    """The selection pipeline both stanzas render: everything between the
    base search's index-time bound and the stanza's own window branch."""
    _, _, tail = search_text.partition("_index_latest=now ")
    return tail.split(EXCLUDED_CLAUSE, 1)[0].split(SELECTED_CLAUSE, 1)[0]


def search_text(body):
    found = re.search(r"^search = (.*)$", body, re.M)
    return found.group(1) if found else ""


search = search_text(stanza)
full_search = search
base = search.split("|", 1)[0] if search else ""
earliest = re.search(r"^dispatch\.earliest_time = -(\d+)h$", stanza, re.M)

if "_index_earliest=-6m" not in base or "_index_latest=now" not in base:
    errors.append("FAIL: base search is not bounded by _index_earliest=-6m/_index_latest=now")
if not earliest or int(earliest.group(1)) < 24:
    errors.append("FAIL: dispatch.earliest_time must reach at least -24h of record time")

privileged_predicates = (
    "'auth.metadata.role_name'=\"github-admin-claude\"",
    'token_type="root"',
    'like(policies, "%root%")',
    'like(policies, "%ai-admin%")',
    'like(\'request.path\', "sys/generate-root%")',
    'like(\'request.path\', "sys/rekey%")',
    'like(\'request.path\', "sys/policies/%")',
    'like(\'request.path\', "sys/audit%")',
    'like(\'request.path\', "sys/mounts%")',
    'like(\'request.path\', "sys/auth%")',
    'like(\'request.path\', "auth/approle/role/%")',
    "'request.operation'=\"create\"",
    "'request.operation'=\"update\"",
    "'request.operation'=\"delete\"",
    'in(caller, "approle-issuer", "approle-secret-id-rotate", "approle-secret-id-rotate-scheduled", "secret-age-audit", "splunk-mcp-rotate", "ai-rotate", "apps-rotate", "rustfs-rotate")',
)
pipeline = shared_pipeline(search)
for predicate in privileged_predicates:
    if predicate not in pipeline:
        errors.append(f"FAIL: privileged-use selection lost predicate {predicate}")

reason_case = re.search(r'eval reason=case\((.*true\(\), "privileged path access"\))', pipeline)
if not reason_case:
    errors.append("FAIL: reason classification is missing from the shared selection pipeline")
else:
    reason = reason_case.group(1)
    ordered_reasons = (
        'token_type="root"',
        'like(policies, "%root%")',
        'like(policies, "%ai-admin%")',
        'like(\'request.path\', "sys/generate-root%")',
        'like(\'request.path\', "sys/rekey%")',
        'like(\'request.path\', "auth/approle/role/%")',
        '"sensitive management operation"',
        'role_name\'="github-admin-claude"',
    )
    positions = [reason.find(marker) for marker in ordered_reasons]
    if any(position < 0 for position in positions):
        errors.append("FAIL: root, sensitive-operation, or role reason is missing")
    elif positions != sorted(positions):
        errors.append("FAIL: generic github-admin-claude reason masks a specific privileged reason")

# The paging stanza drops in-window use AFTER the privileged selection and
# BEFORE the table: nothing in-window reaches its results, so nothing
# in-window reaches its Slack action.
if EXCLUDED_CLAUSE not in search:
    errors.append("FAIL: paging search does not exclude in-window privileged use")
elif f"'auth.metadata.role_name'!=\"{WINDOW_ROLE}\"" in search:
    errors.append(
        "FAIL: paging search excludes with field!=\"value\", which Splunk reads as "
        "null != value and silently drops privileged use by identities with no role_name"
    )
else:
    if not search.index(EXCLUDED_CLAUSE) > search.index("spath input=j"):
        errors.append("FAIL: in-window exclusion runs before the privileged selection")
    if not search.index(EXCLUDED_CLAUSE) < search.index("| table"):
        errors.append("FAIL: in-window exclusion runs after the alert result table")

table_fields = full_search.rsplit("| table ", 1)[-1].split()
for field in ("caller", "policies"):
    if field not in table_fields:
        errors.append(f"FAIL: suppression key {field} is not kept in the alert's result table")

period = re.fullmatch(r"24h", setting(stanza, "alert.suppress.period") or "")
if setting(stanza, "alert.suppress") != "1" or not period:
    errors.append("FAIL: paging alert suppression must be exactly 24h")
if setting(stanza, "alert.suppress.fields") != "caller,policies":
    errors.append("FAIL: paging alert does not throttle by caller and policies")
if setting(stanza, "alert.digest_mode") is not None:
    errors.append("FAIL: paging alert digest mode changed without verified delivery semantics")


def alerts(rows, fields, seen):
    """Splunk field suppression: a row alerts only if its key is unseen."""
    fired = 0
    for row in rows:
        key = tuple(row.get(f) for f in fields)
        if key not in seen:
            seen.add(key)
            fired += 1
    return fired


fields = (setting(stanza, "alert.suppress.fields") or "").split(",")
seen = set()
first = alerts([{"caller": "deploy", "policies": "ai-admin"}], fields, seen)
replayed = alerts([{"caller": "deploy", "policies": "ai-admin"}], fields, seen)
new_identity = alerts([{"caller": "breakglass", "policies": "ai-admin"}], fields, seen)
new_policy = alerts([{"caller": "deploy", "policies": "root"}], fields, seen)
if (first, replayed, new_identity, new_policy) != (1, 0, 1, 1):
    errors.append(
        f"FAIL: suppression on {fields} gave first/replayed/new-identity/new-policy="
        f"{first}/{replayed}/{new_identity}/{new_policy}, want 1/0/1/1"
    )


def rows_surviving_window_filter(rows, search_text):
    """Apply the stanza's window filter to rows that already passed the
    privileged selection. Splunk's NOT(field="value") keeps a row whose field
    is null, unlike field!="value"."""
    found = re.search(
        r"\| where NOT \('auth\.metadata\.role_name'=\"" + re.escape(WINDOW_ROLE) + r"\"\)",
        search_text,
    )
    if not found:
        return None
    return [row for row in rows if row.get("role_name") != WINDOW_ROLE]


privileged_rows = [
    {"role_name": WINDOW_ROLE},
    {"role_name": None},
    {"role_name": "github-admin-claude"},
]
survivors = rows_surviving_window_filter(privileged_rows, search)
if survivors is None:
    errors.append("FAIL: paging search carries no in-window exclusion to simulate")
elif [row.get("role_name") for row in survivors] != [None, "github-admin-claude"]:
    errors.append(
        "FAIL: in-window rows survived to the paging alert, or a null role_name "
        f"was dropped: {[row.get('role_name') for row in survivors]}"
    )

# The digest is the complement: same selection pipeline, the in-window branch,
# one deduplicated line per event, delivered off the paging path.
if dm:
    digest_body = dm.group(1)
    digest_search = search_text(digest_body)
    digest_base = digest_search.split("|", 1)[0] if digest_search else ""
    digest_earliest = re.search(r"^dispatch\.earliest_time = -(\d+)h$", digest_body, re.M)
    if "_index_earliest=-24h" not in digest_base or "_index_latest=now" not in digest_base:
        errors.append("FAIL: digest base search is not bounded by _index_earliest=-24h/_index_latest=now")
    if not digest_earliest or int(digest_earliest.group(1)) < 24:
        errors.append("FAIL: digest dispatch.earliest_time must reach at least -24h of record time")
    if SELECTED_CLAUSE not in digest_search:
        errors.append("FAIL: digest search does not select in-window privileged use")
    elif digest_search.index(SELECTED_CLAUSE) < digest_search.index("spath input=j"):
        errors.append("FAIL: digest in-window selection runs before the privileged selection")
    if shared_pipeline(digest_search) != pipeline:
        errors.append("FAIL: digest selection pipeline drifted from the paging alert's")
    if "| eval request_id='request.id' | dedup request_id" not in digest_search:
        errors.append("FAIL: digest does not dedup replayed copies on the record's request id")
    for fragment in (
        "eventstats values(caller) as callers",
        "paths=mvjoin(mvsort(paths), \",\")",
    ):
        if fragment not in digest_search:
            errors.append(f"FAIL: digest does not aggregate its per-row list ({fragment})")
    for key, want in (
        ("alert.digest_mode", "1"),
        ("alert.suppress", "1"),
        ("alert.suppress.period", "24h"),
        ("alert.track", "0"),
    ):
        if setting(digest_body, key) != want:
            errors.append(f"FAIL: digest {key} is {setting(digest_body, key)!r}, want {want!r}")
    if setting(digest_body, "alert.suppress.fields") is not None:
        errors.append("FAIL: digest sets alert.suppress.fields and splits the daily list")

# The in-window write alert is deliberately narrower than the shared
# privileged-use pipeline: only the admin-window identity's writes to the two
# protected path families are selected.
write_search = search_text(write_stanza)
write_base = write_search.split("|", 1)[0] if write_search else ""
write_earliest = re.search(r"^dispatch\.earliest_time = -48h$", write_stanza, re.M)
expected_write_filter = (
    "| where 'auth.metadata.role_name'=\"ai-admin-session\" AND "
    "in('request.operation', \"create\", \"update\", \"delete\") AND "
    "(like('request.path', \"sys/policies/%\") OR "
    "like('request.path', \"auth/approle/role/%\"))"
)
write_filters = [f.strip() for f in re.findall(r"\| where [^|]+", write_search)]
if "_index_earliest=-6m" not in write_base or "_index_latest=now" not in write_base:
    errors.append("FAIL: RBAC write search does not use paging's index-time window")
if not write_earliest:
    errors.append("FAIL: RBAC write dispatch.earliest_time is not -48h")
if "| rex \"openbao-audit: (?<j>\\{.*)\"" not in write_search or "| spath input=j" not in write_search:
    errors.append("FAIL: RBAC write search does not use the established rex + spath extraction")
if write_filters != [expected_write_filter]:
    errors.append("FAIL: RBAC write search must filter only the window role, three write operations, and two protected path prefixes")
if setting(write_stanza, "cron_schedule") != "*/5 * * * *":
    errors.append("FAIL: RBAC write detector is not scheduled every five minutes")
if setting(write_stanza, "alert.suppress") != "1":
    errors.append("FAIL: RBAC write alert suppression is not enabled")
if setting(write_stanza, "alert.digest_mode") != "0":
    errors.append("FAIL: RBAC write alert is not per-result, so per-path suppression would not apply")
if setting(write_stanza, "alert.suppress.period") != "1h":
    errors.append("FAIL: RBAC write alert suppression is not one hour")
if setting(write_stanza, "alert.suppress.fields") != "request.path":
    errors.append("FAIL: RBAC write alert suppression is not keyed only by request.path")
write_table_fields = write_search.rsplit("| table ", 1)[-1].split()
if "request.path" not in write_table_fields:
    errors.append("FAIL: RBAC write result table drops the request.path suppression key")

# The digest must not ride the paging delivery: render with a hub URL and
# check the paging stanza keeps the alert topic while the digest lands on the
# status topic.
delivered = ansible_env(ROOT / "roles/splunk_docker/templates").get_template(
    "savedsearches.conf.j2"
).render(
    **{
        **render_values,
        "splunk_docker_alert_ntfy_url": "https://ntfy.example.test/keystone",
        "splunk_docker_alert_ntfy_query": DEFAULTS["splunk_docker_alert_ntfy_query"],
    },
)
delivered_stanzas = {
    name: body
    for name, body in (
        (mm.group(1), mm.group(2))
        for mm in re.finditer(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", delivered, re.M | re.S)
    )
}
paging_url = setting(delivered_stanzas.get("openbao_privileged_use", ""), "action.webhook.param.url") or ""
digest_url = setting(delivered_stanzas.get("openbao_window_privileged_use_digest", ""), "action.webhook.param.url") or ""
if action_settings(delivered_stanzas.get("openbao_window_rbac_write", "")) != action_settings(
    delivered_stanzas.get("openbao_privileged_use", "")
):
    errors.append("FAIL: RBAC write alert delivery settings differ from the paging stanza")
if not paging_url.startswith("https://ntfy.example.test/keystone"):
    errors.append("FAIL: paging alert does not use the alert topic")
if "/status" not in digest_url or digest_url.startswith("https://ntfy.example.test/keystone"):
    errors.append("FAIL: in-window digest rides the paging topic instead of the status topic")

for err in errors:
    print(err)
if errors:
    sys.exit(1)
print(
    "PASS: openbao_privileged_use pages only on out-of-window privileged use, "
    "throttled 24h by caller and policies; the in-window case never reaches the "
    "Slack action and lands once a day on the status digest"
)
