#!/usr/bin/env python3
"""
Guard openbao_window_rbac_write: in-window policy and AppRole role writes
are detected on the paging index-time window and throttled once per path per
day, with delivery settings matching the paging alert.

Run from repo root:
  python3 tests/templates/test_openbao_window_rbac_write.py
"""

import re
import sys

from _openbao_privileged_use import render_savedsearches, search_text, setting

rendered = render_savedsearches()
match = re.search(r"^\[openbao_window_rbac_write\]$(.*?)(?=^\[|\Z)", rendered, re.M | re.S)

errors = []
if not match:
    errors.append("FAIL: [openbao_window_rbac_write] not found in rendered output")
write_stanza = match.group(1) if match else ""
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
if setting(write_stanza, "alert.suppress.period") != "24h":
    errors.append("FAIL: RBAC write alert suppression is not 24 hours")
if setting(write_stanza, "alert.suppress.fields") != "request.path":
    errors.append("FAIL: RBAC write alert suppression is not keyed only by request.path")
write_table_fields = write_search.rsplit("| table ", 1)[-1].split()
if "request.path" not in write_table_fields:
    errors.append("FAIL: RBAC write result table drops the request.path suppression key")

# Delivery settings should stay aligned with the established paging stanza.
delivered = render_savedsearches(alert_ntfy_url="https://ntfy.example.test/keystone")
delivered_stanzas = {
    name: body
    for name, body in (
        (stanza.group(1), stanza.group(2))
        for stanza in re.finditer(r"^\[(\S+)\]$(.*?)(?=^\[|\Z)", delivered, re.M | re.S)
    )
}


def action_settings(body):
    return {
        key: value
        for line in body.splitlines()
        if " = " in line
        for key, value in (line.split(" = ", 1),)
        if key.startswith("action.")
    }


if action_settings(delivered_stanzas.get("openbao_window_rbac_write", "")) != action_settings(
    delivered_stanzas.get("openbao_privileged_use", "")
):
    errors.append("FAIL: RBAC write alert delivery settings differ from the paging stanza")

for err in errors:
    print(err)
if errors:
    sys.exit(1)
print("PASS: openbao_window_rbac_write detects in-window policy and AppRole role writes, throttled 24 hours per request path")
