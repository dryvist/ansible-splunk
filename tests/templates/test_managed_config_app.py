#!/usr/bin/env python3
"""Guard the role-owned app scope and key-by-key legacy migration."""

import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml not installed. Run: pip install pyyaml")
    sys.exit(1)

ROOT = Path(__file__).parent.parent.parent
TASKS = yaml.safe_load((ROOT / "roles/splunk_docker/tasks/main.yml").read_text())
task_by_name = {task.get("name"): task for task in TASKS if task.get("name")}
errors = []

app_dir = "{{ splunk_docker_managed_config_app_dir }}"
for name, filename in (
    ("Deploy inputs.conf for HEC configuration", "inputs.conf"),
    ("Deploy indexes.conf", "indexes.conf"),
    ("Deploy web.conf for SSL and update checker configuration", "web.conf"),
    ("Deploy server.conf for internet access control", "server.conf"),
):
    task = task_by_name.get(name, {})
    template = task.get("ansible.builtin.template", {})
    expected_dest = f"{app_dir}/local/{filename}"
    if template.get("dest") != expected_dest:
        errors.append(f"FAIL: {name} must target {expected_dest}")
    if "Restart Splunk container" not in task.get("notify", []):
        errors.append(f"FAIL: {name} must notify the Splunk restart handler")

hec_cleanup = task_by_name.get("Remove role-owned HEC settings from system/local", {})
hec_module = hec_cleanup.get("community.general.ini_file", {})
if hec_module.get("state") != "absent" or hec_module.get("create") is not False:
    errors.append("FAIL: HEC migration must remove individual options without creating a file")
if hec_cleanup.get("no_log") is not True or hec_cleanup.get("diff") is not False:
    errors.append("FAIL: HEC migration must keep token values out of logs and diffs")
if "splunk_docker_legacy_inputs_conf.stat.exists" not in str(hec_cleanup.get("when")):
    errors.append("FAIL: HEC migration must skip a missing legacy file")
hec_spec = str(hec_cleanup)
for value in ("http://", "http://legacy", "token", "description", "indexes"):
    if value not in hec_spec:
        errors.append(f"FAIL: HEC migration omits its managed selector {value!r}")

web_cleanup = task_by_name.get("Remove role-owned web settings from system/local", {})
server_cleanup = task_by_name.get("Remove role-owned server settings from system/local", {})
config_spec = "\n".join((str(web_cleanup), str(server_cleanup)))
for option in (
    "enableSplunkWebSSL",
    "updateCheckerBaseURL",
    "allowInternetAccess",
    "splunkbaseAppsDumpUrl",
    "archivedSplunkbaseAppsDumpUrl",
    "updateHost",
):
    if option not in config_spec:
        errors.append(f"FAIL: web/server migration omits {option}")
if "splunk_docker_legacy_web_conf.stat.exists" not in str(web_cleanup.get("when")):
    errors.append("FAIL: web migration must skip a missing legacy file")
if "splunk_docker_legacy_server_conf.stat.exists" not in str(server_cleanup.get("when")):
    errors.append("FAIL: server migration must skip a missing legacy file")

index_cleanup = task_by_name.get("Remove role-owned index settings from system/local", {})
index_spec = str(index_cleanup)
if "splunk_docker_legacy_indexes_conf.stat.exists" not in str(index_cleanup.get("when")):
    errors.append("FAIL: index migration must skip a missing legacy file")
for option in (
    "maxVolumeDataSizeMB",
    "homePath",
    "coldPath",
    "thawedPath",
    "maxTotalDataSizeMB",
    "frozenTimePeriodInSecs",
    "coldToFrozenScript",
    "coldToFrozenDir",
    "datatype",
):
    if option not in index_spec:
        errors.append(f"FAIL: index migration omits {option}")

cleanup_specs = "\n".join((hec_spec, config_spec, index_spec))
for generated in ("sslPassword", "pass4SymmKey", "lmpool"):
    if generated in cleanup_specs:
        errors.append(f"FAIL: migration must preserve Splunk-generated {generated}")

app_manifest = task_by_name.get("Deploy the role-owned configuration app manifest", {})
manifest = app_manifest.get("ansible.builtin.copy", {}).get("content", "")
if "id = homelab_config" not in manifest or "state = enabled" not in manifest:
    errors.append("FAIL: the managed configuration app must be enabled")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: managed configuration uses an app-local scope and preserves generated system/local settings")
