#!/usr/bin/env python3
"""Keep object tags and the published manifest idempotent between syncs."""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "playbooks/tasks/sync-splunkbase/resolve-and-sync.yml"
REGISTRY = ROOT / "roles/splunk_docker/vars/addons.yml"
tasks = yaml.safe_load(TASKS.read_text())
by_name = {task["name"]: task for task in tasks}
errors = []

nvidia_entries = [
    entry for entry in yaml.safe_load(REGISTRY.read_text())["splunk_docker_addons"]
    if str(entry.get("splunkbase_id")) == "10131"
]
if len(nvidia_entries) != 1:
    errors.append("FAIL: TA-Nvidia must have one Splunkbase registry entry")
elif any(nvidia_entries[0].get(key) != value for key, value in {
    "filename": "TA-Nvidia.tar",
    "app_dir": "TA-Nvidia",
    "pin_version": "1.0.0",
}.items()):
    errors.append("FAIL: TA-Nvidia registry entry does not preserve its app folder and 1.0.0 pin")

resolve_version = by_name["Compute every resolved release's desired version"]["ansible.builtin.set_fact"][
    "splunkbase_desired_all"
]
if "item.0.pin_version if item.0.pin_version is defined" not in resolve_version:
    errors.append("FAIL: Splunkbase version resolution does not honor the configured pin")

query = by_name["Query current object-storage version tag for each entry"]
if query["ansible.builtin.command"]["argv"][-3:] != ["TagSet", "--output", "json"]:
    errors.append("FAIL: the tag probe must return the complete TagSet as JSON")
if query.get("check_mode") is not False:
    errors.append("FAIL: the complete tag probe must still run in check mode")

decisions = by_name["Compute sync decisions (bucket tag vs resolved latest)"]
if "items2dict(key_name='Key', value_name='Value')" not in decisions["vars"]["current_object_tags"]:
    errors.append("FAIL: current tags must be compared as a key/value mapping")
if "needs_tag" not in decisions["ansible.builtin.set_fact"]["splunkbase_plan"]:
    errors.append("FAIL: sync decisions must mark only objects with mismatched tags")
if any(key not in decisions["vars"]["desired_object_tags"]
       for key in ("channel", "version", "splunkbase_id")):
    errors.append("FAIL: desired tags must include channel, version, and Splunkbase ID")

tag = by_name["Tag object-storage objects as the current latest release"]
if tag.get("loop") != "{{ splunkbase_plan }}" or tag.get("when") != "item.needs_tag":
    errors.append("FAIL: tag writes must be limited to plan entries with changed tags")
if tag.get("changed_when") != "item.needs_tag":
    errors.append("FAIL: tag writes must report change only when their tags differ")

manifest_read = by_name["Read existing manifest for scoped updates and change detection"]
if manifest_read.get("when") != "splunkbase_plan | length > 0":
    errors.append("FAIL: one published-manifest read must serve full and scoped updates")
if manifest_read.get("changed_when") is not False or manifest_read.get("no_log") is not True:
    errors.append("FAIL: the published-manifest read must remain read-only and quiet")

publish_decision = by_name["Decide whether the published manifest needs an update"]
expression = publish_decision["ansible.builtin.set_fact"]["splunkbase_manifest_needs_publish"]
if "splunkbase_published_manifest != splunkbase_manifest" not in expression:
    errors.append("FAIL: manifest publication must compare parsed JSON values")
if "splunkbase_published_manifest_readable" not in expression:
    errors.append("FAIL: an absent or unreadable manifest must be republished")
parse_manifest = by_name["Parse published manifest when readable"]
if not parse_manifest.get("rescue"):
    errors.append("FAIL: an unreadable published manifest must fall through to a publish")

publish = by_name["Publish manifest.json to object storage"]
if publish.get("changed_when") != "splunkbase_manifest_needs_publish | bool":
    errors.append("FAIL: manifest publication must report its actual update decision")
if not any("splunkbase_manifest_needs_publish" in condition
           for condition in publish.get("when", [])):
    errors.append("FAIL: an unchanged manifest must skip its S3 publish")


def desired_tags(version, splunkbase_id):
    return {
        "channel": "latest",
        "version": version,
        "splunkbase_id": splunkbase_id,
    }


def sync_actions(entries, current_tags, current_manifest):
    """Model the task contract for two resolved entries."""
    tags_to_write = []
    versions_to_upload = []
    next_manifest = {}
    for entry in entries:
        desired = desired_tags(entry["version"], entry["id"])
        existing = current_tags.get(entry["filename"], {})
        if existing.get("version", "") != entry["version"]:
            versions_to_upload.append(entry["filename"])
        if existing != desired:
            tags_to_write.append(entry["filename"])
        next_manifest[entry["app_dir"]] = {
            "version": entry["version"],
            "filename": entry["filename"],
        }
    return {
        "uploads": versions_to_upload,
        "tags": tags_to_write,
        "publish": current_manifest != next_manifest,
    }


entries = [
    {"app_dir": "app_one", "filename": "one.tgz", "id": "101", "version": "1.0"},
    {"app_dir": "app_two", "filename": "two.tgz", "id": "202", "version": "2.0"},
]
unchanged_tags = {entry["filename"]: desired_tags(entry["version"], entry["id"])
                  for entry in entries}
unchanged_manifest = {entry["app_dir"]: {
    "version": entry["version"], "filename": entry["filename"]
} for entry in entries}
if sync_actions(entries, unchanged_tags, unchanged_manifest) != {
    "uploads": [], "tags": [], "publish": False,
}:
    errors.append("FAIL: an unchanged run must skip uploads, tag writes, and manifest publish")

changed_entries = [dict(entry) for entry in entries]
changed_entries[1]["version"] = "2.1"
changed = sync_actions(changed_entries, unchanged_tags, unchanged_manifest)
if changed != {"uploads": ["two.tgz"], "tags": ["two.tgz"], "publish": True}:
    errors.append("FAIL: one version change must upload and tag only its object and publish once")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("OK: unchanged syncs skip tag writes and publish; one changed version affects one object")
