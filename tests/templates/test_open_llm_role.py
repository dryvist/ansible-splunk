#!/usr/bin/env python3
"""Assert the sandbox Splunk identity keeps its declared search-only grant."""

import re
from pathlib import Path

import yaml
from jinja2.nativetypes import NativeEnvironment

ROOT = Path(__file__).parent.parent.parent
INVENTORY = ROOT / "inventory/group_vars/splunk.yml"
source = INVENTORY.read_text()
inventory = yaml.safe_load(source)

role = next(role for role in inventory["splunk_docker_roles"] if role["name"] == "open-llm")
assert role["imported_roles"] == [], "open-llm must not inherit built-in capabilities"
assert set(role["capabilities"]) == {"mcp_tool_execute", "search"}
assert role["srch_indexes_allowed"] == ["*"]
assert role["srch_indexes_default"] == []
assert role["srch_jobs_quota"] == 3
assert role["srch_disk_quota"] == 100

user = next(user for user in inventory["splunk_docker_users"] if user["name"] == "sandbox-agent")
assert user["roles"] == ["open-llm"]
assert user["token_openbao_path"] == "{{ splunk_docker_open_llm_token_openbao_path }}"
assert user["token_openbao_key"] == "{{ splunk_docker_open_llm_token_openbao_key }}"
assert user["url_openbao_key"] == ""
assert inventory["splunk_docker_open_llm_token_openbao_path"] == "apps/sandbox-agent"
assert inventory["splunk_docker_open_llm_token_openbao_key"] == "splunk_search_token"

assert re.search(
    r"(?m)^\s*# TODO: Restrict indexes when the sandbox index scope is defined\.\n"
    r"\s*- \"\*\"$",
    source,
), "the wildcard allow line must carry the index restriction TODO"
assert source.count("TODO: Restrict indexes") == 1

print("PASS: open-llm grants only search and MCP execution with bounded quotas")

search_user = next(user for user in inventory["splunk_docker_users"] if user["name"] == "svc-platform-search")
assert search_user["roles"] == ["platform_search"]
assert search_user["token_audience"] == "platform-search"
assert search_user["token_openbao_path"] == "platform/splunk/search"
assert search_user["token_openbao_key"] == "SPLUNK_TOKEN"
assert search_user["url_openbao_key"] == ""

platform_role = next(role for role in inventory["splunk_docker_roles"] if role["name"] == "platform_search")
assert platform_role["imported_roles"] == []
assert platform_role["capabilities"] == ["search"]

index_defaults = ROOT / "roles/splunk_docker/defaults/main"
index_registry = []
for filename, variable in (
    ("09-custom-indexes-core.yml", "splunk_docker_indexes_core"),
    ("10-custom-indexes-extra.yml", "splunk_docker_indexes_extra"),
):
    index_registry.extend(yaml.safe_load((index_defaults / filename).read_text())[variable])

render = NativeEnvironment().from_string
platform_allowed = render(platform_role["srch_indexes_allowed"]).render(splunk_docker_indexes=index_registry)
platform_default = render(platform_role["srch_indexes_default"]).render(splunk_docker_indexes=index_registry)
declared_indexes = [entry["name"] for entry in index_registry]
assert platform_allowed == declared_indexes
assert platform_default == declared_indexes
assert all(index and not index.startswith("_") for index in platform_allowed)
assert "*" not in platform_allowed and "_*" not in platform_allowed

hermes_role = next(role for role in inventory["splunk_docker_roles"] if role["name"] == "hermes_search")
assert "admin" not in hermes_role["capabilities"]
assert "user" in hermes_role["imported_roles"]

print("PASS: platform search has only search capability on declared non-internal indexes")
