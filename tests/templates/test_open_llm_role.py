#!/usr/bin/env python3
"""Assert the sandbox Splunk identity keeps its declared search-only grant."""

import re
from pathlib import Path

import yaml

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
