#!/usr/bin/env python3
"""Assert the declared Splunk search identities retain their intended boundaries."""

from pathlib import Path

import yaml
from jinja2.nativetypes import NativeEnvironment

ROOT = Path(__file__).parent.parent.parent
INVENTORY = ROOT / "inventory/group_vars/splunk.yml"
source = INVENTORY.read_text()
inventory = yaml.safe_load(source)

assert not any(role.get("name") == "open-llm" for role in inventory["splunk_docker_roles"])
assert not any(user.get("name") == "sandbox-agent" for user in inventory["splunk_docker_users"])
assert inventory["splunk_docker_retired_users"] == ["sandbox-agent"]
assert inventory["splunk_docker_retired_roles"] == ["open-llm"]
assert not any(
    isinstance(user.get("token_openbao_path"), str)
    and user["token_openbao_path"].startswith("apps/sandbox-agent")
    for user in inventory["splunk_docker_users"]
)
assert "splunk_docker_open_llm_token_openbao_path" not in inventory
assert "splunk_docker_open_llm_token_openbao_key" not in inventory

print("PASS: no Splunk identity mints or publishes a sandbox-agent token")

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
