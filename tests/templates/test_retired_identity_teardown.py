#!/usr/bin/env python3
"""Verify retired Splunk identities drive a guarded, check-mode-safe teardown."""

from pathlib import Path

import yaml
from jinja2 import Environment
from jinja2.nativetypes import NativeEnvironment

ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "roles/splunk_docker/tasks"


def load_tasks(path):
    return yaml.safe_load(path.read_text())


def named_task(tasks, name):
    return next(task for task in tasks if task.get("name") == name)


def expression_result(expression, values):
    env = Environment()
    env.filters["intersect"] = lambda left, right: [value for value in left if value in right]
    return env.compile_expression(expression)(**values)


main = load_tasks(TASKS / "main.yml")
defaults = yaml.safe_load((ROOT / "roles/splunk_docker/defaults/main/03-users-tokens-mcp.yml").read_text())
inventory = yaml.safe_load((ROOT / "inventory/group_vars/splunk.yml").read_text())
assert defaults["splunk_docker_retired_users"] == []
assert defaults["splunk_docker_retired_roles"] == []
assert inventory["splunk_docker_retired_users"] == ["sandbox-agent"]
assert inventory["splunk_docker_retired_roles"] == ["open-llm"]
inventory_names = {
    "splunk_docker_retired_users": inventory["splunk_docker_retired_users"],
    "splunk_docker_users": inventory["splunk_docker_users"],
    "splunk_docker_retired_roles": inventory["splunk_docker_retired_roles"],
    "splunk_docker_roles": inventory["splunk_docker_roles"],
}

guard = main[0]
assert guard["name"] == "Assert retired Splunk identities are not declared"
guard_when = guard["when"]
empty = {"splunk_docker_retired_users": [], "splunk_docker_retired_roles": []}
assert not expression_result(guard_when, empty)
assert expression_result(guard_when, inventory_names)
guard_conditions = guard["ansible.builtin.assert"]["that"]
assert all(expression_result(condition, inventory_names) for condition in guard_conditions)
overlapping_user = {**inventory_names, "splunk_docker_users": [{"name": "sandbox-agent"}]}
assert [expression_result(condition, overlapping_user) for condition in guard_conditions] == [False, True]
overlapping_role = {**inventory_names, "splunk_docker_roles": [{"name": "open-llm"}]}
assert [expression_result(condition, overlapping_role) for condition in guard_conditions] == [True, False]

teardown_include = named_task(main, "Remove retired Splunk identities")
include_when = teardown_include["when"]
assert not expression_result(include_when, empty)
assert expression_result(include_when, inventory_names)
main_names = [task.get("name") for task in main]
assert main_names.index("Manage Splunk service users and tokens") < main_names.index(
    "Remove retired Splunk identities"
)
assert main_names.index("Remove retired Splunk identities") < main_names.index(
    "Audit for auth tokens outside the managed set"
)

teardown = load_tasks(TASKS / "teardown_retired_identities.yml")
assert teardown[0]["ansible.builtin.include_tasks"] == "teardown_one_user.yml"
assert teardown[0]["loop"] == "{{ splunk_docker_retired_users }}"
assert teardown[1]["ansible.builtin.include_tasks"] == "teardown_one_role.yml"
assert teardown[1]["loop"] == "{{ splunk_docker_retired_roles }}"

user_tasks = load_tasks(TASKS / "teardown_one_user.yml")
user_names = [task["name"] for task in user_tasks]
assert user_names == [
    "List auth tokens for retired Splunk user {{ splunk_retired_user }}",
    "Revoke remaining auth tokens for retired Splunk user {{ splunk_retired_user }}",
    "Look up retired Splunk user {{ splunk_retired_user }}",
    "Delete retired Splunk user {{ splunk_retired_user }}",
]
token_list, token_delete, user_lookup, user_delete = user_tasks
assert token_list["ansible.builtin.uri"]["method"] == "GET"
assert "authorization/tokens?" in token_list["ansible.builtin.uri"]["url"]
assert token_list["check_mode"] is False
assert token_list["no_log"] is True
assert token_delete["ansible.builtin.uri"]["method"] == "DELETE"
assert token_delete["ansible.builtin.uri"]["status_code"] == [200, 404]
assert token_delete["when"] == "not ansible_check_mode"
assert token_delete["no_log"] is True
assert user_lookup["ansible.builtin.uri"]["method"] == "GET"
assert user_lookup["check_mode"] is False
assert "ansible_check_mode" in user_lookup["changed_when"]
assert user_delete["ansible.builtin.uri"]["method"] == "DELETE"
assert user_delete["ansible.builtin.uri"]["status_code"] == [200, 404]
assert "not ansible_check_mode" in user_delete["when"]
assert user_delete["no_log"] is True
assert all(
    task["ansible.builtin.uri"].get("user") == "{{ splunk_admin_user | default('admin') }}"
    and task["ansible.builtin.uri"].get("password") == "{{ splunk_docker_password }}"
    and task["ansible.builtin.uri"].get("force_basic_auth") is True
    and task["ansible.builtin.uri"].get("validate_certs") is False
    for task in (token_list, token_delete, user_lookup, user_delete)
)

role_tasks = load_tasks(TASKS / "teardown_one_role.yml")
role_names = [task["name"] for task in role_tasks]
assert role_names.index(
    "Assert Splunk returned its user list before deleting retired role {{ splunk_retired_role }}"
) < role_names.index("Find remaining users assigned to retired Splunk role {{ splunk_retired_role }}")
assert role_names.index("List users before deleting retired Splunk role {{ splunk_retired_role }}") < role_names.index(
    "Delete retired Splunk role {{ splunk_retired_role }}"
)
role_lookup = role_tasks[0]
role_delete = role_tasks[-1]
assert role_lookup["ansible.builtin.uri"]["method"] == "GET"
assert role_lookup["check_mode"] is False
assert role_delete["ansible.builtin.uri"]["method"] == "DELETE"
assert role_delete["ansible.builtin.uri"]["status_code"] == [200, 404]
assert "not ansible_check_mode" in role_delete["when"]
assert role_delete["no_log"] is True
assert not any("openbao" in str(task).lower() for task in teardown + user_tasks + role_tasks)

role_membership_task = next(
    task for task in role_tasks if task.get("name", "").startswith("Find remaining users assigned")
)
role_membership = role_membership_task["ansible.builtin.set_fact"]["splunk_docker_retired_role_users"]
native_env = NativeEnvironment()
native_env.filters["intersect"] = lambda left, right: [value for value in left if value in right]
membership_template = native_env.from_string(role_membership)
membership_context = {
    "splunk_docker_retired_role_users_lookup": {
        "json": {
            "entry": [
                {"name": "sandbox-agent", "content": {"roles": ["open-llm"]}},
                {"name": "hermes", "content": {"roles": ["hermes_search"]}},
            ]
        }
    },
    "splunk_docker_retired_users": ["sandbox-agent"],
    "splunk_retired_role": "open-llm",
}
assert membership_template.render(**membership_context) == []
membership_context["splunk_docker_retired_role_users_lookup"]["json"]["entry"].append(
    {"name": "remaining-user", "content": {"roles": ["open-llm"]}}
)
assert membership_template.render(**membership_context) == ["remaining-user"]

audit_tasks = load_tasks(TASKS / "audit_undeclared_tokens.yml")
audit_task = named_task(audit_tasks, "Select live tokens with an undeclared owner or audience")
audit_expression = audit_task["ansible.builtin.set_fact"]["splunk_docker_undeclared_tokens"]
audit_env = NativeEnvironment()
audit_env.filters["bool"] = bool
audit_template = audit_env.from_string(audit_expression)
audit_context = {
    "splunk_docker_users": [{"name": "hermes"}],
    "splunk_docker_token_owner_exceptions": [],
    "splunk_docker_retired_users": ["sandbox-agent"],
    "splunk_docker_token_audience": "mcp",
    "splunk_docker_live_tokens": [],
    "ansible_check_mode": False,
}
assert audit_template.render(**audit_context) == []
retired_token = {"name": "retired", "content": {"claims": {"sub": "sandbox-agent", "aud": "mcp"}}}
audit_context["splunk_docker_live_tokens"] = [retired_token]
assert audit_template.render(**audit_context) == [retired_token]
audit_context["ansible_check_mode"] = True
assert audit_template.render(**audit_context) == []
other_token = {"name": "unmanaged", "content": {"claims": {"sub": "admin", "aud": "mcp"}}}
audit_context["splunk_docker_live_tokens"] = [other_token]
assert audit_template.render(**audit_context) == [other_token]

print("retired identity teardown declarations, ordering, collision guards and check-mode paths OK")
