#!/usr/bin/env python3
"""Verify retired Splunk identities are validated before two-phase teardown."""

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
    env.filters["bool"] = bool
    return env.compile_expression(expression)(**values)


def rendered_fact(tasks, task_name, fact_name, values):
    expression = named_task(tasks, task_name)["ansible.builtin.set_fact"][fact_name]
    return NativeEnvironment().from_string(expression).render(**values)


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

# The guard is the first teardown task, so it runs before any lookup or delete.
guard = load_tasks(TASKS / "teardown_retired_identities.yml")[0]
assert guard["name"] == "Assert retired Splunk identities are not declared"
empty = {"splunk_docker_retired_users": [], "splunk_docker_retired_roles": []}
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
task_names = [task["name"] for task in teardown]
user_list = named_task(teardown, "List users before validating retired Splunk identities")
role_list = named_task(teardown, "List roles before validating retired Splunk identities")
user_list_assert = named_task(teardown, "Assert Splunk returned its user list before retiring identities")
role_list_assert = named_task(teardown, "Assert Splunk returned its role list before retiring identities")
role_entry_assert = named_task(teardown, "Assert retired role entries can be parsed before checking dependencies")
check_roles = named_task(teardown, "Check dependencies for every retired Splunk role before deletion")
order_roles = named_task(teardown, "Order existing retired roles so importers are deleted first")
order_assert = named_task(teardown, "Assert retired role dependencies can be deleted in order")
delete_users = named_task(teardown, "Delete auth tokens and retired Splunk users")
delete_roles = named_task(teardown, "Delete retired Splunk roles after their users are gone")
assert user_list["ansible.builtin.uri"]["method"] == "GET"
assert role_list["ansible.builtin.uri"]["method"] == "GET"
assert user_list["check_mode"] is role_list["check_mode"] is False
assert user_list["changed_when"] is role_list["changed_when"] is False
assert user_list["no_log"] is role_list["no_log"] is True
assert user_list["ansible.builtin.uri"]["status_code"] == [200]
assert role_list["ansible.builtin.uri"]["status_code"] == [200]
assert task_names.count(user_list["name"]) == 1
assert task_names.count(role_list["name"]) == 1
assert role_entry_assert["loop"] == "{{ splunk_docker_retired_role_roles_lookup.json.entry }}"
assert check_roles["ansible.builtin.include_tasks"] == "teardown_check_one_role.yml"
assert check_roles["loop"] == "{{ splunk_docker_retired_roles }}"
assert delete_users["loop"] == "{{ splunk_docker_retired_users }}"
assert delete_roles["loop"] == "{{ splunk_docker_retired_roles_in_delete_order }}"
assert task_names.index(user_list["name"]) < task_names.index(role_list["name"])
assert task_names.index(role_list["name"]) < task_names.index(user_list_assert["name"])
assert task_names.index(role_list_assert["name"]) < task_names.index(role_entry_assert["name"])
assert task_names.index(role_entry_assert["name"]) < task_names.index(check_roles["name"])
assert task_names.index(check_roles["name"]) < task_names.index(order_roles["name"])
assert task_names.index(order_assert["name"]) < task_names.index(delete_users["name"])
assert task_names.index(delete_users["name"]) < task_names.index(delete_roles["name"])

valid_users = {"splunk_docker_retired_users_lookup": {"json": {"entry": []}}}
malformed_users = {"splunk_docker_retired_users_lookup": {"json": {"entry": "not-a-list"}}}
valid_roles = {"splunk_docker_retired_role_roles_lookup": {"json": {"entry": []}}}
malformed_roles = {
    "splunk_docker_retired_role_roles_lookup": {"json": {"entry": "not-a-list"}}
}
assert all(expression_result(condition, valid_users) for condition in user_list_assert["ansible.builtin.assert"]["that"])
assert not all(
    expression_result(condition, malformed_users)
    for condition in user_list_assert["ansible.builtin.assert"]["that"]
)
assert all(expression_result(condition, valid_roles) for condition in role_list_assert["ansible.builtin.assert"]["that"])
assert not all(
    expression_result(condition, malformed_roles)
    for condition in role_list_assert["ansible.builtin.assert"]["that"]
)
entry_condition = role_entry_assert["ansible.builtin.assert"]["that"][0]
assert expression_result(entry_condition, {"item": {"name": "A"}})
assert not expression_result(entry_condition, {"item": "unparseable"})

check_one_role = load_tasks(TASKS / "teardown_check_one_role.yml")
check_names = [task["name"] for task in check_one_role]
user_membership = named_task(
    check_one_role, "Find users assigned to retired Splunk role {{ splunk_retired_role }}"
)
user_guard = named_task(
    check_one_role, "Assert no remaining user holds retired Splunk role {{ splunk_retired_role }}"
)
role_importers = named_task(
    check_one_role, "Find role importers of retired Splunk role {{ splunk_retired_role }}"
)
importer_guard = named_task(
    check_one_role, "Assert no remaining role imports retired Splunk role {{ splunk_retired_role }}"
)
assert check_names.index(user_membership["name"]) < check_names.index(user_guard["name"])
assert check_names.index(role_importers["name"]) < check_names.index(importer_guard["name"])
assert all(task.get("no_log") is True for task in (user_membership, role_importers))
assert not any(
    task.get("ansible.builtin.uri", {}).get("method") == "DELETE" for task in check_one_role
)

users = [
    {"name": "sandbox-agent", "content": {"roles": ["B"]}},
    {"name": "survivor", "content": {"roles": ["B"]}},
]
roles = [
    {"name": "A", "content": {"imported_roles": []}},
    {"name": "B", "content": {"imported_roles": ["A"]}},
]
guard_context = {
    "splunk_docker_retired_users_lookup": {"json": {"entry": users}},
    "splunk_docker_retired_role_roles_lookup": {"json": {"entry": roles}},
    "splunk_docker_retired_users": ["sandbox-agent"],
    "splunk_docker_retired_roles": ["A", "B"],
    "splunk_retired_role": "B",
}
assert rendered_fact(
    check_one_role,
    user_membership["name"],
    "splunk_docker_retired_role_users",
    guard_context,
) == ["survivor"]
user_guard_expression = user_guard["ansible.builtin.assert"]["that"][0]
assert not expression_result(
    user_guard_expression,
    {"splunk_docker_retired_role_users": ["survivor"]},
)
assert task_names.index(check_roles["name"]) < task_names.index(delete_users["name"])
assert task_names.index(check_roles["name"]) < task_names.index(delete_roles["name"])

single_role = [{"name": "A", "content": {"imported_roles": []}}]
order_expression = order_roles["ansible.builtin.set_fact"]["splunk_docker_retired_roles_in_delete_order"]
order_context = {
    "splunk_docker_retired_role_roles_lookup": {"json": {"entry": roles}},
    "splunk_docker_retired_roles": ["A", "B"],
}
assert NativeEnvironment().from_string(order_expression).render(**order_context) == ["B", "A"]
single_order = {
    "splunk_docker_retired_role_roles_lookup": {"json": {"entry": single_role}},
    "splunk_docker_retired_roles": ["A"],
}
assert NativeEnvironment().from_string(order_expression).render(**single_order) == ["A"]
assert task_names.index(check_roles["name"]) < task_names.index(order_assert["name"])

importer_context = {**guard_context, "splunk_retired_role": "A"}
assert rendered_fact(
    check_one_role,
    role_importers["name"],
    "splunk_docker_retired_role_importers",
    importer_context,
) == []
surviving_importer = {"name": "C", "content": {"imported_roles": ["A"]}}
importer_context["splunk_docker_retired_role_roles_lookup"]["json"]["entry"].append(
    surviving_importer
)
assert rendered_fact(
    check_one_role,
    role_importers["name"],
    "splunk_docker_retired_role_importers",
    importer_context,
) == ["C"]
malformed_importer = {"name": "C", "content": {"imported_roles": "A"}}
importer_context["splunk_docker_retired_role_roles_lookup"]["json"]["entry"][-1] = malformed_importer
assert rendered_fact(
    check_one_role,
    role_importers["name"],
    "splunk_docker_retired_role_importers",
    importer_context,
) == ["C"]
assert not expression_result(
    importer_guard["ansible.builtin.assert"]["that"][0],
    {"splunk_docker_retired_role_importers": ["C"]},
)

role_delete_tasks = load_tasks(TASKS / "teardown_one_role.yml")
role_delete = role_delete_tasks[-1]
role_lookup = role_delete_tasks[0]
would_delete = role_delete_tasks[1]
assert role_lookup["ansible.builtin.uri"]["method"] == "GET"
assert role_lookup["ansible.builtin.uri"]["status_code"] == [200, 404]
assert role_lookup["check_mode"] is False
assert role_lookup["no_log"] is True
assert role_delete["ansible.builtin.uri"]["method"] == "DELETE"
assert role_delete["ansible.builtin.uri"]["status_code"] == [200, 404]
assert "not ansible_check_mode" in role_delete["when"]
assert role_delete["no_log"] is True
assert would_delete["changed_when"] is True
assert "ansible_check_mode" in would_delete["when"]
assert sum(task.get("ansible.builtin.uri", {}).get("method") == "DELETE" for task in role_delete_tasks) == 1
assert not any("openbao" in str(task).lower() for task in teardown + check_one_role + role_delete_tasks)

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
    for task in (token_list, token_delete, user_lookup, user_delete, role_lookup, role_delete, user_list, role_list)
)

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

print("retired identity teardown guards, two-phase order, dependency deletion and check mode OK")
