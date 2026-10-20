#!/usr/bin/env python3
"""Guard app-local config ownership and one-time system/local migration."""

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml not installed. Run: pip install pyyaml")
    sys.exit(1)

ROOT = Path(__file__).parent.parent.parent
ROLE = ROOT / "roles/splunk_docker"
TASKS = ROLE / "tasks"
errors = []


def read_tasks(path):
    return yaml.safe_load(path.read_text())


def task_named(tasks, name):
    return next((task for task in tasks if task.get("name") == name), {})


def normalized(value):
    return re.sub(r"\s+", " ", str(value))


main_tasks = read_tasks(TASKS / "main.yml")
main_include = task_named(main_tasks, "Configure the role-owned configuration files")
if main_include.get("ansible.builtin.include_tasks") != "configure_managed_configs.yml":
    errors.append("FAIL: main.yml must include the split managed-config task file")

config_tasks = read_tasks(TASKS / "configure_managed_configs.yml")
prepare_tasks = read_tasks(TASKS / "prepare_managed_config.yml")
migration_tasks = read_tasks(TASKS / "migrate_system_local.yml")
shared_tasks = read_tasks(TASKS / "migrate_system_local_shared_section.yml")

configs = {
    "indexes.conf": (
        "indexes.conf.j2",
        "Prepare the indexes.conf migration",
        "Deploy indexes.conf",
    ),
    "inputs.conf": (
        "inputs.conf.j2",
        "Prepare the inputs.conf migration",
        "Deploy inputs.conf for HEC configuration",
    ),
    "web.conf": (
        "web.conf.j2",
        "Prepare the web.conf migration",
        "Deploy web.conf for SSL and update checker configuration",
    ),
    "server.conf": (
        "server.conf.j2",
        "Prepare the server.conf migration",
        "Deploy server.conf for internet access control",
    ),
}
for filename, (template_name, prepare_name, deploy_name) in configs.items():
    prepare = task_named(config_tasks, prepare_name)
    deploy = task_named(config_tasks, deploy_name)
    template = deploy.get("ansible.builtin.template", {})
    expected_dest = f"{{{{ splunk_docker_managed_config_app_dir }}}}/local/{filename}"
    if (
        prepare.get("ansible.builtin.include_tasks") != "prepare_managed_config.yml"
        or prepare.get("vars", {}).get("splunk_docker_managed_config_file") != filename
        or prepare.get("vars", {}).get("splunk_docker_managed_config_template") != template_name
    ):
        errors.append(f"FAIL: {filename} must use the shared first-create migration gate")
    if template.get("src") != template_name or template.get("dest") != expected_dest:
        errors.append(f"FAIL: {filename} must deploy from {template_name} to the managed app")
    if "Restart Splunk container" not in deploy.get("notify", []):
        errors.append(f"FAIL: {filename} deploy must notify restart on change")
    if config_tasks.index(prepare) >= config_tasks.index(deploy):
        errors.append(f"FAIL: {filename} must be checked before it is deployed")

app_stat, migration_gate = prepare_tasks
if app_stat.get("ansible.builtin.stat", {}).get("path") != (
    "{{ splunk_docker_managed_config_app_dir }}/local/{{ splunk_docker_managed_config_file }}"
):
    errors.append("FAIL: migration gate must stat the app-local file before deploy")
legacy_stat = migration_tasks[0]
if legacy_stat.get("ansible.builtin.stat", {}).get("path") != (
    "{{ splunk_docker_etc_dir }}/system/local/{{ splunk_docker_migration_file }}"
):
    errors.append("FAIL: migration must stat the matching legacy file")
if "not splunk_docker_managed_config_app_stat.stat.exists" not in normalized(
    migration_gate.get("when")
):
    errors.append("FAIL: migration must run only before the app-local file is first created")
if migration_gate.get("ansible.builtin.include_tasks") != "migrate_system_local.yml":
    errors.append("FAIL: migration must be isolated in migrate_system_local.yml")

whole_sections = task_named(
    migration_tasks,
    "Remove role-owned sections from legacy {{ splunk_docker_migration_file }}",
)
whole_module = whole_sections.get("community.general.ini_file", {})
whole_loop = normalized(whole_sections.get("loop"))
if whole_module.get("state") != "absent" or whole_module.get("create") is not False:
    errors.append("FAIL: role-owned sections must be removed without creating legacy files")
if "option" in whole_module or "Restart Splunk container" not in whole_sections.get("notify", []):
    errors.append("FAIL: role-owned sections must be removed whole and notify restart on change")
if "community.general.from_ini" not in whole_loop or "ansible.builtin.template" not in whole_loop:
    errors.append("FAIL: whole-section targets must come from the rendered role template")
if "rejectattr('key', 'in', ['http', 'settings', 'default'])" not in whole_loop:
    errors.append("FAIL: shared sections must not be removed whole")
if "splunk_docker_legacy_config.stat.exists" not in normalized(whole_sections.get("when")):
    errors.append("FAIL: missing legacy files must not invoke migration modules")

shared_select = task_named(
    migration_tasks,
    "Select shared sections from legacy {{ splunk_docker_migration_file }}",
)
shared_loop = normalized(shared_select.get("loop"))
if "community.general.from_ini" not in shared_loop or "ansible.builtin.template" not in shared_loop:
    errors.append("FAIL: shared keys must come from the rendered role template")
if "selectattr('key', 'in', ['http', 'settings', 'default'])" not in shared_loop:
    errors.append("FAIL: only shared sections may use key-by-key removal")

shared_module = shared_tasks[0].get("community.general.ini_file", {})
if (
    shared_module.get("section") != "{{ splunk_docker_migration_shared_section.key }}"
    or shared_module.get("option") != "{{ item.key }}"
    or shared_module.get("state") != "absent"
    or shared_module.get("create") is not False
    or "dict2items" not in normalized(shared_tasks[0].get("loop"))
):
    errors.append("FAIL: shared-key removal must use only keys from its selected template section")
if "Restart Splunk container" not in shared_tasks[0].get("notify", []):
    errors.append("FAIL: changed shared keys must notify restart")

inputs_deploy = task_named(config_tasks, "Deploy inputs.conf for HEC configuration")
inputs_prepare = task_named(config_tasks, "Prepare the inputs.conf migration")
if inputs_deploy.get("no_log") is not True or inputs_deploy.get("diff") is not False:
    errors.append("FAIL: inputs.conf deployment must hide token values and diffs")
if inputs_prepare.get("no_log") is not True or "diff" in inputs_prepare:
    errors.append("FAIL: inputs.conf migration include must hide token values and omit diff")
if inputs_deploy.get("register") != "splunk_docker_inputs_conf_update":
    errors.append("FAIL: HEC completeness verification must retain the deploy result")

for task in (app_stat, migration_gate, *migration_tasks, *shared_tasks):
    # include_tasks rejects diff at runtime; the included module tasks disable it themselves.
    expected_diff = None if "ansible.builtin.include_tasks" in task else False
    if "splunk_docker_managed_config_file" in str(task) and task.get("diff") is not expected_diff:
        errors.append("FAIL: migration gate modules must disable diffs; includes must omit diff")
    if "splunk_docker_migration_file" in str(task) and task.get("diff") is not expected_diff:
        errors.append("FAIL: migration modules must disable diffs; includes must omit diff")
    if "splunk_docker_managed_config_file" in str(task) or "splunk_docker_migration_file" in str(task):
        if "inputs.conf'" not in normalized(task.get("no_log")):
            errors.append("FAIL: migration tasks must use no_log for inputs.conf")
            break

migration_source = (TASKS / "migrate_system_local.yml").read_text() + (
    TASKS / "migrate_system_local_shared_section.yml"
).read_text()
for generated in (
    "sslPassword",
    "pass4SymmKey",
    "mgmtHostPort",
    "port",
    "serverCert",
    "sslKeysfile",
    "sslRootCAPath",
    "enableSSL",
    "lmpool",
    "expose",
):
    if re.search(rf"\b{re.escape(generated)}\b", migration_source):
        errors.append(f"FAIL: migration must not target generated content {generated}")

template_sources = {path.name: path.read_text() for path in (ROLE / "templates").glob("*.j2")}
for generated in ("sslPassword", "pass4SymmKey", "mgmtHostPort"):
    if any(re.search(rf"(?im)^\s*{generated}\s*=", source) for source in template_sources.values()):
        errors.append(f"FAIL: templates must not make generated key {generated} migration-owned")
for pattern in (r"(?im)^\s*\[lmpool:", r"(?im)^\s*\[expose:"):
    if any(re.search(pattern, source) for source in template_sources.values()):
        errors.append("FAIL: generated lmpool/expose sections must not be migration targets")

http_match = re.search(
    r"(?ms)^\[http\]\s*\n(?P<body>.*?)(?=^\[|\Z)",
    template_sources["inputs.conf.j2"],
)
http_options = set()
if http_match:
    http_options = {
        line.split("=", 1)[0].strip()
        for line in http_match.group("body").splitlines()
        if "=" in line and not line.lstrip().startswith(("#", "{%"))
    }
if http_options != {"disabled", "index"}:
    errors.append("FAIL: role migration may remove only its HEC keys from shared [http]")

app_tasks = read_tasks(TASKS / "prepare_managed_config_app.yml")
manifest = task_named(app_tasks, "Deploy the role-owned configuration app manifest")
content = manifest.get("ansible.builtin.copy", {}).get("content", "")
if "id = homelab_config" not in content or "state = enabled" not in content:
    errors.append("FAIL: the managed configuration app must be enabled")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("PASS: app-local deployment, first-create migration, generated config preservation, and token logging guards")
