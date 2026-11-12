#!/usr/bin/env python3
"""Keep Docker image pruning opt-in and limited to images."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TASKS_DIR = ROOT / "roles/splunk_docker/tasks"
PRUNE_FILE = "prune_unused_images.yml"
PRUNE_TAG = "splunk_docker_prune_images"
PREVIEW_NAME = "Preview unused Docker images that pruning removes"

main_tasks = yaml.safe_load((TASKS_DIR / "main.yml").read_text())
includes = [
    task
    for task in main_tasks
    if isinstance(task.get("ansible.builtin.include_tasks"), dict)
    and task["ansible.builtin.include_tasks"].get("file") == PRUNE_FILE
]
assert len(includes) == 1, f"expected one include of {PRUNE_FILE}, found {len(includes)}"
assert {"never", PRUNE_TAG} <= set(includes[0].get("tags", [])), (
    f"{PRUNE_FILE} include must carry never and {PRUNE_TAG} tags"
)
# Tags on a dynamic include do not reach the included tasks; apply must carry them too.
assert {"never", PRUNE_TAG} <= set(includes[0]["ansible.builtin.include_tasks"].get("apply", {}).get("tags", [])), (
    f"{PRUNE_FILE} include must apply never and {PRUNE_TAG} tags to its tasks"
)

prune_tasks = yaml.safe_load((TASKS_DIR / PRUNE_FILE).read_text())
preview_tasks = [task for task in prune_tasks if task.get("name") == PREVIEW_NAME]
assert len(preview_tasks) == 1, "expected one Docker image prune preview task"
preview = preview_tasks[0]
preview_args = preview.get("community.docker.docker_host_info")
assert preview_args is not None, "the preview must use docker_host_info"
assert preview_args.get("images") is True, "the preview must inspect images"
assert preview_args.get("containers") is True, "the preview must inspect containers"
assert preview_args.get("containers_all") is True, (
    "the preview must inspect running and stopped containers"
)
assert preview_args.get("verbose_output") is True, (
    "the preview needs full image tags, sizes, and container image IDs"
)

unused_images_tasks = [
    task
    for task in prune_tasks
    if task.get("name") == "Find Docker images not referenced by any container"
]
assert len(unused_images_tasks) == 1, "expected one unused-image calculation task"
unused_images = unused_images_tasks[0]["ansible.builtin.set_fact"][
    "splunk_docker_prune_unused_images"
]
assert "attribute='ImageID'" in unused_images, (
    "image usage must compare full Docker image IDs"
)

preview_report_tasks = [
    task
    for task in prune_tasks
    if task.get("name") == "Report the Docker image prune preview"
]
assert len(preview_report_tasks) == 1, "expected one Docker image prune preview report"
preview_report = preview_report_tasks[0]["ansible.builtin.debug"]["msg"]
assert "image.RepoTags" in preview_report and "image.Size" in preview_report, (
    "the preview must report each image's repository tags and size"
)
assert "sum(attribute='Size')" in preview_report, (
    "the preview must report the total image size"
)

prune_actions = [task for task in prune_tasks if "community.docker.docker_prune" in task]
assert len(prune_actions) == 1, "expected one community.docker.docker_prune task"
prune_index = prune_tasks.index(prune_actions[0])
preview_index = prune_tasks.index(preview)
assert preview_index < prune_index, "the preview must run before pruning"
docker_actions_before_prune = [
    key
    for task in prune_tasks[:prune_index]
    for key in task
    if key.startswith("community.docker.")
]
assert docker_actions_before_prune == ["community.docker.docker_host_info"], (
    "the preview may use only read-only Docker info modules before pruning"
)

prune_args = prune_actions[0]["community.docker.docker_prune"]
assert prune_args.get("images") is True, "image pruning must be enabled"
assert prune_args.get("images_filters") == {"dangling": False}, (
    "image pruning must include all unused images, not only dangling images"
)

for prune_kind in ("containers", "networks", "volumes", "builder_cache"):
    assert prune_args.get(prune_kind) is not True, (
        f"{prune_kind} pruning must remain disabled"
    )

report_tasks = [
    task for task in prune_tasks if task.get("name") == "Report removed images and reclaimed space"
]
assert len(report_tasks) == 1, "expected one image prune result report"
report = report_tasks[0]["ansible.builtin.debug"]["msg"]
assert "splunk_docker_prune_result.images |" in report, (
    "removed-image count must use the module's images return key"
)
assert "splunk_docker_prune_result.images_space_reclaimed |" in report, (
    "reclaimed space must use the module's images_space_reclaimed return key"
)

print("PASS: image pruning is opt-in, image-only, and has a read-only preview")
