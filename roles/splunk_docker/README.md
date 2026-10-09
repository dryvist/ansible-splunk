# Splunk Docker Role

Deploys Splunk in a Docker container on a Proxmox VM.

## Overview

This role:

- Installs Docker and Docker Compose
- Deploys Splunk container
- Configures custom indexes
- Installs Technology Add-ons (TAs)
- Applies firewall rules (optional)

## Installation

```bash
ansible-galaxy install -r requirements.yml
```

`install` covers both sections of `requirements.yml`. The `collection`
subcommand reads only `collections:` and silently skips `roles:`, so the
Splunk role would be missing and the play would fail on an unrelated error.

## Requirements

- Debian-based target host
- `SPLUNK_PASSWORD` and `SPLUNK_HEC_TOKEN` in the environment
- VM provisioned by tofu-proxmox with appropriate disk space

## Role Variables

See `defaults/main/` for all variables (one topic per file). Key variables:

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `splunk_docker_image` | `splunk/splunk:10.4.3` | Splunk Docker image (pinned; Renovate-tracked) |
| `splunk_docker_web_port` | `8000` | Web UI port |
| `splunk_docker_hec_port` | `8088` | HEC port |
| `splunk_docker_user` | `41812` | Splunk container user UID |
| `splunk_docker_firewall_enabled` | `false` | Enable firewall rules |

## File Ownership

The Splunk container runs processes as UID 41812 (splunk user inside container).
All Splunk data directories and apps are owned by this UID to ensure proper
permissions inside the container.

## Technology Add-ons

TAs are placed in `files/` and configured in `splunk_docker_addons`:

```yaml
splunk_docker_addons:
  - name: TA-unifi-cloud
    filename: "TA-unifi-cloud-{{ splunk_docker_unifi_ta_version }}.tar"
    description: UniFi Cloud Add-on
```

## Usage

```yaml
- hosts: splunk
  roles:
    - role: splunk_docker
      vars:
        splunk_docker_password: "{{ lookup('env', 'SPLUNK_PASSWORD') }}"
        splunk_docker_hec_token: "{{ lookup('env', 'SPLUNK_HEC_TOKEN') }}"
```

## Dependencies

- community.docker collection
- tofu-proxmox for VM provisioning

## HEC Token Setup

**Per-index tokens** are derived deterministically via UUID v5:

```text
Token = uuidv5(HEC_NAMESPACE, "splunk-hec-<index_name>")
```

Any system holding the `HEC_NAMESPACE` UUID can derive tokens locally.
`SPLUNK_HEC_TOKEN` is the shared legacy
fallback that grants access to all indexes.

### Adding a New Index + Token

1. Add the index to `splunk_docker_indexes_core` or `splunk_docker_indexes_extra`
   in `defaults/main/09-custom-indexes-core.yml` / `10-custom-indexes-extra.yml`
2. Run `ansible-playbook playbooks/site.yml` — token is auto-derived
3. Senders derive the same token locally:

```bash
python3 -c "import uuid; print(uuid.uuid5(uuid.UUID('$HEC_NAMESPACE'), 'splunk-hec-<index_name>'))"
```

## Frozen Archive

When `splunk_docker_frozen_archive_enabled` is `true`, Splunk archives each bucket it ages out instead of deleting it.
Splunk calls `coldToFrozenScript` (`splunk_docker_frozen_script_path`). The script runs `rclone copy` of the bucket
directory to an S3-compatible bucket, under the prefix `<index>/<bucket>/`.

- **Completion marker:** after every file is copied, the script writes `_ARCHIVE_COMPLETE` to the bucket prefix.
  The marker lists the file count and each file's relative path and size. A prefix without the marker is incomplete.
- **Retry:** the script exits `0` only after the marker is written. Any failure exits non-zero, including a bucket
  with no files. Splunk then keeps the bucket on disk and retries it on a later pass.
- **Timeouts:** rclone retries each transfer 5 times. `splunk_docker_frozen_upload_timeout_seconds` is an idle timeout
  per transfer, not a limit on the whole bucket.
- **Pausing:** send `SIGSTOP` to the rclone processes to pause uploads, and `SIGCONT` to resume. Never kill them.
- **rclone:** pinned by `splunk_docker_rclone_version` and `splunk_docker_rclone_zip_sha256`. The two change together.
  The binary is installed into the config volume.
- **Credentials:** the script reads them from the environment first, then from the file at `splunk_docker_frozen_config_path`.
- **Restore:** `restore_from_frozen.py` (`splunk_docker_frozen_restore_script_path`) is run by an operator. Splunk never calls it.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `splunk_docker_frozen_archive_enabled` | `false` | Archive aged-out buckets instead of deleting them |
| `splunk_docker_frozen_upload_concurrency` | `8` | Concurrent transfers, including parts of one large file |
| `splunk_docker_frozen_upload_timeout_seconds` | `900` | Idle timeout per transfer |
| `splunk_docker_rclone_version` | `1.74.4` | Pinned rclone version |

All variables: `defaults/main/07-frozen-archive.yml`.

Spend caps and usage reports: see the private documentation site.

## MCP Server Verification

The Splunk MCP Server (app 7931) enables AI agents to query Splunk directly
via the Model Context Protocol (MCP). The MCP JSON-RPC endpoint clients connect
to is `<mgmt-base>/services/mcp` (for example,
`SPLUNK_MCP_URL=https://<host>:8089/services/mcp`).
Tokens are minted via the app's `/services/mcp_token` endpoint. Configure the MCP client in
`~/git/nix-ai/main/modules/mcp/default.nix`.

When OpenBao publication is enabled, the role writes the shared connection as
`SPLUNK_MCP_URL` and `SPLUNK_MCP_TOKEN` at `secret/ai/mcp/splunk`. The KV-v2
write preserves sibling fields and uses metadata-based compare-and-set, including
when the latest secret version was soft-deleted. The publishing token needs
KV-v2 data read/write, metadata read, and undelete access for this exact path.
Every converge validates the published JWT's subject, audience, validity window,
and token ID against Splunk; inventory presence alone never suppresses repair of
a missing or invalid canonical credential, and duplicate live tokens trigger
replacement so a failed cleanup is recovered by the next default converge.

For an operator-initiated rotation, run one converge with
`splunk_docker_token_force_rotate: true`. Publication must also be enabled. The
role mints exactly one replacement per user, publishes it with KV-v2 compare-and-set,
then re-enumerates Splunk and revokes every other eligible token for that user
and audience, including tokens minted concurrently after the initial snapshot.
A final read proves the published token is the sole eligible token. Disabled or
expired tokens, and tokens whose not-before time is still in the future, do not
count as live. If publication fails, the role attempts to revoke the unpublished
replacement and leaves the old snapshot untouched; if final revocation fails,
both old and new tokens remain usable. Leave the option at its default `false`
for ordinary converges; default mode still repairs an undelivered token.

### MCP-token rotator identity

`splunk_docker_manage_mcp_rotator` (`tasks/manage_mcp_rotator.yml`) creates a
separate `svc-mcp-rotator` user holding only the `mcp_token_minter` role
(capability `edit_tokens_all` — mint/manage tokens for any user, nothing
else). Unlike every user in `splunk_docker_users`, it is never itself the
owner of a minted MCP token: an external, schedule-driven rotator
authenticates AS this user (HTTP basic auth) to mint/revoke tokens for the
managed users above. Its password is generated once at creation and published
to OpenBao `secret/apps/splunk-rotator` (fields `mgmt_url`, `username`,
`password`); an existing user's password is never regenerated, and a
converge fails loud if that published credential ever goes missing, since it
cannot be recovered from Splunk.

### Available MCP Tools

| Tool | Description |
| --- | --- |
| `run_splunk_query` | Execute SPL search queries |
| `get_indexes` | List all Splunk indexes |
| `get_sourcetypes` | List available sourcetypes |

### Verifying MCP Connection

```bash
# Check MCP Server app is installed and REST API responds
ansible-playbook playbooks/validate.yml

# Direct REST API test
curl -sk https://<SPLUNK_HOST_IP>:8089/services/apps/local/splunk-mcp-server \
  -u "admin:$SPLUNK_PASSWORD" | grep -o '"name">.*<'
```
