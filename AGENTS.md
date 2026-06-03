# ansible-splunk - AI Agent Documentation

Ansible automation for Splunk Enterprise deployment on a Proxmox VM.
**Single source of truth** for Splunk configuration in the dryvist
homelab.

## Container strategy: Docker (exception)

Splunk runs in Docker on a dedicated VM (VMID 200) — a deliberate
exception to the global LXC-first rule (see `~/git/CLAUDE.md` Container
Deployment Rules).

**Why Docker:** This repository standardizes on Splunk Enterprise via
the official `splunk/splunk` Docker image. Native Linux package and
tarball installs exist but are out of scope. The `splunk_docker` role
manages the container lifecycle via Docker Compose.

**Implication:** New features and integrations target Docker Compose
on the Splunk VM. Do not propose LXC migration or new Docker containers
for ancillary services — those belong in `ansible-proxmox-apps` as LXC.

## This repo owns

- Splunk Enterprise container deployment (Docker Compose on Proxmox VM)
- HEC (HTTP Event Collector) configuration
- Custom index creation and retention
- Technology Add-ons (TAs) and Splunkbase apps
- MCP Server integration (app 7931)

## Critical constraints

- **Firewall disabled**: Guest firewall is off
  (`splunk_docker_firewall_enabled: false`). Docker DNAT conflicts with
  iptables FORWARD chain. The Proxmox firewall is the sole network
  security (see `dryvist/terraform-proxmox` firewall modules).
- **HEC tokens**: Per-index tokens are derived via
  `uuidv5(HEC_NAMESPACE, "splunk-hec-<index_name>")` when
  `HEC_NAMESPACE` is set. `SPLUNK_HEC_TOKEN` is the shared legacy
  fallback (always required).
- **HEC transport**: HTTPS (Splunk Docker image default, SSL enabled).
- **Secrets**: All via Doppler (`doppler run --`).

## Dependencies

### Upstream

- **`dryvist/terraform-proxmox`**: provisions Splunk VM 200 and
  exports `ansible_inventory` output for dynamic inventory.

### External services

- **Doppler**: Secrets for `SPLUNK_PASSWORD`, `HEC_NAMESPACE`,
  `SPLUNK_HEC_TOKEN`, `SPLUNK_MCP_TOKEN`, `PROXMOX_SSH_KEY_PATH`.

## Sources of truth

| What | Where |
| --- | --- |
| Index definitions | `roles/splunk_docker/defaults/main.yml` |
| Add-on registry | `roles/splunk_docker/vars/addons.yml` |
| Splunkbase app registry | `roles/splunk_docker/vars/splunkbase_apps.yml` |
| Custom TA definitions | `roles/splunk_docker/vars/custom_addons.yml` |
| MCP Server configuration | `roles/splunk_docker/vars/mcp.yml` |
| Inventory | `inventory/load_tofu.yml` |
| Pipeline architecture | `~/git/CLAUDE.md` |
| HEC setup and MCP verification | `roles/splunk_docker/README.md` |

## Key files

| Path | Purpose |
| --- | --- |
| `roles/splunk_docker/` | Splunk deployment role |
| `roles/splunk_docker/files/` | App archives (gitignored) |
| `playbooks/site.yml` | Full deployment playbook |
| `playbooks/sync-splunkbase.yml` | MinIO sync for Splunkbase artifacts |
| `playbooks/validate.yml` | Post-deploy validation |
| `inventory/load_tofu.yml` | Dynamic inventory loader |

## Commands

```bash
# Full deployment (MinIO → Splunk VM, direct target-side pull)
doppler run -- ansible-playbook playbooks/site.yml

# Sync Splunkbase → MinIO (run before site.yml when versions bumped)
doppler run -- ansible-playbook playbooks/sync-splunkbase.yml

# Validate deployment
doppler run -- ansible-playbook playbooks/validate.yml

# Lint
ansible-lint
```

## Agent tasks

### Troubleshooting

- **Health check fails**: Check container logs with `docker logs splunk`.
- **Apps not visible**: Verify ownership is UID 41812.
- **HEC not working**: Confirm `SPLUNK_HEC_TOKEN` in Doppler; set
  `HEC_NAMESPACE` for per-index tokens.
- **MCP Server not responding**: Create token via Splunk MCP Server
  config page (Settings → MCP Server); confirm port 8089 is accessible.

### Adding Splunkbase apps

1. Edit `roles/splunk_docker/vars/splunkbase_apps.yml` — add entry or
   set `enabled: true`.
2. Download archive from Splunkbase and place it in
   `roles/splunk_docker/files/`.
3. Re-run `doppler run -- ansible-playbook playbooks/site.yml`.

### Adding custom add-ons

1. Place `.tar` or `.tgz` in `roles/splunk_docker/files/`.
2. Add entry to `roles/splunk_docker/vars/custom_addons.yml`.
3. Re-run `doppler run -- ansible-playbook playbooks/site.yml`.

## Artifact store (MinIO)

Custom add-ons that cannot be downloaded from Splunkbase or GitHub are
served from a self-hosted MinIO instance (LXC container `minio`).

- Bucket: `splunk-addons` (anonymous read on internal network).
- Add-ons with `artifact_store: true` in `vars/custom_addons.yml`
  auto-download.
- Upload new versions via `mc cp` — filenames are version-free,
  versions tracked via MinIO object tags.
- See `roles/splunk_docker/files/README.md` for upload instructions.

## MCP Server tools

The Splunk MCP Server provides these tools for AI agents after deployment:

| Tool | Description | Example |
| --- | --- | --- |
| `run_splunk_query` | Execute SPL searches | `\| makeresults \| eval test="ok"` |
| `get_indexes` | List all indexes | Returns 11 custom + system indexes |
| `get_sourcetypes` | List sourcetypes | Returns ingested sourcetypes |

Configure the MCP client in `dryvist/nix-ai` (`modules/mcp/`).

## Secrets management

All secrets retrieved from Doppler at runtime. Required secrets:

| Secret | Purpose |
| --- | --- |
| `SPLUNK_PASSWORD` | Admin password |
| `HEC_NAMESPACE` | UUID namespace for per-index HEC token derivation (optional) |
| `SPLUNK_HEC_TOKEN` | Shared legacy HEC token (always required) |
| `SPLUNK_MCP_TOKEN` | MCP Server Bearer token (client-side, created via Splunk UI) |
| `PROXMOX_SSH_KEY_PATH` | SSH key for VM access |

## Tooling baseline (inherited from dryvist/.github)

- **Markdown lint:** `markdownlint-cli2` with the canonical
  `.markdownlint-cli2.yaml` synced from
  [`dryvist/.github`](https://github.com/dryvist/.github).
  `MD013 line_length: 160`; no 80-char heading/code restrictions.
  `CHANGELOG.md`, `.github/workflows/*.md`, `.github/aw/**`, and
  `.claude/**` are ignored. `MD024` strict-by-default everywhere
  actually linted — never disabled across the board.
- **Pre-commit hooks** (this is NOT a Nix-flake-based repo so we keep
  `.pre-commit-config.yaml`):
  `pre-commit/pre-commit-hooks@v6.0.0` meta-pack,
  `DavidAnson/markdownlint-cli2@v0.22.0`, `gitleaks/gitleaks@v8.30.1`,
  `adrienverge/yamllint`, local `ansible-lint`.

Do NOT commit local copies of `.markdownlint-cli2.{jsonc,yaml}` that
drift from the dryvist canonical, and do NOT re-introduce leniency
rules to work around stale tooling.

## Related repositories

| Repo | Relationship |
| --- | --- |
| `dryvist/terraform-proxmox` | Upstream: provisions Splunk VM + MinIO LXC |
| `dryvist/ansible-proxmox-apps` | Peer: owns Cribl (sends to HEC), deploys MinIO |
| `dryvist/ansible-proxmox` | Peer: Proxmox host config |
| `dryvist/nix-ai` | MCP client configuration (`modules/mcp/`) |
