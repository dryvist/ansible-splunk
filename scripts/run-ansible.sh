#!/usr/bin/env bash
# Ansible runner — prefers a short-lived SSH certificate from the OpenBao CA
# (ssh-certificate-authority ADR) over the shared static key, then runs the
# playbook. Invoke under your secrets manager so BAO_ADDR and one of the
# AppRole pairs are ambient:
#   doppler run -- scripts/run-ansible.sh playbooks/site.yml [args...]
# Prefers OPENBAO_APPROLE_SEMAPHORE_{ROLE,SECRET}_ID (execution-plane
# identity); falls back to OPENBAO_APPROLE_ANSIBLE_{ROLE,SECRET}_ID (shared
# identity). Without either pair the static PROXMOX_SSH_KEY_PATH flow is
# unchanged.
set -euo pipefail

usage() {
  echo "Usage: $0 <playbook> [ansible-playbook args...]"
  echo "Example: doppler run -- $0 playbooks/site.yml --limit vms"
  exit 1
}

[[ $# -lt 1 ]] && usage

PLAYBOOK="$1"
shift

CERT_DIR=""
RUNNER_BAO_TOKEN=""
BAO_TOKEN_WAS_SET=${BAO_TOKEN+x}

revoke_runner_token() {
  [[ -z $RUNNER_BAO_TOKEN ]] && return 0
  { set +x; } 2>/dev/null
  if curl -fsSL --max-time 10 --request POST \
    -H @<(printf 'X-Vault-Token: %s\n' "$RUNNER_BAO_TOKEN") \
    --output /dev/null \
    "$BAO_ADDR/v1/auth/token/revoke-self"; then
    RUNNER_BAO_TOKEN=""
    return 0
  fi
  return 1
}

cleanup() {
  local status=$? revoke_status=0
  revoke_runner_token || revoke_status=$?
  [[ -n $CERT_DIR ]] && rm -rf "$CERT_DIR"
  if (( revoke_status != 0 )); then
    echo "ERROR: failed to revoke the runner-owned OpenBao token." >&2
  fi
  if (( status != 0 )); then
    exit "$status"
  fi
  if (( revoke_status != 0 )); then
    exit "$revoke_status"
  fi
}
trap cleanup EXIT

# Mint an ephemeral ed25519 keypair signed by the OpenBao SSH CA. OpenSSH
# pairs id + id-cert.pub automatically via PROXMOX_SSH_KEY_PATH. No secret
# material on any command line.
bao_login() {
  jq -nc --arg r "$CONVERGE_ROLE_ID" --arg s "$CONVERGE_SECRET_ID" \
    '{role_id: $r, secret_id: $s}' \
    | curl -fsSL --max-time 10 -H 'Content-Type: application/json' --data @- \
      "$BAO_ADDR/v1/auth/approle/login"
}

mint_ssh_cert() {
  local mount=${SSH_CA_MOUNT:-ssh-client-ca} login token signed
  CERT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ansible-sshcert.XXXXXX") || return 1
  chmod 700 "$CERT_DIR"
  (umask 077 && ssh-keygen -q -t ed25519 -N '' -C "$CONVERGE_IDENTITY" -f "$CERT_DIR/id") || return 1
  { set +x; } 2>/dev/null
  login=$(bao_login) || {
    # A refused semaphore login (bad/revoked secret_id) is not fatal — the
    # shared ansible identity is still a valid principal on target hosts.
    if [[ $CONVERGE_IDENTITY == semaphore && -n ${OPENBAO_APPROLE_ANSIBLE_ROLE_ID:-} && -n ${OPENBAO_APPROLE_ANSIBLE_SECRET_ID:-} ]]; then
      echo "WARNING: semaphore AppRole login failed — falling back to the shared 'ansible' identity." >&2
      CONVERGE_ROLE_ID="$OPENBAO_APPROLE_ANSIBLE_ROLE_ID"
      CONVERGE_SECRET_ID="$OPENBAO_APPROLE_ANSIBLE_SECRET_ID"
      CONVERGE_SIGN_ROLE="automation-ansible"
      CONVERGE_IDENTITY="ansible"
      login=$(bao_login) || return 1
    else
      return 1
    fi
  }
  token=$(printf '%s' "$login" | jq -er '.auth.client_token') || return 1
  RUNNER_BAO_TOKEN="$token"
  export CONVERGE_ROLE_ID CONVERGE_SECRET_ID
  signed=$(jq -nc --rawfile pub "$CERT_DIR/id.pub" --arg ttl "${SSH_CERT_TTL:-1h}" \
    '{public_key: $pub, ttl: $ttl}' \
    | curl -fsSL --max-time 10 \
      -H @<(printf 'X-Vault-Token: %s\n' "$RUNNER_BAO_TOKEN") --data @- \
      "$BAO_ADDR/v1/$mount/sign/$CONVERGE_SIGN_ROLE" \
    | jq -er '.data.signed_key') || return 1
  printf '%s\n' "$signed" > "$CERT_DIR/id-cert.pub"
  if [[ -z $BAO_TOKEN_WAS_SET ]]; then
    export BAO_TOKEN="$token"
  fi
  export PROXMOX_SSH_KEY_PATH="$CERT_DIR/id"
}

# Prefer the execution plane's own AppRole (principal `semaphore`) so a
# plane-run is distinguishable from a shared-identity run in sshd logs.
CONVERGE_ROLE_ID="" CONVERGE_SECRET_ID="" CONVERGE_SIGN_ROLE="" CONVERGE_IDENTITY=""
if [[ -n ${OPENBAO_APPROLE_SEMAPHORE_ROLE_ID:-} && -n ${OPENBAO_APPROLE_SEMAPHORE_SECRET_ID:-} ]]; then
  CONVERGE_ROLE_ID="$OPENBAO_APPROLE_SEMAPHORE_ROLE_ID"
  CONVERGE_SECRET_ID="$OPENBAO_APPROLE_SEMAPHORE_SECRET_ID"
  CONVERGE_SIGN_ROLE="automation-semaphore"
  CONVERGE_IDENTITY="semaphore"
elif [[ -n ${OPENBAO_APPROLE_ANSIBLE_ROLE_ID:-} && -n ${OPENBAO_APPROLE_ANSIBLE_SECRET_ID:-} ]]; then
  CONVERGE_ROLE_ID="$OPENBAO_APPROLE_ANSIBLE_ROLE_ID"
  CONVERGE_SECRET_ID="$OPENBAO_APPROLE_ANSIBLE_SECRET_ID"
  CONVERGE_SIGN_ROLE="automation-ansible"
  CONVERGE_IDENTITY="ansible"
  echo "WARNING: OPENBAO_APPROLE_SEMAPHORE_ROLE_ID/OPENBAO_APPROLE_SEMAPHORE_SECRET_ID not set —" >&2
  echo "authenticating as the shared 'ansible' identity instead of the execution plane's own." >&2
fi

if [[ -n ${BAO_ADDR:-} && -n $CONVERGE_ROLE_ID && -n $CONVERGE_SECRET_ID ]] \
  && mint_ssh_cert; then
  echo "Using a short-lived SSH certificate from the OpenBao CA ($CONVERGE_SIGN_ROLE)."
  echo "  authenticated as: $CONVERGE_IDENTITY"
elif [[ -z ${PROXMOX_SSH_KEY_PATH:-} ]]; then
  echo "ERROR: no SSH auth available — set BAO_ADDR + an OPENBAO_APPROLE_* pair for cert" >&2
  echo "minting, or PROXMOX_SSH_KEY_PATH for the static break-glass key." >&2
  exit 1
fi

ansible-playbook "$PLAYBOOK" "$@"
