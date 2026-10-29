#!/usr/bin/env bash
set -euo pipefail

export RUN_ANSIBLE_IDENTITIES="${RUN_ANSIBLE_IDENTITIES:-signer,semaphore?,ansible}"
export RUN_ANSIBLE_FALLBACK_ON_ERROR="${RUN_ANSIBLE_FALLBACK_ON_ERROR:-1}"
export RUN_ANSIBLE_STATIC_KEY_FALLBACK="${RUN_ANSIBLE_STATIC_KEY_FALLBACK:-1}"
export RUN_ANSIBLE_REVOKE_ATTEMPTS="${RUN_ANSIBLE_REVOKE_ATTEMPTS:-3}"
export RUN_ANSIBLE_RETIRING_IDENTITIES="${RUN_ANSIBLE_RETIRING_IDENTITIES:-ansible}"
export RUN_ANSIBLE_EXPORT_CONVERGE_IDENTITY="${RUN_ANSIBLE_EXPORT_CONVERGE_IDENTITY:-1}"

# renovate: datasource=github-releases depName=dryvist/homelab-contracts
HOMELAB_CONTRACTS_REF=v5.32.0
exec nix run "github:dryvist/homelab-contracts/${HOMELAB_CONTRACTS_REF}#run-ansible" -- "$@"
