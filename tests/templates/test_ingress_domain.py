#!/usr/bin/env python3
"""Every Traefik-fronted URL this role builds must use the ingress subdomain.

The estate apex (``tofu_data.domain`` / ``PROXMOX_DOMAIN``) hosts only the
Proxmox nodes and their load balancer. Service routes live one level down, on
``PROXMOX_SUBDOMAIN`` — the base the traefik role serves — so a role that
composes ``https://<route>.<apex>`` publishes a name nothing answers on. Two
defaults did exactly that (the MCP URL and the ntfy alert URL) and the MCP one
was published into the shared secret store for every consumer to trust.

This reads the defaults as text: a rendered fixture restates the value and
cannot see which variable it was built from.
"""

import re
import sys
from pathlib import Path

DEFAULTS = Path(__file__).parent.parent.parent / "roles/splunk_docker/defaults/main"
INGRESS_ROUTES = ("splunk-mgmt", "ntfy")

errors = []
for path in sorted(DEFAULTS.glob("*.yml")):
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for route in INGRESS_ROUTES:
            if f"{route}." not in line:
                continue
            if re.search(r"tofu_data\.domain|'PROXMOX_DOMAIN'", line):
                errors.append(
                    f"FAIL: {path.name}:{lineno} builds the {route} ingress URL from the "
                    f"apex; use lookup('env', 'PROXMOX_SUBDOMAIN'): {line.strip()}"
                )
            elif "PROXMOX_SUBDOMAIN" in line:
                print(f"PASS: {path.name}:{lineno} {route} URL uses the ingress subdomain")

if errors:
    print()
    for err in errors:
        print(err)
    sys.exit(1)

print("\nAll tests passed.")
