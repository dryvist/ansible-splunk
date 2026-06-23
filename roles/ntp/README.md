# ntp

Time synchronization for the Splunk VM via **systemd-timesyncd**, Debian's
built-in SNTP client. This repo's copy deliberately **diverges** from the
chrony-based [`ansible-proxmox` ntp role](https://github.com/JacobPEvans/ansible-proxmox/tree/main/roles/ntp):
the Proxmox hosts run chrony (they *serve* stratum-2); the Splunk VM is a pure
*client* and uses the native timesyncd, which needs no package and — crucially —
no config `validate:` step. The old chrony `validate: chronyd -p -f %s` ran as
the privilege-dropped `_chrony` user and could not read Ansible's `0700` staged
temp file, breaking every deploy at the NTP step (#274/#279); timesyncd removes
that failure mode entirely.

## What it does

1. Ensures `tzdata`, removes `chrony` (timesyncd and chrony conflict over the clock).
2. Renders `/etc/systemd/timesyncd.conf` with `NTP=` (internal servers) and
   `FallbackNTP=` (public pool).
3. Enables + starts `systemd-timesyncd` (skipped under Docker so molecule can
   test in containers).

## Installation

This role lives in this repository under `roles/ntp/`. Reference it from a
playbook in the `roles:` block — no Galaxy install needed:

```yaml
- hosts: splunk
  roles:
    - role: ntp
```

## Usage

`playbooks/site.yml` wires `ntp_servers` from `PROXMOX_NTP_SERVERS` (Doppler) and
runs the role on the Splunk VM:

```yaml
- role: ntp
  vars:
    ntp_servers: "{{ (lookup('env', 'PROXMOX_NTP_SERVERS') | default('', true)).split(',') | map('trim') | select | list }}"
```

An empty `PROXMOX_NTP_SERVERS` leaves only the pool fallback, so the role stays
safe when Doppler omits it.

### Variables

See `defaults/main.yml`.

- `ntp_servers` (list, default `[]`) — primary sources → timesyncd `NTP=`. Point
  at the internal Proxmox stratum-2 servers. Only the host token of each entry is
  used, so chrony-style options (`10.0.10.10 iburst`) are tolerated and stripped.
- `ntp_pools` (list, default Debian pool) → timesyncd `FallbackNTP=`. Used only
  when the `NTP=` set is unreachable.

### Verification

```sh
timedatectl show-timesync --property=ServerName,ServerAddress,NTPMessage
timedatectl status        # 'System clock synchronized: yes', 'NTP service: active'
```

## Contributing

Pair changes with a `molecule test` run from the repo root. Update this README
whenever a variable is added, removed, or changes default.

## License

Internal — same license as the parent repository.
