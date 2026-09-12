#!/usr/bin/env python3
"""Every literal stanza name declared in a savedsearches/*.j2 source file must
survive as its own recognizable stanza in the fully rendered savedsearches.conf.

THE DEFECT THIS EXISTS TO CATCH
-------------------------------
Two adjacent `{% include %}` lines in savedsearches.conf.j2 with no blank line
between them: under Ansible's real settings (keep_trailing_newline=False,
matching Jinja's own default -- see _render_env.py's CORRECTION note), each
included sub-template loses its own trailing newline, so the last line of one
include welds onto the first line of the next:

    quantity = 0[llm_surface_freshness]

Splunk's .conf parser does not recognize a `[stanza]` header that is not at
the start of a line, so the whole second stanza -- including EVERY key it
declares -- is silently absorbed as extra (nonsensical, but not
parser-fatal) lines under the FIRST stanza. The first stanza still parses,
still schedules, still runs -- reading exactly like health. The second
stanza never exists as far as Splunk is concerned; the scheduler runs
whatever definition (if any) predates this deploy, forever.

test_search_not_welded.py's own stanza-splitting regex has this identical
blind spot (it also anchors on the start-of-line stanza marker), so it
cannot see a welded stanza
disappear -- it only ever counts stanzas that ARE still recognized. This
test instead compares against an independent source of truth: the literal
stanza names declared in each per-file template's own (un-rendered, so
unaffected by cross-file include welding) source text.

FALSIFIABILITY
--------------
Run against a fixture that reproduces the exact weld before trusting it
against the real template.
"""

import re
import sys
from pathlib import Path

from _defaults_loader import load_defaults

from _render_env import ansible_env

ROOT = Path(__file__).parent.parent.parent
TEMPLATES = ROOT / "roles/splunk_docker/templates"
SAVEDSEARCHES_DIR = TEMPLATES / "savedsearches"
DEFAULTS = load_defaults(ROOT)

STANZA_RE = re.compile(r"^\[(\S+)\]$", re.M)


def literal_stanza_names(source_text):
    """Stanza names that are plain text, not a Jinja-templated (dynamic) name."""
    return [m.group(1) for m in STANZA_RE.finditer(source_text) if "{{" not in m.group(1)]


# --- prove the check can fail before trusting it -----------------------------

FIXTURE_WELDED = "[a_detector]\nquantity = 0[b_detector]\ndescription = x\n"
FIXTURE_CLEAN = "[a_detector]\nquantity = 0\n\n[b_detector]\ndescription = x\n"

assert literal_stanza_names(FIXTURE_WELDED) == [
    "a_detector"
], "a welded fixture must not expose 'b_detector' as its own recognized stanza"
assert literal_stanza_names(FIXTURE_CLEAN) == ["a_detector", "b_detector"]

# --- expected names: declared per-file, unaffected by cross-file welding ----

expected = set()
for f in sorted(SAVEDSEARCHES_DIR.glob("*.j2")):
    expected.update(literal_stanza_names(f.read_text()))

assert expected, (
    "no literal stanza names found in roles/splunk_docker/templates/savedsearches/*.j2 "
    "-- extraction regex needs updating"
)

# --- actual: full render, same settings Ansible uses -----------------------

rendered = ansible_env(TEMPLATES).get_template("savedsearches.conf.j2").render(
    splunk_docker_silence_detectors=DEFAULTS["splunk_docker_silence_detectors"],
    splunk_docker_silence_lookback_multiplier=DEFAULTS["splunk_docker_silence_lookback_multiplier"],
    splunk_docker_llm_freshness_indexes=DEFAULTS["splunk_docker_llm_freshness_indexes"],
    splunk_docker_indexes_core=DEFAULTS["splunk_docker_indexes_core"],
    splunk_docker_indexes_extra=DEFAULTS["splunk_docker_indexes_extra"],
    splunk_docker_alert_ntfy_url=None,
    splunk_docker_alert_slack_webhook=None,
)

found = set(literal_stanza_names(rendered))
missing = expected - found

if missing:
    print(
        f"FAIL: {len(missing)} stanza(s) declared in a savedsearches/*.j2 source file "
        "do not survive as their own recognized [stanza] in the rendered conf -- "
        "each is welded onto the end of a preceding stanza's value:"
    )
    for name in sorted(missing):
        print(f"  {name}")
    sys.exit(1)

print(
    f"PASS: all {len(expected)} literal stanza names declared across savedsearches/*.j2 "
    "survive as their own recognized stanza in the rendered conf (no include-boundary weld)"
)
