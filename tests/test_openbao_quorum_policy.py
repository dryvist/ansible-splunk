#!/usr/bin/env python3
"""Model voter-health decisions and guard the rendered SPL contract.

Run: python3 tests/test_openbao_quorum_policy.py
This does not execute SPL; a Splunk dispatch remains the runtime check.
"""

import configparser
import re
import unittest
from pathlib import Path

from templates._render_env import ansible_env

ROOT = Path(__file__).resolve().parents[1]
RENDERED = ansible_env(ROOT / "roles/splunk_docker/templates").get_template(
    "savedsearches/14-openbao.j2"
).render()
CONFIG = configparser.ConfigParser(interpolation=None)
CONFIG.read_string(RENDERED)
RULE = CONFIG["openbao_raft_quorum"]
SEARCH = RULE["search"]


def classify(samples):
    """Reference policy over chronological (healthy voters, expected) samples."""
    if not samples:
        return "sampler_silent"
    expected = samples[-1][1]
    if expected is None or expected < 1 or any(n is None for _, n in samples):
        return "topology_unknown"
    if samples[-1][0] < expected // 2 + 1:
        return "quorum_loss_suspected"
    if max(voters for voters, _ in samples) < expected:
        return "redundancy_degraded"
    return "healthy"


class QuorumPolicyTests(unittest.TestCase):
    def test_decision_scenarios(self):
        scenarios = {
            "fully healthy": ([(5, 5)] * 15, "healthy"),
            "recovered blip": ([(4, 5)] + [(5, 5)] * 14, "healthy"),
            "recovered suspected loss": ([(0, 5), (5, 5)], "healthy"),
            "new non-quorum deficit waits": ([(5, 5)] * 14 + [(4, 5)], "healthy"),
            "sustained single loss": ([(4, 5)] * 15, "redundancy_degraded"),
            "exact majority preserved": ([(3, 5)] * 15, "redundancy_degraded"),
            "latest below majority": ([(5, 5)] * 14 + [(2, 5)], "quorum_loss_suspected"),
            "zero healthy endpoints": ([(0, 5)] * 15, "quorum_loss_suspected"),
            "even majority preserved": ([(3, 4)] * 15, "redundancy_degraded"),
            "even half is insufficient": ([(2, 4)] * 15, "quorum_loss_suspected"),
            "single member healthy": ([(1, 1)], "healthy"),
            "different topology healthy": ([(3, 3)] * 15, "healthy"),
            "sampler silent": ([], "sampler_silent"),
            "legacy sampler": ([(5, None)] * 15, "topology_unknown"),
            "missing newest topology": ([(5, 5), (5, None)], "topology_unknown"),
            "mixed sampler versions": ([(5, None), (5, 5)], "topology_unknown"),
            "invalid zero topology": ([(0, 0)], "topology_unknown"),
        }
        for name, (samples, expected) in scenarios.items():
            with self.subTest(name=name):
                self.assertEqual(classify(samples), expected)
                print(f"PASS: {name}: {expected}")

    def test_rendered_spl_contract(self):
        stages = SEARCH.split(" | ")
        self.assertEqual(stages, [
            'index=os sourcetype=syslog "openbao-voter-health"',
            r'rex "voters=(?<voters>\d+)"',
            r'rex "expected=(?<expected>\d+)"',
            'where isnotnull(voters)',
            'stats max(voters) as max_voters latest(voters) as latest_voters '
            'latest(expected) as expected count(expected) as topology_samples count as samples',
            'eval quorum = floor(expected / 2) + 1',
            'eval alert_reason=case(samples == 0, "sampler_silent", '
            'isnull(expected) OR expected < 1 OR topology_samples < samples, "topology_unknown", '
            'latest_voters < quorum, "quorum_loss_suspected", '
            'max_voters < expected, "redundancy_degraded", true(), "healthy")',
            'where alert_reason != "healthy"',
        ])
        for field in ("voters", "expected"):
            extraction = re.search(r'rex "(' + field + r'=[^"]+)"', SEARCH)
            assert extraction is not None
            pattern = extraction.group(1).replace("(?<", "(?P<")
            match = re.search(pattern, "voters=4 expected=5")
            assert match is not None
            self.assertEqual(match[field], "4" if field == "voters" else "5")
        self.assertEqual(RULE["alert.severity"], "3")
        self.assertEqual(RULE["dispatch.earliest_time"], "-15m")
        self.assertEqual(RULE["cron_schedule"], "*/5 * * * *")
        self.assertEqual(RULE["disabled"], "0")
        self.assertEqual(RULE["enableSched"], "1")
        self.assertEqual(RULE["is_visible"], "1")
        self.assertIn("not verified Raft quorum failure", RULE["description"])
        print("PASS: rendered SPL, extraction, warning severity and schedule contract")


if __name__ == "__main__":
    unittest.main(verbosity=2)
