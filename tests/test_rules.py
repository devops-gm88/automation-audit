import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from automation_audit.model import load_export
from automation_audit.n8n import build_inventory
from automation_audit.rules import RULE_DEFS, run_rules


def run(path):
    wfs = load_export(os.path.join(ROOT, "fixtures", path))
    inv = build_inventory(wfs)
    return run_rules(wfs, inv)


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.findings = run("estate_12.json")

    def test_every_rule_fires_at_least_once(self):
        fired = {f.rule_id for f in self.findings}
        for rdef in RULE_DEFS:
            self.assertIn(rdef["rule_id"], fired, f"{rdef['rule_id']} never fired on the planted estate")

    def test_clean_control_produces_no_findings(self):
        self.assertEqual(run("estate_clean.json"), [])

    def test_findings_are_unique_and_deterministic(self):
        a = [(f.rule_id, f.pointer) for f in self.findings]
        b = [(f.rule_id, f.pointer) for f in run("estate_12.json")]
        self.assertEqual(a, b)
        self.assertEqual(len(set(a)), len(a))

    def test_sorted_by_severity_then_rule(self):
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        keys = [(rank[f.severity], f.rule_id) for f in self.findings]
        self.assertEqual(keys, sorted(keys))

    def test_findings_carry_a_citation_and_an_expectation(self):
        for f in self.findings:
            self.assertTrue(f.pointer.startswith("/"))
            self.assertTrue(f.expected)
            self.assertTrue(f.message)
            self.assertIn(f.severity, {"critical", "high", "medium", "low"})


if __name__ == "__main__":
    unittest.main()
