import copy
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from automation_audit.model import load_export
from automation_audit.n8n import build_inventory
from automation_audit.rules import rules_metadata, run_rules
from automation_audit.verify import verify_findings


def payload(path="estate_12.json"):
    wfs = load_export(os.path.join(ROOT, "fixtures", path))
    inv = build_inventory(wfs)
    findings = run_rules(wfs, inv)
    doc = {
        "findings": [{**f.to_json(), "finding_id": f.finding_id} for f in findings],
    }
    return wfs, doc


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.wfs, self.doc = payload()
        self.meta = rules_metadata()

    def test_every_finding_re_derives(self):
        ok, errors, stats = verify_findings(self.wfs, self.doc, self.meta)
        self.assertTrue(ok, errors)
        self.assertEqual(stats["verified"], stats["findings"])
        self.assertEqual(stats["errors"], 0)

    def test_editing_the_export_breaks_verification(self):
        tampered = copy.deepcopy(self.wfs)
        target = self.doc["findings"][0]
        parts = target["pointer"].strip("/").split("/")
        node = tampered[int(parts[0])]["nodes"][int(parts[2])]
        before = node.get("name")
        node["name"] = "renamed node"
        ok, errors, _ = verify_findings(tampered, self.doc, self.meta)
        self.assertFalse(ok)
        self.assertTrue(any("no longer matches" in e or "is node" in e for e in errors), errors)
        self.assertNotEqual(before, node["name"])

    def test_deleting_the_cited_node_is_the_negative_control(self):
        tampered = copy.deepcopy(self.wfs)
        target = next(f for f in self.doc["findings"] if f["pointer"].count("/") >= 3)
        parts = target["pointer"].strip("/").split("/")
        wi, ni = int(parts[0]), int(parts[2])
        del tampered[wi]["nodes"][ni]
        ok, errors, stats = verify_findings(tampered, self.doc, self.meta)
        self.assertFalse(ok)
        self.assertLess(stats["verified"], stats["findings"])
        self.assertTrue(any("does not resolve" in e for e in errors))

    def test_unknown_rule_id_is_refused(self):
        doc = {"findings": [{"rule_id": "R99", "pointer": "/0/nodes/0", "node_name": "x",
                             "workflow_id": "wf00", "observed": {}, "finding_id": "F-x"}]}
        ok, errors, _ = verify_findings(self.wfs, doc, self.meta)
        self.assertFalse(ok)
        self.assertTrue(any("rule registry" in e for e in errors))

    def test_secret_value_is_never_written_into_findings(self):
        blob = json.dumps(self.doc)
        self.assertNotIn("test-only-token-0000", blob)
        self.assertIn("REDACTED-NONEMPTY", blob)


if __name__ == "__main__":
    unittest.main()
