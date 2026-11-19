import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from automation_audit.model import KNOWN_TYPES, Inventory, NodeRecord, load_export
from automation_audit.n8n import build_inventory, trigger_signature


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.wfs = load_export(os.path.join(ROOT, "fixtures", "estate_12.json"))
        self.inv = build_inventory(self.wfs)

    def test_workflow_and_node_counts(self):
        self.assertEqual(len(self.wfs), 12)
        self.assertEqual(self.inv.total_nodes, 38)
        self.assertEqual(self.inv.analysed_nodes, 38)
        self.assertEqual(len(self.inv.not_analysed), 0)

    def test_every_node_has_a_pointer_that_resolves(self):
        doc = self.wfs
        for rec in self.inv.nodes:
            parts = rec.pointer.strip("/").split("/")
            node = doc[int(parts[0])]["nodes"][int(parts[2])]
            self.assertEqual(node["name"], rec.name)

    def test_unknown_node_type_is_recorded_not_dropped(self):
        wf = [{"id": "x", "name": "odd", "nodes": [{"name": "Mystery", "type": "n8n-nodes-base.quantum"}],
               "connections": {}}]
        inv = build_inventory(wf)
        self.assertEqual(inv.total_nodes, 1)
        self.assertEqual(inv.analysed_nodes, 0)
        self.assertEqual(inv.not_analysed[0]["node_type"], "n8n-nodes-base.quantum")
        ok, msg = inv.coverage_ok()
        self.assertTrue(ok, msg)
        self.assertNotIn("n8n-nodes-base.quantum", KNOWN_TYPES)

    def test_coverage_gate_fails_on_an_unaccounted_node(self):
        inv = Inventory(workflows=[{"id": "a", "name": "a", "nodes": [{}]}])
        inv.nodes.append(NodeRecord(0, "a", "a", 0, "n", "t", "/0/nodes/0", True, ""))
        inv.nodes.append(NodeRecord(0, "a", "a", 1, "ghost", "t", "/0/nodes/1", True, ""))
        ok, msg = inv.coverage_ok()
        self.assertFalse(ok)
        self.assertIn("neither analysed nor listed", msg)

    def test_duplicate_trigger_signatures(self):
        sigs = [trigger_signature(w) for w in self.wfs]
        self.assertEqual(sigs[0], sigs[1])  # the two invoice workflows share the mailbox
        self.assertEqual(len([s for s in sigs if s and s[0] == "imap"]), 4)


if __name__ == "__main__":
    unittest.main()
