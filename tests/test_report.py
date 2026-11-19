import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "fixtures")


def audit(export, out, claims=None):
    cmd = [sys.executable, os.path.join(ROOT, "audit.py"), "audit", os.path.join(FIX, export),
           "--out", out, "--as-of", "2026-11-18"]
    if claims:
        cmd += ["--claims", os.path.join(FIX, claims)]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.out = os.path.join(cls.tmp, "estate")
        res = audit("estate_12.json", cls.out, "claims.json")
        assert res.returncode == 0, res.stderr

    def test_pdf_is_a_pdf_with_at_least_two_pages(self):
        data = open(os.path.join(self.out, "report.pdf"), "rb").read()
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertGreaterEqual(data.count(b"/Type /Page "), 2)
        self.assertGreater(len(data), 3000)

    def test_pdf_and_markdown_name_every_finding(self):
        findings = json.load(open(os.path.join(self.out, "findings.json")))["findings"]
        md = open(os.path.join(self.out, "report.md")).read()
        pdf = open(os.path.join(self.out, "report.pdf"), "rb").read()
        for f in findings:
            self.assertIn(f["finding_id"], md)
            self.assertIn(f["pointer"], md)
        self.assertIn(b"Findings", pdf)

    def test_markdown_has_claims_and_coverage_and_limitations(self):
        md = open(os.path.join(self.out, "report.md")).read()
        for heading in ("## Findings", "## Evidence", "## Client claims", "## Coverage", "## Limitations"):
            self.assertIn(heading, md)
        self.assertIn("contradicted", md)
        self.assertIn("not proof", md)

    def test_no_secret_reaches_any_artifact(self):
        for name in ("report.md", "report.pdf", "findings.json"):
            blob = open(os.path.join(self.out, name), "rb").read()
            self.assertNotIn(b"test-only-token-0000", blob, name)

    def test_summary_counts_match_the_findings(self):
        doc = json.load(open(os.path.join(self.out, "findings.json")))
        self.assertEqual(len(doc["findings"]), 14)
        self.assertEqual(doc["critical"], 3)
        self.assertEqual(doc["high"], 5)
        self.assertEqual(doc["medium"], 6)

    def test_inventory_json_is_written(self):
        inv = json.load(open(os.path.join(self.out, "inventory.json")))
        self.assertEqual(inv["workflow_count"], 12)
        self.assertEqual(inv["total_nodes"], 38)
        self.assertEqual(inv["analysed_nodes"], 38)


if __name__ == "__main__":
    unittest.main()
