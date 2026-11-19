import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "fixtures")
AUDIT = os.path.join(ROOT, "audit.py")


class CliTests(unittest.TestCase):
    def test_audit_then_verify_round_trip(self):
        tmp = tempfile.mkdtemp()
        out = os.path.join(tmp, "a")
        r = subprocess.run([sys.executable, AUDIT, "audit", os.path.join(FIX, "estate_12.json"),
                            "--claims", os.path.join(FIX, "claims.json"), "--out", out, "--as-of", "2026-11-18"],
                           capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)
        for name in ("findings.json", "inventory.json", "report.md", "report.pdf"):
            self.assertTrue(os.path.exists(os.path.join(out, name)), name)
        v = subprocess.run([sys.executable, AUDIT, "verify", os.path.join(FIX, "estate_12.json"),
                            os.path.join(out, "findings.json")], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(v.returncode, 0, v.stderr)
        self.assertIn("VERIFY OK", v.stdout)

    def test_verify_tampered_findings_exits_one(self):
        tmp = tempfile.mkdtemp()
        out = os.path.join(tmp, "a")
        subprocess.run([sys.executable, AUDIT, "audit", os.path.join(FIX, "estate_12.json"),
                        "--out", out, "--as-of", "2026-11-18"], check=True, capture_output=True, cwd=ROOT)
        doc = json.load(open(os.path.join(out, "findings.json")))
        doc["findings"][0]["observed"] = "something else"
        bad = os.path.join(tmp, "bad.json")
        json.dump(doc, open(bad, "w"))
        v = subprocess.run([sys.executable, AUDIT, "verify", os.path.join(FIX, "estate_12.json"), bad],
                           capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(v.returncode, 1)
        self.assertIn("VERIFY FAILED", v.stderr)

    def test_rules_command_lists_ten(self):
        r = subprocess.run([sys.executable, AUDIT, "rules"], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sum(1 for line in r.stdout.splitlines() if line.startswith("R")), 10)


if __name__ == "__main__":
    unittest.main()
