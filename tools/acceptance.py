#!/usr/bin/env python3
"""Fifteen named acceptance checks. Exit 0 only when all fifteen pass.

Each check is something a buyer can re-run: the rule coverage on the planted
estate, the clean control, verification, the negative control, and the artifact
itself. Nothing here trusts a previous run - the audit is executed first.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT = os.path.join(ROOT, "audit.py")
FIX = os.path.join(ROOT, "fixtures")
SECRET = "test-only-token-0000"

results: list[tuple[str, bool, str]] = []


def check(name: str):
    def deco(fn):
        try:
            ok, detail = fn()
        except Exception as exc:  # a check that throws is a failed check
            ok, detail = False, f"{exc.__class__.__name__}: {exc}"
        results.append((name, bool(ok), str(detail)))
        return fn

    return deco


def run(*args, cwd=ROOT):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, cwd=cwd)


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="audit-acceptance-")
    out = os.path.join(tmp, "estate")
    res = run(AUDIT, "audit", os.path.join(FIX, "estate_12.json"), "--claims",
              os.path.join(FIX, "claims.json"), "--out", out, "--as-of", "2026-11-18")
    clean_out = os.path.join(tmp, "clean")
    clean = run(AUDIT, "audit", os.path.join(FIX, "estate_clean.json"), "--out", clean_out, "--as-of", "2026-11-18")

    with open(os.path.join(out, "findings.json")) as fh:
        doc = json.load(fh)
    findings = doc["findings"]
    export = json.load(open(os.path.join(FIX, "estate_12.json")))
    total_nodes = sum(len(w["nodes"]) for w in export)

    # 1
    @check("estate parses to 12 workflows")
    def _():
        return len(export) == 12, f"{len(export)} workflows"

    # 2
    @check("every node in the export is inventoried")
    def _():
        return doc["nodes"] == total_nodes, f"{doc['nodes']} inventoried of {total_nodes}"

    # 3
    @check("all ten rules fire on the planted estate")
    def _():
        fired = {f["rule_id"] for f in findings}
        missing = [f"R{i:02d}" for i in range(1, 11) if f"R{i:02d}" not in fired]
        return not missing, f"fired {sorted(fired)}" if not missing else f"missing {missing}"

    # 4
    @check("clean control produces zero findings")
    def _():
        cd = json.load(open(os.path.join(clean_out, "findings.json")))
        return clean.returncode == 0 and len(cd["findings"]) == 0, f"{len(cd['findings'])} findings"

    # 5
    @check("every finding re-derives from the export (verify)")
    def _():
        v = run(AUDIT, "verify", os.path.join(FIX, "estate_12.json"), os.path.join(out, "findings.json"))
        return v.returncode == 0 and "VERIFY OK" in v.stdout, v.stdout.strip().splitlines()[-1] if v.stdout else v.stderr[-120:]

    # 6
    @check("every finding cites a resolvable pointer")
    def _():
        bad = []
        for f in findings:
            parts = f["pointer"].strip("/").split("/")
            try:
                if len(parts) == 1:
                    export[int(parts[0])]["id"]
                else:
                    export[int(parts[0])]["nodes"][int(parts[2])]
            except (IndexError, KeyError, ValueError):
                bad.append(f["finding_id"])
        return not bad, "all resolve" if not bad else f"unresolved {bad}"

    # 7
    @check("findings cite a node or workflow that exists by name")
    def _():
        bad = []
        for f in findings:
            parts = f["pointer"].strip("/").split("/")
            if len(parts) == 1:
                if export[int(parts[0])]["id"] != f["workflow_id"]:
                    bad.append(f["finding_id"])
            elif export[int(parts[0])]["nodes"][int(parts[2])]["name"] != f["node_name"]:
                bad.append(f["finding_id"])
        return not bad, f"{len(findings)} citations checked"

    # 8
    @check("coverage balances: analysed + not analysed == export nodes")
    def _():
        cov = doc["coverage"]
        return cov["analysed"] + len(cov["not_analysed"]) == cov["nodes"] == total_nodes, str(cov)

    # 9
    @check("finding ids are unique")
    def _():
        ids = [f["finding_id"] for f in findings]
        return len(ids) == len(set(ids)), f"{len(ids)} ids"

    # 10
    @check("client claims: two contradicted, three with no finding")
    def _():
        statuses = [c["status"] for c in doc["claims"]]
        return statuses.count("contradicted") == 2 and statuses.count("no finding") == 3, str(statuses)

    # 11
    @check("report.pdf is a real PDF of at least two pages")
    def _():
        data = open(os.path.join(out, "report.pdf"), "rb").read()
        pages = data.count(b"/Type /Page ")
        return data.startswith(b"%PDF-") and pages >= 2, f"{pages} pages, {len(data)} bytes"

    # 12
    @check("report.md names every finding and every pointer")
    def _():
        md = open(os.path.join(out, "report.md")).read()
        missing = [f["finding_id"] for f in findings if f["finding_id"] not in md]
        ptrs = [f["pointer"] for f in findings if f["pointer"] not in md]
        return not missing and not ptrs, f"{len(findings)} findings, {len(ptrs)} missing pointers"

    # 13
    @check("no credential value reaches any artifact")
    def _():
        leaked = [name for name in ("report.md", "report.pdf", "findings.json")
                  if SECRET.encode() in open(os.path.join(out, name), "rb").read()]
        return not leaked, "clean" if not leaked else f"leaked in {leaked}"

    # 14
    @check("negative control: deleting a cited node fails verification")
    def _():
        broken = json.loads(json.dumps(export))
        target = next(f for f in findings if f["pointer"].count("/") >= 3)
        parts = target["pointer"].strip("/").split("/")
        wi, ni = int(parts[0]), int(parts[2])
        del broken[wi]["nodes"][ni]
        path = os.path.join(tmp, "broken.json")
        json.dump(broken, open(path, "w"))
        v = run(AUDIT, "verify", path, os.path.join(out, "findings.json"))
        return v.returncode == 1 and "VERIFY FAILED" in v.stderr, f"exit {v.returncode}"

    # 15
    @check("clean control verifies as an empty, passing report")
    def _():
        v = run(AUDIT, "verify", os.path.join(FIX, "estate_clean.json"), os.path.join(clean_out, "findings.json"))
        return v.returncode == 0 and "VERIFY OK" in v.stdout, v.stdout.strip() if v.stdout else v.stderr[-120:]

    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if not ok else ""))
    print(f"\n{passed}/{len(results)} acceptance checks")
    if passed == len(results):
        print("ALL GOOD")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
