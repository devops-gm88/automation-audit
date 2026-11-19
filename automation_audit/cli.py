"""CLI: audit <export> / verify <export> <findings> / rules."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import report as report_mod
from . import rules as rules_mod
from . import verify as verify_mod
from .model import load_export
from .n8n import build_inventory


def _load_claims(path: str | None) -> list[dict]:
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, dict):
        doc = doc.get("claims") or []
    return doc


def cmd_audit(args) -> int:
    workflows = load_export(args.export)
    inv = build_inventory(workflows)
    ok_cov, cov_msg = inv.coverage_ok()
    if not ok_cov:
        print(f"FAIL: coverage gate: {cov_msg}", file=sys.stderr)
        return 2
    findings = rules_mod.run_rules(workflows, inv)
    claims = _load_claims(args.claims)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    meta = report_mod.summary(inv, findings, args.export, args.as_of)
    payload = {
        **meta,
        "rules": rules_mod.rules_metadata(),
        "coverage": {
            "nodes": inv.total_nodes,
            "analysed": inv.analysed_nodes,
            "not_analysed": inv.not_analysed,
        },
        "findings": [
            {**f.to_json(), "finding_id": f.finding_id} for f in findings
        ],
        "claims": report_mod.claims_rows(workflows, claims, findings),
    }
    (out / "findings.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "inventory.json").write_text(json.dumps(inv.to_json(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md = report_mod.render_markdown(inv, findings, claims, meta)
    (out / "report.md").write_text(md, encoding="utf-8")
    pages = report_mod.render_pdf(inv, findings, claims, meta, str(out / "report.pdf"))
    print(
        f"{len(findings)} findings across {len(workflows)} workflows "
        f"({inv.total_nodes} nodes, {inv.analysed_nodes} analysed); report {pages}p -> {out}"
    )
    return 0


def cmd_verify(args) -> int:
    workflows = load_export(args.export)
    with open(args.findings, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    ok, errors, stats = verify_mod.verify_findings(workflows, doc, rules_mod.rules_metadata())
    for err in errors:
        print(f"FAIL {err}", file=sys.stderr)
    print(
        f"verify: {stats['verified']}/{stats['findings']} findings re-derived from the export, "
        f"{stats['nodes_cited']} nodes cited of {stats['nodes_in_export']}"
    )
    if not ok:
        print("VERIFY FAILED: the report cites something the export no longer contains.", file=sys.stderr)
        return 1
    print("VERIFY OK")
    return 0


def cmd_rules(args) -> int:
    for r in rules_mod.rules_metadata():
        scope = "estate" if r["estate_level"] else "workflow"
        print(f"{r['rule_id']}  {r['severity']:<8} {scope:<8} {r['title']}")
        print(f"      {r['description']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="audit.py", description="Evidence-cited audit of an n8n automation estate.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="audit an export and write findings, inventory, report.md and report.pdf")
    a.add_argument("export")
    a.add_argument("--claims", default=None, help="JSON file of client beliefs")
    a.add_argument("--out", default="out", help="output directory")
    a.add_argument("--as-of", default="", help="date stamp written into the report")
    a.set_defaults(func=cmd_audit)

    v = sub.add_parser("verify", help="re-derive every finding from the export")
    v.add_argument("export")
    v.add_argument("findings")
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("rules", help="list the rules")
    r.set_defaults(func=cmd_rules)

    args = p.parse_args(argv)
    if args.cmd == "audit" and not args.as_of:
        import datetime

        args.as_of = datetime.date.today().isoformat()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
