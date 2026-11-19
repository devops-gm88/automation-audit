"""Report rendering: one evidence table, the claims it settles, the coverage it has.

The PDF is written by the dependency-free builder reused from ClaimCheck, so a
clone with no packages produces it; the Markdown is byte-stable so a reviewer can
diff two audits.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .model import Finding, Inventory
from .pdfwriter import PdfBuilder

VERSION = "0.1.0"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def claims_rows(workflows: list[dict], claims: list[dict], findings: list[Finding]) -> list[dict]:
    """A claim is contradicted when a finding lands in the workflow it names."""
    by_workflow: dict[str, list[Finding]] = {}
    for f in findings:
        by_workflow.setdefault(f.workflow_id, []).append(f)
    by_name: dict[str, list[Finding]] = {}
    for f in findings:
        by_name.setdefault(f.workflow_name, []).append(f)
    rows = []
    for claim in claims:
        wid = str(claim.get("workflow_id", ""))
        wname = str(claim.get("workflow_name", ""))
        hits = by_workflow.get(wid) or by_name.get(wname) or []
        if hits:
            status = "contradicted"
            evidence = ", ".join(sorted({f"{f.rule_id}" for f in hits}))
            note = f"{len(hits)} finding(s) in this workflow"
        else:
            status = "no finding"
            evidence = "-"
            note = "nothing detected; this is not proof that it works"
        rows.append(
            {
                "claim_id": claim.get("claim_id", ""),
                "claim": claim.get("claim", ""),
                "workflow": wname or wid,
                "status": status,
                "evidence": evidence,
                "note": note,
            }
        )
    return rows


def _observed_text(observed) -> str:
    if observed == "REDACTED-NONEMPTY":
        return "a credential-shaped value is present (value withheld)"
    return json.dumps(observed, sort_keys=True)


def summary(inventory: Inventory, findings: list[Finding], exported: str, as_of: str) -> dict:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    rules_hit = sorted({f.rule_id for f in findings})
    return {
        "source": exported,
        "source_sha256": _sha256(exported) if Path(exported).exists() else "",
        "as_of": as_of,
        "workflows": len(inventory.workflows),
        "nodes": inventory.total_nodes,
        "analysed": inventory.analysed_nodes,
        "not_analysed": len(inventory.not_analysed),
        "findings": len(findings),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "rules_hit": rules_hit,
        "version": VERSION,
    }


def render_markdown(inv: Inventory, findings: list[Finding], claims: list[dict], meta: dict) -> str:
    lines: list[str] = []
    lines.append("# Automation estate audit")
    lines.append("")
    lines.append(
        "Evidence-cited audit of an n8n workflow export. Every finding names the workflow, the node and a "
        "JSON pointer that re-verifies from the export bytes."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    for key in ("as_of", "workflows", "nodes", "analysed", "not_analysed", "findings", "critical", "high", "medium"):
        lines.append(f"- **{key.replace('_', ' ').title()}:** {meta[key]}")
    lines.append(f"- **Rules hit:** {', '.join(meta['rules_hit']) or 'none'}")
    lines.append(f"- **Export SHA-256:** `{meta['source_sha256']}`")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("| id | severity | rule | workflow | node | what |")
    lines.append("|---|---|---|---|---|---|")
    for f in findings:
        lines.append(
            f"| {f.finding_id} | {f.severity} | {f.rule_id} {f.rule_title} | {f.workflow_name} | "
            f"{f.node_name} | {f.message} |"
        )
    if not findings:
        lines.append("| - | - | - | - | - | no findings |")
    lines.append("")
    lines.append("## Evidence")
    lines.append("")
    for f in findings:
        lines.append(f"### {f.finding_id} - {f.rule_id} {f.rule_title}")
        lines.append("")
        lines.append(f"- pointer: `{f.pointer}`")
        lines.append(f"- observed: `{_observed_text(f.observed)}`")
        lines.append(f"- expected: {f.expected}")
        lines.append("")
    lines.append("## Client claims")
    lines.append("")
    lines.append("| claim | status | evidence | note |")
    lines.append("|---|---|---|---|")
    for row in claims_rows(inv.workflows, claims, findings):
        lines.append(f"| {row['claim']} | {row['status']} | {row['evidence']} | {row['note']} |")
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    lines.append(
        f"{inv.analysed_nodes} of {inv.total_nodes} nodes analysed; "
        f"{len(inv.not_analysed)} listed as not analysed."
    )
    lines.append("")
    for na in inv.not_analysed:
        lines.append(f"- `{na['pointer']}` {na['node_type']} - {na['reason']}")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    lines.append(
        "- The rules are conservative heuristics over the export. A finding is a citation that something is "
        "missing in the file; it is not proof of behaviour at run time."
    )
    lines.append(
        "- n8n exports only. Make blueprints, Zapier and assistant/bot estates are not parsed by this version."
    )
    lines.append(
        "- A clean workflow can still be broken at run time; no finding does not mean no defect."
    )
    return "\n".join(lines) + "\n"


def render_pdf(inv: Inventory, findings: list[Finding], claims: list[dict], meta: dict, path: str) -> int:
    b = PdfBuilder()
    b.title("Automation estate audit")
    b.role("Evidence-cited audit of an n8n export. Every finding re-verifies from the export bytes.")
    b.kv(
        [
            ("As of", str(meta["as_of"])),
            ("Workflows", str(meta["workflows"])),
            ("Nodes", f"{meta['nodes']} ({meta['analysed']} analysed, {meta['not_analysed']} not analysed)"),
            ("Findings", f"{meta['findings']} - {meta['critical']} critical, {meta['high']} high, {meta['medium']} medium"),
            ("Rules hit", ", ".join(meta["rules_hit"]) or "none"),
            ("Export SHA-256", meta["source_sha256"]),
        ]
    )
    b.heading("Findings")
    rows = [
        [
            f.finding_id,
            f.severity,
            f"{f.rule_id} {f.rule_title}",
            f.workflow_name,
            f.node_name,
            f.message,
        ]
        for f in findings
    ]
    if rows:
        b.table(["id", "severity", "rule", "workflow", "node", "what"], rows, [0.1, 0.075, 0.195, 0.175, 0.145, 0.31])
    else:
        b.paragraph("No findings. That is not proof the estate works - see Limitations.")
    b.heading("Evidence")
    for f in findings:
        b.kv(
            [
                (f"{f.finding_id} pointer", f.pointer),
                ("observed", _observed_text(f.observed)),
                ("expected", f.expected),
            ]
        )
    b.heading("Client claims")
    rows = [[r["claim"], r["status"], r["evidence"], r["note"]] for r in claims_rows(inv.workflows, claims, findings)]
    if rows:
        b.table(["claim", "status", "evidence", "note"], rows, [0.36, 0.13, 0.15, 0.36])
    else:
        b.note("No claims file supplied.")
    b.heading("Coverage")
    b.paragraph(
        f"{inv.analysed_nodes} of {inv.total_nodes} nodes analysed; {len(inv.not_analysed)} listed as not analysed."
    )
    for na in inv.not_analysed:
        b.note(f"{na['pointer']}  {na['node_type']}  -  {na['reason']}")
    b.heading("Limitations")
    b.bullets(
        [
            "The rules are conservative heuristics over the export. A finding cites something missing in the file; it is not proof of run-time behaviour.",
            "n8n exports only. Make blueprints and assistant/bot estates are not parsed by this version.",
            "A clean workflow can still fail at run time. No finding does not mean no defect.",
        ]
    )
    b.footer(
        f"Generated by automation-audit {VERSION}. Findings source: {meta['source']} (SHA-256 {meta['source_sha256'][:16]}...). "
        "Every row is re-verified by `audit.py verify`."
    )
    b.save(path)
    return b.page_count
