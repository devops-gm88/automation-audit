"""Re-derive every finding from the export. This is what makes it an audit.

`verify` does not re-run the rules. Each finding carries two kinds of fact:

* ``observed`` - fields of the cited node (or scalars at the cited pointer) as
  they exist in the export;
* ``derived`` - values computed from the export by the same pure graph helpers
  the rules use (a trigger signature, a branch count, a system name).

Both are recomputed here from the export bytes. Delete the node a finding
depends on, or edit it, and verification fails - that failure is the negative
control, not a rule being re-run.
"""
from __future__ import annotations

import json
from typing import Any

from . import n8n
from .model import is_write_node, pointer_get, system_of

REDACTED = "REDACTED-NONEMPTY"


def _parts(pointer: str) -> list[str]:
    return pointer.strip("/").split("/")


def _node_at(doc: list, pointer: str) -> tuple[dict | None, int | None, int | None]:
    parts = _parts(pointer)
    if len(parts) >= 3 and parts[1] == "nodes":
        try:
            wi, ni = int(parts[0]), int(parts[2])
            return doc[wi]["nodes"][ni], wi, ni
        except (IndexError, KeyError, ValueError, TypeError):
            return None, None, None
    if len(parts) == 1:
        try:
            wi = int(parts[0])
            return doc[wi], wi, None
        except (IndexError, ValueError, TypeError):
            return None, None, None
    return None, None, None


def derive(rule_id: str, doc: list, wi: int, ni: int | None, node: dict) -> dict:
    """Recompute the derived facts for a finding, from the export only."""
    wf = doc[wi]
    if rule_id == "R06":
        sig = n8n.trigger_signature(wf)
        return {"trigger_signature": list(sig) if sig else None}
    if rule_id == "R08":
        return {"branches": len(n8n.main_branches(wf, str(node.get("name"))))}
    if rule_id == "R09":
        params = node.get("parameters") or {}
        rules = params.get("rules") or {}
        values = rules.get("values") if isinstance(rules, dict) else None
        return {
            "rule_count": len(values) if isinstance(values, list) else 0,
            "branches": len(n8n.main_branches(wf, str(node.get("name")))),
        }
    if rule_id == "R10":
        return {"system": system_of(node), "is_write": is_write_node(node)}
    return {}


def verify_findings(doc: list[dict], findings_doc: dict, rules_meta: list[dict]) -> tuple[bool, list[str], dict]:
    known = {r["rule_id"] for r in rules_meta}
    findings = findings_doc.get("findings") or []
    errors: list[str] = []
    checked = 0
    cited_nodes: set[str] = set()

    for f in findings:
        fid = f.get("finding_id") or "(no id)"
        rule_id = f.get("rule_id")
        pointer = f.get("pointer", "")
        if rule_id not in known:
            errors.append(f"{fid}: rule {rule_id!r} is not in the rule registry")
            continue
        try:
            resolved = pointer_get(doc, pointer)
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            errors.append(f"{fid}: pointer {pointer} does not resolve ({exc.__class__.__name__})")
            continue

        node, wi, ni = _node_at(doc, pointer)
        if node is not None:
            if ni is None:
                # a workflow-level finding: the pointer resolves to the workflow itself
                if str(node.get("id")) != str(f.get("workflow_id")):
                    errors.append(f"{fid}: workflow at {pointer} is not {f.get('workflow_id')!r}")
                    continue
            else:
                if str(node.get("name")) != str(f.get("node_name")):
                    errors.append(f"{fid}: {pointer} is node {node.get('name')!r}, finding names {f.get('node_name')!r}")
                    continue
                if str(doc[wi].get("id")) != str(f.get("workflow_id")):
                    errors.append(f"{fid}: workflow at {pointer} is not {f.get('workflow_id')!r}")
                    continue
                cited_nodes.add(pointer)

        observed = f.get("observed", {})
        if observed == REDACTED:
            if not (isinstance(resolved, str) and resolved.strip()):
                errors.append(f"{fid}: expected a non-empty value at {pointer}")
                continue
        elif isinstance(observed, dict):
            if not isinstance(resolved, dict):
                errors.append(f"{fid}: {pointer} resolves to {type(resolved).__name__}, not an object")
                continue
            mismatch = [k for k, v in observed.items() if resolved.get(k) != v]
            if mismatch:
                now = {k: resolved.get(k) for k in mismatch}
                errors.append(f"{fid}: {pointer} no longer matches on {', '.join(mismatch)} (now {now})")
                continue
        else:
            if resolved != observed:
                errors.append(f"{fid}: {pointer} is now {resolved!r}, finding says {observed!r}")
                continue

        derived = f.get("derived") or {}
        if derived and node is not None and ni is not None:
            actual = derive(rule_id, doc, wi, ni, node)
            mismatch = [k for k, v in derived.items() if k in actual and actual[k] != v]
            if mismatch:
                now = {k: actual.get(k) for k in mismatch}
                errors.append(f"{fid}: derived fact {', '.join(mismatch)} no longer holds (now {now})")
                continue
        checked += 1

    total_nodes = sum(len(w.get("nodes") or []) for w in doc)
    stats = {
        "findings": len(findings),
        "verified": checked,
        "errors": len(errors),
        "nodes_in_export": total_nodes,
        "nodes_cited": len(cited_nodes),
    }
    return (not errors and checked == len(findings)), errors, stats


def dump(findings_doc: dict) -> str:
    return json.dumps(
        {"source_sha256": findings_doc.get("source_sha256"), "findings": findings_doc.get("findings")},
        indent=2,
    )
