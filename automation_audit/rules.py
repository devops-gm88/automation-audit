"""The ten rules. Each returns findings that must re-verify against the export.

A rule is allowed to be conservative (miss something) but not to invent: the
finding carries the pointer and the values that made it fire, so `verify` can
re-derive it without running the rule again.
"""
from __future__ import annotations

import json
from typing import Callable

from . import n8n
from .model import (
    ID_KEYS,
    SECRET_KEYS,
    SECRET_VALUE,
    Finding,
    Inventory,
    is_expression,
    is_trigger,
    is_write_node,
    json_pointer,
    system_of,
    walk_parameters,
)

REDACTED = "REDACTED-NONEMPTY"

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _node_pointer(wi: int, ni: int) -> str:
    return json_pointer(wi, "nodes", ni)


def _obs(node: dict, *keys: str) -> dict:
    return {k: node.get(k) for k in keys}


def _finding(rule: dict, wi: int, ni: int, node: dict, observed, expected: str, message: str,
             derived: dict | None = None) -> Finding:
    return Finding(
        rule_id=rule["rule_id"],
        rule_title=rule["title"],
        severity=rule["severity"],
        workflow_id="",
        workflow_name="",
        node_name=str(node.get("name", f"node-{ni}")),
        pointer=_node_pointer(wi, ni),
        observed=observed,
        expected=expected,
        message=message,
        derived=derived or {},
    )


# --------------------------------------------------------------------- R01/R07
def _write_nodes_with(workflows: list[dict]):
    for wi, wf in enumerate(workflows):
        for ni, node in enumerate(wf.get("nodes") or []):
            if is_write_node(node):
                yield wi, ni, wf, node


def r01_no_error_path(workflows, inv):
    rule = _rule("R01")
    out = []
    for wi, ni, wf, node in _write_nodes_with(workflows):
        if not node.get("onError"):
            out.append(
                _finding(
                    rule, wi, ni, node,
                    _obs(node, "type", "onError"),
                    "onError set to continueErrorOutput so a failed write has a branch",
                    f"{node.get('name')} writes to an external system and has no error branch",
                )
            )
    return out


def r07_write_no_retry(workflows, inv):
    rule = _rule("R07")
    out = []
    for wi, ni, wf, node in _write_nodes_with(workflows):
        if node.get("retryOnFail") is not True:
            out.append(
                _finding(
                    rule, wi, ni, node,
                    _obs(node, "type", "retryOnFail"),
                    "retryOnFail true with a bounded retry count",
                    f"{node.get('name')} can fail on a transient error and will not retry",
                )
            )
    return out


# ------------------------------------------------------------------------- R02
def r02_imap_no_dedupe(workflows, inv):
    rule = _rule("R02")
    out = []
    for wi, wf in enumerate(workflows):
        nodes = wf.get("nodes") or []
        trigger_idx = next((i for i, n in enumerate(nodes) if "emailreadimap" in str(n.get("type", "")).lower()), None)
        if trigger_idx is None:
            continue
        blob = json.dumps(wf, sort_keys=True).lower()
        if "messageid" in blob or "message-id" in blob or "dedupe" in blob:
            continue
        node = nodes[trigger_idx]
        out.append(
            _finding(
                rule, wi, trigger_idx, node,
                _obs(node, "type", "name"),
                "a dedupe step keyed on messageId before the workflow writes anything",
                f"{wf.get('name')} reads a mailbox and nothing in it keys on messageId",
            )
        )
    return out


# ------------------------------------------------------------------------- R03
def r03_hardcoded_id(workflows, inv):
    rule = _rule("R03")
    out = []
    for wi, wf in enumerate(workflows):
        for ni, node in enumerate(wf.get("nodes") or []):
            for path, leaf in walk_parameters(node.get("parameters") or {}):
                if not path:
                    continue
                key = str(path[-1])
                if key.lower() not in ID_KEYS:
                    continue
                if not isinstance(leaf, str) or not leaf.strip() or is_expression(leaf):
                    continue
                pointer = _node_pointer(wi, ni)
                for part in ("parameters",) + path:
                    pointer += "/" + str(part).replace("~", "~0").replace("/", "~1")
                out.append(
                    Finding(
                        rule_id=rule["rule_id"],
                        rule_title=rule["title"],
                        severity=rule["severity"],
                        workflow_id="",
                        workflow_name="",
                        node_name=str(node.get("name", "")),
                        pointer=pointer,
                        observed=leaf,
                        expected="an expression or a credential reference, never a literal identifier",
                        message=f"{node.get('name')} carries the {key} value inline",
                    )
                )
    return out


# ------------------------------------------------------------------------- R04
def r04_secret_in_body(workflows, inv):
    rule = _rule("R04")
    out = []
    for wi, wf in enumerate(workflows):
        for ni, node in enumerate(wf.get("nodes") or []):
            for path, leaf in walk_parameters(node.get("parameters") or {}):
                if not path or not isinstance(leaf, str) or not leaf.strip():
                    continue
                key = str(path[-1])
                if not (SECRET_KEYS.search(key) or SECRET_VALUE.match(leaf.strip())):
                    continue
                pointer = _node_pointer(wi, ni)
                for part in ("parameters",) + path:
                    pointer += "/" + str(part).replace("~", "~0").replace("/", "~1")
                out.append(
                    Finding(
                        rule_id=rule["rule_id"],
                        rule_title=rule["title"],
                        severity=rule["severity"],
                        workflow_id="",
                        workflow_name="",
                        node_name=str(node.get("name", "")),
                        pointer=pointer,
                        observed=REDACTED,
                        expected="a credential reference; the value never lives in the workflow body",
                        message=f"{node.get('name')} holds a credential-shaped value in the node body",
                    )
                )
    return out


# ------------------------------------------------------------------------- R05
def r05_no_trigger(workflows, inv):
    rule = _rule("R05")
    out = []
    for wi, wf in enumerate(workflows):
        if any(is_trigger(n) for n in wf.get("nodes") or []):
            continue
        out.append(
            Finding(
                rule_id=rule["rule_id"],
                rule_title=rule["title"],
                severity=rule["severity"],
                workflow_id=str(wf.get("id", "")),
                workflow_name=str(wf.get("name", "")),
                node_name=str(wf.get("name", "")),
                pointer=json_pointer(wi),
                observed={"id": wf.get("id"), "name": wf.get("name")},
                expected="a workflow with no trigger node either never runs or runs from a manual edit",
                message=f"{wf.get('name')} has no trigger node",
            )
        )
    return out


# ------------------------------------------------------------------------- R06
def r06_duplicate_trigger(workflows, inv):
    rule = _rule("R06")
    groups: dict[tuple, list[tuple[int, int]]] = {}
    for wi, wf in enumerate(workflows):
        sig = n8n.trigger_signature(wf)
        if not sig:
            continue
        ti = next((i for i, n in enumerate(wf.get("nodes") or []) if is_trigger(n)), None)
        if ti is None:
            continue
        groups.setdefault(sig, []).append((wi, ti))
    out = []
    for sig, members in groups.items():
        if len(members) < 2:
            continue
        names = [str(workflows[wi].get("name")) for wi, _ in members]
        for wi, ti in members:
            node = (workflows[wi].get("nodes") or [])[ti]
            others = [n for n in names if n != str(workflows[wi].get("name"))]
            out.append(
                _finding(
                    rule, wi, ti, node,
                    _obs(node, "type", "name"),
                    "one owner per trigger; a shared trigger needs an explicit dedupe or a merge",
                    f"{workflows[wi].get('name')} shares its trigger with {', '.join(others)}",
                    derived={"trigger_signature": list(sig)},
                )
            )
    return out


# ------------------------------------------------------------------------- R08
def r08_silent_filter_drop(workflows, inv):
    rule = _rule("R08")
    out = []
    for wi, wf in enumerate(workflows):
        for ni, node in enumerate(wf.get("nodes") or []):
            ntype = str(node.get("type", ""))
            if ntype not in {"n8n-nodes-base.filter", "n8n-nodes-base.if"}:
                continue
            params = json.dumps(node.get("parameters") or {}).lower()
            if "pdf" not in params and "extension" not in params:
                continue
            branches = n8n.main_branches(wf, str(node.get("name")))
            if len(branches) >= 2 and branches[1]:
                continue
            out.append(
                _finding(
                    rule, wi, ni, node,
                    _obs(node, "type", "name"),
                    "the rejected branch is connected (a hold queue or a notification), never dropped",
                    f"{node.get('name')} filters on file type and the rejected items go nowhere",
                    derived={"branches": len(branches)},
                )
            )
    return out


# ------------------------------------------------------------------------- R09
def r09_switch_no_fallback(workflows, inv):
    rule = _rule("R09")
    out = []
    for wi, wf in enumerate(workflows):
        for ni, node in enumerate(wf.get("nodes") or []):
            if str(node.get("type", "")) != "n8n-nodes-base.switch":
                continue
            params = node.get("parameters") or {}
            rules = params.get("rules") or {}
            values = rules.get("values") if isinstance(rules, dict) else None
            rule_count = len(values) if isinstance(values, list) else 0
            if rule_count == 0:
                continue
            blob = json.dumps(params).lower()
            branches = n8n.main_branches(wf, str(node.get("name")))
            has_fallback = "fallback" in blob or len(branches) >= rule_count + 1
            if has_fallback:
                continue
            out.append(
                _finding(
                    rule, wi, ni, node,
                    _obs(node, "type", "name"),
                    "a fallback output so an unmatched item is routed, not lost",
                    f"{node.get('name')} routes {rule_count} cases and has no fallback",
                    derived={"rule_count": rule_count, "branches": len(branches)},
                )
            )
    return out


# ------------------------------------------------------------------------- R10
def r10_write_to_unread_system(workflows, inv):
    rule = _rule("R10")
    systems = n8n.summarise_systems(workflows)
    dead = {s for s, rw in systems.items() if rw["write"] and not rw["read"]}
    if not dead:
        return []
    out = []
    seen: set[tuple[str, int]] = set()
    for wi, wf in enumerate(workflows):
        for ni, node in enumerate(wf.get("nodes") or []):
            system = system_of(node)
            if system not in dead or not is_write_node(node):
                continue
            if (system, wi) in seen:
                continue
            seen.add((system, wi))
            out.append(
                _finding(
                    rule, wi, ni, node,
                    _obs(node, "type", "name"),
                    "either a read path exists for what is written, or the write is deliberately write-only and documented",
                    f"{node.get('name')} writes to {system}, which no workflow in this estate reads",
                    derived={"system": system},
                )
            )
    return out


# --------------------------------------------------------------------- registry
RULE_DEFS: list[dict] = [
    {
        "rule_id": "R01",
        "title": "Write without an error branch",
        "severity": "high",
        "estate_level": False,
        "description": "A node that writes to another system has no onError handling, so a failure is silent.",
        "function": r01_no_error_path,
    },
    {
        "rule_id": "R02",
        "title": "Mailbox read with no dedupe key",
        "severity": "high",
        "estate_level": False,
        "description": "An IMAP trigger runs with nothing keyed on messageId, so a re-read reprocesses the same mail.",
        "function": r02_imap_no_dedupe,
    },
    {
        "rule_id": "R03",
        "title": "Hardcoded vendor identifier",
        "severity": "high",
        "estate_level": False,
        "description": "A sheet, base, table or document id is typed into the node body instead of an expression.",
        "function": r03_hardcoded_id,
    },
    {
        "rule_id": "R04",
        "title": "Credential-shaped value in the workflow body",
        "severity": "critical",
        "estate_level": False,
        "description": "A token, key or password is stored in node parameters, where it is copied with every export.",
        "function": r04_secret_in_body,
    },
    {
        "rule_id": "R05",
        "title": "Workflow with no trigger",
        "severity": "high",
        "estate_level": False,
        "description": "No trigger node: the workflow cannot run on its own, or runs only from a manual edit.",
        "function": r05_no_trigger,
    },
    {
        "rule_id": "R06",
        "title": "Two workflows on one trigger",
        "severity": "critical",
        "estate_level": True,
        "description": "The same mailbox, cron or webhook is owned by more than one workflow: the double-send risk.",
        "function": r06_duplicate_trigger,
    },
    {
        "rule_id": "R07",
        "title": "Write with no retry",
        "severity": "medium",
        "estate_level": False,
        "description": "A write node has no retryOnFail, so one transient error loses the item.",
        "function": r07_write_no_retry,
    },
    {
        "rule_id": "R08",
        "title": "Filter drops the rejected items",
        "severity": "medium",
        "estate_level": False,
        "description": "A file-type filter has no rejected branch: non-PDF attachments disappear without a record.",
        "function": r08_silent_filter_drop,
    },
    {
        "rule_id": "R09",
        "title": "Router with no fallback",
        "severity": "high",
        "estate_level": False,
        "description": "A switch routes its cases and has no fallback output for the item that matches none.",
        "function": r09_switch_no_fallback,
    },
    {
        "rule_id": "R10",
        "title": "Written system that nothing reads",
        "severity": "medium",
        "estate_level": True,
        "description": "A system receives writes and no workflow in the estate reads it: the data goes nowhere visible.",
        "function": r10_write_to_unread_system,
    },
]

_BY_ID = {r["rule_id"]: r for r in RULE_DEFS}


def _rule(rule_id: str) -> dict:
    return _BY_ID[rule_id]


def rules_metadata() -> list[dict]:
    return [
        {k: v for k, v in r.items() if k != "function"} for r in RULE_DEFS
    ]


def run_rules(workflows: list[dict], inventory: Inventory) -> list[Finding]:
    findings: list[Finding] = []
    for rdef in RULE_DEFS:
        produced = rdef["function"](workflows, inventory) or []
        for f in produced:
            if not f.workflow_id:
                wf = workflows[int(f.pointer.split("/")[1])] if f.pointer.startswith("/") else {}
                # workflow pointers /wi resolve to the workflow itself
                if f.pointer.count("/") == 1:
                    wf = workflows[int(f.pointer.strip("/"))]
                f.workflow_id = str(wf.get("id", ""))
                f.workflow_name = str(wf.get("name", ""))
            if not f.rule_title:
                f.rule_title = rdef["title"]
        findings.extend(produced)

    # A rule must not report the same defect twice.
    seen: set[tuple[str, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.pointer)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.rule_id, f.workflow_name, f.node_name))
    return unique
