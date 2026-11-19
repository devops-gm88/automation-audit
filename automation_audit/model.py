"""Data model and shared helpers for the automation audit.

Every finding is a citation: a rule id, the workflow that breaks it, the node
that breaks it, and a JSON pointer into the export that re-derives the finding.
If a pointer cannot be resolved against the export, the finding is not allowed
to exist, and `verify` fails the build.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

SEVERITIES = ("critical", "high", "medium", "low")

# Node families the rules understand. A node type outside this set is still
# inventoried (nothing is dropped silently), but it is marked not analysed.
KNOWN_TYPES = {
    "n8n-nodes-base.emailReadImap",
    "n8n-nodes-base.gmailTrigger",
    "n8n-nodes-base.scheduleTrigger",
    "n8n-nodes-base.cron",
    "n8n-nodes-base.interval",
    "n8n-nodes-base.webhook",
    "n8n-nodes-base.manualTrigger",
    "n8n-nodes-base.formTrigger",
    "n8n-nodes-base.httpRequest",
    "n8n-nodes-base.googleSheets",
    "n8n-nodes-base.airtable",
    "n8n-nodes-base.dropbox",
    "n8n-nodes-base.postgres",
    "n8n-nodes-base.gmail",
    "n8n-nodes-base.if",
    "n8n-nodes-base.switch",
    "n8n-nodes-base.filter",
    "n8n-nodes-base.code",
    "n8n-nodes-base.function",
    "n8n-nodes-base.set",
    "n8n-nodes-base.merge",
    "n8n-nodes-base.splitInBatches",
    "n8n-nodes-base.noOp",
    "n8n-nodes-base.stopAndError",
    "n8n-nodes-base.respondToWebhook",
    "n8n-nodes-base.moveBinaryData",
}

TRIGGER_MARKERS = (
    "trigger",
    "webhook",
    "emailreadimap",
    "cron",
    "interval",
    "schedule",
)

# Systems a node reads or writes, for the cross-estate rule (R10).
SYSTEM_BY_TYPE = {
    "n8n-nodes-base.googleSheets": "google-sheets",
    "n8n-nodes-base.airtable": "airtable",
    "n8n-nodes-base.dropbox": "dropbox",
    "n8n-nodes-base.postgres": "postgres",
    "n8n-nodes-base.gmail": "gmail",
}

SECRET_KEYS = re.compile(
    r"(?i)(api[-_]?key|api[-_]?token|access[-_]?token|auth[-_]?token|password|passwd|secret|authorization|bearer)"
)
SECRET_VALUE = re.compile(r"(^sk-[A-Za-z0-9]{8,}$|^Bearer\s+[A-Za-z0-9._~+/=-]{8,}$|^gh[pousr]_[A-Za-z0-9]{10,}$)")
EXPRESSION = re.compile(r"^\s*\{\{.*\}\}\s*$", re.S)

# Parameter keys that hold a vendor object identifier. These belong in a
# credential or an expression, not typed into a node body.
ID_KEYS = {
    "spreadsheetid",
    "sheetid",
    "documentid",
    "baseid",
    "tableid",
    "appid",
    "channelid",
    "calendarid",
    "folderid",
    "formid",
    "workspaceid",
    "projectid",
}


def json_pointer(workflow_index: int, *parts: str | int) -> str:
    """RFC 6901 pointer into the parsed export document."""
    segs = [str(workflow_index)]
    for p in parts:
        segs.append(str(p).replace("~", "~0").replace("/", "~1"))
    return "/" + "/".join(segs)


def pointer_get(doc: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 pointer. Raises KeyError/IndexError/TypeError."""
    if pointer in ("", "/"):
        return doc
    if not pointer.startswith("/"):
        raise KeyError(f"not a pointer: {pointer!r}")
    cur = doc
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            cur = cur[int(token)]
        elif isinstance(cur, dict):
            cur = cur[token]
        else:
            raise TypeError(f"cannot descend into {type(cur).__name__} at {token!r}")
    return cur


def walk_parameters(value: Any, path: tuple[Any, ...] = ()) -> Iterable[tuple[tuple[Any, ...], Any]]:
    """Yield (path, leaf) for every leaf under a node's parameters."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from walk_parameters(v, path + (k,))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from walk_parameters(v, path + (i,))
    else:
        yield path, value


def is_expression(value: Any) -> bool:
    return isinstance(value, str) and bool(EXPRESSION.match(value))


def is_trigger(node: dict) -> bool:
    ntype = str(node.get("type", "")).lower()
    return any(marker in ntype for marker in TRIGGER_MARKERS) or bool(node.get("trigger"))


def is_write_node(node: dict) -> bool:
    """A node that changes state somewhere outside the workflow."""
    ntype = str(node.get("type", ""))
    if ntype == "n8n-nodes-base.httpRequest":
        method = str(node.get("parameters", {}).get("method", "GET")).upper()
        return method not in {"GET", "HEAD", "OPTIONS"}
    if ntype in SYSTEM_BY_TYPE:
        operation = json.dumps(node.get("parameters", {})).lower()
        return any(
            verb in operation
            for verb in ("append", "create", "update", "upload", "insert", "delete", "send", "write")
        )
    return False


def system_of(node: dict) -> str | None:
    """Which external system a node talks to, if we can say."""
    ntype = str(node.get("type", ""))
    if ntype == "n8n-nodes-base.httpRequest":
        url = str(node.get("parameters", {}).get("url", ""))
        m = re.match(r"https?://([^/:]+)", url)
        return m.group(1).lower() if m else None
    return SYSTEM_BY_TYPE.get(ntype)


def is_write_system_node(node: dict) -> bool:
    return is_write_node(node)


@dataclass(frozen=True)
class NodeRecord:
    workflow_index: int
    workflow_id: str
    workflow_name: str
    node_index: int
    name: str
    node_type: str
    pointer: str
    analysed: bool
    reason: str


@dataclass
class Finding:
    rule_id: str
    severity: str
    workflow_id: str
    workflow_name: str
    node_name: str
    pointer: str
    observed: Any
    expected: str
    message: str
    rule_title: str = ""
    derived: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "workflow_id": self.workflow_id,
            "workflow_name": self.workflow_name,
            "node_name": self.node_name,
            "pointer": self.pointer,
            "observed": self.observed,
            "expected": self.expected,
            "message": self.message,
            "rule_title": self.rule_title,
            "derived": self.derived,
        }

    @property
    def finding_id(self) -> str:
        import hashlib

        key = f"{self.rule_id}|{self.workflow_id}|{self.pointer}|{self.node_name}".encode()
        return "F-" + hashlib.sha256(key).hexdigest()[:8]


@dataclass
class Rule:
    rule_id: str
    title: str
    severity: str
    estate_level: bool
    description: str
    function: Any


@dataclass
class Inventory:
    workflows: list[dict]
    nodes: list[NodeRecord] = field(default_factory=list)
    not_analysed: list[dict] = field(default_factory=list)

    @property
    def total_nodes(self) -> int:
        return len(self.nodes)

    @property
    def analysed_nodes(self) -> int:
        return sum(1 for n in self.nodes if n.analysed)

    def coverage_ok(self) -> tuple[bool, str]:
        export_total = sum(len(w.get("nodes") or []) for w in self.workflows)
        missing = export_total - (self.analysed_nodes + len(self.not_analysed))
        if missing != 0 or self.total_nodes != export_total:
            return False, (
                f"coverage does not balance: {missing} node(s) are neither analysed nor listed as "
                f"not analysed (inventory {self.total_nodes}, export {export_total})"
            )
        return True, (
            f"{self.analysed_nodes} analysed, {len(self.not_analysed)} not analysed, "
            f"{self.total_nodes} total"
        )

    def to_json(self) -> dict:
        return {
            "workflow_count": len(self.workflows),
            "total_nodes": self.total_nodes,
            "analysed_nodes": self.analysed_nodes,
            "not_analysed_count": len(self.not_analysed),
            "workflows": [
                {"id": w.get("id"), "name": w.get("name"), "nodes": len(w.get("nodes") or [])}
                for w in self.workflows
            ],
            "not_analysed": self.not_analysed,
        }


def load_export(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, dict) and "workflows" in doc:
        doc = doc["workflows"]
    if not isinstance(doc, list):
        raise ValueError("export must be a JSON array of workflows (or an object with a 'workflows' array)")
    for wf in doc:
        if not isinstance(wf, dict) or not isinstance(wf.get("nodes"), list):
            raise ValueError("each workflow needs an 'id', a 'name' and a 'nodes' array")
    return doc
