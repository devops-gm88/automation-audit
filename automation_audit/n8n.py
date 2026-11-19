"""n8n export parsing: inventory plus the graph helpers the rules need."""
from __future__ import annotations

import json
from typing import Any

from .model import (
    KNOWN_TYPES,
    Inventory,
    NodeRecord,
    is_trigger,
    json_pointer,
)


def build_inventory(workflows: list[dict]) -> Inventory:
    inv = Inventory(workflows=workflows)
    for wi, wf in enumerate(workflows):
        wid = str(wf.get("id", f"workflow-{wi}"))
        wname = str(wf.get("name", wid))
        for ni, node in enumerate(wf.get("nodes") or []):
            ntype = str(node.get("type", ""))
            name = str(node.get("name", f"node-{ni}"))
            analysed = ntype in KNOWN_TYPES
            rec = NodeRecord(
                workflow_index=wi,
                workflow_id=wid,
                workflow_name=wname,
                node_index=ni,
                name=name,
                node_type=ntype,
                pointer=json_pointer(wi, "nodes", ni),
                analysed=analysed,
                reason="" if analysed else "node type not modelled by any rule",
            )
            inv.nodes.append(rec)
            if not analysed:
                inv.not_analysed.append(
                    {
                        "workflow_id": wid,
                        "node_name": name,
                        "node_type": ntype or "(missing type)",
                        "pointer": rec.pointer,
                        "reason": rec.reason,
                    }
                )
    return inv


def connections(workflow: dict) -> dict:
    return workflow.get("connections") or {}


def main_branches(workflow: dict, node_name: str) -> list[list[dict]]:
    """The node's main outputs as a list of branches, each a list of targets."""
    conns = connections(workflow)
    entry = conns.get(node_name) or {}
    main = entry.get("main") or []
    return [branch or [] for branch in main]


def downstream(workflow: dict, node_name: str) -> list[str]:
    seen: set[str] = set()
    order: list[str] = []
    queue = [t.get("node") for branch in main_branches(workflow, node_name) for t in branch]
    while queue:
        cur = queue.pop(0)
        if not cur or cur in seen:
            continue
        seen.add(cur)
        order.append(cur)
        for branch in main_branches(workflow, cur):
            queue.extend(t.get("node") for t in branch)
    return order


def node_map(workflow: dict) -> dict[str, dict]:
    return {str(n.get("name")): n for n in workflow.get("nodes") or []}


def trigger_signature(workflow: dict) -> tuple | None:
    """A signature two workflows must not share, or None when it is harmless."""
    for node in workflow.get("nodes") or []:
        if not is_trigger(node):
            continue
        ntype = str(node.get("type", ""))
        params = node.get("parameters") or {}
        if "emailreadimap" in ntype.lower():
            cred = ""
            creds = node.get("credentials") or {}
            if isinstance(creds.get("imap"), dict):
                cred = str(creds["imap"].get("name", ""))
            return ("imap", str(params.get("mailbox", "INBOX")), cred)
        if "schedule" in ntype.lower() or ntype.endswith(".cron"):
            cron = params.get("cronExpression") or params.get("rule") or ""
            return ("schedule", json.dumps(cron, sort_keys=True))
        if "webhook" in ntype.lower():
            return ("webhook", str(params.get("path", "")))
        if "manualtrigger" in ntype.lower():
            return None
    return None


def write_nodes(workflow: dict) -> list[tuple[int, dict]]:
    from .model import is_write_node

    return [(i, n) for i, n in enumerate(workflow.get("nodes") or []) if is_write_node(n)]


def summarise_systems(workflows: list[dict]) -> dict[str, dict[str, list[str]]]:
    """system -> {"read": [workflow names], "write": [...]} across the estate."""
    from .model import is_write_node, system_of

    out: dict[str, dict[str, list[str]]] = {}
    for wf in workflows:
        wname = str(wf.get("name", wf.get("id", "?")))
        for node in wf.get("nodes") or []:
            system = system_of(node)
            if not system:
                continue
            role = "write" if is_write_node(node) else "read"
            out.setdefault(system, {"read": [], "write": []})[role].append(wname)
    return out


def pointer_for(wi: int, ni: int, *rest: Any) -> str:
    return json_pointer(wi, "nodes", ni, *rest)
