"""Small, validated edits ("patches") to a :class:`~.ir.Flow`.

The chat copilot edits a flow by emitting patches instead of regenerating the
whole graph: each patch is one auditable operation (add a node, remove a node,
change a field, rewire an edge). Patches apply to a *copy* and the result must
pass :meth:`Flow.validate` -- a bad patch list leaves the original untouched.
Because every applied patch list is saved through the store, an AI edit is a
new flow version the prior one can be rolled back to, same as a designer edit.

Ops (each patch is a dict with an ``op`` key):

- ``{"op": "add_node", "node": {...}, "after": "<id>"}`` -- insert a node; with
  ``after`` it is spliced into that node's ``next`` chain, else it is appended
  unlinked (or becomes ``start`` in an empty flow).
- ``{"op": "remove_node", "id": "<id>"}`` -- remove a node; routing that pointed
  at it is healed to the removed node's ``next``.
- ``{"op": "set_field", "id": "<id>", "field": "brief", "value": ...}`` -- set
  one node field (anything but ``id``).
- ``{"op": "set_flow_field", "field": "name", "value": ...}`` -- set a
  flow-level field (``name``/``start``/``notify``/``max_seconds``/
  ``max_dollars``/``schedule``/``timezone``/``max_concurrent``/``inputs``).
- ``{"op": "rewire", "id": "<id>", "field": "next", "to": "<id>|null"}`` --
  repoint one routing edge (``next``/``if_true``/``if_false``/``on_error``/
  ``on_expire``).
"""
from __future__ import annotations

from typing import Any

from .draft import _sanitize_inputs
from .ir import Flow, FlowNode, partition_draft_validation_errors

PATCH_OPS = frozenset({"add_node", "remove_node", "set_field", "set_flow_field", "rewire"})

_ROUTE_FIELDS = frozenset({"next", "if_true", "if_false", "on_error", "on_expire"})
_FLOW_FIELDS = frozenset({
    "name", "start", "notify", "notify_on", "max_seconds", "max_dollars", "schedule",
    "timezone", "max_concurrent", "inputs",
})
_NODE_FIELDS = frozenset({
    "kind", "next", "tool", "params", "brief", "condition", "if_true", "if_false",
    "cases", "items", "var", "body", "limit", "concurrent", "concurrency", "branches", "prompt",
    "choices", "seconds", "flow_ref", "retries", "retry_backoff", "on_error", "timeout", "output",
    "label", "x", "y",
    # rich human-task fields (approval) -- documented in FLOW_SCHEMA_BLOCK, so
    # the copilot must be able to set them, else "make it expire / escalate /
    # collect a note" edits are rejected as un-editable fields.
    "assignee", "expires_after", "on_expire", "form",
})


class PatchError(ValueError):
    """A patch was malformed, referenced a missing node, or produced an
    invalid flow. The input flow is never mutated."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise PatchError(msg)


def _add_node(flow: Flow, p: dict) -> None:
    node_d = p.get("node")
    _require(isinstance(node_d, dict) and node_d.get("id") and node_d.get("kind"),
             "add_node needs a node object with id and kind")
    node = FlowNode.from_dict(node_d)
    _require(node.id not in flow.nodes, f"add_node: id {node.id!r} already exists")
    after = p.get("after")
    if after is not None:
        prev = flow.nodes.get(str(after))
        _require(prev is not None, f"add_node: after -> unknown node {after!r}")
        if node.next is None:
            node.next = prev.next
        prev.next = node.id
    flow.nodes[node.id] = node
    if not flow.start:
        flow.start = node.id


def _heal(ref: str | None, removed: str, successor: str | None) -> str | None:
    return successor if ref == removed else ref


def _remove_node(flow: Flow, p: dict) -> None:
    nid = str(p.get("id") or "")
    node = flow.nodes.get(nid)
    _require(node is not None, f"remove_node: unknown node {nid!r}")
    successor = node.next if node.next != nid else None
    del flow.nodes[nid]
    for n in flow.nodes.values():
        n.next = _heal(n.next, nid, successor)
        n.if_true = _heal(n.if_true, nid, successor)
        n.if_false = _heal(n.if_false, nid, successor)
        n.on_error = _heal(n.on_error, nid, successor)
        n.on_expire = _heal(n.on_expire, nid, successor)
        for case in n.cases:
            if case.get("to") == nid:
                case["to"] = successor
    if flow.start == nid:
        flow.start = successor or (next(iter(flow.nodes)) if flow.nodes else "")


def _set_field(flow: Flow, p: dict) -> None:
    nid = str(p.get("id") or "")
    field = str(p.get("field") or "")
    node = flow.nodes.get(nid)
    _require(node is not None, f"set_field: unknown node {nid!r}")
    _require(field in _NODE_FIELDS, f"set_field: field {field!r} is not editable")
    d = node.to_dict()
    value = p.get("value")
    if value in ("", None) and field in d and field not in ("next", "if_true", "if_false", "on_error"):
        d.pop(field, None)
    else:
        d[field] = value
    try:
        flow.nodes[nid] = FlowNode.from_dict(d)
    except (TypeError, ValueError, KeyError) as e:
        raise PatchError(f"set_field: bad value for {field!r}: {e}") from e


def _set_flow_field(flow: Flow, p: dict) -> None:
    field = str(p.get("field") or "")
    _require(field in _FLOW_FIELDS, f"set_flow_field: field {field!r} is not editable")
    value = p.get("value")
    if field == "inputs":
        _require(isinstance(value, list) and len(value) <= 32,
                 "set_flow_field: inputs must be a list of at most 32 questions")
        clean = _sanitize_inputs(value)
        _require(len(clean) == len(value),
                 "set_flow_field: each question needs a unique name and supported answer type")
        value = clean
    elif field == "max_concurrent":
        _require(type(value) is int and 0 <= value <= 32,
                 "set_flow_field: simultaneous runs must be between 0 and 32")
    elif field == "timezone":
        _require(isinstance(value, str) and len(value) <= 80,
                 "set_flow_field: time zone must be a valid location name")
        value = value.strip()
        if value:
            from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

            try:
                ZoneInfo(value)
            except (ValueError, ZoneInfoNotFoundError) as e:
                raise PatchError("set_flow_field: unknown time zone") from e
    d = flow.to_dict()
    d[field] = value
    try:
        updated = Flow.from_dict(d)
    except (TypeError, ValueError, KeyError) as e:
        raise PatchError(f"set_flow_field: bad value for {field!r}: {e}") from e
    setattr(flow, field, getattr(updated, field))


def _rewire(flow: Flow, p: dict) -> None:
    nid = str(p.get("id") or "")
    field = str(p.get("field") or "")
    node = flow.nodes.get(nid)
    _require(node is not None, f"rewire: unknown node {nid!r}")
    _require(field in _ROUTE_FIELDS, f"rewire: {field!r} is not a routing field")
    to = p.get("to")
    if to is not None:
        to = str(to)
        _require(to in flow.nodes, f"rewire: -> unknown node {to!r}")
    setattr(node, field, to)


_APPLIERS = {
    "add_node": _add_node,
    "remove_node": _remove_node,
    "set_field": _set_field,
    "set_flow_field": _set_flow_field,
    "rewire": _rewire,
}


def describe_patch(p: dict) -> str:
    """One human line per patch, for the chat transcript / audit trail."""
    op = p.get("op", "?")
    if op == "add_node":
        n = p.get("node") or {}
        where = f" after {p['after']}" if p.get("after") else ""
        return f"add {n.get('kind', '?')} node {n.get('id', '?')}{where}"
    if op == "remove_node":
        return f"remove node {p.get('id', '?')}"
    if op == "set_field":
        if p.get("field") == "concurrency":
            return f"set items at once for {p.get('id', '?')} to {p.get('value') or 'Shared workflow limit'}"
        return f"set {p.get('id', '?')}.{p.get('field', '?')}"
    if op == "set_flow_field":
        return f"set flow.{p.get('field', '?')}"
    if op == "rewire":
        return f"rewire {p.get('id', '?')}.{p.get('field', '?')} -> {p.get('to')}"
    return f"unknown op {op!r}"


def apply_patches(
    flow: Flow,
    patches: list[dict[str, Any]],
    *,
    allow_unclassified_draft: bool = False,
) -> Flow:
    """Apply ``patches`` in order to a copy of ``flow`` and return the result.

    Raises :class:`PatchError` if any patch is malformed or the patched flow
    fails :meth:`Flow.validate`; ``flow`` itself is never mutated. The
    ``allow_unclassified_draft`` escape hatch is reserved for an unsaved
    authoring preview: it tolerates only the exact unclassified-action policy
    error, never a structural, safety, or tool-binding error.
    """
    _require(isinstance(patches, list) and patches, "no patches to apply")
    out = flow.copy()
    for i, p in enumerate(patches):
        _require(isinstance(p, dict), f"patch {i}: not an object")
        op = p.get("op")
        applier = _APPLIERS.get(op)
        _require(applier is not None, f"patch {i}: unknown op {op!r}")
        try:
            applier(out, p)
        except PatchError as e:
            raise PatchError(f"patch {i} ({describe_patch(p)}): {e}") from e
    errs = out.validate()
    blocking, unclassified = partition_draft_validation_errors(errs)
    rejected = blocking or ([] if allow_unclassified_draft else unclassified)
    if rejected:
        raise PatchError("patched flow is invalid: " + "; ".join(rejected[:5]))
    return out


__all__ = ["apply_patches", "describe_patch", "PatchError", "PATCH_OPS"]
