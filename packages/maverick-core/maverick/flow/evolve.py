"""Flow self-rewrite -- propose node-type swaps from grounded per-node outcomes.

The differentiator of holding BOTH representations (deterministic action + agentic
goal) is that a flow can migrate work between them as evidence accumulates:

* an ``agent`` node that succeeds almost every time is a candidate to harden into
  a deterministic ``action`` (cheaper, auditable, no model variance);
* an ``action`` node that fails often is a candidate to hand to an ``agent`` (let
  intelligence absorb the variation the fixed step can't).

Like the operations scientist, this only *proposes* -- it never rewrites a live
flow. A human (or a downstream validation) applies a proposal. Proposals need
``min_support`` observations so a couple of flukes can't move a node. Gated: an
empty list unless the flow engine is on and enough signal has accumulated.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass

from . import node_outcomes
from .ir import (
    LEARNED_OPERATOR_SCHEMA,
    NODE_ACTION,
    NODE_AGENT,
    Flow,
    FlowNode,
    ensure_high_risk_approvals,
    learned_operator_work_digest,
    validate_learned_operator,
)

_DEFAULT_MIN_SUPPORT = 10
_HARDEN_THRESHOLD = 0.9     # agent this reliable -> propose hardening to an action
_SOFTEN_THRESHOLD = 0.5     # action failing this often -> propose softening to an agent
_SWAPPABLE = frozenset({NODE_ACTION, NODE_AGENT})


@dataclass(frozen=True)
class NodeProposal:
    node_id: str
    from_kind: str
    to_kind: str
    reason: str
    n: int
    mean: float
    inferred_tool: str = ""   # for a harden proposal: the tool the node has been calling
    applicable: bool = True
    blocking_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id, "from_kind": self.from_kind,
            "to_kind": self.to_kind, "reason": self.reason,
            "n": self.n, "mean": round(self.mean, 3),
            "inferred_tool": self.inferred_tool,
            "applicable": self.applicable,
            "blocking_reason": self.blocking_reason,
        }


def _infer_tool(flow_id: str, node_id: str) -> str:
    """The single tool an agent node has consistently called (for hardening it to
    a deterministic action), or ``""`` when there's no confident answer -- capture
    off, too few runs, or mixed tools. Never raises."""
    try:
        from . import node_tools
        return node_tools.dominant_tool(flow_id, node_id) or ""
    except Exception:  # pragma: no cover -- inference is best-effort
        return ""


def propose(flow: Flow, *, min_support: int = _DEFAULT_MIN_SUPPORT,
            stats: dict[str, dict] | None = None) -> list[NodeProposal]:
    """Node-type swap proposals for ``flow`` from its grounded per-node outcomes.

    ``stats`` may be injected (else read from :mod:`.node_outcomes`). Only nodes
    with at least ``min_support`` observations are considered."""
    node_stats = stats if stats is not None else node_outcomes.stats(flow.id)
    out: list[NodeProposal] = []
    for node_id, node in flow.nodes.items():
        s = node_stats.get(node_id)
        if not s or s["n"] < min_support:
            continue
        mean = s["mean"]
        if node.kind == NODE_AGENT and mean >= _HARDEN_THRESHOLD:
            tool = _infer_tool(flow.id, node_id)
            reason = (f"agent node succeeds {mean:.0%} over {s['n']} runs -- its behaviour "
                      "is predictable enough to harden into a deterministic action")
            if tool:
                reason += f", and it consistently calls `{tool}`"
            reason += "; canonical parameter bindings still need review or replay evidence"
            out.append(NodeProposal(
                node_id,
                NODE_AGENT,
                NODE_ACTION,
                reason,
                s["n"],
                mean,
                inferred_tool=tool,
                applicable=False,
                blocking_reason=(
                    "tool-name telemetry does not prove the parameters needed to replay "
                    "this behavior"
                ),
            ))
        elif node.kind == NODE_ACTION and mean < _SOFTEN_THRESHOLD:
            out.append(NodeProposal(
                node_id, NODE_ACTION, NODE_AGENT,
                f"action node lands only {mean:.0%} over {s['n']} runs -- hand it to "
                "an agent to absorb the variation the fixed step can't",
                s["n"], mean))
    # Most-evidence first so the strongest signals lead.
    out.sort(key=lambda p: p.n, reverse=True)
    return out


def maybe_propose(flow: Flow, *, min_support: int = _DEFAULT_MIN_SUPPORT) -> list[NodeProposal]:
    """Governed entry point: proposals when the flow engine is on, else empty."""
    from . import enabled
    if not enabled():
        return []
    try:
        return propose(flow, min_support=min_support)
    except Exception:  # pragma: no cover -- a maintenance pass must never crash
        return []


# ---- apply: enact a proposal -------------------------------------------------
#
# This is the arrow that turns a *proposal* into a *changed flow* -- the point
# where the system rewrites itself. It only builds the new definition; the caller
# persists it (versioned, via store.save_flow) and logs the apply so the change
# can be measured and rolled back. Swaps are between the two work kinds only.


def apply_proposal(flow: Flow, node_id: str, to_kind: str, *,
                   tool: str = "", params: dict | None = None,
                   brief: str = "") -> Flow:
    """Return a COPY of ``flow`` with ``node_id`` swapped to ``to_kind`` (does not
    persist). Hardening to an ``action`` needs a ``tool``; softening to an
    ``agent`` needs a ``brief`` (falls back to the node's existing brief/label).

    Raises ``KeyError`` for an unknown node, ``ValueError`` for a non-swappable
    kind or a swap that would leave the node structurally invalid (no tool / no
    brief) -- so an unusable apply is rejected here, before anything is saved."""
    node = flow.nodes.get(node_id)
    if node is None:
        raise KeyError(f"no such node {node_id!r}")
    if to_kind not in _SWAPPABLE:
        raise ValueError(f"can only swap between {sorted(_SWAPPABLE)}, not {to_kind!r}")
    if node.kind not in _SWAPPABLE:
        raise ValueError(f"node {node_id!r} is a {node.kind!r}, not a swappable work node")
    new = flow.copy()
    n: FlowNode = new.nodes[node_id]
    n.kind = to_kind
    n.learned_operator = None
    n.learned_fallback = True
    # A node-kind rewrite never inherits an automatic replay policy from the old
    # implementation. Agent attempts and high-risk actions may already have
    # produced side effects before reporting failure.
    n.retries = 0
    if to_kind == NODE_ACTION:
        n.tool = (tool or n.tool).strip()
        n.brief = ""
        if not n.tool:
            raise ValueError("hardening to an action needs a tool name")
        if params is None:
            raise ValueError(
                "hardening to an action needs reviewed parameter bindings; "
                "tool-name-only evidence is not replayable"
            )
        n.params = dict(params)
    else:  # NODE_AGENT
        n.brief = (brief or n.brief or n.label or "").strip()
        n.tool = ""
        n.params = {}
        if not n.brief:
            raise ValueError("softening to an agent needs a brief")
    return ensure_high_risk_approvals(new)


# ---- measure: did the applied change help? -----------------------------------


_REVERT_MIN_AFTER = 5       # need this many post-change outcomes before judging
_REVERT_MARGIN = 0.15       # revert only a clear drop, never noise


def regressed(impact: dict, *, min_after: int = _REVERT_MIN_AFTER,
              margin: float = _REVERT_MARGIN) -> bool:
    """Whether a measured change clearly HURT: enough post-change outcomes AND the
    mean fell by more than ``margin`` vs. before. Conservative -- thin or
    ambiguous evidence is not a regression, so the autonomous pass never thrashes
    on noise or reverts a change that simply hasn't been exercised yet."""
    after = impact.get("after") or {}
    delta = impact.get("delta")
    if int(after.get("n") or 0) < min_after or delta is None:
        return False
    return delta < -abs(margin)


def revert_node(flow: Flow, node_id: str, prior: FlowNode) -> Flow:
    """Return a copy of ``flow`` with ``node_id``'s WORK definition (kind + tool/
    params or brief) restored from ``prior`` -- an earlier version of that node --
    while keeping the current routing / output / label / layout. Undoes a
    regressed rewrite without disturbing topology that legitimately changed since
    the rewrite was applied."""
    if node_id not in flow.nodes:
        raise KeyError(f"no such node {node_id!r}")
    new = flow.copy()
    n = new.nodes[node_id]
    n.kind, n.tool, n.params, n.brief = prior.kind, prior.tool, dict(prior.params), prior.brief
    n.retries = int(prior.retries)
    n.timeout = prior.timeout
    n.learned_operator = copy.deepcopy(prior.learned_operator)
    n.learned_fallback = prior.learned_fallback
    # Output routing remains the current definition's property. Never silently
    # rebind a restored operator if that contract changed after the prior version.
    if (n.learned_operator is not None
            and (not isinstance(n.learned_operator, dict)
                 or n.learned_operator.get("work_sha256") != learned_operator_work_digest(n))):
        n.learned_operator = None
        n.learned_fallback = True
    return new


def attach_learned_operator(flow: Flow, node_id: str, artifact: dict) -> Flow:
    """Return a draft attaching a validated bounded scalar/composed operator.

    This does not save, activate, or claim an improvement. Existing flow review,
    versioning, publication and rollback remain the authority for deployment.
    """
    if node_id not in flow.nodes:
        raise KeyError(f"no such node {node_id!r}")
    new = flow.copy()
    node = new.nodes[node_id]
    node.learned_operator = {
        "schema": LEARNED_OPERATOR_SCHEMA,
        "work_sha256": learned_operator_work_digest(node),
        "artifact": copy.deepcopy(artifact),
    }
    validate_learned_operator(node)
    return new


def remove_learned_operator(flow: Flow, node_id: str) -> Flow:
    """Return a draft restoring ordinary agent execution, without publishing it."""
    if node_id not in flow.nodes:
        raise KeyError(f"no such node {node_id!r}")
    new = flow.copy()
    new.nodes[node_id].learned_operator = None
    new.nodes[node_id].learned_fallback = True
    return new


def harden_evidence_renewal(flow: Flow, *, bindings: dict[str, str]) -> Flow:
    """Restrict one reviewed renewal agent step to existing pure flow nodes.

    Authority/source/downstream preconditions are enforced by the vendor
    evolution application service before this graph receives its typed data.
    No tool telemetry, tool generation, credential use or new permissions are
    inferred. Only these two reviewed bindings are supported initially.
    """
    from .ir import NODE_BRANCH, NODE_SCOPE, NODE_SETVAR

    if bindings != {"due_at": "due_at", "now": "now"}:
        raise ValueError("renewal automation requires exact reviewed due_at/now bindings")
    if len(flow.nodes) != 1 or flow.nodes[flow.start].kind != NODE_AGENT:
        raise ValueError("renewal hardening supports one isolated agent step")
    new = flow.copy()
    new.nodes[flow.start] = FlowNode(
        id=flow.start, kind=NODE_SCOPE,
        body=Flow(id="renewal-arithmetic", name="Evidence freshness comparison", start="remaining", nodes={
            "remaining": FlowNode(id="remaining", kind=NODE_SETVAR, next="due",
                                  assignments={"remaining": "{{sub(due_at,now)}}"}),
            "due": FlowNode(id="due", kind=NODE_BRANCH, condition="remaining <= 0",
                            if_true="renew", if_false="fresh"),
            "renew": FlowNode(id="renew", kind=NODE_SETVAR,
                              assignments={"classification": "renewal_due"}),
            "fresh": FlowNode(id="fresh", kind=NODE_SETVAR,
                              assignments={"classification": "fresh"}),
        }),
    )
    errors = new.validate()
    if errors:
        raise ValueError("; ".join(errors))
    return new


def same_work_definition(left: FlowNode, right: FlowNode) -> bool:
    """Whether a later save preserved the exact work implementation.

    Routing, labels, layout, and other node metadata may legitimately change
    after a rewrite. Automatic regression rollback may cross those later saves
    only while the applied kind/tool/params/brief/retry behavior is untouched.
    """
    return (
        left.kind == right.kind
        and left.tool == right.tool
        and dict(left.params) == dict(right.params)
        and left.brief == right.brief
        and int(left.retries) == int(right.retries)
        and left.timeout == right.timeout
        and left.output == right.output
        and left.learned_operator == right.learned_operator
    )


def _mean(vals: list[float]) -> float | None:
    return sum(vals) / len(vals) if vals else None


def measure(
    flow_id: str,
    node_id: str,
    since_ts: float | None = None,
    *,
    before_revision: str = "",
    after_revision: str = "",
    series: list[tuple[float, float]] | None = None,
) -> dict:
    """Compare explicit immutable definition cohorts for an applied rewrite.

    ``before_revision`` and ``after_revision`` are the authoritative production
    path. ``since_ts`` plus an injected ``series`` remains as a compatibility
    seam for deterministic callers/tests written before definition cohorts were
    persisted; wall-clock partitioning is never used by the autonomous driver.
    """
    if before_revision and after_revision:
        before = [
            value
            for _ts, value in node_outcomes.series(
                flow_id, node_id, cohort=before_revision,
            )
        ]
        after = [
            value
            for _ts, value in node_outcomes.series(
                flow_id, node_id, cohort=after_revision,
            )
        ]
    else:
        if since_ts is None:
            raise ValueError("measurement needs explicit before/after revisions")
        rows = series if series is not None else node_outcomes.series(flow_id, node_id)
        before = [v for ts, v in rows if ts < since_ts]
        after = [v for ts, v in rows if ts >= since_ts]
    bmean, amean = _mean(before), _mean(after)
    delta = (amean - bmean) if (bmean is not None and amean is not None) else None
    return {
        "before": {"n": len(before), "mean": bmean},
        "after": {"n": len(after), "mean": amean},
        "delta": delta,
        "improved": (delta is not None and delta > 0),
        "before_revision": str(before_revision),
        "after_revision": str(after_revision),
    }


__all__ = ["NodeProposal", "propose", "maybe_propose", "apply_proposal",
           "measure", "regressed", "revert_node", "same_work_definition",
           "attach_learned_operator", "remove_learned_operator"]
