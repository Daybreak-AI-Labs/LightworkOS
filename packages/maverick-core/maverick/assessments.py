"""Governance assessments: privacy, security, and AI-risk reviews of every
capability the platform runs.

An *assessment* is a governance record for one subject (an agent pack or a
flow). It carries three lenses -- ``privacy``, ``security``, ``ai_risk`` -- each
a list of findings auto-drafted from the subject's *declared* surface (the tools
it may reach, the data/hosts/paths it touches, its risk ceiling, whether a human
gate exists). A human then reviews each lens (accept / needs-work), attaches
evidence, and sets a re-review cadence. When the subject's surface later changes,
:func:`refresh` detects the drift (via a surface hash) and flips an accepted
assessment back to ``needs_review`` -- the "naturally improves as it changes"
guarantee.

Storage is a private, versioned JSON register under the tenant data home. Every
mutation is a strict cross-process transaction with atomic publication and
revision CAS. Auto-draft heuristics remain conservative and explainable, while
an accepted review fails closed unless its audit decision is durably committed.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections import deque
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from .paths import data_dir

LENSES = ("privacy", "security", "ai_risk")
LENS_LABELS = {"privacy": "Privacy", "security": "Security", "ai_risk": "AI risk"}
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Assessment is a security boundary, so adversarial graphs need explicit
# resource ceilings independent of the runner's own cycle guard.  A partial
# walk is never presented as a low/medium-risk complete result.
_FLOW_MAX_DEPTH = 32
_FLOW_MAX_NODES = 10_000
_FLOW_MAX_SUBFLOWS = 512

# Tool-name substrings that signal a capability class. Matched case-insensitively
# against a subject's allow_tools; deliberately broad so a new tool named e.g.
# ``slack_bot`` still reads as an egress/network sink.
_SHELL_HINTS = ("shell", "exec", "bash", "subprocess", "code_run", "python")
_WRITE_HINTS = ("write", "edit", "create_file", "delete", "fs_", "file_write")
_EGRESS_HINTS = ("web", "browser", "http", "fetch", "email", "slack", "webhook",
                 "post", "send", "upload", "sms", "call", "publish")
_READ_DATA_HINTS = ("read_file", "files", "knowledge", "search", "db", "sql",
                    "query", "email_read", "crm", "sheet")
_CRED_HINTS = ("connector", "oauth", "token", "secret", "credential", "api_key")


# --------------------------------------------------------------------------- #
# Subject surface -- the declared capability footprint we assess.
# --------------------------------------------------------------------------- #

def agent_surface(name: str) -> dict[str, Any] | None:
    """The assessed surface of an agent pack, or ``None`` if unknown."""
    try:
        from .domain_edit import resolved_view
        v = resolved_view(name)
    except Exception:  # pragma: no cover -- factory layer optional
        return None
    if v is None:
        return None
    steps = v.get("workflow") or []
    declared = v.get("declared_prompt_gate")
    enforced = v.get("enforced_gate")
    return {
        "kind": "agent",
        "subject": name,
        "description": v.get("description") or "",
        "allow_tools": sorted(v.get("allow_tools") or []),
        "deny_tools": sorted(v.get("deny_tools") or []),
        "max_risk": v.get("max_risk") or "low",
        "allow_paths": sorted(v.get("allow_paths") or []),
        "allow_hosts": sorted(v.get("allow_hosts") or []),
        "mcp_servers": sorted(v.get("mcp_servers") or []),
        "knowledge_sources": sorted(v.get("knowledge_sources") or []),
        "declared_prompt_gate": declared,
        "enforced_gate": enforced,
        # Backward-compatible surface field, narrowed to an actual control.
        "has_human_gate": bool(enforced),
        "steps": len(steps),
    }


def _node_attr(node: Any, name: str, default: Any = None) -> Any:
    if isinstance(node, dict):
        return node.get(name, default)
    return getattr(node, name, default)


def _flow_nodes(flow: Any) -> dict[str, Any]:
    raw = getattr(flow, "nodes", None)
    if isinstance(raw, dict):
        return {str(key): value for key, value in raw.items()}
    if isinstance(raw, list):
        return {
            str(_node_attr(node, "id", index)): node
            for index, node in enumerate(raw)
        }
    return {}


@dataclass
class _FlowAnalysis:
    tools: set[str] = field(default_factory=set)
    tool_risks: dict[str, str] = field(default_factory=dict)
    kinds: set[str] = field(default_factory=set)
    approval_gaps: set[str] = field(default_factory=set)
    risky_actions: set[str] = field(default_factory=set)
    unresolved_tools: set[str] = field(default_factory=set)
    unresolved_subflows: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)
    approval_nodes: int = 0
    node_count: int = 0
    subflow_count: int = 0
    complete: bool = True

    def fail(self, message: str) -> None:
        self.complete = False
        if message not in self.errors and len(self.errors) < 100:
            self.errors.append(message[:500])


def _flow_successors(
    node: Any, approved: bool, *, approval_can_authorize: bool,
) -> list[tuple[str, bool]]:
    """Every runtime route from a node, carrying approval provenance.

    Binary approval ``next`` is the only edge that establishes authorization.
    Choice approvals are data-routing inputs and expiry/error lanes do not prove
    approval.  Existing authorization from an earlier gate is never discarded.
    """
    kind = str(_node_attr(node, "kind", "") or "")
    out: list[tuple[str, bool]] = []

    def add(target: Any, state: bool = approved) -> None:
        if target not in (None, ""):
            item = (str(target), bool(state))
            if item not in out:
                out.append(item)

    if kind == "branch":
        default = _node_attr(node, "next")
        add(_node_attr(node, "if_true") or default)
        add(_node_attr(node, "if_false") or default)
    elif kind == "switch":
        for case in _node_attr(node, "cases", []) or []:
            if isinstance(case, dict):
                add(case.get("to") or _node_attr(node, "next"))
        add(_node_attr(node, "next"))
    elif kind == "approval":
        choices = _node_attr(node, "choices", []) or []
        add(
            _node_attr(node, "next"),
            approved or (approval_can_authorize and not bool(choices)),
        )
        add(_node_attr(node, "on_expire"), approved)
    else:
        add(_node_attr(node, "next"))

    # Work failures and scope/subflow catch lanes may bypass an otherwise safe
    # success route.  Including the edge for every node is conservative when a
    # handler cannot currently fail that way, and future-proofs the assessment.
    add(_node_attr(node, "on_error"), approved)
    return out


def _analyse_flow_graph(  # noqa: C901 - bounded abstract flow interpreter
    root: Any,
    *,
    flow_store: Any,
    manifest: dict[str, str | None] | None,
    initial_errors: list[str] | None = None,
) -> _FlowAnalysis:
    from .safety.tool_risk import (
        RISK_LEVELS,
        risk_rank,
        tool_risk,
        tool_risk_is_classified,
    )
    from .tool_reliability import is_retry_safe

    result = _FlowAnalysis()
    for error in initial_errors or []:
        result.fail(error)

    loaded_snapshots: dict[str, Any] = {}
    analysed_states: set[tuple[str, bool]] = set()
    counted_flows: set[str] = set()
    counted_subflows: set[str] = set()

    def register_tool(tool_value: Any, location: str, approved: bool) -> None:
        tool = str(tool_value or "").strip()
        if not tool:
            result.unresolved_tools.add(f"{location}:<missing>")
            result.risky_actions.add(location)
            if not approved:
                result.approval_gaps.add(location)
            result.fail(f"{location}: action tool is missing")
            return
        result.tools.add(tool)
        try:
            classified = bool(tool_risk_is_classified(tool))
            risk = str(tool_risk(tool))
        except Exception:
            classified, risk = False, "high"
        if not classified or risk not in RISK_LEVELS:
            result.unresolved_tools.add(tool)
            result.fail(f"{location}: tool {tool!r} has no verified risk classification")
            risk = "high"
        previous = result.tool_risks.get(tool, "low")
        if risk_rank(risk) > risk_rank(previous):
            result.tool_risks[tool] = risk
        else:
            result.tool_risks.setdefault(tool, previous)
        try:
            irreversible = not is_retry_safe(tool)
        except Exception:
            irreversible = True
        requires_gate = risk_rank(risk) >= risk_rank("high") or irreversible
        if requires_gate:
            result.risky_actions.add(f"{location}:{tool}")
            if not approved:
                result.approval_gaps.add(f"{location}:{tool}")

    def resolve_subflow(ref: str) -> tuple[Any | None, str]:
        if manifest is not None:
            if ref not in manifest:
                result.unresolved_subflows.add(ref)
                result.fail(f"subflow {ref!r} is absent from the pinned release manifest")
                return None, f"missing:{ref}"
            digest = manifest.get(ref)
            if digest is None:
                result.unresolved_subflows.add(ref)
                result.fail(f"subflow {ref!r} is unresolved in the pinned release")
                return None, f"missing:{ref}"
            token = f"snapshot:{digest}"
            if token not in loaded_snapshots:
                try:
                    child = flow_store.load_flow_snapshot(str(digest))
                except Exception:
                    result.unresolved_subflows.add(ref)
                    result.fail(f"subflow {ref!r} pinned snapshot cannot be verified")
                    return None, token
                if str(getattr(child, "id", "") or "") != ref:
                    result.unresolved_subflows.add(ref)
                    result.fail(f"subflow {ref!r} pinned snapshot has the wrong identity")
                    return None, token
                loaded_snapshots[token] = child
            return loaded_snapshots[token], token
        try:
            child = flow_store.load_flow(ref)
        except Exception:
            child = None
        if child is None:
            result.unresolved_subflows.add(ref)
            result.fail(f"subflow {ref!r} cannot be resolved")
            return None, f"live-missing:{ref}"
        revision = str(getattr(child, "revision", "") or "")
        version = int(getattr(child, "version", 0) or 0)
        return child, f"live:{ref}:{revision}:v{version}"

    def analyse(  # noqa: C901 - node kinds intentionally mirror the flow IR
        flow: Any,
        *,
        inherited_approval: bool,
        depth: int,
        token: str,
        location: str,
        active_subflows: frozenset[str],
        approval_can_authorize: bool,
    ) -> None:
        if depth > _FLOW_MAX_DEPTH:
            result.fail(f"{location}: flow analysis exceeded the depth limit")
            return
        state_key = (token, bool(inherited_approval))
        if state_key in analysed_states:
            return
        analysed_states.add(state_key)
        nodes = _flow_nodes(flow)
        if not nodes:
            result.fail(f"{location}: flow has no readable nodes")
            return
        if token not in counted_flows:
            counted_flows.add(token)
            if result.node_count + len(nodes) > _FLOW_MAX_NODES:
                result.fail(f"{location}: flow analysis exceeded the node limit")
                return
            result.node_count += len(nodes)
            for node in nodes.values():
                kind = str(_node_attr(node, "kind", "") or "")
                result.kinds.add(kind or "<unknown>")
                if kind == "approval":
                    result.approval_nodes += 1

        start = str(getattr(flow, "start", "") or "")
        if start not in nodes:
            result.fail(f"{location}: flow start cannot be resolved")
            return
        queue: deque[tuple[str, bool]] = deque([(start, inherited_approval)])
        seen: set[tuple[str, bool]] = set()
        while queue:
            node_id, approved = queue.popleft()
            route_state = (node_id, approved)
            if route_state in seen:
                continue
            seen.add(route_state)
            node = nodes.get(node_id)
            if node is None:
                result.fail(f"{location}: route targets missing node {node_id!r}")
                continue
            kind = str(_node_attr(node, "kind", "") or "")
            node_location = f"{location}/{node_id}"
            if kind == "action":
                register_tool(_node_attr(node, "tool", ""), node_location, approved)
            elif kind == "agent":
                # Agent nodes deliberately omit a tool allow-list.  Until the
                # invoked pack/release is pinned into the IR, its action surface
                # is unknowable and therefore cannot inherit a guessed medium.
                unresolved = f"agent:{node_location}"
                result.unresolved_tools.add(unresolved)
                result.risky_actions.add(unresolved)
                if not approved:
                    result.approval_gaps.add(unresolved)
                result.fail(f"{node_location}: agent tool surface is not pinned")
            elif kind in {"foreach", "while", "scope"}:
                body = _node_attr(node, "body")
                if body is None:
                    result.fail(f"{node_location}: {kind} body is missing")
                else:
                    analyse(
                        body,
                        inherited_approval=approved,
                        depth=depth + 1,
                        token=f"{token}/{node_id}:body",
                        location=f"{node_location}:body",
                        active_subflows=active_subflows,
                        approval_can_authorize=False,
                    )
            elif kind == "parallel":
                branches = list(_node_attr(node, "branches", []) or [])
                if not branches:
                    result.fail(f"{node_location}: parallel branches are missing")
                for index, branch in enumerate(branches):
                    analyse(
                        branch,
                        inherited_approval=approved,
                        depth=depth + 1,
                        token=f"{token}/{node_id}:branch:{index}",
                        location=f"{node_location}:branch:{index}",
                        active_subflows=active_subflows,
                        approval_can_authorize=False,
                    )
            elif kind == "subflow":
                ref = str(_node_attr(node, "flow_ref", "") or "").strip()
                if not ref:
                    result.unresolved_subflows.add("<missing>")
                    result.fail(f"{node_location}: subflow reference is missing")
                else:
                    child, child_token = resolve_subflow(ref)
                    cycle_token = child_token
                    if cycle_token in active_subflows:
                        result.unresolved_subflows.add(ref)
                        result.fail(f"{node_location}: cyclic subflow {ref!r} is not executable")
                    elif child is not None:
                        if cycle_token not in counted_subflows:
                            if len(counted_subflows) >= _FLOW_MAX_SUBFLOWS:
                                result.fail("flow analysis exceeded the subflow limit")
                                child = None
                            else:
                                counted_subflows.add(cycle_token)
                                result.subflow_count += 1
                        if child is not None:
                            analyse(
                                child,
                                inherited_approval=approved,
                                depth=depth + 1,
                                token=child_token,
                                location=f"{node_location}:subflow:{ref}",
                                active_subflows=active_subflows | {cycle_token},
                                approval_can_authorize=False,
                            )
            elif kind not in {
                "approval", "branch", "switch", "delay", "wait_event", "setvar",
            }:
                result.fail(f"{node_location}: unknown node kind {kind!r}")

            for target, next_approved in _flow_successors(
                node, approved, approval_can_authorize=approval_can_authorize,
            ):
                queue.append((target, next_approved))

    root_id = str(getattr(root, "id", "") or "<root>")
    analyse(
        root,
        inherited_approval=False,
        depth=0,
        token=f"root:{root_id}",
        location=root_id,
        active_subflows=frozenset({f"root:{root_id}"}),
        approval_can_authorize=True,
    )
    return result


def flow_surface(flow_id: str) -> dict[str, Any] | None:
    """Conservatively assess one coherent flow release/draft snapshot.

    The walk covers every executable route through nested container bodies,
    error/expiry lanes, parallel branches, and transitive pinned subflows.  It
    proves approval dominance path-by-path; an unrelated approval node is not
    treated as an enforcement control.  Missing pins, unknown tools, agent
    capability envelopes, cycles, or resource-limit exhaustion fail high.
    """
    try:
        from .flow import store as flow_store
    except Exception:  # pragma: no cover -- flow engine optional
        return None

    initial_errors: list[str] = []
    release: dict[str, Any] = {}
    manifest: dict[str, str | None] | None = None
    source = "draft"
    try:
        published = flow_store.load_published_bundle(flow_id)
    except Exception:
        published = None
        initial_errors.append("published release failed integrity verification")
    if published is not None:
        flow, release = published
        manifest = dict(release.get("subflow_digests") or {})
        source = "published"
    else:
        try:
            flow = flow_store.load_flow(flow_id)
        except Exception:  # pragma: no cover -- storage failure
            return None
        if flow is None:
            return None
        # Pin a coherent current-definition bundle for this assessment.  The
        # objects are immutable CAS evidence; this does not activate the flow.
        try:
            digest, version, manifest = flow_store.snapshot_current_flow_bundle(flow_id)
            flow = flow_store.load_flow_snapshot(digest)
            release = {
                "definition_digest": digest,
                "definition_version": version,
                "subflow_digests": manifest,
                "release_digest": flow_store.release_digest_for(digest, manifest),
            }
            source = "assessment_snapshot"
        except Exception:
            # Invalid drafts still need a useful fail-high assessment instead of
            # disappearing from governance.  Live child resolution is marked by
            # the missing immutable release digest in the surface hash.
            manifest = None
            initial_errors.append("draft could not be pinned as a verified flow release")

    analysis = _analyse_flow_graph(
        flow,
        flow_store=flow_store,
        manifest=manifest,
        initial_errors=initial_errors,
    )
    max_risk = "low"
    from .safety.tool_risk import risk_rank

    for risk in analysis.tool_risks.values():
        if risk_rank(risk) > risk_rank(max_risk):
            max_risk = risk
    if not analysis.complete:
        max_risk = "high"
    declared_gate = "approval" if analysis.approval_nodes else None
    enforced_gate = (
        "approval"
        if analysis.complete and analysis.approval_nodes and not analysis.approval_gaps
        else None
    )
    return {
        "kind": "flow",
        "subject": flow_id,
        "description": getattr(flow, "name", "") or "",
        "allow_tools": sorted(analysis.tools),
        "deny_tools": [],
        "max_risk": max_risk,
        "tool_risks": dict(sorted(analysis.tool_risks.items())),
        "allow_paths": [], "allow_hosts": [], "mcp_servers": [],
        "knowledge_sources": [],
        "declared_prompt_gate": declared_gate,
        "enforced_gate": enforced_gate,
        "has_human_gate": bool(enforced_gate),
        "analysis_complete": analysis.complete,
        "analysis_errors": analysis.errors,
        "approval_gaps": sorted(analysis.approval_gaps),
        "unresolved_tools": sorted(analysis.unresolved_tools),
        "unresolved_subflows": sorted(analysis.unresolved_subflows),
        "release_source": source,
        "definition_digest": release.get("definition_digest"),
        "release_digest": release.get("release_digest"),
        "release_id": release.get("release_id"),
        "subflow_digests": dict(sorted((manifest or {}).items())),
        "steps": analysis.node_count,
        "subflows": analysis.subflow_count,
    }


def subject_surface(kind: str, name: str) -> dict[str, Any] | None:
    return agent_surface(name) if kind == "agent" else flow_surface(name)


def _hash_surface(surface: dict[str, Any]) -> str:
    """A stable digest of the capability-bearing fields, so a later change to
    tools / data / risk / gating is detectable as drift."""
    keyed = {k: surface.get(k) for k in (
        "allow_tools", "deny_tools", "max_risk", "allow_paths", "allow_hosts",
        "mcp_servers", "knowledge_sources", "declared_prompt_gate",
        "enforced_gate", "has_human_gate", "tool_risks", "analysis_complete",
        "approval_gaps", "unresolved_tools", "unresolved_subflows",
        "release_digest")}
    blob = json.dumps(keyed, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Auto-draft heuristics -- one generator per lens.
# --------------------------------------------------------------------------- #

def _matches(tools: list[str], hints: tuple[str, ...]) -> list[str]:
    lo = [t.lower() for t in tools]
    return sorted({tools[i] for i, t in enumerate(lo) if any(h in t for h in hints)})


def _finding(lens: str, control: str, severity: str, note: str, mitigation: str) -> dict:
    return {"lens": lens, "control": control, "severity": severity, "note": note,
            "mitigation": mitigation, "status": "open", "evidence": []}


def _privacy_findings(s: dict) -> list[dict]:
    out: list[dict] = []
    reads = _matches(s["allow_tools"], _READ_DATA_HINTS)
    egress = _matches(s["allow_tools"], _EGRESS_HINTS)
    if s["knowledge_sources"]:
        out.append(_finding("privacy", "Sensitive data access", "medium",
            f"Reads {len(s['knowledge_sources'])} knowledge source(s); may surface personal or confidential data.",
            "Confirm the sources contain no PII beyond what this task needs; apply redaction at ingestion."))
    if reads:
        out.append(_finding("privacy", "Data collection", "low",
            "Can read data via: " + ", ".join(reads) + ".",
            "Scope reads to the minimum records required (data minimisation)."))
    if reads and egress:
        out.append(_finding("privacy", "Cross-border / third-party transfer", "high",
            "Reads data AND can send it outward via: " + ", ".join(egress) + ".",
            "Verify a lawful basis and DPA for any external recipient; keep an egress allow-list."))
    if s["allow_hosts"]:
        out.append(_finding("privacy", "External endpoints", "low",
            "Reaches hosts: " + ", ".join(s["allow_hosts"]) + ".",
            "Confirm each host is an approved processor."))
    if not out:
        out.append(_finding("privacy", "Data handling", "low",
            "No obvious data-access or egress tools declared.",
            "Re-check after any tool change."))
    return out


def _security_findings(s: dict) -> list[dict]:
    out: list[dict] = []
    if not s.get("analysis_complete", True):
        detail = "; ".join((s.get("analysis_errors") or [])[:3])
        out.append(_finding("security", "Incomplete capability analysis", "high",
            "The executable capability graph could not be fully verified."
            + (f" {detail}" if detail else ""),
            "Resolve every tool/subflow pin and re-run the bounded assessment before approval."))
    if s.get("approval_gaps"):
        out.append(_finding("security", "Approval path bypass", "high",
            f"{len(s['approval_gaps'])} high-risk or irreversible action path(s) can execute without a dominating approval.",
            "Route every incoming, error, expiry, nested, and subflow path through a binary persisted approval."))
    shell = _matches(s["allow_tools"], _SHELL_HINTS)
    writes = _matches(s["allow_tools"], _WRITE_HINTS)
    creds = _matches(s["allow_tools"], _CRED_HINTS)
    if shell:
        out.append(_finding("security", "Arbitrary code / shell execution", "high",
            "Can execute code/shell via: " + ", ".join(shell) + ".",
            "Ensure execution is sandboxed (sandbox.exec); require an approval gate for risky steps."))
    if writes or s["allow_paths"]:
        out.append(_finding("security", "Write / filesystem access", "medium",
            "Can modify state via: " + ", ".join(writes + s["allow_paths"]) + ".",
            "Constrain writable paths; prefer review before irreversible writes."))
    if creds or s["mcp_servers"]:
        out.append(_finding("security", "Credential / connector reach", "medium",
            "Uses connectors/servers: " + ", ".join(creds + s["mcp_servers"]) + ".",
            "Store secrets as sealed connections; scope tokens to least privilege."))
    if _SEVERITY_RANK.get(s["max_risk"], 0) >= _SEVERITY_RANK["high"]:
        out.append(_finding("security", "Risk ceiling", "high",
            "Risk ceiling is 'high' — the widest action envelope.",
            "Justify why 'high' is required; add a human gate on the terminal step."))
    if not out:
        out.append(_finding("security", "Capability envelope", "low",
            "No high-risk execution, write, or credential tools declared.",
            "Re-check after any tool or risk-ceiling change."))
    return out


def _ai_risk_findings(s: dict) -> list[dict]:
    out: list[dict] = []
    if not s.get("analysis_complete", True):
        out.append(_finding("ai_risk", "Assessment completeness", "high",
            "The system could not prove the complete executable tool and subflow surface.",
            "Do not accept this assessment until every capability is pinned, classified, and traversed."))
    risky = _SEVERITY_RANK.get(s["max_risk"], 0) >= 1
    enforced = s.get("enforced_gate")
    # Legacy/custom callers may provide only has_human_gate.  Preserve that
    # behavior without treating a declared_prompt_gate as enforcement.
    if enforced is None and "enforced_gate" not in s and s.get("has_human_gate"):
        enforced = "approval"
    declared = s.get("declared_prompt_gate")
    gate_rank = {None: 0, "review": 1, "approval": 2}
    prompt_gap = gate_rank.get(declared, 0) > gate_rank.get(enforced, 0)
    if prompt_gap:
        note = (
            f"Declares a prompt-only {declared} gate, but terminal release is "
            f"protected by only {enforced or 'no persisted checkpoint'}."
        )
        mitigation = (
            "Move the gate to the terminal playbook step or output contract, "
            "or compile the playbook into an executable approval flow."
        )
        out.append(_finding("ai_risk", "Human oversight", "high",
            note, mitigation))
    elif risky and not enforced:
        note = (
            "Acts at medium/high risk with no persisted approval or review "
            "gate protecting terminal release."
        )
        mitigation = "Add an enforced approval/review gate before release."
        out.append(_finding("ai_risk", "Human oversight", "high",
            note, mitigation))
    elif enforced:
        out.append(_finding("ai_risk", "Human oversight", "low",
            f"A persisted {enforced} sign-off protects terminal deliverable release.",
            "Keep the release guard bound to the reviewed deliverable version."))
    else:
        out.append(_finding("ai_risk", "Human oversight", "low",
            "Low-risk ceiling; autonomous operation is proportionate.",
            "Re-evaluate if the risk ceiling is raised."))
    out.append(_finding("ai_risk", "Accuracy / hallucination", "low",
        "Model output can be wrong or fabricated; impact scales with the action envelope.",
        "Ground with knowledge sources where possible; verify before acting on generated facts."))
    if _matches(s["allow_tools"], _EGRESS_HINTS):
        out.append(_finding("ai_risk", "Autonomous external action", "medium",
            "Can take outward actions (send/post/publish) that are hard to reverse.",
            "Gate outward actions; log them to the operating record for audit."))
    return out


_GENERATORS = {"privacy": _privacy_findings, "security": _security_findings,
               "ai_risk": _ai_risk_findings}

# Built-in templates select which lenses to run. Custom templates (same shape)
# can be dropped into <home>/assessments/templates.json.
TEMPLATES: dict[str, dict] = {
    "baseline": {"label": "Baseline (privacy · security · AI risk)", "lenses": list(LENSES)},
    "security_only": {"label": "Security review only", "lenses": ["security"]},
    "privacy_only": {"label": "Privacy / DPIA only", "lenses": ["privacy"]},
}


def list_templates() -> dict[str, dict]:
    """Built-in templates merged with any custom ones on disk."""
    out = dict(TEMPLATES)
    path = data_dir("assessments", "templates.json")
    try:
        if path.exists():
            for tid, tpl in (json.loads(path.read_text("utf-8")) or {}).items():
                lenses = [x for x in (tpl.get("lenses") or []) if x in LENSES]
                if lenses:
                    out[str(tid)] = {"label": str(tpl.get("label") or tid), "lenses": lenses}
    except Exception:  # pragma: no cover -- custom templates fail soft
        pass
    return out


def lens_status(findings: list[dict]) -> str:
    """'attention' if any open finding is high severity, else 'ok'."""
    for f in findings:
        if f.get("status") == "open" and _SEVERITY_RANK.get(f.get("severity"), 0) >= 2:
            return "attention"
    return "ok"


def auto_draft(kind: str, name: str, template: str = "baseline",
               now: float | None = None) -> dict | None:
    """A fresh assessment for ``name``, findings generated per the template's
    lenses. ``None`` if the subject is unknown."""
    surface = subject_surface(kind, name)
    if surface is None:
        return None
    now = time.time() if now is None else now
    tpl = list_templates().get(template) or TEMPLATES["baseline"]
    lenses: dict[str, dict] = {}
    for lens in tpl["lenses"]:
        findings = _GENERATORS[lens](surface)
        lenses[lens] = {"status": "open", "findings": findings, "reviewer": "",
                        "reviewed_at": None, "note": ""}
    return {
        "kind": kind, "subject": name, "template": template,
        "description": surface.get("description") or "",
        "subject_hash": _hash_surface(surface),
        "status": "draft", "lenses": lenses,
        "cadence_days": 0, "created_at": now, "updated_at": now,
        "reviewed_at": None, "due_at": None,
    }


# --------------------------------------------------------------------------- #
# Store -- one JSON register keyed by "<kind>:<subject>".
# --------------------------------------------------------------------------- #

_REGISTER_SCHEMA = 2
_REVIEW_TRANSACTIONS = "_review_transactions"
_REVIEW_TRANSACTION_LIMIT = 16


class AssessmentRegisterError(RuntimeError):
    """The governance register is corrupt, unavailable, or unsafe to mutate."""


class AssessmentVersionConflict(AssessmentRegisterError):
    """A caller attempted to mutate a stale assessment revision."""


class AssessmentAuditError(AssessmentRegisterError):
    """A mandatory review audit row could not be durably committed."""


def _review_transactions(record: dict) -> list[dict]:
    raw = record.get(_REVIEW_TRANSACTIONS, [])
    if not isinstance(raw, list) or len(raw) > _REVIEW_TRANSACTION_LIMIT:
        raise AssessmentRegisterError("assessment review outbox is invalid")
    out: list[dict] = []
    for item in raw:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("transaction_id"), str)
            or item.get("phase") not in {"prepared", "published_pending_audit"}
            or not isinstance(item.get("candidate"), dict)
        ):
            raise AssessmentRegisterError("assessment review outbox is invalid")
        _validated_revision(item.get("base_revision"), label="review base")
        _validated_revision(item.get("new_revision"), label="review candidate")
        out.append(item)
    return out


def _without_review_transactions(record: dict) -> dict:
    return {
        key: value for key, value in record.items()
        if key != _REVIEW_TRANSACTIONS
    }


def _ensure_no_pending_review(record: dict) -> None:
    if _review_transactions(record):
        raise AssessmentVersionConflict(
            "assessment has a pending review transaction; recover it first"
        )

def _path():
    return data_dir("assessments", "register.json")


def _key(kind: str, name: str) -> str:
    return f"{kind}:{name}"


def _validated_revision(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise AssessmentRegisterError(f"{label} revision is invalid")
    return value


def _record_revision(record: dict | None) -> int:
    if record is None:
        return 0
    return _validated_revision(record.get("revision", 0), label="assessment")


def _check_expected_revision(record: dict | None, expected: int | None) -> int:
    revision = _record_revision(record)
    if expected is not None:
        expected_value = _validated_revision(expected, label="expected assessment")
        if revision != expected_value:
            raise AssessmentVersionConflict(
                f"assessment changed (expected revision {expected_value}, found {revision})"
            )
    return revision


def _read_register_unlocked() -> tuple[dict[str, dict], int]:
    path = _path()
    if not path.exists():
        return {}, 0
    try:
        ensure_private_file(path, 0o600)
        raw = json.loads(atomic_read_text(path, encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise AssessmentRegisterError("assessment register is unreadable or corrupt") from exc
    if not isinstance(raw, dict):
        raise AssessmentRegisterError("assessment register must be a JSON object")

    # Legacy registers were the assessment mapping itself.  Migrate on the
    # next write without silently discarding it.
    if "schema_version" not in raw and "assessments" not in raw:
        records, revision = raw, 0
    else:
        if raw.get("schema_version") != _REGISTER_SCHEMA:
            raise AssessmentRegisterError("assessment register schema is unsupported")
        revision = _validated_revision(raw.get("revision"), label="register")
        records = raw.get("assessments")
        if not isinstance(records, dict):
            raise AssessmentRegisterError("assessment register records are invalid")
    validated: dict[str, dict] = {}
    for key, record in records.items():
        if not isinstance(key, str) or not isinstance(record, dict):
            raise AssessmentRegisterError("assessment register contains an invalid record")
        _record_revision(record)
        _review_transactions(record)
        validated[key] = record
    return validated, revision


def _write_register_unlocked(
    data: dict[str, dict], *, expected_register_revision: int,
    effect_guard: Callable[[], None] | None = None,
) -> int:
    path = _path()
    # CAS even though disciplined callers hold the strict lock.  This catches a
    # legacy writer that bypasses the lock instead of overwriting its update.
    _current, current_revision = _read_register_unlocked()
    if current_revision != expected_register_revision:
        raise AssessmentVersionConflict(
            "assessment register changed during the transaction"
        )
    next_revision = current_revision + 1
    payload = {
        "schema_version": _REGISTER_SCHEMA,
        "revision": next_revision,
        "assessments": data,
    }
    atomic_write_text(
        path,
        json.dumps(payload, sort_keys=True, indent=2, default=str),
        mode=0o600, effect_guard=effect_guard,
    )
    ensure_private_file(path, 0o600)
    return next_revision


def _recover_published_reviews_unlocked(
    data: dict[str, dict], register_revision: int,
) -> int:
    """Retry final publication audit receipts without replaying a decision."""
    changed = False
    for record in data.values():
        transactions = _review_transactions(record)
        kept = []
        for transaction in transactions:
            if (
                transaction["phase"] == "published_pending_audit"
                and _audit_review_transaction(transaction, "published")
            ):
                changed = True
                continue
            kept.append(transaction)
        if len(kept) != len(transactions):
            if kept:
                record[_REVIEW_TRANSACTIONS] = kept
            else:
                record.pop(_REVIEW_TRANSACTIONS, None)
    if not changed:
        return register_revision
    try:
        return _write_register_unlocked(
            data, expected_register_revision=register_revision,
        )
    except (OSError, AssessmentRegisterError):
        # The publication audit already committed. Leaving the receipt on disk
        # only causes a stable-id retry; it never rolls back authority.
        return register_revision


def _load_all() -> dict[str, dict]:
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        data, revision = _read_register_unlocked()
        _recover_published_reviews_unlocked(data, revision)
        return data


def _save_all(data: dict[str, dict]) -> None:
    """Compatibility wrapper for a serialized, atomic full-register write."""
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        _current, revision = _read_register_unlocked()
        _write_register_unlocked(data, expected_register_revision=revision)


def list_assessments() -> list[dict]:
    """Every stored assessment, newest-updated first, with a rolled-up summary."""
    out = [_summarize(a) for a in _load_all().values()]
    out.sort(key=lambda a: a.get("updated_at") or 0, reverse=True)
    return out


def _summarize(a: dict) -> dict:
    lenses = a.get("lenses") or {}
    open_high = sum(
        1 for lv in lenses.values() for f in lv.get("findings", [])
        if f.get("status") == "open" and _SEVERITY_RANK.get(f.get("severity"), 0) >= 2)
    return {**_without_review_transactions(a), "open_high": open_high,
            "lens_status": {k: lens_status(v.get("findings", [])) for k, v in lenses.items()}}


def get_assessment(kind: str, name: str) -> dict | None:
    a = _load_all().get(_key(kind, name))
    return _summarize(a) if a else None


def _confirm_mutation_access(effect_guard):
    if effect_guard is not None:
        try:
            effect_guard()
        except Exception as exc:
            raise AssessmentRegisterError(
                "assessment change was saved but completion is unconfirmed"
            ) from exc


def delete_assessment(
    kind: str, name: str, *, expected_revision: int | None = None,
    effect_guard: Callable[[], None] | None = None,
) -> bool:
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        if effect_guard is not None:
            effect_guard()
        data, register_revision = _read_register_unlocked()
        key = _key(kind, name)
        existing = data.get(key)
        if existing is None:
            if expected_revision not in (None, 0):
                _check_expected_revision(None, expected_revision)
            return False
        _ensure_no_pending_review(existing)
        _check_expected_revision(existing, expected_revision)
        del data[key]
        _write_register_unlocked(
            data, expected_register_revision=register_revision,
            **({"effect_guard": effect_guard} if effect_guard is not None else {}),
        )
        _confirm_mutation_access(effect_guard)
        return True


def _refresh_unlocked(
    data: dict[str, dict],
    kind: str,
    name: str,
    *,
    template: str | None,
    now: float,
    expected_revision: int | None,
    create_if_missing: bool,
) -> tuple[dict | None, bool]:
    key = _key(kind, name)
    existing = data.get(key)
    if existing is None and not create_if_missing:
        if expected_revision not in (None, 0):
            _check_expected_revision(None, expected_revision)
        return None, False
    if existing is not None:
        _ensure_no_pending_review(existing)
    revision = _check_expected_revision(existing, expected_revision)
    tpl = template or (existing or {}).get("template") or "baseline"
    fresh = auto_draft(kind, name, tpl, now=now)
    if fresh is None:
        return None, False
    if existing is None:
        fresh["revision"] = 1
        data[key] = fresh
        return fresh, True

    drifted = existing.get("subject_hash") != fresh["subject_hash"]
    merged = dict(existing)
    merged["subject_hash"] = fresh["subject_hash"]
    merged["template"] = tpl
    merged["description"] = fresh["description"]
    merged["updated_at"] = now
    old_by_key = {
        (lens, finding.get("control")): finding
        for lens, lv in (existing.get("lenses") or {}).items()
        for finding in lv.get("findings", [])
    }
    new_lenses: dict[str, dict] = {}
    for lens, lv in fresh["lenses"].items():
        prev_lv = (existing.get("lenses") or {}).get(lens, {})
        findings = []
        for finding in lv["findings"]:
            old = old_by_key.get((lens, finding.get("control")))
            if old and not drifted:
                finding = {
                    **finding,
                    "status": old.get("status", "open"),
                    "evidence": list(old.get("evidence") or []),
                }
            findings.append(finding)
        new_lenses[lens] = {
            "status": "open" if drifted else prev_lv.get("status", "open"),
            "findings": findings,
            "reviewer": "" if drifted else prev_lv.get("reviewer", ""),
            "reviewed_at": None if drifted else prev_lv.get("reviewed_at"),
            "note": prev_lv.get("note", ""),
        }
    merged["lenses"] = new_lenses
    if drifted and existing.get("status") in ("reviewed", "accepted"):
        merged["status"] = "needs_review"
        merged["drift_note"] = "The subject changed since last review — re-assess."
    merged["revision"] = revision + 1
    data[key] = merged
    return merged, True


def refresh(
    kind: str,
    name: str,
    template: str | None = None,
    now: float | None = None,
    *,
    expected_revision: int | None = None,
    effect_guard: Callable[[], None] | None = None,
) -> dict | None:
    """Create or re-draft under a strict transaction with revision CAS."""
    now = time.time() if now is None else now
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        if effect_guard is not None:
            effect_guard()
        data, register_revision = _read_register_unlocked()
        refreshed, changed = _refresh_unlocked(
            data,
            kind,
            name,
            template=template,
            now=now,
            expected_revision=expected_revision,
            create_if_missing=True,
        )
        if changed:
            _write_register_unlocked(
                data, expected_register_revision=register_revision,
                **({"effect_guard": effect_guard} if effect_guard is not None else {}),
            )
        if changed:
            _confirm_mutation_access(effect_guard)
        return _summarize(refreshed) if refreshed else None


def _candidate_digest(candidate: dict) -> str:
    blob = json.dumps(
        candidate, sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _build_review_candidate(
    record: dict,
    *,
    lens: str,
    decision: str,
    reviewer: str,
    note: str,
    cadence_days: int | None,
    now: float,
) -> dict | None:
    candidate = deepcopy(_without_review_transactions(record))
    lv = (candidate.get("lenses") or {}).get(lens)
    if lv is None:
        return None
    lv["status"] = "accepted" if decision == "accepted" else "open"
    lv["reviewer"] = reviewer
    lv["reviewed_at"] = now
    lv["note"] = note
    if decision == "accepted":
        for finding in lv.get("findings", []):
            if finding.get("status") == "open":
                finding["status"] = "accepted"
    if cadence_days is not None:
        candidate["cadence_days"] = max(0, int(cadence_days))
    candidate["updated_at"] = now
    candidate.pop("drift_note", None)
    all_accepted = all(
        (candidate["lenses"].get(item) or {}).get("status") == "accepted"
        for item in candidate["lenses"]
    )
    if all_accepted:
        candidate["status"] = "reviewed"
        candidate["reviewed_at"] = now
        candidate["due_at"] = (
            now + candidate["cadence_days"] * 86400
            if candidate.get("cadence_days") else None
        )
    else:
        candidate["status"] = "in_review"
    candidate["revision"] = _record_revision(record) + 1
    return candidate


def _review_request_matches(
    transaction: dict,
    *,
    lens: str,
    decision: str,
    reviewer: str,
    note: str,
    cadence_days: int | None,
) -> bool:
    return all((
        transaction.get("lens") == lens,
        transaction.get("decision") == decision,
        transaction.get("reviewer") == reviewer,
        transaction.get("note") == note,
        transaction.get("cadence_days") == cadence_days,
    ))


def _audit_review_transaction(transaction: dict, phase: str) -> bool:
    args = (
        str(transaction.get("subject_kind") or ""),
        str(transaction.get("subject") or ""),
        str(transaction.get("lens") or ""),
        str(transaction.get("decision") or ""),
        str(transaction.get("reviewer") or ""),
        str(transaction.get("result_status") or ""),
        float(transaction.get("created_at") or time.time()),
    )
    metadata = {
        "phase": phase,
        "transaction_id": str(transaction.get("transaction_id") or ""),
        "prior_revision": int(transaction.get("base_revision") or 0),
        "new_revision": int(transaction.get("new_revision") or 0),
        "surface_hash": str(transaction.get("surface_hash") or ""),
        "candidate_hash": str(transaction.get("candidate_hash") or ""),
    }
    try:
        return bool(_audit_review(*args, **metadata))
    except TypeError:
        # Preserve compatibility with legacy test/deployment hooks that wrapped
        # the seven-argument audit callback before phase metadata was added.
        try:
            return bool(_audit_review(*args))
        except Exception:  # noqa: BLE001 -- durable outbox remains for retry
            return False
    except Exception:  # noqa: BLE001 -- durable outbox remains for retry
        return False


def record_review(kind: str, name: str, lens: str, decision: str, *,
                  reviewer: str = "", note: str = "", cadence_days: int | None = None,
                  now: float | None = None,
                  expected_revision: int | None = None,
                  effect_guard: Callable[[], None] | None = None) -> dict | None:
    """Record a reviewer's decision on one lens (``accepted`` / ``needs_work``).
    Accepting a lens marks its open findings accepted. When every lens is
    accepted the assessment is ``reviewed`` and (if a cadence is set) a re-review
    ``due_at`` is scheduled."""
    if lens not in LENSES:
        raise ValueError(f"unknown lens: {lens!r}")
    if decision not in ("accepted", "needs_work"):
        raise ValueError("decision must be 'accepted' or 'needs_work'")
    now = time.time() if now is None else now
    published = False

    def guard():
        if effect_guard is not None:
            try:
                effect_guard()
            except Exception as exc:
                if published:
                    raise AssessmentAuditError(
                        "assessment review was published but completion is unconfirmed"
                    ) from exc
                raise

    # Older native callers do not need a callback and retain their writer hook.
    write_options = {"effect_guard": guard} if effect_guard is not None else {}
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        guard()
        data, register_revision = _read_register_unlocked()
        key = _key(kind, name)
        record = data.get(key)
        if record is None:
            return None
        revision = _check_expected_revision(record, expected_revision)
        transactions = _review_transactions(record)
        prepared = [item for item in transactions if item["phase"] == "prepared"]
        transaction = next((
            item for item in prepared
            if item.get("base_revision") == revision
            and _review_request_matches(
                item, lens=lens, decision=decision, reviewer=reviewer,
                note=note, cadence_days=cadence_days,
            )
        ), None)
        if transaction is None:
            if prepared:
                raise AssessmentVersionConflict(
                    "a different review transaction is already prepared"
                )
            if transactions:
                raise AssessmentVersionConflict(
                    "a review publication audit is pending recovery"
                )
            candidate = _build_review_candidate(
                record,
                lens=lens,
                decision=decision,
                reviewer=reviewer,
                note=note,
                cadence_days=cadence_days,
                now=now,
            )
            if candidate is None:
                return None
            transaction = {
                "transaction_id": uuid.uuid4().hex,
                "phase": "prepared",
                "subject_kind": kind,
                "subject": name,
                "lens": lens,
                "decision": decision,
                "reviewer": reviewer,
                "note": note,
                "cadence_days": cadence_days,
                "created_at": now,
                "base_revision": revision,
                "new_revision": candidate["revision"],
                "surface_hash": str(record.get("subject_hash") or ""),
                "candidate_hash": _candidate_digest(candidate),
                "result_status": candidate["status"],
                "candidate": candidate,
            }
            if len(transactions) >= _REVIEW_TRANSACTION_LIMIT:
                raise AssessmentAuditError("assessment review outbox is full")
            record[_REVIEW_TRANSACTIONS] = [*transactions, transaction]
            register_revision = _write_register_unlocked(
                data, expected_register_revision=register_revision, **write_options,
            )
        candidate = deepcopy(transaction["candidate"])
        if _candidate_digest(candidate) != transaction.get("candidate_hash"):
            raise AssessmentRegisterError("assessment review candidate is corrupt")

        # PREPARE records the proposed decision only. COMMIT_AUTHORIZED is the
        # mandatory signed authorization to publish; neither phase claims that
        # the register was changed. A failed promotion therefore leaves the old
        # authoritative record plus a retryable durable candidate.
        guard()
        if not _audit_review_transaction(transaction, "prepare"):
            raise AssessmentAuditError(
                "assessment review prepare audit could not be committed"
            )
        guard()
        if not _audit_review_transaction(transaction, "commit_authorized"):
            raise AssessmentAuditError(
                "assessment review authorization audit could not be committed"
            )

        published_transaction = deepcopy(transaction)
        published_transaction["phase"] = "published_pending_audit"
        candidate[_REVIEW_TRANSACTIONS] = [published_transaction]
        data[key] = candidate
        register_revision = _write_register_unlocked(
            data, expected_register_revision=register_revision, **write_options,
        )
        published = True
        guard()
        if _audit_review_transaction(published_transaction, "published"):
            candidate.pop(_REVIEW_TRANSACTIONS, None)
            data[key] = candidate
            try:
                _write_register_unlocked(
                    data, expected_register_revision=register_revision, **write_options,
                )
            except (OSError, AssessmentRegisterError):
                # The published row is already signed. The durable on-disk
                # receipt remains and a later read safely retries cleanup.
                pass
        guard()
        return _summarize(candidate)


def _audit_review(kind: str, name: str, lens: str, decision: str, reviewer: str,
                  result_status: str, now: float, *, phase: str = "published",
                  transaction_id: str = "", prior_revision: int = 0,
                  new_revision: int = 0, surface_hash: str = "",
                  candidate_hash: str = "") -> bool:
    """Append one phase of a review's prepare/authorize/publish protocol."""
    try:
        from .audit.events import AuditEvent, EventKind
        from .audit.writer import default_audit_log
        return bool(default_audit_log().record(AuditEvent(
            ts=now, kind=EventKind.ASSESSMENT_REVIEW, agent="governance",
            payload={"subject_kind": kind, "subject": name, "lens": lens,
                     "decision": decision, "reviewer": reviewer or "",
                     "result_status": result_status, "phase": phase,
                     "transaction_id": transaction_id,
                     "prior_revision": prior_revision,
                     "new_revision": new_revision,
                     "surface_hash": surface_hash,
                     "candidate_hash": candidate_hash})))
    except Exception:  # noqa: BLE001 -- the caller fails the publication closed
        return False


def refresh_on_change(
    kind: str,
    name: str,
    now: float | None = None,
    *,
    expected_revision: int | None = None,
    effect_guard: Callable[[], None] | None = None,
) -> dict | None:
    """Re-draft an assessment ONLY if one already exists (detecting drift), for
    callers that just changed a subject (e.g. an agent-override save). Returns the
    refreshed assessment, or ``None`` if the subject has no assessment yet — a
    changed subject that was never assessed shouldn't spawn one silently."""
    now = time.time() if now is None else now
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        if effect_guard is not None:
            effect_guard()
        data, register_revision = _read_register_unlocked()
        refreshed, changed = _refresh_unlocked(
            data,
            kind,
            name,
            template=None,
            now=now,
            expected_revision=expected_revision,
            create_if_missing=False,
        )
        if changed:
            _write_register_unlocked(
                data, expected_register_revision=register_revision,
                **({"effect_guard": effect_guard} if effect_guard is not None else {}),
            )
        if changed:
            _confirm_mutation_access(effect_guard)
        return _summarize(refreshed) if refreshed else None


def add_evidence(kind: str, name: str, lens: str, control: str, evidence: str,
                 now: float | None = None, *,
                 expected_revision: int | None = None,
                 effect_guard: Callable[[], None] | None = None) -> dict | None:
    """Attach an evidence note/link to a specific finding."""
    now = time.time() if now is None else now
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        if effect_guard is not None:
            effect_guard()
        data, register_revision = _read_register_unlocked()
        a = data.get(_key(kind, name))
        if a is None:
            return None
        _ensure_no_pending_review(a)
        revision = _check_expected_revision(a, expected_revision)
        for finding in (a.get("lenses") or {}).get(lens, {}).get("findings", []):
            if finding.get("control") == control:
                finding.setdefault("evidence", []).append(str(evidence))
                a["updated_at"] = now
                a["revision"] = revision + 1
                _write_register_unlocked(
                    data, expected_register_revision=register_revision,
                    **({"effect_guard": effect_guard} if effect_guard is not None else {}),
                )
                _confirm_mutation_access(effect_guard)
                return _summarize(a)
        return None


def _due_records(records: dict, now: float) -> list[dict]:
    out = []
    for a in records.values():
        overdue = bool(a.get("due_at")) and a["due_at"] <= now
        if overdue or a.get("status") in ("needs_review", "draft"):
            out.append(_summarize(a))
    out.sort(key=lambda a: (a.get("due_at") or 0))
    return out

def due_assessments(now: float | None = None) -> list[dict]:
    """Assessments needing attention or a scheduled re-review."""
    now = time.time() if now is None else now
    return _due_records(_load_all(), now)


def _read_current_register(effect_guard):
    """Pure guarded manual read; legacy publication recovery is separate."""
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        effect_guard()
        records, _revision = _read_register_unlocked()
        effect_guard()
        return records



def sweep_due(now: float | None = None, *,
              effect_guard: Callable[[], None] | None = None) -> dict:
    """Re-draft stored assessments, preserving incomplete manual check results."""
    now = time.time() if now is None else now
    refreshed = 0
    if effect_guard is None:
        # Preserve the scheduler/legacy best-effort contract.
        for key in list(_load_all().keys()):
            kind, _, name = key.partition(":")
            try:
                if refresh_on_change(kind, name, now=now) is not None:
                    refreshed += 1
            except Exception:  # pragma: no cover -- one bad subject never stops the sweep
                pass
        return {"refreshed": refreshed, "due": due_assessments(now=now)}

    authority_refused = False

    def guard():
        nonlocal authority_refused
        try:
            effect_guard()
        except Exception:
            authority_refused = True
            raise

    guard()
    keys = list(_read_current_register(guard))
    guard()
    unavailable = 0
    for key in keys:
        kind, _, name = key.partition(":")
        try:
            if refresh_on_change(kind, name, now=now, effect_guard=guard) is None:
                unavailable += 1
            else:
                refreshed += 1
        except Exception:
            if authority_refused:
                raise
            unavailable += 1
    guard()
    due = _due_records(_read_current_register(guard), now)
    guard()
    return {"refreshed": refreshed, "due": due, "requested": len(keys),
            "checked": refreshed, "changed": refreshed, "unavailable": unavailable,
            "complete": unavailable == 0}


def export_rows() -> list[dict]:
    """One flat row per finding, for CSV/JSON audit export."""
    rows = []
    for a in _load_all().values():
        for lens, lv in (a.get("lenses") or {}).items():
            for f in lv.get("findings", []):
                rows.append({
                    "kind": a.get("kind"), "subject": a.get("subject"),
                    "assessment_status": a.get("status"), "lens": lens,
                    "lens_status": lv.get("status"), "control": f.get("control"),
                    "severity": f.get("severity"), "finding_status": f.get("status"),
                    "note": f.get("note"), "mitigation": f.get("mitigation"),
                    "evidence": "; ".join(f.get("evidence") or []),
                    "reviewer": lv.get("reviewer"), "reviewed_at": lv.get("reviewed_at"),
                })
    return rows
