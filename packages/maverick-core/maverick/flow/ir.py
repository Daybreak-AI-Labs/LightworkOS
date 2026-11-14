"""Flow IR -- a deterministic skeleton with agentic muscle.

A :class:`Flow` is a graph of typed nodes. The control-flow nodes (branch /
foreach / parallel / approval / delay) run deterministically and are auditable
and replayable; the *work* nodes are either a deterministic ``action`` (a typed
connector/tool call -- with an explicit human gate when high-risk) or an ``agent``
(a brief run as a governed goal -- what today's templates already are). This is
the "do both" architecture: the graph decides *when/whether/in what order* and
requires approval at an explicit ``approval`` node; the agent decides
*what happens inside a step*. A single ``agent`` node with no routing IS
today's template, so a Flow is a superset, not a parallel product.

The IR is a plain data structure -- no execution here (see :mod:`.runner`), no
persistence here (see :mod:`.store`). It is JSON-serialisable so it can be
imported from another platform's graph, stored, versioned, and diffed. foreach
and parallel bodies are *nested* Flows, which keeps the graph a clean tree of
sub-flows rather than a soup of cross-referencing ids.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any

# Node kinds ------------------------------------------------------------------
NODE_ACTION = "action"      # a deterministic tool/connector call
NODE_AGENT = "agent"        # an agentic goal (a brief); the "figure it out" node
NODE_BRANCH = "branch"      # conditional: evaluate, go if_true / if_false
NODE_SWITCH = "switch"      # n-way conditional: route by a data key's value
NODE_FOREACH = "foreach"    # loop: run a body sub-flow per item in a list
NODE_WHILE = "while"        # loop: run a body sub-flow while a condition holds
NODE_PARALLEL = "parallel"  # fan out branch sub-flows, join their data
NODE_APPROVAL = "approval"  # human-in-the-loop gate: pause until approved
NODE_DELAY = "delay"        # wait N seconds, then continue
NODE_WAIT = "wait_event"    # pause until an external event resumes the run
NODE_SCOPE = "scope"        # try/catch: run a body; a failure routes to on_error
NODE_SUBFLOW = "subflow"    # run another saved flow as a nested step (reuse)
NODE_SETVAR = "setvar"      # set flow-data keys from expressions (compose / loop counter)

MAX_FLOW_NODE_RETRIES = 10
MAX_FLOW_NODE_RETRY_BACKOFF_TOTAL = 120.0
MAX_FLOW_NODE_RETRY_SLEEP = 30.0
MAX_FLOW_LOOP_LIMIT = 10_000   # explicit foreach/while limit; the runtime has no other pass cap

NODE_KINDS = frozenset({
    NODE_ACTION, NODE_AGENT, NODE_BRANCH, NODE_SWITCH, NODE_FOREACH, NODE_WHILE,
    NODE_PARALLEL, NODE_APPROVAL, NODE_DELAY, NODE_WAIT, NODE_SCOPE, NODE_SUBFLOW,
    NODE_SETVAR,
})
_WORK_KINDS = frozenset({NODE_ACTION, NODE_AGENT})
_DEFAULT_MAX_NODE_RETRIES = 5
_HARD_MAX_NODE_RETRIES = 50
LEARNED_OPERATOR_SCHEMA = "flow-learned-operator-v1"


def learned_operator_work_digest(node: FlowNode) -> str:
    """Bind a pure specialization to the original agent's work and output contract."""
    payload = {
        "kind": node.kind, "brief": node.brief, "output": node.output,
        "retries": node.retries, "timeout": node.timeout,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def validate_learned_operator(node: FlowNode, *, check_work: bool = True) -> None:
    """Validate an attached artifact without interpreting arbitrary code or tools."""
    envelope = node.learned_operator
    if envelope is None:
        return
    if node.kind != NODE_AGENT or not node.brief or not node.output:
        raise ValueError("learned operator requires an agent brief and output key")
    if not isinstance(envelope, dict) or set(envelope) != {"schema", "work_sha256", "artifact"}:
        raise ValueError("invalid learned operator envelope")
    if envelope["schema"] != LEARNED_OPERATOR_SCHEMA:
        raise ValueError("unsupported learned operator envelope schema")
    digest = envelope["work_sha256"]
    if (not isinstance(digest, str) or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)):
        raise ValueError("invalid learned operator work digest")
    if check_work and digest != learned_operator_work_digest(node):
        raise ValueError("learned operator original work definition changed")
    from .operator_artifacts import validate_artifact

    validate_artifact(envelope["artifact"])


def max_node_retries() -> int:
    """Operator-configured ceiling for per-node retries.

    Bound the knob itself so a bad environment/config value cannot turn flow
    retries into a worker/spend-amplification vector.
    """
    import os

    raw = os.environ.get("MAVERICK_FLOW_MAX_NODE_RETRIES")
    if raw is None:
        try:
            from ..config import get_flows
            raw = get_flows().get("max_node_retries", _DEFAULT_MAX_NODE_RETRIES)
        except Exception:  # pragma: no cover -- config lookup must not block validation
            raw = _DEFAULT_MAX_NODE_RETRIES
    try:
        value = int(raw or 0)
    except (TypeError, ValueError):
        value = _DEFAULT_MAX_NODE_RETRIES
    return min(_HARD_MAX_NODE_RETRIES, max(0, value))


# Flow action nodes bypass the governed agent loop and dispatch one tool
# directly.  Host/workspace/code/device primitives therefore do not belong in
# this IR at all: use an agent node (which carries capability, sandbox, consent,
# and tool-ACL enforcement) or a purpose-built connector action instead.
UNSAFE_ACTION_TOOLS = frozenset({
    "shell",
    "read_file",
    "write_file",
    "list_dir",
    "str_replace_editor",
    "apply_patch",
    "ast_edit",
    "code_exec",
    "compute",
    "container_build",
    "notebook_exec",
    "wasm_run",
    "computer",
    "browser",
    "clipboard",
    "serial",
    "ros",
    "android",
    "ios_sim",
    "repo_map",
    "dep_graph",
    "preview_diff",
    "semantic_code_search",
    "lsp_bridge",
    "cross_repo_deps",
    "git_advanced",
    "file_watcher",
    "workspace_snapshot",
    "plugin_lockfile",
    "memory",
    "kv_memory",
    "obsidian",
    "list_attachments",
    "view_image",
    "view_video",
    "transcribe_audio",
    "speak",
    "spreadsheet",
    "spreadsheet_read",
    "pandas_query",
    "sql_query",
    "sql_query_read",
    "self_edit",
})


def action_tool_policy_error(tool: str) -> str:
    """Return why ``tool`` may not be a direct flow action, or ``""``.

    Unknown plugin/generated tools are not assumed safe merely because the
    compatibility risk display calls them ``medium``.  An operator must first
    classify them through the central tool-risk policy; runtime repeats this
    check so a forged/stale graph cannot bypass validation.
    """
    name = str(tool or "").strip()
    if not name:
        return "action tool is missing"
    if name in UNSAFE_ACTION_TOOLS:
        return f"unsafe direct action tool {name!r}"
    from ..safety.tool_risk import tool_risk_is_classified

    if not tool_risk_is_classified(name):
        return f"unclassified direct action tool {name!r}"
    return ""


_DRAFT_UNCLASSIFIED_ACTION = "draft_unclassified_action"


class _ValidationError(str):
    """A display-compatible validation error carrying a non-forgeable code.

    Node ids, tool names, and imported labels are attacker-controlled strings.
    Draft policy must therefore never infer an error class by searching its
    rendered text: a crafted id could make an unrelated structural error look
    like the one preview-only exception. A ``str`` subclass keeps every public
    caller and JSON response compatible while carrying internal provenance.
    """

    def __new__(cls, message: str, *, code: str = ""):
        obj = super().__new__(cls, message)
        obj.code = code
        return obj


def _prefix_validation_errors(
    prefix: str, errors: list[str],
) -> list[str]:
    """Prefix nested errors without discarding their internal provenance."""
    return [
        _ValidationError(
            f"{prefix}{error}", code=str(getattr(error, "code", "")),
        )
        for error in errors
    ]


def partition_draft_validation_errors(
    errors: list[str],
) -> tuple[list[str], list[str]]:
    """Split save/runtime blockers from draft-only classification blockers.

    An authoring/import surface may display a structurally sound action whose
    installed tool has not yet been assigned an operator risk policy. That
    graph remains deliberately unsaveable and unexecutable; only the unsaved
    first-pass response may tolerate this one exact error class.
    """
    policy = []
    blocking = []
    for error in errors:
        target = (
            policy
            if getattr(error, "code", "") == _DRAFT_UNCLASSIFIED_ACTION
            else blocking
        )
        target.append(error)
    return blocking, policy


@dataclass
class FlowNode:
    """One node in a flow. Kind-specific fields are unused for other kinds.

    Routing: ``next`` is the default successor id (``None`` ends the flow);
    a ``branch`` routes to ``if_true``/``if_false`` instead.
    """

    id: str
    kind: str
    next: str | None = None          # default successor node id

    # action ------------------------------------------------------------------
    tool: str = ""                   # tool/connector name
    params: dict[str, Any] = field(default_factory=dict)   # rendered from flow data
    # agent -------------------------------------------------------------------
    brief: str = ""                  # goal brief (rendered from flow data)
    # branch ------------------------------------------------------------------
    condition: str = ""              # a safe "<key> <op> <value>" expression
                                     # (switch: the data key to route on;
                                     #  while: the keep-looping condition)
    if_true: str | None = None
    if_false: str | None = None
    # switch ------------------------------------------------------------------
    cases: list[dict] = field(default_factory=list)   # [{"value": x, "to": node_id}]
    # foreach / while ----------------------------------------------------------
    items: str = ""                  # flow-data key holding the list to iterate
    var: str = "item"                # loop variable exposed to the body
    body: Flow | None = None         # sub-flow run per item / per while pass / scope
    limit: int = 0                   # cap iterations (0 = default cap); body may set _break
    concurrent: bool = False         # foreach: run iterations on a bounded pool
    # setvar ------------------------------------------------------------------
    assignments: dict[str, Any] = field(default_factory=dict)   # {key: expression}; sets flow data
    # parallel ----------------------------------------------------------------
    branches: list[Flow] = field(default_factory=list)   # sub-flows run + joined
    # approval / wait_event ----------------------------------------------------
    prompt: str = ""                 # what a human approves / what the run waits for
    choices: list[str] = field(default_factory=list)  # approval: allowed verdicts
                                     # beyond approve/reject (recorded to output)
    assignee: str = ""               # approval: who to notify / who owns the task
    expires_after: float = 0.0       # approval: seconds until it auto-resolves
                                     # (0 = waits forever); its own field so a kind
                                     # change never confuses it with the execution
                                     # `timeout`. Falls back to `timeout` for
                                     # approvals saved before this field existed.
    on_expire: str | None = None     # approval: route here on expiry (else rejected)
    form: list[dict] = field(default_factory=list)   # approval: fields to collect
                                     # on sign-off [{"name","label"}] (merged into data)
    # delay -------------------------------------------------------------------
    seconds: float = 0.0
    # subflow -----------------------------------------------------------------
    flow_ref: str = ""               # a saved flow id to run as a nested step
    subflow_inputs: dict[str, Any] = field(default_factory=dict)   # {child_key: expr};
                                     # when set, the child runs ISOLATED on only these
                                     # (no shared parent data); outputs return via `output`
    # error handling ----------------------------------------------------------
    retries: int = 0                 # re-run a failed work node up to N more times
    retry_backoff: float = 0.0       # base seconds between retries; exponential (0 = tight loop)
    on_error: str | None = None      # route here when the node fails (else `next`)
    timeout: float = 0.0             # per-node soft wall-clock cap in seconds (0 = none)
    # common ------------------------------------------------------------------
    output: str = ""                 # flow-data key to store this node's result under
    label: str = ""                  # human label (provenance / UI)
    # designer layout (opaque to execution) -----------------------------------
    x: float = 0.0                   # canvas position for the visual designer
    y: float = 0.0
    # Optional pure scalar specialization; original agent remains the fallback.
    learned_operator: dict[str, Any] | None = None
    # A reviewed rule-only release must stop on uncertainty instead of invoking AI.
    learned_fallback: bool = True
    recipe_step: int | None = None  # requires the parent flow's complete recipe
    concurrency: int = 0          # foreach: simultaneous items; 0 keeps the shared pool

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"id": self.id, "kind": self.kind}
        for key in ("next", "tool", "brief", "condition", "if_true", "if_false",
                    "items", "var", "prompt", "flow_ref", "on_error", "output", "label",
                    "assignee", "on_expire"):
            v = getattr(self, key)
            if v not in ("", None):
                d[key] = v
        if self.params:
            d["params"] = self.params
        if self.recipe_step is not None:
            d["recipe_step"] = self.recipe_step
        if self.learned_operator is not None:
            d["learned_operator"] = copy.deepcopy(self.learned_operator)
        if self.learned_fallback is not True:
            d["learned_fallback"] = self.learned_fallback
        for key in ("seconds", "retries", "retry_backoff", "timeout", "limit"):
            value = getattr(self, key)
            if value:
                d[key] = value
        if self.concurrent:
            d["concurrent"] = True
        if self.concurrency:
            d["concurrency"] = self.concurrency
        if self.cases:
            d["cases"] = self.cases
        if self.choices:
            d["choices"] = self.choices
        if self.expires_after:
            d["expires_after"] = self.expires_after
        if self.form:
            d["form"] = self.form
        if self.assignments:
            d["assignments"] = self.assignments
        if self.subflow_inputs:
            d["subflow_inputs"] = self.subflow_inputs
        if self.x or self.y:
            d["x"], d["y"] = self.x, self.y
        if self.body is not None:
            d["body"] = self.body.to_dict()
        if self.branches:
            d["branches"] = [b.to_dict() for b in self.branches]
        return d

    @staticmethod
    def from_dict(d: dict) -> FlowNode:
        body = d.get("body")
        concurrency = d.get("concurrency", 0)
        if type(concurrency) is not int or not 0 <= concurrency <= 8:
            raise ValueError("Choose Shared workflow limit or between 1 and 8 items at once.")
        # Legacy-shape migration, done HERE so every consumer (runner, sweep,
        # designer, drafter) sees one field: old approvals encoded their expiry
        # in `timeout` before `expires_after` existed.
        expires_after = float(d.get("expires_after", 0.0) or 0.0)
        if str(d.get("kind")) == NODE_APPROVAL and not expires_after:
            expires_after = float(d.get("timeout", 0.0) or 0.0)
        return FlowNode(
            id=str(d["id"]), kind=str(d["kind"]),
            next=d.get("next"), tool=str(d.get("tool", "")),
            params=dict(d.get("params") or {}), brief=str(d.get("brief", "")),
            learned_operator=copy.deepcopy(d.get("learned_operator")),
            learned_fallback=d.get("learned_fallback", True),
            recipe_step=d.get("recipe_step"),
            condition=str(d.get("condition", "")),
            if_true=d.get("if_true"), if_false=d.get("if_false"),
            items=str(d.get("items", "")), var=str(d.get("var", "item")),
            limit=int(d.get("limit", 0) or 0),
            concurrent=bool(d.get("concurrent", False)),
            concurrency=concurrency,
            cases=[dict(c) for c in (d.get("cases") or []) if isinstance(c, dict)],
            choices=[str(c) for c in (d.get("choices") or [])],
            assignee=str(d.get("assignee", "")),
            expires_after=expires_after,
            on_expire=d.get("on_expire"),
            form=[c for c in (d.get("form") or []) if isinstance(c, dict)],
            assignments=dict(d.get("assignments") or {}),
            subflow_inputs=dict(d.get("subflow_inputs") or {}),
            body=Flow.from_dict(body) if body else None,
            branches=[Flow.from_dict(b) for b in (d.get("branches") or [])],
            prompt=str(d.get("prompt", "")), seconds=float(d.get("seconds", 0.0)),
            flow_ref=str(d.get("flow_ref", "")),
            retries=int(d.get("retries", 0) or 0),
            retry_backoff=float(d.get("retry_backoff", 0.0) or 0.0),
            on_error=d.get("on_error"),
            timeout=float(d.get("timeout", 0.0) or 0.0),
            output=str(d.get("output", "")), label=str(d.get("label", "")),
            x=float(d.get("x", 0.0)), y=float(d.get("y", 0.0)),
        )


@dataclass
class Flow:
    """A named graph of nodes with a single entry point (``start``).

    ``version`` is a monotonic definition version stamped by the store on each
    save (see :mod:`.store`), so an applied self-rewrite or a designer edit is a
    new version the prior one can be rolled back to.
    """

    id: str
    name: str
    start: str
    nodes: dict[str, FlowNode] = field(default_factory=dict)
    version: int = 1
    # Opaque, non-reused store generation token.  The IR only round-trips it;
    # persistence owns creation and compare-and-swap semantics.
    revision: str = ""
    notify: bool = False             # push a notification on approval-pause / finish
    max_seconds: float = 0.0         # whole-flow wall-clock deadline (0 = no limit)
    max_dollars: float = 0.0         # aggregate agent spend ceiling for one run (0 = no limit)
    schedule: str = ""               # a cron expression to run this flow on (empty = not scheduled)
    timezone: str = ""               # IANA zone the schedule is in (empty = UTC)
    owner: str = ""                  # principal that owns this flow (for RBAC + attributing scheduled runs)
    max_concurrent: int = 0          # cap simultaneous in-flight runs of this flow (0 = unlimited)
    inputs: list[dict] = field(default_factory=list)   # declared manual-run inputs:
                                     # [{key, type: text|number|bool|date, label, required, default}]
    learned_recipe: dict | None = None  # reviewed action dataflow; exact generated graph
    recipe_lineage: dict | None = None  # admitted signed evidence; never caller run data
    recipe_teaching: dict | None = None  # explicit native human teaching, not general guard bypass
    notify_on: str = "all"           # all opted-in events, or problems only

    def node(self, node_id: str | None) -> FlowNode | None:
        return self.nodes.get(node_id) if node_id else None

    def copy(self) -> Flow:
        """A deep, independent copy (round-trips through the dict form)."""
        return Flow.from_dict(self.to_dict())

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "start": self.start,
            "version": self.version, "revision": self.revision, "notify": self.notify,
            "notify_on": self.notify_on,
            "max_seconds": self.max_seconds, "max_dollars": self.max_dollars,
            "schedule": self.schedule, "timezone": self.timezone, "owner": self.owner,
            "max_concurrent": self.max_concurrent, "inputs": self.inputs,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            **({"learned_recipe": copy.deepcopy(self.learned_recipe)}
               if self.learned_recipe is not None else {}),
            **({"recipe_lineage": copy.deepcopy(self.recipe_lineage)}
               if self.recipe_lineage is not None else {}),
            **({"recipe_teaching": copy.deepcopy(self.recipe_teaching)}
               if self.recipe_teaching is not None else {}),
        }

    @staticmethod
    def from_dict(d: dict) -> Flow:
        notify_on = d.get("notify_on", "all")
        if not isinstance(notify_on, str) or notify_on not in {"all", "problems"}:
            raise ValueError("Choose alerts for all updates or problems only.")
        nodes = [FlowNode.from_dict(n) for n in (d.get("nodes") or [])]
        return Flow(
            id=str(d.get("id", "")), name=str(d.get("name", "")),
            start=str(d.get("start", "")),
            nodes={n.id: n for n in nodes},
            version=int(d.get("version", 1) or 1),
            revision=str(d.get("revision", "") or ""),
            notify=bool(d.get("notify", False)),
            notify_on=notify_on,
            max_seconds=float(d.get("max_seconds", 0.0) or 0.0),
            max_dollars=float(d.get("max_dollars", 0.0) or 0.0),
            schedule=str(d.get("schedule", "")), timezone=str(d.get("timezone", "")),
            owner=str(d.get("owner", "")),
            max_concurrent=int(d.get("max_concurrent", 0) or 0),
            inputs=[dict(i) for i in (d.get("inputs") or []) if isinstance(i, dict)],
            learned_recipe=copy.deepcopy(d.get("learned_recipe")),
            recipe_lineage=copy.deepcopy(d.get("recipe_lineage")),
            recipe_teaching=copy.deepcopy(d.get("recipe_teaching")),
        )

    def unreachable_node_ids(self) -> list[str]:
        """Steps that no run can reach from this flow's first step."""
        reached: set[str] = set()
        pending = [self.start]
        while pending:
            node_id = pending.pop()
            if node_id in reached or node_id not in self.nodes:
                continue
            reached.add(node_id)
            node = self.nodes[node_id]
            if node.kind == NODE_BRANCH:
                targets = [node.if_true or node.next, node.if_false or node.next]
            elif node.kind == NODE_SWITCH:
                targets = [node.next] + [
                    case.get("to") or node.next
                    for case in node.cases if isinstance(case, dict)
                ]
            else:
                targets = [node.next]
            if node.kind in (_WORK_KINDS | {NODE_SCOPE}):
                targets.append(node.on_error)
            if node.kind == NODE_APPROVAL:
                targets.append(node.on_expire)
            pending.extend(target for target in targets
                           if isinstance(target, str) and target)
        return sorted(self.nodes.keys() - reached)

    def reachability_errors(self) -> list[str]:
        """Publication blockers, including disconnected nested flow steps."""
        errors = [
            f"step {self.nodes[node_id].label or node_id!r} can never run; connect it from the first step"
            for node_id in self.unreachable_node_ids()
        ]
        for node in self.nodes.values():
            if node.body is not None:
                errors.extend(f"{node.label or node.id}: {error}"
                              for error in node.body.reachability_errors())
            for branch in node.branches:
                errors.extend(f"{node.label or node.id}: {error}"
                              for error in branch.reachability_errors())
        return errors

    def validate(self, *, _inherited_approval: bool = False) -> list[str]:
        """Structural problems (empty list = valid). Not an execution check."""
        errs: list[str] = []
        if not isinstance(self.notify_on, str) or self.notify_on not in {"all", "problems"}:
            errs.append("Choose alerts for all updates or problems only.")
        if self.recipe_lineage is not None and self.learned_recipe is None:
            errs.append("recipe lineage requires its complete parent recipe")
        if self.recipe_teaching is not None and self.learned_recipe is None:
            errs.append("recipe teaching requires its complete parent recipe")
        if self.learned_recipe is None and any(n.recipe_step is not None for n in self.nodes.values()):
            errs.append("learned action node requires its complete parent recipe")
        if self.learned_recipe is not None:
            from .recipe_flow import validate_flow
            try:
                validate_flow(self)
            except (ValueError, TypeError):
                errs.append("invalid or edited learned action recipe graph")
        if not self.nodes:
            errs.append("flow has no nodes")
            return errs
        if self.start not in self.nodes:
            errs.append(f"start node {self.start!r} is not in the flow")
        if self.schedule.strip():
            from ..scheduler import CronError, next_run
            try:
                next_run(self.schedule, tz=self.timezone.strip())
            except CronError as e:
                errs.append(f"invalid schedule {self.schedule!r}: {e}")
        seen_ids = set()
        for nid, n in self.nodes.items():
            if n.id != nid:
                errs.append(f"node id mismatch: keyed {nid!r} but node.id={n.id!r}")
            if n.id in seen_ids:
                errs.append(f"duplicate node id {n.id!r}")
            seen_ids.add(n.id)
            if n.kind not in NODE_KINDS:
                errs.append(f"node {n.id!r}: unknown kind {n.kind!r}")
            if type(n.concurrency) is not int or not 0 <= n.concurrency <= 8:
                errs.append(f"node {n.id!r}: choose Shared workflow limit or between 1 and 8 items at once")
            errs.extend(self._validate_retry_policy(n))
            errs.extend(_validate_node_numbers(n))
            errs.extend(self._validate_routing(n))
            errs.extend(self._validate_retry_budget(n))
            errs.extend(self._validate_kind(
                n, inherited_approval=_inherited_approval))
        errs.extend(self._validate_high_risk_approval_paths(
            inherited_approval=_inherited_approval))
        errs.extend(
            f"{name} must be a finite number >= 0"
            for name in ("max_seconds", "max_dollars")
            if not _finite_non_negative(getattr(self, name))
        )
        seen_input_keys = set()
        for i, spec in enumerate(self.inputs):
            key = str(spec.get("key") or "").strip()
            if not key:
                errs.append(f"input {i}: no key")
                continue
            if key in seen_input_keys:
                errs.append(f"duplicate input key {key!r}")
            seen_input_keys.add(key)
            typ = str(spec.get("type") or "text")
            if typ not in INPUT_TYPES:
                errs.append(f"input {key!r}: unknown type {typ!r}")
        return errs

    def _validate_retry_policy(self, n: FlowNode) -> list[str]:
        errs = []
        if type(n.learned_fallback) is not bool:
            errs.append(f"node {n.id!r}: learned fallback must be a boolean")
        elif not n.learned_fallback and (n.kind != NODE_AGENT or n.learned_operator is None):
            errs.append(f"node {n.id!r}: rule-only work requires a learned operator")
        retries = max(0, n.retries)
        backoff = max(0.0, n.retry_backoff)
        if retries > MAX_FLOW_NODE_RETRIES:
            errs.append(f"node {n.id!r}: retries must be <= {MAX_FLOW_NODE_RETRIES}")
        if backoff and _retry_backoff_total(min(retries, MAX_FLOW_NODE_RETRIES), backoff) > MAX_FLOW_NODE_RETRY_BACKOFF_TOTAL:
            errs.append(
                f"node {n.id!r}: retry backoff total must be <= "
                f"{MAX_FLOW_NODE_RETRY_BACKOFF_TOTAL:g}s"
            )
        return errs

    def _validate_retry_budget(self, n: FlowNode) -> list[str]:
        max_retries = max_node_retries()
        if n.retries < 0:
            return [f"node {n.id!r}: retries must be >= 0"]
        if n.retries > max_retries:
            return [f"node {n.id!r}: retries {n.retries} exceeds max_node_retries {max_retries}"]
        return []

    def _validate_routing(self, n: FlowNode) -> list[str]:
        errs = []
        for ref, label in ((n.next, "next"), (n.if_true, "if_true"),
                           (n.if_false, "if_false"), (n.on_error, "on_error"),
                           (n.on_expire, "on_expire")):
            if ref is not None and ref not in self.nodes:
                errs.append(f"node {n.id!r}: {label} -> unknown node {ref!r}")
        return errs

    def _validate_kind(
        self, n: FlowNode, *, inherited_approval: bool = False,
    ) -> list[str]:
        return self._validate_kind_fields(n) + self._validate_kind_nested(
            n, inherited_approval=inherited_approval)

    def _validate_kind_fields(self, n: FlowNode) -> list[str]:
        """Flat required-field checks per kind (no sub-flow recursion)."""
        errs = []
        if n.learned_operator is not None:
            try:
                validate_learned_operator(n)
            except (TypeError, ValueError):
                errs.append(f"node {n.id!r}: invalid or stale learned operator")
        if n.kind == NODE_ACTION:
            if not n.tool:
                errs.append(f"action node {n.id!r} has no tool")
            elif policy_error := action_tool_policy_error(n.tool):
                code = (
                    _DRAFT_UNCLASSIFIED_ACTION
                    if policy_error.startswith("unclassified direct action tool ")
                    else ""
                )
                errs.append(_ValidationError(
                    f"action node {n.id!r} uses {policy_error}", code=code))
            elif n.retries:
                from ..tool_reliability import is_retry_safe
                if not is_retry_safe(n.tool):
                    errs.append(
                        f"action node {n.id!r}: high-risk tool {n.tool!r} cannot be retried")
        if n.kind == NODE_AGENT and not n.brief:
            errs.append(f"agent node {n.id!r} has no brief")
        if n.kind == NODE_AGENT and n.retries:
            errs.append(
                f"agent node {n.id!r} cannot be automatically retried; "
                "its prior attempt may have produced side effects")
        if n.kind == NODE_BRANCH and not n.condition:
            errs.append(f"branch node {n.id!r} has no condition")
        if n.kind == NODE_SWITCH:
            if not n.condition:
                errs.append(f"switch node {n.id!r} has no key (condition)")
            if not n.cases:
                errs.append(f"switch node {n.id!r} has no cases")
            for i, c in enumerate(n.cases):
                to = c.get("to")
                if to is not None and to not in self.nodes:
                    errs.append(f"switch {n.id!r} case {i}: to -> unknown node {to!r}")
        if n.kind == NODE_WAIT and not n.prompt:
            errs.append(f"wait_event node {n.id!r} has no prompt")
        if n.kind == NODE_APPROVAL and not n.prompt:
            errs.append(f"approval node {n.id!r} has no prompt")
        if n.kind == NODE_SUBFLOW and not n.flow_ref:
            errs.append(f"subflow node {n.id!r} has no flow_ref")
        return errs

    def _incoming_edges(self, node_id: str) -> list[tuple[FlowNode, str]]:
        """Return every root-graph edge that can enter ``node_id``."""
        incoming: list[tuple[FlowNode, str]] = []
        for source in self.nodes.values():
            for label, target in (
                ("next", source.next),
                ("if_true", source.if_true),
                ("if_false", source.if_false),
                ("on_error", source.on_error),
                ("on_expire", source.on_expire),
            ):
                if target == node_id:
                    incoming.append((source, label))
            for case in source.cases:
                target = case.get("to") if isinstance(case, dict) else None
                if target == node_id:
                    incoming.append((source, "case"))
        return incoming

    def _is_approval_gated(self, node_id: str) -> bool:
        """Whether all entries to a non-start node resolve an approval first."""
        if node_id == self.start:
            return False
        incoming = self._incoming_edges(node_id)
        return bool(incoming) and all(
            source.kind == NODE_APPROVAL and label == "next" and not source.choices
            for source, label in incoming
        )

    def _validate_high_risk_approval_paths(
        self, *, inherited_approval: bool = False,
    ) -> list[str]:
        """Require every route into a high-risk action to cross a human gate.

        A connector's static ``confirm=true`` parameter is not an authorization.
        The only accepted incoming edge is a binary approval node's ordinary
        ``next`` edge, which is traversed only after literal ``approved``.
        Choice approvals are routing inputs, not authorization: every declared
        choice continues, so values such as ``hold`` must never unlock an action.
        Checking *all* incoming edges prevents a branch/error/expiry route from
        bypassing a gate that merely exists elsewhere in the graph.
        """
        from ..tool_reliability import is_retry_safe

        errs: list[str] = []
        for node in self.nodes.values():
            if (node.kind != NODE_ACTION or not node.tool
                    or node.tool in UNSAFE_ACTION_TOOLS or is_retry_safe(node.tool)):
                continue
            # A top-level human gate before the enclosing durable container
            # authorizes its nested work. Nested flows cannot pause safely, so
            # generated/imported graphs deliberately hoist the gate instead of
            # inserting an approval into a foreach/parallel/scope body.
            if inherited_approval:
                continue
            if node.id == self.start:
                errs.append(
                    f"high-risk action node {node.id!r} cannot be the flow start; "
                    "it must follow an approval node")
            edges = self._incoming_edges(node.id)
            if not edges:
                errs.append(
                    f"high-risk action node {node.id!r} must be reached from an "
                    "approval node's next edge")
                continue
            bypasses = [
                f"{source.id}.{label}"
                for source, label in edges
                if (source.kind != NODE_APPROVAL or label != "next"
                    or bool(source.choices))
            ]
            if bypasses:
                errs.append(
                    f"high-risk action node {node.id!r} has approval-bypassing "
                    f"incoming edge(s): {', '.join(bypasses)}")
        return errs

    def _validate_kind_nested(
        self, n: FlowNode, *, inherited_approval: bool = False,
    ) -> list[str]:
        """Body/branch checks for the container kinds (recurses into sub-flows)."""
        errs = []
        nested_approval = inherited_approval or self._is_approval_gated(n.id)
        if n.kind == NODE_WHILE and not n.condition:
            errs.append(f"while node {n.id!r} has no condition")
        if n.kind == NODE_FOREACH and not n.items:
            errs.append(f"foreach node {n.id!r} has no items key")
        if n.kind in (NODE_WHILE, NODE_SCOPE, NODE_FOREACH):
            if n.body is None:
                errs.append(f"{n.kind} node {n.id!r} has no body")
            else:
                errs.extend(_prefix_validation_errors(
                    f"{n.kind} {n.id!r} body: ",
                    n.body.validate(_inherited_approval=nested_approval),
                ))
                errs.extend(f"{n.kind} {n.id!r} body: {e}" for e in _pause_node_errors(n.body))
        if n.kind == NODE_PARALLEL:
            if not n.branches:
                errs.append(f"parallel node {n.id!r} has no branches")
            for i, b in enumerate(n.branches):
                errs.extend(_prefix_validation_errors(
                    f"parallel {n.id!r} branch {i}: ",
                    b.validate(_inherited_approval=nested_approval),
                ))
                errs.extend(f"parallel {n.id!r} branch {i}: {e}" for e in _pause_node_errors(b))
        if n.kind == NODE_SETVAR and not n.assignments:
            errs.append(f"setvar node {n.id!r} has no assignments")
        return errs

    def is_single_agent(self) -> bool:
        """Whether this flow is just one agent node -- i.e. today's template, the
        degenerate case a Flow generalises."""
        if len(self.nodes) != 1:
            return False
        only = next(iter(self.nodes.values()))
        return only.kind == NODE_AGENT and not only.next


def _finite_non_negative(value: object) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and value >= 0)


def _validate_node_numbers(n: FlowNode) -> list[str]:
    """Reject NaN, infinity and negative durations and unbounded loop limits."""
    errs = [
        f"node {n.id!r}: {name} must be a finite number >= 0"
        for name in ("seconds", "timeout", "expires_after", "retry_backoff")
        if not _finite_non_negative(getattr(n, name))
    ]
    if type(n.limit) is not int or not 0 <= n.limit <= MAX_FLOW_LOOP_LIMIT:
        errs.append(f"node {n.id!r}: limit must be between 0 and {MAX_FLOW_LOOP_LIMIT:,}")
    return errs


def clamp_saved_numbers(flow: Flow) -> list[str]:
    """Bring a stored definition inside the numeric bounds that saving enforces.

    A snapshot published before the bounds existed must stay loadable: a loop
    limit above the maximum runs to the maximum, and a NaN, infinite or negative
    duration or budget means "not set" (0), which is how the runtime already
    treated it.  Returns a description of each change for the caller to log.
    """
    changes: list[str] = []
    for name in ("max_seconds", "max_dollars"):
        if not _finite_non_negative(getattr(flow, name)):
            setattr(flow, name, 0.0)
            changes.append(f"{flow.id}.{name}")
    for node in flow.nodes.values():
        for name in ("seconds", "timeout", "expires_after", "retry_backoff"):
            if not _finite_non_negative(getattr(node, name)):
                setattr(node, name, 0.0)
                changes.append(f"{flow.id}/{node.id}.{name}")
        if type(node.limit) is int and node.limit > MAX_FLOW_LOOP_LIMIT:
            node.limit = MAX_FLOW_LOOP_LIMIT
            changes.append(f"{flow.id}/{node.id}.limit")
        elif type(node.limit) is int and node.limit < 0:
            node.limit = 0
            changes.append(f"{flow.id}/{node.id}.limit")
        for sub in ([node.body] if node.body is not None else []) + list(node.branches):
            changes.extend(clamp_saved_numbers(sub))
    return changes


def _is_high_risk_action(node: FlowNode) -> bool:
    from ..tool_reliability import is_retry_safe

    return bool(
        node.kind == NODE_ACTION
        and node.tool
        and node.tool not in UNSAFE_ACTION_TOOLS
        and not is_retry_safe(node.tool)
    )


def _contains_high_risk(flow: Flow) -> bool:
    for node in flow.nodes.values():
        if _is_high_risk_action(node):
            return True
        if node.body is not None and _contains_high_risk(node.body):
            return True
        if any(_contains_high_risk(branch) for branch in node.branches):
            return True
    return False


def _clamp_high_risk_retries(flow: Flow) -> None:
    for node in flow.nodes.values():
        if _is_high_risk_action(node):
            node.retries = 0
        if node.body is not None:
            _clamp_high_risk_retries(node.body)
        for branch in node.branches:
            _clamp_high_risk_retries(branch)


def _approval_gate_id(flow: Flow, target_id: str) -> str:
    base = f"{target_id}_approval"
    gate_id = base
    suffix = 2
    while gate_id in flow.nodes:
        gate_id = f"{base}_{suffix}"
        suffix += 1
    return gate_id


def _rewire_gate_bypasses(
    target_id: str,
    gate_id: str,
    bypasses: list[tuple[FlowNode, str]],
) -> None:
    for source, edge_label in bypasses:
        if edge_label != "case":
            setattr(source, edge_label, gate_id)
            continue
        for case in source.cases:
            if isinstance(case, dict) and case.get("to") == target_id:
                case["to"] = gate_id


def _gate_before(flow: Flow, target: FlowNode, *, nested: bool) -> None:
    incoming = flow._incoming_edges(target.id)
    bypasses = [
        (source, edge_label) for source, edge_label in incoming
        if source.kind != NODE_APPROVAL or edge_label != "next"
    ]
    if flow.start != target.id and incoming and not bypasses:
        return

    gate_id = _approval_gate_id(flow, target.id)
    _rewire_gate_bypasses(target.id, gate_id, bypasses)
    if flow.start == target.id:
        flow.start = gate_id
    label = target.label or target.tool or target.id
    prompt = (f"Approve high-risk actions in: {label}?" if nested
              else f"Approve high-risk action: {label}?")
    flow.nodes[gate_id] = FlowNode(
        id=gate_id,
        kind=NODE_APPROVAL,
        prompt=prompt,
        next=target.id,
        label=f"Approve {label}",
    )


def ensure_high_risk_approvals(flow: Flow) -> Flow:
    """Return a copy with deterministic human gates before high-risk actions.

    This is the safe boundary for generated and imported first-pass graphs. At
    the durable root it gates each direct high-risk action. When such an action
    lives inside a non-resumable foreach/parallel/scope body, it instead gates
    the nearest enclosing root container; validation treats that human decision
    as inherited authorization inside the container. Repeated application is
    idempotent.
    """
    governed = flow.copy()
    _clamp_high_risk_retries(governed)
    for node in list(governed.nodes.values()):
        if _is_high_risk_action(node):
            _gate_before(governed, node, nested=False)
            continue
        nested_risk = (
            (node.body is not None and _contains_high_risk(node.body))
            or any(_contains_high_risk(branch) for branch in node.branches)
        )
        if nested_risk:
            _gate_before(governed, node, nested=True)
    return governed


def _pause_node_errors(flow: Flow) -> list[str]:
    """Errors for pausing nodes anywhere inside a NESTED sub-flow
    (a foreach body, a parallel branch, and recursively their own nested bodies).
    Human-in-the-loop lives only at the top flow: a nested context can't pause, so
    a nested approval or event wait rejects the run and a nested delay is skipped.
    Flagging it at validation turns a runtime footgun into a clear save-time error."""
    errs: list[str] = []
    for n in flow.nodes.values():
        if n.kind == NODE_APPROVAL:
            errs.append(f"approval node {n.id!r} can't pause inside a loop/branch "
                        "(nested approvals reject the whole run); move it to the top flow")
        if n.kind == NODE_DELAY:
            errs.append(f"delay node {n.id!r} can't wait inside a loop/branch "
                        "(nested delays are skipped); move it to the top flow")
        if n.kind == NODE_WAIT:
            errs.append(f"Wait for another app step {n.label or n.id!r} cannot wait "
                        "inside a loop or parallel path; move it to the main flow")
        if n.kind in (NODE_FOREACH, NODE_WHILE, NODE_SCOPE) and n.body is not None:
            errs.extend(_pause_node_errors(n.body))
        if n.kind == NODE_PARALLEL:
            for b in n.branches:
                errs.extend(_pause_node_errors(b))
    return errs


def single_agent_flow(flow_id: str, name: str, brief: str) -> Flow:
    """A one-node flow that runs ``brief`` as an agentic goal -- the bridge from a
    plain template to the flow model (every template is a trivial flow)."""
    n = FlowNode(id="n0", kind=NODE_AGENT, brief=brief, label=name)
    return Flow(id=flow_id, name=name, start="n0", nodes={"n0": n})


INPUT_TYPES = frozenset({"text", "number", "bool", "date"})


def coerce_inputs(flow: Flow, data: dict) -> tuple[dict, list[str]]:
    """Validate + coerce a manual run's ``data`` against ``flow.inputs`` (the
    declared input schema). Returns ``(coerced, errors)``: numbers become floats,
    bools are parsed from truthy strings, dates are ISO-validated, a missing input
    falls back to its ``default`` (else errors if ``required``). Keys not in the
    schema pass through untouched, so a flow with no declared inputs is a clean
    no-op. Pure -- the run endpoint 400s when ``errors`` is non-empty."""
    out = dict(data or {})
    errors: list[str] = []
    for spec in (flow.inputs or []):
        key = str(spec.get("key") or "").strip()
        if not key:
            continue
        typ = str(spec.get("type") or "text")
        present = key in out and out[key] not in (None, "")
        if not present:
            if "default" in spec:
                out[key] = spec["default"]
            elif spec.get("required"):
                errors.append(f"missing required input {key!r}")
            continue
        val = out[key]
        if typ == "number":
            try:
                out[key] = float(val)
            except (TypeError, ValueError):
                errors.append(f"input {key!r} must be a number")
        elif typ == "bool":
            out[key] = val if isinstance(val, bool) else \
                str(val).strip().lower() in ("true", "1", "yes", "on")
        elif typ == "date":
            import datetime as _dt
            try:
                _dt.date.fromisoformat(str(val)[:10])
            except ValueError:
                errors.append(f"input {key!r} must be an ISO date (YYYY-MM-DD)")
    return out, errors


__all__ = [
    "Flow", "FlowNode", "single_agent_flow", "ensure_high_risk_approvals",
    "action_tool_policy_error", "partition_draft_validation_errors",
    "coerce_inputs", "INPUT_TYPES",
    "NODE_ACTION", "NODE_AGENT", "NODE_BRANCH", "NODE_SWITCH", "NODE_FOREACH",
    "NODE_WHILE", "NODE_PARALLEL", "NODE_APPROVAL", "NODE_DELAY", "NODE_WAIT",
    "NODE_SCOPE", "NODE_SUBFLOW", "NODE_KINDS",
]


def _retry_backoff_total(retries: int, backoff: float) -> float:
    total = 0.0
    for attempt in range(1, max(0, retries) + 1):
        total += min(MAX_FLOW_NODE_RETRY_SLEEP, backoff * (2 ** (attempt - 1)))
    return total
