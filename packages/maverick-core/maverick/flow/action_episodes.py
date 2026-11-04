"""Opt-in observations from native governed Flow action execution.

The collector never dispatches, changes an action result, or grants permission.
Only the native action runner supplies observations after its authorization and
terminal audit. This is local Python provenance, not protection against a caller
that can modify this process. Export review is an explicit local assertion, not
an authenticated human approval. Durable captures require a separately enrolled
governed record; their state and review authority live in action_episode_review.
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import math
import re
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from . import store
from .ir import NODE_ACTION, NODE_APPROVAL, Flow, FlowNode, action_tool_policy_error
from .redact import redact

MAX_STEPS = 8
MAX_VALUE_BYTES = 16_384
MAX_EPISODE_BYTES = 131_072
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z")
_SECRET_EXPRESSION = re.compile(r"\bsecret\s*\(", re.IGNORECASE)
_SECRET_KEY = re.compile(
    r"token|secret|password|passwd|api[_-]?key|apikey|authorization|auth|"
    r"bearer|credential|private[_-]?key|client[_-]?secret|access[_-]?key", re.IGNORECASE,
)
_REDACTED = ("***redacted***", "[REDACTED:", "[truncated]", "…[truncated]")


def _encoded(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _snapshot(value: Any, *, limit=MAX_VALUE_BYTES, private=True, max_depth=8) -> Any:
    """Bound traversal before serialization and preserve exact JSON types."""
    if type(max_depth) is not int or not 0 <= max_depth <= 24:
        raise ValueError("capture depth limit must be between zero and twenty-four")
    remaining = limit

    def visit(item, depth=0):
        nonlocal remaining
        remaining -= 8
        if depth > max_depth or remaining < 0:
            raise ValueError("capture value exceeds its size or depth limit")
        if item is None or type(item) is bool:
            return item
        if type(item) is int:
            if abs(item) > 10**24:
                raise ValueError("capture integer exceeds its limit")
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise ValueError("capture requires finite JSON values")
            return item
        if type(item) is str:
            remaining -= len(item.encode("utf-8"))
            if remaining < 0:
                raise ValueError("capture string exceeds its limit")
            if private and (_SECRET_EXPRESSION.search(item) or any(mark in item for mark in _REDACTED)):
                raise ValueError("capture excludes secret expressions and incomplete values")
            return item
        if type(item) is list:
            return [visit(child, depth + 1) for child in item]
        if type(item) is dict:
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError("capture requires string object keys")
                if private and _SECRET_KEY.search(key):
                    raise ValueError("capture excludes credential-bearing fields")
                visit(key, depth + 1)
                result[key] = visit(child, depth + 1)
            return result
        raise ValueError("capture requires strict JSON data")

    copied = visit(value)
    raw = _encoded(copied)
    if len(raw.encode("utf-8")) > limit:
        raise ValueError("capture value exceeds its byte limit")
    if private and _encoded(redact(copied, strict=True)) != raw:
        raise ValueError("capture excludes values changed by credential redaction")
    return copied


def _digest(value: Any) -> str:
    return hashlib.sha256(_encoded(value).encode("utf-8")).hexdigest()


def _object(value: Any) -> dict:
    if type(value) is not dict:
        raise ValueError("capture requires a complete JSON object")
    return _snapshot(value)


def _result_object(value: Any) -> dict:
    from ..tool_results import ToolResultText, tool_result_failed
    from .action_recipe import require_complete_result

    if type(value) is str or isinstance(value, ToolResultText):
        if tool_result_failed(value):
            raise ValueError("capture excludes failed or oversized results")
        value = str(value)
        if len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            raise ValueError("capture excludes failed or oversized results")

        def pairs(entries):
            result = {}
            for key, item in entries:
                if key in result:
                    raise ValueError("capture excludes duplicate JSON keys")
                result[key] = item
            return result

        def constant(_value):
            raise ValueError("capture requires finite JSON results")

        value = json.loads(value, object_pairs_hook=pairs, parse_constant=constant)
    result = _object(value)
    require_complete_result(result)
    return result


def _learning_enabled() -> bool:
    from ..config import get_flows
    from ..learning_guard import learning_write_allowed
    from . import enabled

    return (enabled() and get_flows().get("action_recipes") is True
            and learning_write_allowed("flow_action_episode_capture"))


def _durable_learning_enabled() -> bool:
    from ..config import get_flows
    from ..learning_guard import learning_write_allowed
    from . import enabled

    return (enabled() and get_flows().get("action_episode_capture") is True
            and learning_write_allowed("flow_action_episode_capture"))


@dataclass
class _Invocation:
    capture: ActionEpisodeCapture | _DurableCaptureAdapter
    node_id: str
    tool: str
    observation: dict | None = None
    completed: bool = False
    durable_token: Any = None


_CURRENT: contextvars.ContextVar[_Invocation | None] = contextvars.ContextVar(
    "flow_action_episode_invocation", default=None,
)


def capture_plan(flow: Flow, *, allowed_tools, max_steps=MAX_STEPS, no_forms=False) -> list[tuple[str, str]]:
    """Validate the bounded source graph, without supplying execution authority."""
    expected = []
    seen = set()
    cursor = flow.start
    while cursor is not None:
        if cursor in seen or cursor not in flow.nodes or len(seen) >= max_steps * 2:
            raise ValueError("capture requires a bounded straight-line flow")
        seen.add(cursor)
        node = flow.nodes[cursor]
        if (node.kind not in {NODE_ACTION, NODE_APPROVAL} or node.retries or node.on_error
                or node.body is not None or node.branches or node.flow_ref or node.on_expire
                or (no_forms and node.form)):
            raise ValueError("capture excludes branching, nested, agent and retried work")
        if node.kind == NODE_ACTION:
            if node.tool not in allowed_tools or action_tool_policy_error(node.tool):
                raise ValueError("capture tool is not admitted")
            _object(node.params)
            expected.append((node.id, node.tool))
        cursor = node.next
    if len(seen) != len(flow.nodes) or not 1 <= len(expected) <= max_steps:
        raise ValueError("capture requires only reachable bounded action steps")
    return expected


TEACHING_FAMILY = "native_governed_flow_choice_teaching_v1"
TEACHING_MARKER = {"schema": "lightwork.action-choice-teaching.v1"}


def teaching_capture_plan(flow: Flow, *, allowed_tools) -> dict:
    """Admit only the exact generated teaching graph, separately from v1 capture."""
    from . import action_recipe, recipe_flow

    if (getattr(flow, "recipe_teaching", None) != TEACHING_MARKER
            or type(flow.learned_recipe) is not dict
            or flow.learned_recipe.get("schema") != action_recipe.CHOICE_SCHEMA
            or flow.recipe_lineage is None):
        raise ValueError("teaching capture requires an admitted bounded choice graph")
    recipe_flow.validate_flow(flow)
    artifact = flow.learned_recipe
    prefix = ["action_0", artifact["steps"][0]["tool"]]
    branches = {branch["route"]: [f"action_1_{branch['route']}", branch["tool"]]
                for branch in artifact["branches"]}
    actual_tools = {prefix[1], *(pair[1] for pair in branches.values())}
    if set(allowed_tools) != actual_tools or any(action_tool_policy_error(tool) for tool in actual_tools):
        raise ValueError("teaching capture requires exactly every possible native tool")
    for node in flow.nodes.values():
        if (node.retries or node.on_error or node.body is not None or node.branches
                or node.flow_ref or node.on_expire or node.form):
            raise ValueError("teaching capture excludes nested, retried and form work")
        if node.kind == NODE_ACTION:
            _object(node.params)
    return {"prefix": prefix, "branches": branches}


class _DurableCaptureAdapter:
    """Private native-observation bridge; the service owns CAS and authority."""

    def __init__(self, handle, run: store.FlowRun):
        from ..paths import current_tenant_id_strict

        self.handle = handle
        self._status = "capturing"
        self._source = {"tenant": current_tenant_id_strict() or "", "owner": run.owner,
                        "run_id": run.run_id, "flow_id": run.flow_id,
                        "definition_digest": run.definition_digest}

    @property
    def status(self) -> str:
        return self._status

    def _refuse(self, reason: str) -> None:
        self._status = "unusable"
        try:
            self.handle.invalidate(reason)
        except Exception:
            # Capture storage is optional to the business operation. The
            # incomplete durable prefix can never certify a complete episode.
            pass

    def _finish(self, run: store.FlowRun) -> None:
        if self._status != "capturing":
            return
        self.handle.finish(run)
        self._status = "finished"


def resume_capture(flow: Flow, run: store.FlowRun, *, initial_data: dict,
                   submitted_inputs: dict, from_failure: bool, expired: bool,
                   decision: str, decided_by: str = "", approval_binding_sha256: str = "",
                   approval_authority_binding_sha256: str = "", decision_attestation=None) -> _DurableCaptureAdapter | None:
    """Find an enrolled capture by the authoritative run, never queue metadata.

    The caller has already validated the native approval and holds the run
    execution lock. A service failure only loses optional learning evidence.
    """
    try:
        if not _durable_learning_enabled():
            return None
        from .action_episode_review import DurableActionEpisodeCapture, load_capture_runtime

        handle = load_capture_runtime(
            flow, run, resumed=True, initial_data=initial_data,
            submitted_inputs=submitted_inputs, from_failure=from_failure,
            expired=expired, decision=decision, decided_by=decided_by,
            approval_binding_sha256=approval_binding_sha256,
            approval_authority_binding_sha256=approval_authority_binding_sha256,
            decision_attestation=decision_attestation,
        )
        if type(handle) is DurableActionEpisodeCapture:
            return _DurableCaptureAdapter(handle, run)
    except Exception:
        pass
    return None


class ActionEpisodeCapture:
    """A single-use local collector with explicit business inputs and tool list.

    Inputs must exactly equal the run's ``input`` object when present, otherwise
    its complete starting data. An allowlist permits capture only; runtime tool
    authorization is independently enforced for every action as before.
    """

    def __init__(self, *, allowed_tools: list[str], input_data: dict, max_steps: int = MAX_STEPS):
        if (type(allowed_tools) is not list or not 1 <= len(allowed_tools) <= MAX_STEPS
                or any(type(name) is not str or not _NAME.fullmatch(name) for name in allowed_tools)
                or len(set(allowed_tools)) != len(allowed_tools)):
            raise ValueError("capture requires an explicit unique tool allowlist")
        if type(max_steps) is not int or not 1 <= max_steps <= MAX_STEPS:
            raise ValueError("capture max_steps must be between one and eight")
        self._tools = frozenset(allowed_tools)
        self._inputs = _object(input_data)
        self._max_steps = max_steps
        self._status = "new"
        self._reason = "not_started"
        self._source: dict = {}
        self._expected: list[tuple[str, str]] = []
        self._steps: list[dict] = []
        self._receipts: list[dict] = []

    @property
    def status(self) -> str:
        return self._status

    @property
    def reason(self) -> str:
        return self._reason

    @property
    def input_data(self) -> dict:
        return _snapshot(self._inputs)

    def _refuse(self, reason: str) -> None:
        if self._status != "unusable":
            self._reason = reason
        self._status = "unusable"
        self._steps.clear()
        self._receipts.clear()

    def _begin(self, flow: Flow, run: store.FlowRun, *, initial_data: dict, resumed: bool) -> None:
        from ..paths import current_tenant_id_strict

        if self._status != "new":
            raise ValueError("capture collector is single-use")
        if not _learning_enabled():
            raise ValueError("capture feature is disabled or learning is halted")
        if resumed or run.dry_run:
            raise ValueError("capture excludes resumed and dry runs")
        if not run.owner or run.owner != flow.owner:
            raise ValueError("capture requires the saved flow owner")
        current = store.load_flow(flow.id)
        pinned = store.load_flow_snapshot(run.definition_digest)
        if (current is None or _encoded(current.to_dict()) != _encoded(flow.to_dict())
                or _encoded(pinned.to_dict()) != _encoded(flow.to_dict())):
            raise ValueError("capture requires the exact saved source definition")
        source_inputs = initial_data.get("input", initial_data)
        if _encoded(_object(source_inputs)) != _encoded(self._inputs):
            raise ValueError("capture business inputs do not match the run")
        self._expected = capture_plan(flow, allowed_tools=self._tools, max_steps=self._max_steps)
        self._source = {
            "family": "native_governed_flow_actions_v1",
            "tenant": current_tenant_id_strict() or "", "owner": run.owner,
            "run_id": run.run_id, "flow_id": run.flow_id,
            "definition_digest": run.definition_digest,
            "definition_version": run.definition_version,
            "definition_revision": run.definition_revision,
        }
        self._status, self._reason = "capturing", "awaiting_native_actions"

    def _finish(self, run: store.FlowRun) -> None:
        from ..paths import current_tenant_id_strict

        if self._status != "capturing":
            return
        if not _learning_enabled() or (current_tenant_id_strict() or "") != self._source["tenant"]:
            raise ValueError("capture learning authority changed")
        if (run.status != "completed" or run.run_id != self._source["run_id"]
                or run.definition_digest != self._source["definition_digest"]
                or run.owner != self._source["owner"] or run.dry_run
                or len(self._steps) != len(self._expected)):
            raise ValueError("capture requires a complete native episode")
        persisted = store.load_run(run.run_id, owner=run.owner, flow_id=run.flow_id)
        if (persisted is None or persisted.status != "completed"
                or persisted.definition_digest != run.definition_digest):
            raise ValueError("capture source completion is not durably saved")
        if _encoded(_object(persisted.input_data.get("input", persisted.input_data))) != _encoded(self._inputs):
            raise ValueError("capture source inputs changed")
        self._status, self._reason = "complete", "native_episode_complete"

    def export(self, *, reviewed: bool, rationale: str) -> dict:
        """Return independent bytes with explicit, unauthenticated local review."""
        from ..learning_guard import check_learning_halt
        from ..paths import current_tenant_id_strict

        check_learning_halt("flow_action_episode_capture", "export")
        if self._status != "complete" or not _learning_enabled():
            raise ValueError("capture is not a complete exportable episode")
        if reviewed is not True or type(rationale) is not str or not rationale.strip() or len(rationale) > 2000:
            raise ValueError("export requires explicit local review and a nonempty rationale")
        rationale = _snapshot(rationale.strip())
        if (current_tenant_id_strict() or "") != self._source["tenant"]:
            raise ValueError("capture belongs to another tenant")
        episode = {"id": self._source["run_id"], "inputs": self._inputs, "steps": self._steps}
        result = {
            "episode": episode,
            "provenance": {**self._source, "steps": self._receipts, "episode_sha256": _digest(episode)},
            "review": {"reviewed": True, "rationale": rationale,
                       "authority": "local_caller_assertion", "authenticated": False},
        }
        # Business values and rationale have already passed privacy checks.
        # Provenance uses reserved metadata such as "authenticated" which is
        # not a credential field and must not be screened as business input.
        return _snapshot(result, limit=MAX_EPISODE_BYTES, private=False)


def begin_capture(capture: ActionEpisodeCapture | None, flow: Flow, run: store.FlowRun,
                  *, initial_data: dict, resumed: bool) -> None:
    if type(capture) is not ActionEpisodeCapture:
        return
    try:
        capture._begin(flow, run, initial_data=initial_data, resumed=resumed)
    except Exception:
        capture._refuse("source_not_admitted")


def finish_capture(capture: ActionEpisodeCapture | None, run: store.FlowRun) -> None:
    if type(capture) not in {ActionEpisodeCapture, _DurableCaptureAdapter}:
        return
    try:
        capture._finish(run)
    except Exception:
        capture._refuse("episode_incomplete")


@contextmanager
def action_capture_scope(capture: ActionEpisodeCapture | None, node: FlowNode):
    invocation = None
    if type(capture) in {ActionEpisodeCapture, _DurableCaptureAdapter} and capture.status == "capturing":
        try:
            if type(capture) is ActionEpisodeCapture:
                expected = capture._expected[len(capture._steps)]
                if expected != (node.id, node.tool):
                    raise ValueError("unexpected action invocation")
            invocation = _Invocation(capture, node.id, node.tool)
        except Exception:
            capture._refuse("unexpected_action")
    # Clear an outer invocation too: reentrant execution cannot borrow its ID.
    token = _CURRENT.set(invocation)
    try:
        yield
    finally:
        _CURRENT.reset(token)
        if invocation is not None and not invocation.completed:
            capture._refuse("native_action_incomplete")


def native_authorized(tool: str, arguments: dict, *, call_id: str, principal: str | None,
                      input_schema: dict) -> _Invocation | None:
    """Native runner hook only, after authorize and before registry dispatch."""
    invocation = _CURRENT.get()
    if invocation is None:
        return None
    capture = invocation.capture
    try:
        from ..paths import current_tenant_id_strict

        learning_enabled = (_durable_learning_enabled() if type(capture) is _DurableCaptureAdapter
                            else _learning_enabled())
        if (capture.status != "capturing" or invocation.observation is not None
                or tool != invocation.tool or not learning_enabled
                or (current_tenant_id_strict() or "") != capture._source["tenant"]
                or type(input_schema) is not dict
                or type(call_id) is not str or not re.fullmatch(r"[0-9a-f]{24}", call_id)):
            raise ValueError("native observation is not bound to this invocation")
        invocation.observation = {
            "arguments": _object(arguments), "call_id": call_id,
            "principal": _snapshot(principal or ""),
            "tool_schema_sha256": _digest(_snapshot(input_schema, private=False, max_depth=24)),
        }
        if type(capture) is _DurableCaptureAdapter:
            invocation.durable_token = capture.handle.prepare(
                invocation.node_id, tool, invocation.observation["arguments"],
                call_id=call_id, principal=principal or "",
                input_schema=_snapshot(input_schema, private=False, max_depth=24),
            )
            if invocation.durable_token is None:
                raise ValueError("durable preparation was not recorded")
        return invocation
    except Exception:
        capture._refuse("arguments_not_admitted")
        return None


def native_completed(invocation: _Invocation | None, result: Any, *, terminal_recorded: bool) -> None:
    """Optional observation must not turn an executed effect into a retry."""
    if invocation is None:
        return
    capture = invocation.capture
    try:
        learning_enabled = (_durable_learning_enabled() if type(capture) is _DurableCaptureAdapter
                            else _learning_enabled())
        if (capture.status != "capturing" or invocation is not _CURRENT.get()
                or invocation.completed or invocation.observation is None
                or terminal_recorded is not True or not learning_enabled):
            raise ValueError("native terminal evidence is unavailable")
        observation = invocation.observation
        step = {"tool": invocation.tool, "arguments": observation["arguments"],
                "result": _result_object(result)}
        receipt = {"node_id": invocation.node_id, "call_id": observation["call_id"],
                   "principal": observation["principal"], "tool_schema_sha256": observation["tool_schema_sha256"],
                   "step_sha256": _digest(step), "terminal_disposition": "completed"}
        if type(capture) is _DurableCaptureAdapter:
            capture.handle.complete(invocation.durable_token, step["result"], terminal_recorded=True)
        else:
            _snapshot([*capture._steps, step], limit=MAX_EPISODE_BYTES)
            capture._steps.append(step)
            capture._receipts.append(receipt)
        invocation.completed = True
    except Exception:
        capture._refuse("result_not_admitted")
