"""Flow interpreter -- runs a :class:`~.ir.Flow` deterministically.

The control-flow nodes (branch / foreach / parallel / approval / delay) are
evaluated here; the *work* nodes call injected executors (``agent_fn`` for an
agentic goal, ``action_fn`` for a deterministic tool call), so the interpreter is
pure and unit-testable without an LLM or a live connector. A ``data`` dict is
threaded through the graph -- each node may read prior values (``{{key}}`` in a
brief/param, ``key`` in a condition) and write its result under ``output``.

Durability / resume: the top-level run PAUSES at an ``approval`` node (when the
``approve_fn`` policy returns ``pending``) or a ``delay`` node, returning enough
state to continue later (:func:`run_flow` with ``resume=``). foreach bodies and
parallel branches run to completion in one pass (v1: no pause inside a loop
body/branch -- an approval there must resolve via ``approve_fn``); the outer graph
is where human-in-the-loop lives.
"""
from __future__ import annotations

import copy
import threading
import time
from collections.abc import Callable
from contextvars import copy_context
from dataclasses import dataclass, field
from typing import Any

from ..audit.errors import AuditRefused
from ..budget import BudgetExceeded
from ..killswitch import Halted
from .continuation_frame import ContinuationFrame
from .expressions import (
    _CREDENTIAL_REPAIR,
    _FN_CALL,
    FlowRegexRefused,
    _as_text,
    _dig,
    _split_args,
    eval_condition,
    render,
)
from .expressions import (
    _regex_is_safe as _regex_is_safe,
)
from .ir import (
    MAX_FLOW_NODE_RETRY_SLEEP,
    NODE_ACTION,
    NODE_AGENT,
    NODE_APPROVAL,
    NODE_BRANCH,
    NODE_DELAY,
    NODE_FOREACH,
    NODE_PARALLEL,
    NODE_SCOPE,
    NODE_SETVAR,
    NODE_SUBFLOW,
    NODE_SWITCH,
    NODE_WAIT,
    NODE_WHILE,
    Flow,
    FlowNode,
    learned_operator_work_digest,
    max_node_retries,
    validate_learned_operator,
)
from .resume_plan import prepare_resume
from .run_events import (
    FlowApprovalStale,
    FlowBudgetExceeded,
    FlowCredentialRefused,
    _Indeterminate,
    _NodeError,
    _Pause,
    _Reject,
    _safe_error_text,
)
from .run_result import execute_chain_result
from .run_state import (
    ACTIVE_STATUSES,
    PAUSED_STATUSES,
    QUARANTINED_STATUSES,
    STATUS_BUDGET_LIMITED,
    STATUS_CLAIMED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_INDETERMINATE,
    STATUS_PAUSED_APPROVAL,
    STATUS_PAUSED_DELAY,
    STATUS_PAUSED_EVENT,
    STATUS_QUEUED,
    STATUS_REJECTED,
    STATUS_RESUMING,
    STATUS_RUNNING,
    FlowRunResult,
)
from .work_policy import explicit_unknown, needs_reconciliation, work_policy

_WHILE_DEFAULT_CAP = 100   # while-loop iterations when the node sets no limit
_PARALLEL_MAX_WORKERS = 8   # cap fan-out threads for the whole flow run

# Executor signatures (injected):
#   agent_fn(node, rendered_brief, data) -> (result: str, outcome: float | None)
#   action_fn(node, rendered_params, data) -> (result, outcome: float | None)
#   approve_fn(node, data) -> "approved" | "rejected" | "pending"
#   on_node(node, status: str, outcome: float | None) -> None   (telemetry/grounding)
AgentFn = Callable[[FlowNode, str, dict], tuple[Any, float | None]]
ActionFn = Callable[[FlowNode, dict, dict], tuple[Any, float | None]]


@dataclass
class _Ctx:
    agent_fn: AgentFn
    action_fn: ActionFn
    approve_fn: Callable[[FlowNode, dict], str] | None
    on_node: Callable[[FlowNode, str, float | None], None]
    now: Callable[[], float]
    allow_pause: bool
    resolve_flow: Callable[[str], Flow | None] | None = None
    flow_stack: set = field(default_factory=set)   # subflow ids on the call stack
    deadline: float | None = None                  # whole-flow wall-clock deadline
    parallel_slots: Any = None                     # shared worker budget for fan-out
    frame: dict = field(default_factory=dict)
    control_stop: list = field(default_factory=list)
    run_id: str = ""                # supplied by durable execution; empty for library calls
    recipe: dict | None = None      # comes only from the current validated flow
    recipe_lineage: dict | None = None
    recipe_owner: str = ""
    recipe_lineage_check: dict | None = None
    recipe_choice_check: dict | None = None
    recipe_teaching: dict | None = None
    recipe_teaching_check: dict | None = None
    recipe_workflow_check: dict | None = None
    execution_owner: str | None = None  # inherited from the root, never an inline graph

    def nested(self, slot: str = "body") -> _Ctx:
        # A copy that cannot pause (foreach body / subflow run straight). Shares
        # flow_stack + deadline so cycle detection and the whole-flow deadline
        # span the linear nesting.
        return _Ctx(self.agent_fn, self.action_fn, self.approve_fn, self.on_node,
                    self.now, allow_pause=False, resolve_flow=self.resolve_flow,
                    flow_stack=self.flow_stack, deadline=self.deadline,
                    parallel_slots=self.parallel_slots,
                    frame=self.frame.setdefault("children", {}).setdefault(slot, {}),
                    control_stop=self.control_stop, run_id=self.run_id,
                    execution_owner=self.execution_owner)

    def branched(self, slot: str = "body") -> _Ctx:
        # For a CONCURRENT parallel branch: its own flow_stack copy (independent
        # cycle detection -- a sibling branch's subflow isn't a cycle here), but a
        # shared clock/deadline and the shared on_node sink.
        return _Ctx(self.agent_fn, self.action_fn, self.approve_fn, self.on_node,
                    self.now, allow_pause=False, resolve_flow=self.resolve_flow,
                    flow_stack=set(self.flow_stack), deadline=self.deadline,
                    parallel_slots=self.parallel_slots,
                    frame=self.frame.setdefault("children", {}).setdefault(slot, {}),
                    control_stop=self.control_stop, run_id=self.run_id,
                    execution_owner=self.execution_owner)


def _secret_expression(expression: str) -> bool:
    """Inspect call/quoted-argument structure, not raw keywords.

    An unknown wrapper around a secret call is conservatively migration-bound,
    even though today's evaluator would leave that unknown expression inert.
    """
    pending = [expression.strip()]
    while pending:
        part = pending.pop()
        if len(part) >= 2 and part[0] in "'\"" and part[-1] == part[0]:
            continue  # A quoted example is data, never a nested function call.
        call = _FN_CALL.match(part)
        if call:
            if call.group(1) == "secret":
                return True
            pending.extend(_split_args(call.group(2)))
    return False


def _check_action_credentials(value) -> None:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
        elif isinstance(item, str):
            position = 0
            while (start := item.find("{{", position)) >= 0:
                end = item.find("}}", start + 2)
                if end < 0:
                    break
                if _secret_expression(item[start + 2:end]):
                    raise FlowCredentialRefused(_CREDENTIAL_REPAIR)
                position = end + 2


def _credential_review(flow: Flow, resolve_flow):
    """Check the entire graph before any effect; freeze saved subflow lookups.

    This also runs on persisted continuation/approval resumes. The resolver's
    reviewed copies are used at execution, so a second lookup cannot swap in
    an unchecked graph after a harmless prefix has already executed.
    """
    pending, seen, resolved = [flow], set(), {}
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        for node in current.nodes.values():
            if node.kind == NODE_ACTION:
                _check_action_credentials(node.params)
            if node.body is not None:
                pending.append(node.body)
            pending.extend(node.branches or [])
            if node.kind == NODE_SUBFLOW and resolve_flow:
                if node.flow_ref not in resolved:
                    resolved[node.flow_ref] = copy.deepcopy(resolve_flow(node.flow_ref))
                if resolved[node.flow_ref] is not None:
                    pending.append(resolved[node.flow_ref])
    return (lambda reference: resolved.get(reference)) if resolve_flow else None


def _render_params(node: FlowNode, data: dict) -> dict:
    _check_action_credentials(node.params)
    values = {k: render(v, data, allow_secrets=True) if isinstance(v, str) else v
              for k, v in (node.params or {}).items()}
    # A data-key substitution must not silently hand an unresolved legacy
    # expression to a connector either. No second template evaluation occurs.
    _check_action_credentials(values)
    return values


def _learned_agent_result(node: FlowNode, data: dict, *, flow_id: str, run_id: str) -> tuple[bool, Any]:
    """Select pure learned computation or the original agent, before any effect.

    The receipt reports selection, never independently established correctness.
    No example, input, output, or original brief is copied into that receipt.
    """
    from .. import audit
    from ..config import get_flows
    from ..learning_guard import check_learning_halt
    from . import enabled as flows_enabled
    from .operator_artifacts import COMPOSED_SCHEMA, evaluate

    check_learning_halt("flow_learned_operator", "select")
    reason, applied, value, candidate_count = "invalid_artifact", False, None, 0
    artifact_digest, work_digest = "", ""
    envelope = node.learned_operator
    if isinstance(envelope, dict):
        artifact = envelope.get("artifact")
        if isinstance(artifact, dict):
            claimed = artifact.get("artifact_sha256")
            if (isinstance(claimed, str) and len(claimed) == 64
                    and all(c in "0123456789abcdef" for c in claimed)):
                artifact_digest = claimed
        try:
            work_digest = learned_operator_work_digest(node)
        except (TypeError, ValueError):
            pass
        settings = get_flows()
        composed = isinstance(artifact, dict) and artifact.get("schema") == COMPOSED_SCHEMA
        if (not flows_enabled() or settings.get("learned_operators") is not True
                or (composed and settings.get("composed_operators") is not True)):
            reason = "feature_disabled"
        elif envelope.get("work_sha256") != work_digest:
            reason = "work_changed"
        else:
            try:
                validate_learned_operator(node)
                decision = evaluate(envelope["artifact"], data)
            except (TypeError, ValueError):
                reason = "invalid_artifact"
            else:
                reason = decision.reason
                if reason not in {"agreement", "outside_domain", "ambiguity", "invalid_artifact",
                                  "evaluation_limit"}:
                    reason = "invalid_artifact"
                applied = decision.applied is True and reason == "agreement"
                value = decision.value if applied else None
                candidate_count = decision.candidate_count
    check_learning_halt("flow_learned_operator", "receipt")
    try:
        written = audit.record(
            audit.EventKind.FLOW_LEARNED_OPERATOR_DECISION,
            agent="flow:learned_operator", flow_id=flow_id, flow_run_id=run_id, node_id=node.id,
            status="applied" if applied else "fallback", reason=reason,
            artifact_sha256=artifact_digest, work_sha256=work_digest,
            candidate_count=candidate_count,
        )
    except (AuditRefused, BudgetExceeded, Halted, FlowApprovalStale):
        raise
    except Exception as exc:
        raise AuditRefused("learned operator decision audit failed") from exc
    if written is not True:
        raise AuditRefused("learned operator decision requires a durable audit receipt")
    check_learning_halt("flow_learned_operator", "dispatch")
    return applied, value


def _invoke_work(node: FlowNode, data: dict, ctx: _Ctx):
    def _call():
        if node.kind == NODE_AGENT:
            if node.learned_operator is not None:
                applied, value = _learned_agent_result(
                    node, data, flow_id=ctx.frame["flow_id"], run_id=ctx.run_id,
                )
                if applied:
                    # Execution agreement is not an independent correctness label.
                    return value, None
                if node.learned_fallback is False:
                    raise ValueError("These learned rules cannot answer this input. Review the examples before trying again.")
            return ctx.agent_fn(node, render(node.brief, data), data)
        if node.recipe_step is not None:
            return _invoke_recipe_action(node, data, ctx)
        return ctx.action_fn(node, _render_params(node, data), data)
    if not (node.timeout and node.timeout > 0):
        return _call()
    # Soft per-node timeout: Python cannot kill a running thread safely.  Once a
    # call crosses the deadline we therefore MUST wait for its authoritative
    # result.  Discarding a later success and labelling it failed would invite a
    # retry of an external mutation that actually committed.
    import concurrent.futures as _cf
    with _cf.ThreadPoolExecutor(max_workers=1) as ex:
        # Tenant, connector authority and execution controls are ContextVars.
        # Each submission needs its own Context, including nested fan-out.
        fut = ex.submit(copy_context().run, _call)
        try:
            return fut.result(timeout=node.timeout)
        except _cf.TimeoutError:
            return fut.result()


def _recipe_features_enabled(artifact, *, teaching=False):
    from ..config import get_flows
    from . import action_recipe
    from . import enabled as flows_enabled

    settings = get_flows()
    return (flows_enabled() and settings.get("action_recipes") is True
            and (artifact.get("schema") not in {action_recipe.TRANSFORM_SCHEMA, action_recipe.CHOICE_SCHEMA,
                                                *action_recipe.WORKFLOW_SCHEMAS}
                 or settings.get("action_recipe_transforms") is True)
            and (artifact.get("schema") not in action_recipe.WORKFLOW_SCHEMAS
                 or (settings.get("action_workflow_learning") is True
                     and settings.get("action_recipe_lineage") is True))
            and (artifact.get("schema") != action_recipe.MEMORY_SCHEMA
                 or settings.get("action_workflow_memory_learning") is True)
            and (artifact.get("schema") != action_recipe.CHOICE_SCHEMA
                 or settings.get("action_recipe_choices") is True)
            and (not teaching or (settings.get("action_recipe_teaching") is True
                                  and settings.get("action_recipe_lineage") is True)))


def _recipe_choice_binding(node, data, ctx, index, resolved):
    from . import action_recipe, recipe_flow

    if ctx.recipe.get("schema") in action_recipe.WORKFLOW_SCHEMAS:
        from .workflow_recipe_flow import selected_binding
        if resolved.tool != node.tool:
            return "workflow_changed", None
        try:
            ctx.recipe_workflow_check = selected_binding(ctx.recipe, data, index, node.tool)
        except (ValueError, TypeError, RecursionError, UnicodeError):
            return "workflow_changed", None
        return "agreement", None
    if ctx.recipe.get("schema") != action_recipe.CHOICE_SCHEMA:
        return "agreement", None
    if resolved.tool != node.tool:
        return "choice_changed", None
    if index == 0:
        return "agreement", None
    # The resolver established argument agreement and either guard agreement
    # or an exact teaching selection, separately bound to its real observation.
    binding = recipe_flow.choice_binding(ctx.recipe, data, resolved.tool)
    if data.get("_recipe_choice") != binding:
        return "choice_changed", None
    return "agreement", binding


def _recipe_dispatch_eligibility(ctx):
    """Refresh eligibility after the required selected-receipt I/O boundary.

    This is a final current-state check, not an atomic revocation fence across
    the external connector. Native tool authority still runs at dispatch.
    """
    from ..audit import default_audit_log
    from . import action_recipe, recipe_flow

    if not _recipe_features_enabled(ctx.recipe, teaching=ctx.recipe_teaching is not None):
        return "feature_disabled", None
    try:
        current = recipe_flow.check_lineage(ctx.recipe, ctx.recipe_lineage, owner=ctx.recipe_owner)
    except (AuditRefused, BudgetExceeded, Halted, FlowApprovalStale):
        raise
    except Exception:
        return "evidence_ineligible", None
    if (ctx.recipe.get("schema") in action_recipe.WORKFLOW_SCHEMAS
            and default_audit_log().signing_enabled is not True):
        # A successful selected receipt cannot authorize a later unsigned
        # dispatch if the resolved signing policy changed across that I/O.
        # The strict completion write still handles failures after the effect.
        raise AuditRefused("learned workflow requires signed execution receipts")
    previous = ctx.recipe_lineage_check
    if current is not None and previous is not None and current.get("trust_sha256") != previous.get("trust_sha256"):
        return "evidence_changed", None
    return "agreement", current


def _recipe_resolve(node, data, ctx, index):
    from . import choice_teaching, recipe_flow

    ctx.recipe_teaching_check = None
    if index != 1 or ctx.recipe_teaching is None or "_recipe_teaching_selection" not in data:
        return recipe_flow.decision(ctx.recipe, index, data)
    try:
        question = recipe_flow.validate_teaching_question(ctx.recipe, data)
        decision = data.get("_recipe_teaching_decision")
        if type(decision) is not str or decision not in {"route:0", "route:1"}:
            raise ValueError("teaching selection changed")
        route = decision.removeprefix("route:")
        binding = choice_teaching.selection_binding(ctx.recipe, question, route)
        if data["_recipe_teaching_selection"] != binding or binding["tool"] != node.tool:
            raise ValueError("teaching selection changed")
        resolved = choice_teaching.select(ctx.recipe, question, route, data.get("input"), data.get("_recipe_step_0"))
        if resolved.applied:
            ctx.recipe_teaching_check = binding
        return resolved
    except (ValueError, TypeError):
        from .action_recipe import Decision
        return Decision(False, reason="teaching_changed")


def _recipe_arguments(node: FlowNode, data: dict, ctx: _Ctx, index: int, *, record: bool):
    from ..learning_guard import check_learning_halt
    from . import recipe_flow

    check_learning_halt("flow_action_recipe", "resolve")
    if ctx.recipe is None:
        raise ValueError("learned action is missing its parent recipe")
    resolved = _recipe_resolve(node, data, ctx, index)
    reason = resolved.reason
    if not _recipe_features_enabled(ctx.recipe, teaching=ctx.recipe_teaching is not None):
        reason = "feature_disabled"
    ctx.recipe_choice_check = None
    ctx.recipe_workflow_check = None
    if resolved.applied is True and reason in {"agreement", "teaching_selection"}:
        bound_reason, ctx.recipe_choice_check = _recipe_choice_binding(node, data, ctx, index, resolved)
        if bound_reason != "agreement":
            reason = bound_reason
    applied = resolved.applied is True and reason in {"agreement", "teaching_selection"}
    ctx.recipe_lineage_check = None
    if applied:
        try:
            ctx.recipe_lineage_check = recipe_flow.check_lineage(
                ctx.recipe, ctx.recipe_lineage, owner=ctx.recipe_owner)
        except (AuditRefused, BudgetExceeded, Halted, FlowApprovalStale):
            raise
        except Exception:
            reason, applied = "evidence_ineligible", False
    if record or not applied:
        recipe_flow.record_decision(
            ctx.recipe, flow_id=ctx.frame["flow_id"], run_id=ctx.run_id, node_id=node.id,
            index=index, status="selected" if applied else "blocked", reason=reason,
            arguments=resolved.arguments if applied else None,
            lineage=ctx.recipe_lineage_check,
            choice=ctx.recipe_choice_check,
            teaching=ctx.recipe_teaching_check,
            workflow=ctx.recipe_workflow_check,
        )
    if applied and record:
        reason, ctx.recipe_lineage_check = _recipe_dispatch_eligibility(ctx)
        applied = reason == "agreement"
        if not applied:
            recipe_flow.record_decision(ctx.recipe, flow_id=ctx.frame["flow_id"], run_id=ctx.run_id,
                node_id=node.id, index=index, status="blocked", reason=reason,
                choice=ctx.recipe_choice_check, teaching=ctx.recipe_teaching_check,
                workflow=ctx.recipe_workflow_check)
    if not applied:
        # This is a stop, never a fallback to an agent or a replay of the prefix.
        if index:
            ctx.on_node(node, STATUS_INDETERMINATE, None)
            raise _Indeterminate(node.id, f"learned action stopped: {reason}; preserve completed work",
                                 boundary="learned action sequence")
        raise ValueError(f"learned action stopped before dispatch: {reason}")
    check_learning_halt("flow_action_recipe", "dispatch")
    return resolved.arguments


def _invoke_recipe_action(node: FlowNode, data: dict, ctx: _Ctx):
    from . import action_recipe, recipe_flow

    index = node.recipe_step
    params = _recipe_arguments(node, data, ctx, index, record=True)
    result, outcome = ctx.action_fn(copy.deepcopy(node), copy.deepcopy(params), copy.deepcopy(data))
    if outcome == 0.0:
        return result, outcome
    try:
        parsed = action_recipe.parse_result(result)
        action_recipe.validate_result(ctx.recipe, index, parsed, tool=node.tool)
    except (TypeError, ValueError):
        ctx.on_node(node, STATUS_INDETERMINATE, None)
        raise _Indeterminate(node.id, "action returned an unsupported result; reconcile before continuing",
                             boundary="learned action result") from None
    completed_workflow = ctx.recipe_workflow_check
    if ctx.recipe.get("schema") == action_recipe.MEMORY_SCHEMA:
        from .workflow_recipe_flow import completed_memory_binding
        completed_workflow = completed_memory_binding(ctx.recipe, data, index,
            tool=node.tool, arguments=params, result=parsed)
    recipe_flow.record_decision(
        ctx.recipe, flow_id=ctx.frame["flow_id"], run_id=ctx.run_id, node_id=node.id,
        index=index, status="completed",
        reason="result_domain_valid" if ctx.recipe.get("schema") in {
            action_recipe.TRANSFORM_SCHEMA, action_recipe.CHOICE_SCHEMA, *action_recipe.WORKFLOW_SCHEMAS}
        else "result_shape_valid", arguments=params, lineage=ctx.recipe_lineage_check, choice=ctx.recipe_choice_check,
        teaching=ctx.recipe_teaching_check,
        workflow=completed_workflow,
    )
    if ctx.recipe.get("schema") in action_recipe.WORKFLOW_SCHEMAS:
        from .workflow_recipe_flow import retain_result
        retain_result(ctx.recipe, data, index, tool=node.tool, arguments=params, result=parsed)
    return parsed, outcome


def _run_work(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    # Retry a failed work node up to `retries` more times -- a transient tool/agent
    # failure (outcome 0.0) OR a hard exception from the executor gets another
    # attempt before we give up. With `retry_backoff` set, wait an exponentially
    # growing interval between attempts (capped) instead of re-hammering instantly;
    # backoff 0 keeps the original tight loop (and adds no sleep to existing flows).
    backoff = max(0.0, node.retry_backoff)
    result: Any = None
    outcome: float | None = None
    last_exc: Exception | None = None
    explicit_indeterminate = False
    policy = work_policy(node, max_retries=max_node_retries())
    for attempt in range(policy.retries + 1):
        if ctx.deadline is not None and ctx.now() > ctx.deadline:
            raise RuntimeError("flow exceeded its wall-clock deadline during node retries")
        if attempt and backoff:
            _sleep_retry_backoff(ctx, min(MAX_FLOW_NODE_RETRY_SLEEP, backoff * (2 ** (attempt - 1))))
        try:
            result, outcome = _invoke_work(node, data, ctx)
            last_exc = None
        except (BudgetExceeded, Halted, FlowApprovalStale, AuditRefused, FlowCredentialRefused, FlowRegexRefused):
            raise
        except Exception as e:   # a raising executor is a retryable failure, not instant death
            last_exc, outcome = e, 0.0
            continue
        if explicit_unknown(node, result, outcome):
            # Unknown effects must not be re-driven even for normally safe tools.
            explicit_indeterminate = True
            break
        if outcome != 0.0:
            break
    # A hard exception that survived every retry stays terminal (records WHERE it
    # failed via _NodeError up the chain) -- retries buy attempts, not silence.
    # A reserved refusal/preview proves the effect was intentionally NOT
    # attempted (approval denied, Shield blocked, or confirm gate returned its
    # dry-run preview). Those are terminal failures, not reconciliation cases.
    # Ordinary ERROR/exception results remain ambiguous for a high-risk tool
    # because the remote system may have committed before acknowledgement loss.
    if needs_reconciliation(policy, result=result, outcome=outcome,
                            error=last_exc, unknown=explicit_indeterminate):
        detail = _safe_error_text(
            f"{type(last_exc).__name__}: {last_exc}"
            if last_exc is not None else result
        )
        # Ambiguity is not a grounded failure signal.  Preserve the trace status
        # but do not feed a guessed 0.0 into self-learning.
        ctx.on_node(node, STATUS_INDETERMINATE, None)
        raise _Indeterminate(
            node.id,
            detail[:500],
            boundary=(
                "agent trajectory"
                if policy.ambiguous_agent
                else "action evidence"
                if explicit_indeterminate
                else "high-risk action"
            ),
        )
    if last_exc is not None:
        raise last_exc
    ctx.on_node(node, "done", outcome)
    # A node that still failed routes to its on_error handler if it has one, so a
    # flow can catch and recover instead of poisoning `data` and marching on.
    # Never publish a failed connector result under its ordinary output key: it
    # may contain raw auth headers/error bodies and is not valid business data.
    if outcome == 0.0 and node.on_error:
        return node.on_error
    if outcome == 0.0:
        raise RuntimeError(f"work node failed: {_safe_error_text(result)}")
    if node.output:
        data[node.output] = result
    return node.next


def _sleep_retry_backoff(ctx: _Ctx, seconds: float) -> None:
    if seconds <= 0:
        return
    if ctx.deadline is None:
        time.sleep(seconds)
        return
    remaining = ctx.deadline - ctx.now()
    if remaining <= 0:
        raise RuntimeError("flow exceeded its wall-clock deadline during retry backoff")
    time.sleep(min(seconds, remaining))
    if seconds > remaining:
        raise RuntimeError("flow exceeded its wall-clock deadline during retry backoff")


def _run_subflow(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    sub = ctx.resolve_flow(node.flow_ref) if ctx.resolve_flow else None
    if sub is None or sub.id in ctx.flow_stack:   # missing OR would recurse -> failure
        ctx.on_node(node, "error", 0.0)
        if node.on_error is not None:
            return node.on_error
        raise RuntimeError(f"subflow {node.flow_ref!r} is missing or cyclic")
    # Runs on the SAME data dict (threaded), so the sub-flow reads parent data and
    # its outputs flow back. Nested: it cannot pause (v1 -- HITL lives up top). The
    # flow id is on the stack for its duration so a cyclic reference is caught.
    ctx.flow_stack.add(sub.id)
    # Two modes. Default (no subflow_inputs): the child runs on the SHARED data dict
    # -- it reads parent data and its outputs flow back (v1 behaviour). Scoped (with
    # subflow_inputs): the child runs on an ISOLATED dict seeded with ONLY the mapped
    # inputs, so a reusable subflow can't read or clobber unrelated parent keys; its
    # results return solely via `output`. Nested: it cannot pause (HITL lives up top).
    if node.subflow_inputs:
        child = {str(k): (render(v, data) if isinstance(v, str) else v)
                 for k, v in node.subflow_inputs.items()}
        seeded = set(child)
        try:
            _run_chain(sub, child, ctx.nested(), sub.start)
        finally:
            ctx.flow_stack.discard(sub.id)
        if node.output:
            data[node.output] = {k: child[k] for k in child if k not in seeded}
    else:
        before = set(ctx.frame.setdefault("return_seed", list(data)))
        try:
            _run_chain(sub, data, ctx.nested(), sub.start)
        finally:
            ctx.flow_stack.discard(sub.id)
        # Capture the subflow's return -- the keys it ADDED -- under node.output, so a
        # reusable subflow's result can be referenced by name instead of only leaking
        # into the shared data dict by side effect.
        if node.output:
            data[node.output] = {k: data[k] for k in data if k not in before}
    # Ground success as 1.0 (failure already grounds 0.0 above), so a subflow
    # node has a symmetric success-rate signal the self-rewrite loop can measure.
    ctx.on_node(node, "done", 1.0)
    return node.next


def _run_branch(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    took = eval_condition(node.condition, data)
    ctx.on_node(node, "true" if took else "false", None)
    nxt = node.if_true if took else node.if_false
    return nxt if nxt is not None else node.next


_FOREACH_DEFAULT_CAP = 1000   # runaway guard when a foreach sets no explicit limit


def _run_switch(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    """n-way route: the value under the ``condition`` data key is compared (as
    text) to each case's ``value``; the first match routes to its ``to``. No
    match falls through to ``next`` (the default arm)."""
    from .action_recipe import CHOICE_SCHEMA, WORKFLOW_SCHEMAS

    if ctx.recipe is not None and ctx.recipe.get("schema") in WORKFLOW_SCHEMAS:
        return _run_workflow_decision(node, data, ctx)
    if ctx.recipe is not None and ctx.recipe.get("schema") == CHOICE_SCHEMA:
        if ctx.recipe_teaching is not None and node.id == "teaching_choice":
            return _run_teaching_choice(node, data, ctx)
        return _run_recipe_choice(node, data, ctx)
    subject = _as_text(_dig(data, node.condition))
    for case in node.cases:
        if _as_text(case.get("value")) == subject:
            ctx.on_node(node, f"case:{_as_text(case.get('value'))[:40]}", None)
            to = case.get("to")
            return to if to is not None else node.next
    ctx.on_node(node, "default", None)
    return node.next


def _run_workflow_decision(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    """Learned next call or END, bound to the actual completed invocation history."""
    from ..learning_guard import check_learning_halt
    from . import recipe_flow, workflow_recipe_flow

    check_learning_halt("flow_action_workflow", "select")
    index = int(node.id.removeprefix("decision_"))
    if index == 0:
        workflow_recipe_flow.clear_initial(data)
    selected = workflow_recipe_flow.resolve(ctx.recipe, data, index)
    reason = selected.reason
    if not _recipe_features_enabled(ctx.recipe):
        reason = "feature_disabled"
    applied = selected.applied is True and reason == "agreement"
    ctx.recipe_lineage_check = None
    if applied:
        try:
            ctx.recipe_lineage_check = recipe_flow.check_lineage(ctx.recipe, ctx.recipe_lineage, owner=ctx.recipe_owner)
        except (AuditRefused, BudgetExceeded, Halted, FlowApprovalStale):
            raise
        except Exception:
            reason, applied = "evidence_ineligible", False
    binding = workflow_recipe_flow.binding(ctx.recipe, data, index, selected) if applied else None
    recipe_flow.record_decision(ctx.recipe, flow_id=ctx.frame["flow_id"], run_id=ctx.run_id,
        node_id=node.id, index=index, status="workflow_selected" if applied else "workflow_blocked",
        reason=reason, lineage=ctx.recipe_lineage_check, workflow=binding)
    if applied:
        reason, ctx.recipe_lineage_check = _recipe_dispatch_eligibility(ctx)
        applied = reason == "agreement"
        if not applied:
            recipe_flow.record_decision(ctx.recipe, flow_id=ctx.frame["flow_id"], run_id=ctx.run_id,
                node_id=node.id, index=index, status="workflow_blocked", reason=reason, workflow=binding)
    if not applied:
        if index:
            ctx.on_node(node, STATUS_INDETERMINATE, None)
            raise _Indeterminate(node.id, f"learned workflow stopped: {reason}; preserve completed work",
                                 boundary="learned workflow decision")
        raise ValueError(f"learned workflow stopped before dispatch: {reason}")
    check_learning_halt("flow_action_workflow", "route")
    data[workflow_recipe_flow.SELECTION] = binding
    if selected.kind == "complete":
        data.pop("_recipe_next_arguments", None)
        ctx.on_node(node, "case:complete", None)
        return None
    ordinal = ctx.recipe["allowed_tools"].index(selected.tool)
    ctx.on_node(node, f"case:{ordinal}", None)
    return f"approval_{index}_{ordinal}"


def _run_recipe_choice(node: FlowNode, data: dict, ctx: _Ctx) -> str:
    """Infer the route from retained observations, never a caller-supplied flag."""
    from ..learning_guard import check_learning_halt
    from . import action_choice, choice_teaching, recipe_flow

    check_learning_halt("flow_action_choice", "select")
    # Original caller data cannot preselect a teaching answer. Every fresh
    # prefix produces its own question before a separately bound human pause.
    for key in ("_recipe_teaching_question", "_recipe_teaching_decision", "_recipe_teaching_selection"):
        data.pop(key, None)
    selected = action_choice.resolve_choice(ctx.recipe, data.get("input"), [data.get("_recipe_step_0")])
    reason = selected.reason
    if not _recipe_features_enabled(ctx.recipe, teaching=ctx.recipe_teaching is not None):
        reason = "feature_disabled"
    if reason == "ambiguity" and ctx.recipe_teaching is not None:
        try:
            question = choice_teaching.propose(ctx.recipe, data.get("input"), data.get("_recipe_step_0"))
        except choice_teaching.TeachingUnavailable as exc:
            reason = exc.reason
        else:
            return _request_teaching_review(node, data, ctx, question)
    applied = selected.applied is True and reason == "agreement"
    ctx.recipe_lineage_check = None
    if applied:
        try:
            ctx.recipe_lineage_check = recipe_flow.check_lineage(ctx.recipe, ctx.recipe_lineage, owner=ctx.recipe_owner)
        except (AuditRefused, BudgetExceeded, Halted, FlowApprovalStale):
            raise
        except Exception:
            reason, applied = "evidence_ineligible", False
    binding = recipe_flow.choice_binding(ctx.recipe, data, selected.tool) if applied else None
    recipe_flow.record_decision(ctx.recipe, flow_id=ctx.frame["flow_id"], run_id=ctx.run_id,
        node_id=node.id, index=1, status="choice_selected" if applied else "choice_blocked",
        reason=reason, lineage=ctx.recipe_lineage_check, choice=binding)
    if not applied:
        ctx.on_node(node, STATUS_INDETERMINATE, None)
        raise _Indeterminate(node.id, f"learned choice stopped: {reason}; preserve completed work",
                             boundary="learned action choice")
    check_learning_halt("flow_action_choice", "route")
    data["_recipe_choice"] = binding
    ctx.on_node(node, f"case:{selected.route}", None)
    return f"approval_1_{selected.route}"


def _teaching_eligibility(ctx):
    from ..learning_guard import check_learning_halt
    from . import recipe_flow

    check_learning_halt("flow_action_teaching", "review")
    if (ctx.recipe_teaching is None or ctx.recipe_lineage is None
            or not _recipe_features_enabled(ctx.recipe, teaching=True)):
        raise ValueError("native choice teaching is disabled or lacks signed lineage")
    return recipe_flow.check_lineage(ctx.recipe, ctx.recipe_lineage, owner=ctx.recipe_owner)


def _request_teaching_review(node, data, ctx, question):
    from . import recipe_flow

    lineage = _teaching_eligibility(ctx)
    recipe_flow.record_decision(ctx.recipe, flow_id=ctx.frame["flow_id"], run_id=ctx.run_id,
        node_id=node.id, index=1, status="teaching_requested", reason="guard_ambiguity",
        lineage=lineage, teaching={key: question[key] for key in
            ("artifact_sha256", "guard_artifact_sha256", "question_sha256", "input_sha256", "prefix_sha256")})
    _teaching_eligibility(ctx)
    data["_recipe_teaching_question"] = question
    data.pop("_recipe_choice", None)
    ctx.on_node(node, "teaching_requested", None)
    return "teaching_review"


def _run_teaching_choice(node, data, ctx):
    from . import choice_teaching, recipe_flow

    lineage = _teaching_eligibility(ctx)
    question = recipe_flow.validate_teaching_question(ctx.recipe, data)
    decision = data.get("_recipe_teaching_decision")
    if type(decision) is not str or decision not in {"route:0", "route:1"}:
        raise ValueError("teaching requires an explicit offered continuation choice")
    route = decision.removeprefix("route:")
    selected = choice_teaching.select(ctx.recipe, question, route, data.get("input"), data.get("_recipe_step_0"))
    if selected.applied is not True:
        raise ValueError("teaching choice no longer matches the completed observations")
    binding = choice_teaching.selection_binding(ctx.recipe, question, route)
    choice = recipe_flow.choice_binding(ctx.recipe, data, selected.tool)
    recipe_flow.record_decision(ctx.recipe, flow_id=ctx.frame["flow_id"], run_id=ctx.run_id,
        node_id=node.id, index=1, status="teaching_selected", reason="teaching_selection",
        arguments=selected.arguments, lineage=lineage, choice=choice, teaching=binding)
    _teaching_eligibility(ctx)
    data["_recipe_teaching_selection"] = binding
    data["_recipe_choice"] = choice
    ctx.on_node(node, f"case:{route}", None)
    return f"approval_1_{route}"


def _run_while(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    """Run the body sub-flow while the condition holds, on the SAME data dict
    (so the body can change what the condition sees). Iterations are capped by
    ``limit`` (default 100) as the runaway guard; the body may set ``_break``."""
    cap = node.limit if node.limit and node.limit > 0 else _WHILE_DEFAULT_CAP
    passes = int(ctx.frame.get("passes", 0))
    while passes < cap and (
        "body" in ctx.frame.get("children", {}) or eval_condition(node.condition, data)
    ):
        _run_chain(node.body, data, ctx.nested(), node.body.start)
        passes += 1
        ctx.frame["passes"] = passes
        ctx.frame.pop("children", None)
        if data.get("_break"):
            data.pop("_break", None)
            break
    if node.output:
        data[node.output] = passes
    ctx.on_node(node, "done", None)
    return node.next


def _run_wait(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    """Pause the run until an external event resumes it (a webhook delivery,
    an API resume). Nested contexts can't pause, so there it is a no-op step
    (the outer graph is where waiting lives, same as approvals)."""
    if ctx.allow_pause:
        ctx.on_node(node, "waiting", None)
        raise _Pause("event", node, data)
    # Nested (foreach/while/scope body, parallel branch): can't pause. Fail
    # CLOSED like a nested approval rather than silently continuing -- otherwise
    # downstream nodes run before the awaited event's data has arrived.
    ctx.on_node(node, "skipped", None)
    raise _Reject(
        node, data,
        error="A wait for another app cannot run inside repeated or parallel work. "
              "Move it to the main flow.",
    )


def _run_scope(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    """try/catch: run the body on the shared data; if a body node raises, route
    to ``on_error`` (the catch arm) instead of failing the whole run. Without an
    ``on_error`` the failure propagates -- a try with no catch still fails."""
    try:
        _run_chain(node.body, data, ctx.nested(), node.body.start)
    except _NodeError as e:
        if node.on_error is None:
            raise
        data["_error"] = _safe_error_text(e)  # safe for downstream catch branches
        ctx.on_node(node, "caught", 0.0)
        return node.on_error
    ctx.on_node(node, "done", None)
    return node.next


def _run_foreach(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    if type(node.concurrency) is not int or not 0 <= node.concurrency <= _PARALLEL_MAX_WORKERS:
        raise _Reject(node, data, error="Choose Shared workflow limit or between 1 and 8 items at once.")
    items = copy.deepcopy(ctx.frame.get("items", list(_dig(data, node.items) or [])))
    if node.limit and node.limit > 0:
        items = items[:node.limit]          # cap iterations (a runaway-list guard)
    elif len(items) > _FOREACH_DEFAULT_CAP:
        # An implicit safety ceiling is not consent to discard the list's tail.
        # Refuse before the first body iteration rather than report partial work
        # as complete. Deliberately chosen positive limits still select a prefix.
        ctx.on_node(node, "skipped", None)
        raise _Reject(node, data, error=(
            f"This list has {len(items):,} items. Without a chosen item limit, "
            f"repeated work supports up to {_FOREACH_DEFAULT_CAP:,} items. "
            "This step processed no items. Choose an explicit item limit and "
            "review the workflow before running again. Earlier steps may have completed."
        ))
    ctx.frame["items"] = items
    results = copy.deepcopy(ctx.frame.get("results", []))
    if node.concurrent and len(items) > 1:
        # Concurrent iteration: each item gets an isolated data copy and its own
        # branch context (independent cycle detection), on the same bounded pool
        # the parallel node uses. Results keep ITEM ORDER; ``_break`` doesn't
        # apply (iterations overlap, there is no "early" to stop at).
        import concurrent.futures as _cf
        subs = []
        for item in items:
            sub = dict(data)
            sub[node.var] = item
            subs.append(sub)
        threaded = []
        inline = []
        # Explicit caps include the calling thread, which processes inline items.
        # Zero preserves older definitions' use of the unchanged shared pool.
        spawn_cap = node.concurrency - 1 if node.concurrency else _PARALLEL_MAX_WORKERS
        for index, sub in enumerate(subs):
            if (len(threaded) < spawn_cap and ctx.parallel_slots is not None
                    and ctx.parallel_slots.acquire(blocking=False)):
                threaded.append((index, sub))
            else:
                inline.append((index, sub))
        first_error = None
        if threaded:
            with _cf.ThreadPoolExecutor(max_workers=len(threaded)) as ex:
                futs = [ex.submit(copy_context().run, _run_chain_with_parallel_slot, node.body, sub,
                                  ctx.branched(str(index)), node.body.start)
                        for index, sub in threaded]
                for index, sub in inline:
                    try:
                        _run_chain(node.body, sub, ctx.branched(str(index)), node.body.start)
                    except Exception as e:
                        first_error = first_error or e
                for f in futs:
                    try:
                        f.result()
                    except Exception as e:
                        first_error = first_error or e
        else:
            for index, sub in inline:
                _run_chain(node.body, sub, ctx.branched(str(index)), node.body.start)
        if ctx.control_stop:
            raise ctx.control_stop[0]
        if first_error is not None:
            raise first_error
        results = subs
    else:
        for item in items[len(results):]:
            sub = dict(data)
            sub[node.var] = item
            _run_chain(node.body, sub, ctx.nested(), node.body.start)
            results.append(sub)      # per-iteration data snapshot (body outputs included)
            ctx.frame["results"] = copy.deepcopy(results)
            ctx.frame.pop("children", None)
            if node.output:
                # Publish partial results after EACH iteration, so a whole-flow
                # deadline or a failure mid-loop keeps the batch's completed work
                # (run_flow returns the data as-of the abort) instead of losing it.
                data[node.output] = list(results)
            if sub.get("_break"):    # the body asked to stop early (sequential only)
                break
    if node.output:
        data[node.output] = results
    ctx.on_node(node, "done", None)
    return node.next


def _run_parallel(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    base = dict(data)                     # frozen pre-parallel snapshot
    branch_outputs = [dict(base) for _ in node.branches]   # each isolated (sees only base)
    if len(node.branches) > 1:
        # Run the branches CONCURRENTLY. Each has an isolated data copy and its
        # own flow_stack (ctx.branched()); the shared world DB serialises writes
        # (WAL + busy_timeout). A branch that raises propagates after the pool
        # joins the rest, so there are no leaked threads.
        import concurrent.futures as _cf
        futs = []
        inline = []
        for index, (br, sub) in enumerate(zip(node.branches, branch_outputs, strict=True)):
            if ctx.parallel_slots is not None and ctx.parallel_slots.acquire(blocking=False):
                futs.append((index, br, sub))
            else:
                inline.append((index, br, sub))
        first_error = None
        if futs:
            with _cf.ThreadPoolExecutor(max_workers=len(futs)) as ex:
                futs = [ex.submit(copy_context().run, _run_chain_with_parallel_slot, br, sub,
                                  ctx.branched(str(index)), br.start)
                        for index, br, sub in futs]
                for index, br, sub in inline:
                    try:
                        _run_chain(br, sub, ctx.branched(str(index)), br.start)
                    except Exception as e:
                        first_error = first_error or e
                for f in futs:
                    try:
                        f.result()        # wait for all; re-raise the first error
                    except Exception as e:
                        first_error = first_error or e
        else:
            for index, br, sub in inline:
                _run_chain(br, sub, ctx.branched(str(index)), br.start)
        if ctx.control_stop:
            raise ctx.control_stop[0]
        if first_error is not None:
            raise first_error
    else:
        for br, sub in zip(node.branches, branch_outputs, strict=True):
            _run_chain(br, sub, ctx.nested(), br.start)
    for sub in branch_outputs:            # merge new keys deterministically, in order
        for k, v in sub.items():          # (a later branch wins a key conflict)
            if k not in base:
                data[k] = v
    if node.output:
        data[node.output] = branch_outputs
    ctx.on_node(node, "done", None)
    return node.next


def _approval_outcome(decision: str) -> float | None:
    # A decided approval is the highest-value grounded HUMAN signal: which gates
    # humans keep rejecting (rework them) vs. rubber-stamp (automate them away).
    # A still-pending pause is not yet a decision, so it grounds nothing.
    if decision == "approved":
        return 1.0
    if decision == "rejected":
        return 0.0
    return None


def _run_approval(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    # A policy callback reviews a snapshot. It cannot rewrite a learned action's
    # already displayed input or node through mutable reference aliases.
    review_node = copy.deepcopy(node) if ctx.recipe is not None else node
    review_data = copy.deepcopy(data) if ctx.recipe is not None else data
    if ctx.recipe_teaching is not None and node.id == "teaching_review":
        # A generic autoapproval callback cannot supply a training choice.
        # The native executor must authenticate a separate durable resume.
        decision = "pending"
    else:
        decision = ctx.approve_fn(review_node, review_data) if ctx.approve_fn else "pending"
    # Ground the decided verdict (B7): approved=1.0 / rejected=0.0 / pending=None --
    # the highest-value human signal for the self-rewrite loop.
    ctx.on_node(node, decision, _approval_outcome(decision))
    # "approved" -- or any verdict the node explicitly offers (a choice approval:
    # "ship"/"hold"/"escalate") -- continues; the verdict is recorded to `output`
    # so downstream nodes (a branch/switch) can route on it.
    if decision == "approved" or (node.choices and decision in node.choices):
        if node.output:
            data[node.output] = decision
        return node.next
    if decision == "rejected":
        raise _Reject(node, data)
    if ctx.allow_pause:                    # pending + top level -> wait for a human
        # An approval's EXPIRY is `expires_after` (its own field, so it can't be
        # confused with the execution `timeout`). Older flows that encoded it in
        # `timeout` are migrated at LOAD time (FlowNode.from_dict), so every
        # consumer -- this runner, the designer, the sweep -- sees one field.
        expiry = node.expires_after
        resume_at = ctx.now() + expiry if expiry and expiry > 0 else None
        raise _Pause("approval", node, data, resume_at=resume_at)
    raise _Reject(node, data)              # nested can't pause -> treat as not approved


def _run_delay(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    if ctx.allow_pause and node.seconds > 0:
        raise _Pause("delay", node, data, resume_at=ctx.now() + node.seconds)
    return node.next


def _run_setvar(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    """Set flow-data keys from expressions -- the 'compose'/'set variable' step.
    A string value is rendered (so ``{{add(count,1)}}`` computes a loop counter and
    ``{{upper(name)}}`` composes a field); a non-string is stored as-is. This is
    what makes computed state + a while-loop (setvar counter -> branch -> back)
    expressible in the graph."""
    for key, expr in (node.assignments or {}).items():
        data[str(key)] = render(expr, data) if isinstance(expr, str) else expr
    ctx.on_node(node, "done", None)
    return node.next


_HANDLERS = {
    NODE_AGENT: _run_work, NODE_ACTION: _run_work, NODE_BRANCH: _run_branch,
    NODE_SWITCH: _run_switch, NODE_FOREACH: _run_foreach, NODE_WHILE: _run_while,
    NODE_PARALLEL: _run_parallel, NODE_APPROVAL: _run_approval,
    NODE_DELAY: _run_delay, NODE_WAIT: _run_wait, NODE_SCOPE: _run_scope,
    NODE_SUBFLOW: _run_subflow, NODE_SETVAR: _run_setvar,
}


def _run_node(node: FlowNode, data: dict, ctx: _Ctx) -> str | None:
    handler = _HANDLERS.get(node.kind)
    if handler is None:
        raise ValueError(f"unknown node kind {node.kind!r}")
    return handler(node, data, ctx)


def _run_chain(flow: Flow, data: dict, ctx: _Ctx, start: str | None) -> None:
    from .action_recipe import WORKFLOW_SCHEMAS

    if ctx.execution_owner is None:
        ctx.execution_owner = flow.owner
    ctx.recipe = flow.learned_recipe
    ctx.recipe_lineage = copy.deepcopy(flow.recipe_lineage)
    ctx.recipe_owner = ctx.execution_owner
    ctx.recipe_lineage_check = None
    ctx.recipe_choice_check = None
    ctx.recipe_teaching = copy.deepcopy(flow.recipe_teaching)
    ctx.recipe_teaching_check = None
    ctx.recipe_workflow_check = None
    if ctx.recipe is not None and ctx.recipe.get("schema") in WORKFLOW_SCHEMAS:
        if ctx.recipe_lineage is None or not ctx.allow_pause:
            raise ValueError("learned workflow requires signed lineage and top-level native approvals")
    if ctx.recipe_teaching is not None and (ctx.recipe_lineage is None or not ctx.allow_pause):
        raise ValueError("recipe teaching requires signed lineage and a top-level native pause")
    if ctx.recipe_lineage is not None and flow.owner and flow.owner != ctx.execution_owner:
        raise ValueError("learned recipe owner differs from its authoritative execution owner")
    if ctx.recipe is not None:
        from .recipe_flow import validate_flow
        validate_flow(flow)
    elif (flow.recipe_lineage is not None or flow.recipe_teaching is not None
          or any(node.recipe_step is not None for node in flow.nodes.values())):
        raise ValueError("learned action node is missing its parent recipe")
    frame = ContinuationFrame(ctx.frame, flow.id)
    cursor, seen = frame.start(data, start)
    limit = max(1000, len(flow.nodes) * 100)   # cycle backstop
    while cursor is not None:
        if ctx.control_stop:
            raise ctx.control_stop[0]
        if ctx.deadline is not None and ctx.now() > ctx.deadline:
            raise RuntimeError(f"flow {flow.id!r} exceeded its wall-clock deadline")
        node = flow.node(cursor)
        if node is None:
            raise ValueError("flow continuation node no longer exists")
        try:
            if ctx.recipe is not None and node.kind == NODE_APPROVAL:
                if ctx.recipe_teaching is not None and node.id == "teaching_review":
                    from .recipe_flow import validate_teaching_question
                    validate_teaching_question(ctx.recipe, data)
                    _teaching_eligibility(ctx)
                    data.pop("_recipe_next_arguments", None)
                else:
                    following = flow.node(node.next)
                    data["_recipe_next_arguments"] = _recipe_arguments(
                        following, data, ctx, following.recipe_step, record=False,
                    )
            cursor = _run_node(node, data, ctx)
        except (BudgetExceeded, Halted, FlowApprovalStale, AuditRefused, FlowCredentialRefused, FlowRegexRefused) as exc:
            ctx.control_stop.append(exc)
            raise
        except (_Pause, _Reject, _NodeError, _Indeterminate):
            raise
        except Exception as e:
            raise _NodeError(node.id, e) from e
        finally:
            frame.checkpoint_data(data)
        seen += 1
        frame.advance(cursor, data, seen)
        if seen > limit:
            raise RuntimeError(f"flow {flow.id!r} exceeded {limit} steps (cycle?)")


def _run_chain_with_parallel_slot(flow: Flow, data: dict, ctx: _Ctx, start: str | None) -> None:
    try:
        _run_chain(flow, data, ctx, start)
    finally:
        if ctx.parallel_slots is not None:
            ctx.parallel_slots.release()


def run_flow(flow: Flow, *, agent_fn: AgentFn, action_fn: ActionFn,
             data: dict | None = None,
             run_id: str = "",
             approve_fn: Callable[[FlowNode, dict], str] | None = None,
             on_node: Callable[[FlowNode, str, float | None], None] | None = None,
             resume: dict | None = None,
             now: Callable[[], float] | None = None,
             resolve_flow: Callable[[str], Flow | None] | None = None) -> FlowRunResult:
    """Run ``flow`` to completion or the next pause.

    ``resume`` continues a paused run: ``{"node_id", "data", "decision"?}`` --
    ``decision`` is the human's verdict on the approval node that paused it
    (``approved`` continues, ``rejected`` ends); a delay resume omits it.
    ``resolve_flow(flow_ref) -> Flow | None`` resolves a ``subflow`` node's target
    (with the caller's cycle/depth guard); ``None`` makes a subflow a no-op error.
    ``run_id`` attributes decision receipts to the caller's durable execution;
    direct library calls leave it empty unless their caller supplies an identity.
    """
    flow = copy.deepcopy(flow)
    data = copy.deepcopy(data)
    resume = copy.deepcopy(resume)
    try:
        resolve_flow = _credential_review(flow, resolve_flow)
    except FlowCredentialRefused as exc:
        return FlowRunResult(status=STATUS_FAILED, data=dict((resume or {}).get("data") or data or {}), error=str(exc))
    except (BudgetExceeded, Halted, FlowApprovalStale, AuditRefused):
        raise
    except Exception as exc:
        # A failed saved-subflow read is still a failed run, never an escaped
        # interpreter exception or permission to execute an unchecked prefix.
        return FlowRunResult(status=STATUS_FAILED, data=dict((resume or {}).get("data") or data or {}),
                             error=_safe_error_text(exc, limit=2000))
    _now = now or time.time
    ctx = _Ctx(agent_fn, action_fn, approve_fn, on_node or (lambda *_: None),
               _now, allow_pause=True, resolve_flow=resolve_flow,
               flow_stack={flow.id},   # so the top flow can't recurse into itself
               deadline=(_now() + flow.max_seconds if flow.max_seconds and flow.max_seconds > 0 else None),
               parallel_slots=threading.BoundedSemaphore(_PARALLEL_MAX_WORKERS),
               run_id=run_id)
    plan = prepare_resume(
        flow, data=data, resume=resume, resolve_flow=resolve_flow,
        on_node=on_node, approval_outcome=_approval_outcome,
    )
    if plan.result is not None:
        return plan.result
    if plan.frame is not None:
        ctx.frame = plan.frame
    data, start = plan.data, plan.start
    return _execute_chain_result(flow, data, ctx, start)


def _execute_chain_result(flow: Flow, data: dict, ctx: _Ctx, start: str | None) -> FlowRunResult:
    return execute_chain_result(flow, data, ctx, start, run_chain=_run_chain, render=render)


__all__ = [
    "run_flow", "render", "eval_condition", "FlowRunResult", "FlowApprovalStale",
    "STATUS_QUEUED", "STATUS_CLAIMED", "STATUS_RUNNING", "STATUS_RESUMING",
    "STATUS_COMPLETED", "STATUS_PAUSED_APPROVAL", "STATUS_PAUSED_DELAY",
    "STATUS_PAUSED_EVENT", "STATUS_REJECTED", "STATUS_FAILED", "STATUS_INDETERMINATE",
    "STATUS_BUDGET_LIMITED", "FlowBudgetExceeded",
    "PAUSED_STATUSES", "ACTIVE_STATUSES", "QUARANTINED_STATUSES",
]
