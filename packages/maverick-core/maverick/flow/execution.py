"""Run a stored flow with live executors + durable, resumable run state.

This binds the pure interpreter (:mod:`.runner`) to the real system: an ``agent``
node becomes a governed goal, an ``action`` node a tool call, and every work
node's outcome is recorded per-node (:mod:`.node_outcomes`) for the self-rewrite
pass. The run's state is persisted after each pause/finish (:mod:`.store`) so a
flow paused on an approval survives a restart and resumes days later.

The executors are injected (``agent_runner`` / ``action_runner``), so the whole
driver is testable without an LLM or a live connector; :func:`default_agent_runner`
and :func:`default_action_runner` supply the production bindings.
"""
from __future__ import annotations

import contextvars
import copy
import inspect
from collections.abc import Callable
from typing import Any

from ..tool_results import tool_result_failed
from . import node_outcomes, store
from .action_episodes import (
    ActionEpisodeCapture,
    action_capture_scope,
    begin_capture,
    finish_capture,
    native_authorized,
    native_completed,
    resume_capture,
)
from .approval_dispatch import ApprovalDispatch
from .budgeting import (
    _budget_gated,
    _spend_tracked,
)
from .budgeting import (
    _MeteredAgentResult as _MeteredAgentResult,
)
from .execution_plan import bind_execution_plan, pin_new_plan
from .execution_trace import ExecutionTrace
from .ir import Flow, FlowNode
from .lifecycle import serialize_runs
from .pause_snapshot import ApprovalPauseContext, build_human_pause
from .resume_admission import prepare_saved_resume
from .run_events import FlowBudgetExceeded
from .run_state import (
    STATUS_BUDGET_LIMITED as STATUS_BUDGET_LIMITED,
)
from .run_state import (
    STATUS_CLAIMED as STATUS_CLAIMED,
)
from .run_state import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_INDETERMINATE,
    STATUS_RESUMING,
    STATUS_RUNNING,
)
from .run_state import (
    STATUS_PAUSED_APPROVAL as STATUS_PAUSED_APPROVAL,
)
from .runner import run_flow

TRIGGER_NODE = "__trigger__"  # reserved node id under which a trigger's run-outcome is grounded


class FlowNotResumable(ValueError):
    """A resume was requested for a run that is not paused."""


def _safe_failure(exc: BaseException) -> str:
    try:
        from ..safety.secret_detector import redact

        text, _matches = redact(str(exc))
        return text[:500]
    except Exception:
        return "failure details were redacted"


def _approval_actor_matches(actor: str, assignee: str) -> bool:
    expected = str(assignee or "").strip().casefold()
    if not expected:
        return True
    principal = str(actor or "").strip().casefold()
    aliases = {principal}
    if principal.startswith("user:") and principal[5:]:
        subject = principal[5:]
        aliases.update({subject, f"@{subject}"})
    return expected in aliases

# agent_runner(brief, data) -> (result, outcome: float | None)
# action_runner(tool, params, data) -> (result, outcome: float | None)
AgentRunner = Callable[[str, dict], "tuple[Any, float | None]"]
ActionRunner = Callable[[str, dict, dict], "tuple[Any, float | None]"]


DEFAULT_AGENT_BUDGET = 5.0   # legacy injected-runner reservation; production meters actual usage


# The node an agent runner is currently serving, set by _call_agent around the
# call and read by default_agent_runner to attribute the goal's tool usage back
# to the node (for harden-tool inference). A ContextVar, not a kwarg, so the
# runner contract stays (brief, data[, wall]) -- no new signature to break, and
# no double-invocation of the stateful budget wrappers on a fallback path. Set +
# read happen synchronously on one thread (even under the foreach pool), so the
# value is always the right node.
_active_node: contextvars.ContextVar[tuple[str, str, str, str]] = contextvars.ContextVar(
    "_flow_active_node", default=("", "", "", ""))
_active_value_run: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_flow_value_run", default="")


def _runner_accepts_wall(runner: AgentRunner) -> bool:
    """Inspect the runner contract without executing a stateful call twice."""
    try:
        parameters = inspect.signature(runner).parameters.values()
    except (TypeError, ValueError):
        # The production contract accepts ``wall``. For opaque callables, make
        # one contract-compliant invocation and surface any error; never retry a
        # possibly side-effecting call based on its exception type.
        return True
    return any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        or (
            parameter.name == "wall"
            and parameter.kind
            in {inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}
        )
        for parameter in parameters
    )


def _call_agent(runner: AgentRunner, brief: str, data: dict, wall: float,
                flow_id: str = "", node_id: str = "", revision: str = "",
                cohort: str = "", run_id: str = "") -> tuple:
    """Invoke an agent runner with a node ``timeout`` as its goal's wall-clock
    allowance. The flow waits for the result; it does not abandon running work.
    Action nodes do not apply this allowance. Injected 2-arg runners that do not
    accept ``wall`` are called plainly. Publishes the current node id on a
    ContextVar so the production runner can attribute its goal's tools to it."""
    token = _active_node.set((flow_id, node_id, revision, cohort))
    value_token = _active_value_run.set(run_id)
    try:
        if wall and wall > 0 and _runner_accepts_wall(runner):
            return runner(brief, data, wall=wall)
        return runner(brief, data)
    finally:
        _active_value_run.reset(value_token)
        _active_node.reset(token)


def _serialize_runs(fn):
    # Resolve the redactor at call time to preserve the public driver seam.
    return serialize_runs(fn, safe_failure=lambda exc: _safe_failure(exc))


@_serialize_runs
def execute(flow: Flow, *, agent_runner: AgentRunner, action_runner: ActionRunner,  # noqa: C901
            owner: str = "", data: dict | None = None,
            approve_fn: Callable[[FlowNode, dict], str] | None = None,
            run_id: str | None = None,
            resume_run_id: str | None = None, decision: str | None = None,
            decided_by: str = "",
             expired: bool = False,
             approval_binding_sha256: str = "",
             approval_expiry_binding_sha256: str = "",
             approval_authority_binding_sha256: str = "",
             approval_decision_attestation: object | None = None,
             from_failure: bool = False,
            budget_limit_dollars: float | None = None,
            inputs: dict | None = None, record_outcomes: bool = True,
            agent_budget_dollars: float = DEFAULT_AGENT_BUDGET, origin: str = "manual",
            now: Callable[[], float] | None = None,
            episode_capture: ActionEpisodeCapture | None = None,
            execution_guard: Callable[[], None] | None = None) -> store.FlowRun:
    """Run ``flow`` (or resume a paused run) with live executors, persisting the
    resulting :class:`~.store.FlowRun`. ``run_id`` pre-assigns a fresh run's id
    (so a caller can hand it back for polling); ``decision`` is the human verdict
    when resuming a run paused on an approval (``approved`` / ``rejected``).
    ``record_outcomes=False`` (a dry run) still traces per-node status for the
    overlay but does NOT ground outcomes -- a mock run's fake successes must not
    pollute the self-rewrite signal."""
    # The persisted definition and approved data must describe what executes,
    # even if the original caller edits its objects while a review is pending.
    flow = copy.deepcopy(flow)
    data = copy.deepcopy(data)
    inputs = copy.deepcopy(inputs)
    resume = None
    prior = None
    approval_resume = False
    approval_actor = ""
    approval_submitted_inputs: dict = {}
    approval_check_binding = ""
    approval_check_expired = False
    approval_snapshot = None
    if budget_limit_dollars is not None and not resume_run_id:
        raise FlowNotResumable("a run allowance change requires a saved budget-held run")
    if resume_run_id:
        admission = prepare_saved_resume(
            flow, run_id=resume_run_id, owner=owner, inputs=inputs,
            from_failure=from_failure, budget_limit_dollars=budget_limit_dollars,
            decision=decision, decided_by=decided_by, expired=expired,
            approval_binding=approval_binding_sha256, expiry_binding=approval_expiry_binding_sha256,
            actor_matches=_approval_actor_matches, not_resumable=FlowNotResumable,
        )
        prior, flow, owner, resume = admission.prior, admission.flow, admission.owner, admission.resume
        submitted_inputs = admission.submitted_inputs
        approval_resume = admission.approval_resume
        approval_actor = admission.approval_actor
        approval_check_binding = admission.approval_binding
        approval_check_expired = admission.approval_expired
        if approval_resume:
            approval_submitted_inputs = submitted_inputs
        run_id = prior.run_id
    rid = run_id or store.new_run_id()
    # A fresh run may have a queued placeholder (saved at enqueue with the
    # idempotency key + original inputs) -- preserve those instead of resetting.
    placeholder = store.load_run(rid) if (run_id and not resume_run_id) else None
    plan = bind_execution_plan(flow, prior=prior, placeholder=placeholder)
    flow = plan.flow
    # This flag denotes a previously persisted plan. Legacy resumed runs may
    # still need the historical subflow loader after their new snapshot is made.
    has_pinned_plan = plan.pinned
    execution_channel = plan.execution_channel
    execution_user_id = plan.execution_user_id
    allowed_suites = plan.allowed_suites
    if approval_resume and prior is not None:
        from .approvals import require_current_paused_operation

        # Preserve the exact durable pause that the human reviewed.  The live
        # run row moves to ``resuming`` once an effect is admitted, but every
        # later effect must still be checked against this immutable operation.
        approval_snapshot = copy.deepcopy(prior)
        require_current_paused_operation(
            approval_snapshot,
            flow,
            inputs=approval_submitted_inputs,
            expected_binding=approval_check_binding,
            authority_binding_sha256=approval_authority_binding_sha256,
            decision=str(resume.get("decision") or ""),
            decided_by=approval_actor,
            expired=approval_check_expired,
            decision_attestation=approval_decision_attestation,
        )
    plan = pin_new_plan(plan)
    definition_digest = plan.definition_digest
    release_digest = plan.release_digest
    release_id = plan.release_id
    definition_version = plan.definition_version
    definition_revision = plan.definition_revision
    subflow_digests = dict(plan.subflow_digests or {})
    evidence_cohort = store.definition_cohort(
        definition_revision or flow.revision,
        definition_version or flow.version,
    )
    # Per-node run trace for the designer overlay. Seeded from the prior run on
    # resume so the pre-pause nodes' status survives across the pause.
    node_trace = ExecutionTrace(
        flow_id=flow.id,
        revision=definition_revision or flow.revision,
        cohort=evidence_cohort,
        initial_states=prior.nodes if (resume_run_id and prior) else {},
        record_outcomes=record_outcomes,
        execution_guard=execution_guard,
    )

    # Origin (what fired this run) comes from the queued placeholder when present,
    # else the caller's argument -- carried across a resume from the prior run.
    run_origin = (prior.origin if (resume_run_id and prior)
                  else (placeholder.origin if placeholder else origin))
    # Track reserved agent spend for the run. Seed resumed runs from the durable
    # cost already reserved before the pause so flow.max_dollars remains an
    # aggregate per-run cap across approval/delay resume boundaries. The
    # max_dollars gate updates this list too; without a gate, wrap a plain spend
    # tracker so cost is still recorded.
    spent = [float(prior.cost_dollars) if (resume_run_id and prior) else 0.0]
    run_budget_limit = (
        budget_limit_dollars if budget_limit_dollars is not None
        else prior.budget_limit_dollars if prior is not None and prior.budget_limit_dollars is not None
        else flow.max_dollars
    )
    if record_outcomes:
        if run_budget_limit and run_budget_limit > 0:
            # Aggregate per-run spend ceiling: a wide parallel / long foreach can't
            # fan out unbounded cost (per-node budget alone doesn't bound the COUNT).
            agent_runner = _budget_gated(agent_runner, run_budget_limit, agent_budget_dollars, spent)
        else:
            agent_runner = _spend_tracked(agent_runner, agent_budget_dollars, spent)

    # Write a "running" state before executing so a long run is distinguishable
    # from a stuck "queued" one on the dashboard (a fresh, non-resume run only).
    if not resume_run_id:
        running = store.FlowRun(
            run_id=rid, flow_id=flow.id, status=STATUS_RUNNING, owner=owner,
            data=dict(data or {}), origin=run_origin,
            created=(placeholder.created if placeholder else 0.0),
            input_data=(placeholder.input_data if placeholder else dict(data or {})),
            idem_key=(placeholder.idem_key if placeholder else ""),
            dry_run=(placeholder.dry_run if placeholder else not record_outcomes),
            definition_digest=definition_digest,
            release_digest=release_digest,
            release_id=release_id,
            definition_version=definition_version,
            definition_revision=definition_revision,
            subflow_digests=subflow_digests,
            execution_channel=execution_channel,
            execution_user_id=execution_user_id,
            allowed_suites=allowed_suites,
        )
        store.save_run(running)

    if resume_run_id and prior is not None:
        # Enrollment is loaded by the authoritative tenant/run identity only.
        # Native approval validation above has succeeded; the saved pause is
        # still intact here, before any durable resuming claim or tool effect.
        durable_capture = resume_capture(
            flow, copy.deepcopy(prior), initial_data=copy.deepcopy(prior.input_data),
            submitted_inputs=copy.deepcopy(submitted_inputs), from_failure=from_failure,
            expired=expired, decision=str(decision or ""),
            decided_by=approval_actor,
            approval_binding_sha256=approval_check_binding,
            approval_authority_binding_sha256=approval_authority_binding_sha256,
            decision_attestation=approval_decision_attestation,
        )
        if durable_capture is not None:
            episode_capture = durable_capture
    begin_capture(
        episode_capture, flow, prior if resume_run_id else running,
        initial_data=dict(data or {}), resumed=bool(resume_run_id),
    )

    def _resolve_pinned_flow(flow_ref: str) -> Flow | None:
        if flow_ref in subflow_digests:
            digest = subflow_digests[flow_ref]
            return store.load_flow_snapshot(digest) if digest else None
        # Backward compatibility for a run persisted before subflow snapshots
        # existed.  New runs never reach this path for a resolvable reference.
        return store.load_flow(flow_ref) if (resume_run_id and not has_pinned_plan) else None

    if resume_run_id and prior is not None and not approval_resume:
        # First-writer-wins claim BEFORE any downstream executor is invoked.  A
        # crash after this point leaves an indeterminate run, never the old
        # paused row that another delivery could replay.  An approval resume is
        # claimed by ``ApprovalDispatch`` before its first agent or action.
        prior.status = STATUS_RESUMING
        store.save_run(prior)

    dispatch_action = ApprovalDispatch(
        action_runner=action_runner, flow=flow, prior=prior, snapshot=approval_snapshot,
        approval_resume=approval_resume, submitted_inputs=approval_submitted_inputs,
        binding=approval_check_binding, authority_binding=approval_authority_binding_sha256,
        decision=str((resume or {}).get("decision") or ""), actor=approval_actor,
        expired=approval_check_expired, decision_attestation=approval_decision_attestation,
    )

    def _run_action(node: FlowNode, params: dict, action_data: dict):
        from ..plugin_execution_pins import flow_scope

        with action_capture_scope(episode_capture, node), flow_scope(rid, owner, definition_revision or flow.revision):
            return dispatch_action(node, params, action_data)

    def _run_agent(node: FlowNode, brief: str, agent_data: dict):
        # An approved continuation is claimed before any executor, agent steps
        # included, so an interruption cannot leave a replayable pause behind.
        dispatch_action.admit_agent()
        return node_trace.timed(node.id, lambda: _call_agent(
            agent_runner,
            brief,
            agent_data,
            node.timeout,
            flow_id=flow.id,
            node_id=node.id,
            revision=definition_revision or flow.revision,
            cohort=evidence_cohort,
            run_id=rid,
        ))

    res = run_flow(
        flow,
        run_id=rid,
        agent_fn=_run_agent,
        action_fn=lambda node, params, d: node_trace.timed(
            node.id, lambda: _run_action(node, params, d)
        ),
        approve_fn=approve_fn, data=data, resume=resume, on_node=node_trace.on_node, now=now,
        # A subflow node resolves to another SAVED flow; the runner's flow_stack
        # guards against a cyclic reference (this loader stays a plain lookup).
        resolve_flow=_resolve_pinned_flow,
    )
    # Ground the TRIGGER's run-outcome (which triggers produce valuable runs vs.
    # noise) when a triggered run reaches a terminal state -- the top-of-funnel
    # signal, kept under a reserved node id so it's separable from work nodes.
    if record_outcomes and run_origin != "manual" and res.status in (STATUS_COMPLETED, STATUS_FAILED):
        node_outcomes.record(
            flow.id,
            TRIGGER_NODE,
            "trigger",
            1.0 if res.status == STATUS_COMPLETED else 0.0,
            revision=definition_revision or flow.revision,
            cohort=evidence_cohort,
        )

    human = build_human_pause(ApprovalPauseContext(
        flow=flow, result=res, owner=owner,
        execution_user_id=execution_user_id, execution_channel=execution_channel,
        allowed_suites=allowed_suites, definition_digest=definition_digest,
        release_digest=release_digest, release_id=release_id,
        definition_revision=definition_revision, run_budget_limit=run_budget_limit,
        cost_dollars=spent[0],
    ))
    run = store.FlowRun(
        run_id=rid, flow_id=flow.id, status=res.status, data=res.data,
        cursor=res.cursor, resume_at=res.resume_at, prompt=res.prompt,
        continuation=res.continuation,
        error=res.error, owner=owner, origin=run_origin, cost_dollars=spent[0],
        budget_limit_dollars=run_budget_limit or None,
        human=human,
        decided_by=(
            approval_actor
            if resume_run_id and prior is not None and approval_resume and not expired
            else (prior.decided_by if prior is not None else "")
        ),
        created=(prior.created if resume_run_id and prior
                 else (placeholder.created if placeholder else 0.0)),
        nodes=node_trace.states,
        # Keep the original trigger payload (from the queued placeholder or this
        # fresh data) / carry it across a resume, so a failed run can be retried
        # from scratch with the same inputs; carry the idempotency key too.
        input_data=(prior.input_data if (resume_run_id and prior)
                    else (placeholder.input_data if placeholder else dict(data or {}))),
        idem_key=(prior.idem_key if (resume_run_id and prior)
                  else (placeholder.idem_key if placeholder else "")),
        dry_run=(prior.dry_run if (resume_run_id and prior)
                 else (placeholder.dry_run if placeholder else not record_outcomes)),
        definition_digest=definition_digest,
        release_digest=release_digest,
        release_id=release_id,
        definition_version=definition_version,
        definition_revision=definition_revision,
        subflow_digests=subflow_digests,
        execution_channel=execution_channel,
        execution_user_id=execution_user_id,
        allowed_suites=allowed_suites,
    )
    store.save_run(run)
    if record_outcomes:
        # Content-free execution receipt. A checkpoint or a saved draft alone
        # must never establish performed business work in value reporting.
        from ..audit import EventKind, audit_event
        audit_event(EventKind.CONTROL_PLANE_ACTION, agent="flow",
                    action="intent_value.flow_state", run_id=run.run_id,
                    flow_id=run.flow_id, status=run.status,
                    definition_revision=run.definition_revision,
                    release_id=run.release_id,
                    performed_work_nodes=sum(node.kind in {"agent", "action"}
                        and run.nodes.get(node.id, {}).get("status") == "done"
                        for node in flow.nodes.values()),
                    performed_work_node_ids=[node.id for node in flow.nodes.values()
                        if node.kind in {"agent", "action"}
                        and run.nodes.get(node.id, {}).get("status") == "done"])
    finish_capture(episode_capture, run)
    # Learn the shape of this flow's output keys from a REAL run's data (never a
    # dry run -- mock executors produce placeholder shapes), so the designer's
    # data pills can offer nested keys. Field names + types only; best-effort.
    if record_outcomes and res.status != STATUS_INDETERMINATE:
        from .schema_infer import infer_output_shapes
        # record_flow_schema owns the best-effort swallow.
        store.record_flow_schema(
            flow.id,
            infer_output_shapes(flow, res.data),
            revision=definition_revision or flow.revision,
        )
    return run


def default_agent_runner(
    world,
    *,
    owner: str = "",
    budget_dollars: float | None = None,
    budget_wall_seconds: float | None = None,
    channel: str | None = None,
    user_id: str | None = None,
    allowed_suites: frozenset[str] | None = None,
    concurrency_principal: str | None = None,
) -> AgentRunner:
    """Production ``agent_runner``: an agent node becomes a governed goal.

    Creates a goal from the (rendered) brief, runs it through the durable runner,
    and grounds a terminal outcome (done=1.0 / not=0.0) as the node's signal.
    Best-effort: a runner failure yields a failure result + a 0.0 outcome rather
    than raising into the flow."""
    def run(brief: str, data: dict, wall: float | None = None,
            *, allowance: float | None = None) -> tuple[Any, float | None]:
        from ..runner import clamp_task_limit, configured_max_dollars, configured_max_wall_seconds

        gid = world.create_goal(str(brief)[:200], str(brief)[:8000], owner=owner)
        if _active_value_run.get():
            world.record_goal_origin(gid, "flow_run", _active_value_run.get())
        # A per-node timeout lowers this goal's own wall allowance. The flow
        # waits for its result; the goal enforces the lower cap (kernel rule 3).
        ws = clamp_task_limit(budget_wall_seconds, configured_max_wall_seconds())
        ws = clamp_task_limit(wall if wall and wall > 0 else None, ws)
        dollars = clamp_task_limit(budget_dollars, configured_max_dollars())
        dollars = clamp_task_limit(allowance, dollars)
        usage = []
        try:
            from ..runner import run_goal_in_thread
            result = run_goal_in_thread(
                gid,
                max_dollars=dollars,
                max_wall_seconds=ws,
                channel=channel,
                user_id=user_id,
                allowed_suites=allowed_suites,
                concurrency_principal=(concurrency_principal or owner or user_id),
                usage_observer=usage.append,
            )
        except Exception as e:  # pragma: no cover -- runner wiring varies by env
            return _MeteredAgentResult(
                f"agent step failed: {type(e).__name__}: {_safe_failure(e)}", 0.0,
                usage[-1] if usage else 0.0,
            )
        from ..run_outcome import GoalAdmissionRefused

        if (
            isinstance(result, GoalAdmissionRefused)
            and result.goal_id == gid
            and result.stop_kind in {"budget", "organization_budget"}
        ):
            # This newly-created goal never entered orchestration. A string
            # status, a zero bill, or a budget-looking error after execution
            # began cannot establish the same replay-safe fact.
            raise FlowBudgetExceeded(result.detail)
        g = world.get_goal(gid)
        outcome = 1.0 if (g and g.status == "done") else 0.0
        # Attribute this goal's tool usage back to the node (from the ContextVar
        # _call_agent published), so the self-rewrite pass can infer which tool a
        # reliably-one-tool agent node should harden into. Only on SUCCESS: a node
        # with retries invokes this runner once PER ATTEMPT, so recording every
        # attempt would let one retried run masquerade as many "runs" and inflate
        # the inference support -- and a failed attempt's tools are noise anyway.
        # A reliable node (the only harden candidate) succeeds ~once per run, so
        # this yields ~one tool record per logical run, aligned with node_outcomes.
        fid, nid, revision, cohort = _active_node.get()
        if fid and nid and outcome == 1.0:
            _capture_node_tools(
                fid, nid, gid, revision=revision, cohort=cohort,
            )
        return _MeteredAgentResult(
            g.result if g is not None else (result or ""), outcome,
            usage[-1] if usage else 0.0,
        )
    run._meters_usage = True
    return run


def _capture_node_tools(
    flow_id: str, node_id: str, goal_id: int, *, revision: str = "",
    cohort: str = "",
) -> None:
    """Record the distinct tools an agent node's goal used (for harden inference).
    No-op when trajectory capture is off (nothing to read); never raises."""
    try:
        from .. import trajectory_store
        if not trajectory_store.enabled():
            return
        tools = trajectory_store.tools_for_goal(goal_id)
        from . import node_tools
        node_tools.record(
            flow_id, node_id, tools, revision=revision, cohort=cohort,
        )
    except Exception:  # pragma: no cover -- capture must never break a run
        pass


def default_action_runner(
    world,
    sandbox=None,
    *,
    channel: str | None = None,
    user_id: str | None = None,
) -> ActionRunner:
    """Production ``action_runner``: resolve the named tool from the base registry
    and call it with the rendered params. Outcome is success (1.0) unless the tool
    returns a failed, refused, or indeterminate result (0.0). Ordinary tool
    failures are returned to the flow; intentional control-flow stops propagate
    after one terminal-audit attempt. High-risk nodes turn a 0.0 into the runner's
    indeterminate quarantine rather than an automatic retry."""
    def run(tool: str, params: dict, data: dict) -> tuple[Any, float | None]:
        import asyncio
        import secrets

        from ..audit.errors import AuditRefused

        call_id = secrets.token_hex(12)
        from ..audit import TOOL_CALL_COMMITMENT_ALGORITHM, tool_call_commitment

        call_commitment = tool_call_commitment(
            call_id=call_id,
        )
        authorized = False
        observation = None

        def audit_result(
            status: str,
            *,
            disposition: str,
            safe_summary: str | None = None,
        ) -> bool:
            from ..audit import EventKind, audit_event

            return audit_event(
                EventKind.TOOL_RESULT,
                agent="flow:action",
                name=tool,
                origin="flow",
                principal=user_id,
                call_id=call_id,
                call_commitment=call_commitment,
                call_commitment_algorithm=TOOL_CALL_COMMITMENT_ALGORITHM,
                status=status,
                disposition=disposition,
                # Connector output can echo request credentials under an
                # innocent key, defeating pattern-only redaction. Keep the
                # signed receipt content-free; status/disposition and the
                # call commitment carry the evidence needed for review.
                output_summary=safe_summary or (
                    "Tool completed" if status == "ok" else "Tool failed"
                ),
            )

        try:
            # One authorization gate for every non-agent dispatch. This used to
            # be action_tool_policy_error alone -- no shield scan, no governance
            # policy, and no audit row -- on a path that is live (bound at
            # automation_queue) and reaches every registered connector including
            # stripe, gmail, s3, salesforce, sap and workday.
            #
            # The missing audit row was the worst of it: the attestation's
            # policy_envelope claims "no RECORDED action violated the envelope",
            # so an unrecorded dispatch satisfied it trivially and made the
            # claim unfalsifiable rather than merely incomplete.
            from ..tool_authz import authorize

            if denial := authorize(
                tool, params, origin="flow", principal=user_id, call_id=call_id,
            ):
                return (denial, 0.0)
            authorized = True
            from ..sandbox import LocalBackend
            from ..tools import base_registry
            reg = base_registry(
                world,
                sandbox or LocalBackend(),
                goal_id=None,
                channel=channel,
                user_id=user_id,
            )
            t = next((x for x in reg.all() if x.name == tool), None)
            if t is None:
                result = f"ERROR: no such tool {tool!r}"
            else:
                observation = native_authorized(
                    tool, params, call_id=call_id, principal=user_id,
                    input_schema=getattr(t, "input_schema", None),
                )
                # Go through the registry's authoritative dispatch path: it owns the
                # ToolFn(args_dict) contract, sync/async/generator normalization,
                # tracing, cache invalidation and retry-safety policy.
                from ..workflow import _drive
                result = _drive(reg.run(tool, params))
        except (asyncio.CancelledError, KeyboardInterrupt, SystemExit) as e:
            if authorized:
                if isinstance(e, asyncio.CancelledError):
                    disposition = "cancelled"
                elif isinstance(e, KeyboardInterrupt):
                    disposition = "interrupted"
                else:
                    disposition = "system_exit"
                try:
                    audit_result(
                        "error",
                        disposition=disposition,
                        safe_summary=f"ERROR: {type(e).__name__}",
                    )
                except BaseException:
                    # A terminal writer failure must never replace the caller's
                    # cancellation/process stop.  The audit was attempted once;
                    # the durable flow boundary marks the escaped run
                    # indeterminate and prevents automatic replay.
                    pass
            raise
        except Exception as e:
            from ..budget import BudgetExceeded
            from ..killswitch import Halted
            if isinstance(e, AuditRefused):
                raise
            if isinstance(e, (BudgetExceeded, Halted)):
                if authorized:
                    try:
                        audit_result(
                            "error",
                            disposition=(
                                "budget_exceeded"
                                if isinstance(e, BudgetExceeded)
                                else "halted"
                            ),
                            safe_summary=f"ERROR: {type(e).__name__}",
                        )
                    except AuditRefused:
                        # Preserve the control-flow stop.  The tool boundary has
                        # already raised it, and a terminal evidence refusal must
                        # not replace that stop with a retryable executor error.
                        pass
                raise
            # Connector exceptions can contain response bodies, credentials, or
            # tenant data.  The caller and signed audit row need the failure
            # class, not the exception's attacker-controlled text.
            result = f"ERROR: tool execution raised {type(e).__name__}"
        if isinstance(result, str) and tool_result_failed(result) and result.startswith("ERROR: "):
            # ToolRegistry converts connector exceptions to
            # ``ERROR: ExceptionType: raw message`` instead of raising them.
            # Strip that raw message at this outer trust boundary too.
            exception_name, separator, _detail = result[7:].partition(": ")
            if (
                separator
                and exception_name.replace("_", "").isalnum()
                and exception_name.endswith(("Error", "Exception"))
            ):
                from ..tool_results import ToolResultText, classify_tool_result

                state = classify_tool_result(result)
                cleaned = f"ERROR: tool execution raised {exception_name}"
                # A redacted preview must retain explicit unknown-effect or
                # refusal state, even when the sanitized text reads ERROR.
                result = (ToolResultText(cleaned, state)
                          if classify_tool_result(cleaned) is not state else cleaned)
        ok = not tool_result_failed(result)
        if authorized:
            # Keep result auditing outside the tool-dispatch try block: a strict
            # audit refusal must propagate once, not be mistaken for a tool
            # exception and recursively re-audited.
            try:
                result_recorded = audit_result(
                    "ok" if ok else "error",
                    disposition="completed" if ok else "tool_error",
                )
            except AuditRefused:
                # Authorization refusals occur inside the dispatch try above
                # and still propagate before execution.  This refusal is for
                # the terminal row after the connector returned, so propagating
                # it would make the flow runner retry a possibly committed
                # operation.
                result_recorded = False
            if not result_recorded:
                return (
                    "INDETERMINATE: the tool ran, but its result audit row could "
                    "not be written; reconcile the external state and do not "
                    "retry automatically",
                    0.0,
                )
            native_completed(observation, result, terminal_recorded=(result_recorded is True and ok))
        return (result, 1.0 if ok else 0.0)
    return run


def sandbox_runners() -> tuple[AgentRunner, ActionRunner]:
    """Mock executors for a DRY RUN: they exercise the graph (routing, data
    threading, {{ }} rendering) without creating a real goal or calling a real
    connector, so a user can safely test a flow with sample input before wiring
    it to a live trigger. Each returns a labeled placeholder + a success outcome."""
    def agent(brief: str, data: dict) -> tuple[Any, float | None]:
        # The rendered brief can contain private sample input. It does not
        # belong in the saved test run as a mock agent result.
        return ("[dry-run agent] completed", 1.0)

    def action(tool: str, params: dict, data: dict) -> tuple[Any, float | None]:
        # Rendered parameters are passed only to a live connector. Echoing
        # them here copied arbitrary credential values into the run record.
        return ({"dry_run": True, "tool": tool, "parameters": "withheld"}, 1.0)
    return agent, action


__all__ = [
    "execute", "default_agent_runner", "default_action_runner", "sandbox_runners",
    "STATUS_RUNNING", "STATUS_RESUMING", "STATUS_INDETERMINATE",
]
