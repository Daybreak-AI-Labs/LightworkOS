"""Spawn tools. Let any agent recursively launch sub-agents.

`spawn_subagent` blocks until the child returns. `spawn_swarm` runs many
children in parallel via asyncio.gather and returns their findings.

Both respect the swarm's max_depth and the shared budget.

A fan-out anomaly cap stops an agent that asks to spawn 50 siblings
from burning budget before refusal triggers.
``MAVERICK_MAX_SWARM_FANOUT`` (default 8) caps the per-call branching
factor. Excess agents are dropped with a warning posted to the
blackboard.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from .._envparse import env_float
from ..swarm import verifier_confidence as _verifier_confidence
from . import Tool

if TYPE_CHECKING:
    from ..agent import Agent


def _max_fanout_setting() -> int:
    """``[swarm] max_fanout`` read at startup (env ``MAVERICK_MAX_SWARM_FANOUT`` wins)."""
    from ..env_setting import env_or_config_int

    return env_or_config_int("MAVERICK_MAX_SWARM_FANOUT", "swarm", "max_fanout", 8)


MAX_SWARM_FANOUT = _max_fanout_setting()

# Budget reserved for the top-level goal's synthesis/write step. Once
# cumulative spend crosses (1 - this) of the cap, spawn_swarm refuses new
# fan-out so a recursive research swarm can't consume the budget needed to
# actually produce the answer. Mirrors agent.py's per-worker soft-stop.
SYNTHESIS_RESERVE = env_float("MAVERICK_SYNTHESIS_RESERVE", 0.25)

_RESERVED_CHILD_ROLES = {"orchestrator"}


def _absorb_child_labels(parent: Agent, children: list) -> None:
    """Information flow (maverick.ifc): a child's answer returns to its parent,
    and with it whatever labelled data the child saw."""
    tracker = getattr(parent.ctx, "ifc", None)
    if tracker is not None:
        for child in children:
            tracker.absorb(parent.name, tracker.labels(child.name))


def _reserved_role_error(role: object) -> str | None:
    """Reject child roles reserved for kernel-created agents.

    Spawn tool arguments are model-controlled, so role strings must not be able
    to claim privileged kernel identities used by containment logic.
    """
    if isinstance(role, str) and role.strip().lower() in _RESERVED_CHILD_ROLES:
        return (
            f"ERROR: role '{role}' is reserved for the root orchestrator and "
            "cannot be used for spawned agents"
        )
    return None


def _fanout_cap_for_depth(depth: int) -> int:
    """Per-call fan-out width, DECAYING with depth.

    A flat cap lets a recursive swarm explode geometrically (8 -> 64 -> 512).
    Halving the width each level keeps the deep tail bounded while still letting
    the root parallelize: depth 0 gets the full ``MAVERICK_MAX_SWARM_FANOUT``,
    each level below halves it (floor 1).
    """
    return max(1, MAX_SWARM_FANOUT >> max(0, depth))


def _synthesis_reserve_block(parent: Agent) -> str | None:
    """If spend has crossed the synthesis reserve, return a refusal string.

    Once cumulative spend crosses ``(1 - SYNTHESIS_RESERVE)`` of the cap,
    refuse new fan-out so the budget the top-level goal needs to write its
    answer isn't consumed by deeper spawning. Returns ``None`` when spawning is
    still allowed. Shared by ``spawn_swarm`` and ``spawn_subagent`` so a
    sequential spawn chain (notably from the depth-0 orchestrator, which the
    per-worker soft-stop in agent.py doesn't cover) can't bypass the reserve.
    """
    if SYNTHESIS_RESERVE <= 0:
        return None
    b = parent.ctx.budget
    if b.max_dollars is None or b.dollars < b.max_dollars * (1.0 - SYNTHESIS_RESERVE):
        return None
    parent.ctx.blackboard.post(
        parent.name, "plan",
        f"spawning paused: ${b.dollars:.2f}/${b.max_dollars:.2f} spent; "
        f"holding the final {SYNTHESIS_RESERVE:.0%} for synthesis",
    )
    return (
        f"ERROR: spawning paused to reserve budget for the final answer "
        f"(spent ${b.dollars:.2f} of ${b.max_dollars:.2f}; the last "
        f"{SYNTHESIS_RESERVE:.0%} is held for synthesis). Do NOT spawn "
        "more — synthesize and finalize with the findings you already have."
    )


def _child_capability(parent, role: str, depth: int,
                      tool_name: str | None = None, *,
                      requested_tools: set[str] | None = None,
                      required_tools: set[str] | None = None,
                      max_risk: str | None = None):
    """A child's capability grant via boot negotiation against the parent.

    The base is the parent's **effective** grant for the spawning tool:
    verified handoffs can temporarily narrow a parent's ambient capability,
    and when a spawn tool is allowed by that narrowed grant, descendants must
    inherit the same effective boundary rather than the broader ambient one.
    With no requested scope the result is exactly that base attenuated and
    re-bound to the child principal (``None`` when enforcement is off). When
    the child declares a narrower ``requested_tools`` / ``max_risk`` (or
    ``required_tools`` it can't run without), the boot handshake resolves it
    narrow-only and the result is audit-recordable. Returns the negotiated
    ``Capability`` (or ``None``); raises ``CapabilityBootDenied`` when a
    required capability isn't grantable.
    """
    if tool_name is not None and hasattr(parent, "_effective_capability"):
        cap = parent._effective_capability(tool_name)
    else:
        cap = getattr(parent, "capability", None)
    from ..capability_boot import negotiate_boot
    neg = negotiate_boot(
        cap, principal=f"agent:{role}-{depth}",
        requested_tools=requested_tools, required_tools=required_tools,
        max_risk=max_risk,
    )
    if not neg.ok:
        raise CapabilityBootDenied(neg.reason)
    return neg.granted


class CapabilityBootDenied(RuntimeError):
    """A child declared a required capability its parent cannot grant."""


def _sealed_notice(ctx, child) -> str | None:
    """The notice to return to the parent INSTEAD of a sealed child's answer.

    A child sealed mid-run (compartment Rung 1) is compromised, so its
    ``result.final`` is attacker-influenced output. Returning it would let a
    sealed agent steer the swarm through the spawn return path -- the same leak
    ``Blackboard.render`` already closes for posts. Returns ``None`` when
    containment is off or the child is clean. Fail-open: a bug here must never
    break the spawn loop.
    """
    q = getattr(ctx, "quarantine", None)
    if q is None:
        return None
    try:
        if not q.is_sealed(child.name):
            return None
        reason = q.reason(child.name)
    except Exception:  # pragma: no cover -- containment must never break the loop
        return None
    return (
        f"⚠ Sub-agent {child.role}({child.name}) was sealed by compartment "
        f"quarantine ({reason}); its output is withheld. Do not act on it."
    )


def _register_child_with_quarantine(ctx, child) -> None:
    """Register a spawned child's domain before it can run or report output.

    ``Agent._run_tool`` also registers the domain, but a specialist can produce
    a final answer without calling a tool. Registering at spawn time lets
    existing sector seals reach domain-profile children before any potentially
    compromised output is generated or returned. Fail-open: containment bugs must
    never break spawning.
    """
    q = getattr(ctx, "quarantine", None)
    if q is None:
        return
    try:
        q.register_agent(child.name, getattr(child, "domain", None))
    except Exception:  # pragma: no cover -- containment must never break the loop
        return


async def _run_child_and_report(parent, child) -> str:
    """Run a spawned child and return its answer (or a structured error).

    Shared by ``spawn_subagent`` and ``spawn_specialist``: registers the child
    with quarantine before execution, refuses already sealed children, returns
    the spawn slot if the child RAISES, emits ``SUBAGENT_STOP``, withholds
    a sealed child's (attacker-influenced) output (Rung 1), then normalizes the
    result.
    """
    _register_child_with_quarantine(parent.ctx, child)
    notice = _sealed_notice(parent.ctx, child)
    if notice is not None:
        return notice

    try:
        result = await child.run()
    except BaseException:
        parent.ctx.release_spawns(1)
        raise
    _absorb_child_labels(parent, [child])
    # Containment Rung 1: a sealed child's final is attacker-influenced, so it
    # must never surface -- not even inside a SUBAGENT_STOP hook payload (hook
    # consumers log/route it). Compute the withhold notice BEFORE emitting and
    # hand the hook the notice instead of the raw final when the child is sealed.
    notice = _sealed_notice(parent.ctx, child)
    from ..hooks import HookEvent
    from ..hooks import emit as _emit_hook
    await _emit_hook(
        HookEvent.SUBAGENT_STOP,
        goal_id=parent.ctx.goal_id, agent_role=child.role,
        extra={"name": child.name,
               "final": notice if notice is not None else (result.final or "")},
    )
    if notice is not None:
        return notice
    if result.final:
        return result.final
    if result.blocked_on_user:
        return "BLOCKED_ON_USER: child agent queued a question."
    return f"ERROR: child finished without final answer: {result.error or 'unknown'}"


def spawn_subagent_tool(parent: Agent) -> Tool:
    async def fn(args: dict) -> str:
        if "role" not in args or "task" not in args:
            return "ERROR: spawn_subagent requires 'role' and 'task'"
        role = args["role"]
        task = args["task"]
        from ..agent import Agent

        _blocked_role = _reserved_role_error(role)
        if _blocked_role is not None:
            return _blocked_role

        if parent.depth + 1 > parent.ctx.max_depth:
            return f"ERROR: max depth {parent.ctx.max_depth} reached"
        _blocked = _synthesis_reserve_block(parent)
        if _blocked is not None:
            return _blocked
        if not parent.ctx.try_reserve_spawns(1):
            return (
                f"ERROR: per-goal spawn cap ({parent.ctx.max_total_spawns}) reached"
            )

        # Inherit max_steps
        # from the parent. Without this, sub-agents fall back to env
        # MAVERICK_MAX_STEPS or the 25 default — silently dropping the
        # operator's intent when the parent was constructed with a
        # specific max_steps value.
        # Release the reserved slot if construction raises before the child can
        # run -- otherwise a failed Agent()/_child_capability() permanently
        # erodes the per-goal spawn cap (the run() path releases its own).
        try:
            child = Agent(
                ctx=parent.ctx,
                role=role,
                brief=task,
                depth=parent.depth + 1,
                parent=parent,
                max_steps=parent.max_steps,
                capability=_child_capability(
                    parent, role, parent.depth + 1, "spawn_subagent"
                ),
            )
        except BaseException:
            parent.ctx.release_spawns(1)
            raise
        return await _run_child_and_report(parent, child)

    return Tool(
        name="spawn_subagent",
        description=(
            "Spawn a single specialist sub-agent and block until it returns. "
            "Use for a focused sub-task that needs its own context window. "
            "Role names: researcher, coder, writer, analyst, summarizer."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "role": {
                    "type": "string",
                    "description": "Child specialist role; 'orchestrator' is reserved.",
                },
                "task": {"type": "string", "description": "Concrete sub-goal for the child."},
            },
            "required": ["role", "task"],
        },
        fn=fn,
    )


def _validate_swarm_spec(agents_spec) -> str | None:
    """Validate the ``agents`` argument. Returns an error string, or ``None``."""
    if not isinstance(agents_spec, list) or not agents_spec:
        return "ERROR: 'agents' must be a non-empty list"
    for spec in agents_spec:
        if not isinstance(spec, dict):
            return "ERROR: each swarm agent must be an object"
        if "role" not in spec or "task" not in spec:
            return "ERROR: each swarm agent needs 'role' and 'task'"
        _blocked_role = _reserved_role_error(spec.get("role"))
        if _blocked_role is not None:
            return _blocked_role
    return None


def _resolve_swarm_fanout(parent: Agent) -> int:
    """Per-call fan-out cap, decaying with depth and optionally narrowed by
    adaptive test-time compute. Only ever narrows; fail-open."""
    cap = _fanout_cap_for_depth(parent.depth)
    try:
        from .. import adaptive_compute
        if adaptive_compute.enabled():
            cap = adaptive_compute.adjust_width(
                cap,
                disagreement=float(getattr(parent.ctx, "last_disagreement", 0.0) or 0.0),
                verifier_confidence=_verifier_confidence(parent.ctx),
            ).width
    except Exception:  # pragma: no cover -- never break the spawn loop
        pass
    return cap


def _record_swarm_disagreement(parent: Agent, children: list, results: list) -> bool:
    """Measure disagreement across children's FINAL answers, record it, and
    escalate FINAL verification when it crosses the autonomy threshold.

    Returns ``True`` when verification was escalated (so the caller prepends the
    reconcile note), ``False`` otherwise.
    """
    finals = [
        res.final for child, res in zip(children, results, strict=False)
        if not isinstance(res, Exception) and res.final
        and _sealed_notice(parent.ctx, child) is None  # sealed children don't vote
    ]
    if len(finals) <= 1:
        return False
    from ..disagreement import answer_entropy
    entropy = answer_entropy(finals)
    parent.ctx.blackboard.post(
        parent.name, "verify",
        f"swarm disagreement entropy={entropy:.3f} across {len(finals)} answers",
    )
    # Stamp on the context so the orchestrator's verify branch, the
    # autonomy gate, and the donation selector can read it.
    parent.ctx.last_disagreement = entropy

    # Loop 1: act on high disagreement. Ask the orchestrator's FINAL to
    # be verified by the cross-family ensemble (a stronger, lockstep-
    # resistant label exactly where it matters most) and instruct the
    # caller to reconcile the divergent answers rather than cherry-pick.
    from .. import autonomy
    if not autonomy.should_escalate_verification(entropy):
        return False
    parent.ctx.escalate_verification = True
    parent.ctx.blackboard.post(
        parent.name, "verify",
        f"high swarm disagreement ({entropy:.3f}); escalating FINAL "
        "verification to the cross-family ensemble",
    )
    try:  # tamper-evident record of the escalation; never block
        from ..audit import EventKind, record
        record(
            EventKind.AUTONOMY_ESCALATED,
            agent=parent.name,
            goal_id=parent.ctx.goal_id,
            disagreement=round(entropy, 4),
            answers=len(finals),
        )
    except Exception:  # pragma: no cover -- audit must never break the loop
        pass
    return True


async def _swarm_credit_assignment(parent: Agent, children: list, results: list) -> None:
    """Counterfactual swarm credit assignment (CSCA): attribute the outcome to
    each sub-agent by ablating its contribution and re-scoring with the verifier
    as the value oracle. The credit gate defaults on, but verifier re-scoring
    still requires the separate provider-egress authority. Budget-gated, capped
    to small swarms, and skipped when calibration is frozen. Fail-open; a
    BudgetExceeded/Halt still stops the run."""
    from .. import killswitch as _ks
    from ..budget import BudgetExceeded as _BE
    try:
        from .. import credit as _credit
        if not _credit.enabled():
            return
        from .. import self_learning as _self_learning
        if not _self_learning.provider_egress_enabled():
            return
        contribs = {
            child.name: res.final
            for child, res in zip(children, results, strict=False)
            if not isinstance(res, Exception) and res.final
            and _sealed_notice(parent.ctx, child) is None
        }
        _cs = _credit._settings()
        b = parent.ctx.budget
        headroom_ok = (b.max_dollars is None
                       or b.dollars < b.max_dollars * (1.0 - _cs["min_budget_headroom"]))
        try:
            from ..calibration import learning_frozen as _frozen
            frozen = _frozen()
        except Exception:
            frozen = False
        if not (2 <= len(contribs) <= _cs["max_children"] and headroom_ok and not frozen):
            return
        try:
            from ..safety.secret_detector import redact as _redact
            safe_brief, _ = _redact(str(parent.brief or "")[:8_000])
            contribs = {
                name: _redact(str(value or "")[:8_000])[0]
                for name, value in contribs.items()
            }
        except Exception:
            return
        from ..verifier import verify_proposal

        async def _score(subset: list[str]) -> float:
            v = await verify_proposal(
                safe_brief, "\n\n".join(subset), parent.ctx.llm,
                parent.ctx.budget, proposer_model=getattr(parent, "model", None),
            )
            return float(v.confidence)

        cmap = await _credit.counterfactual_credit(contribs, _score)
        parent.ctx.last_credit = cmap
        parent.ctx.blackboard.post(
            parent.name, "verify",
            "swarm credit: " + ", ".join(
                f"{n}={c:+.2f}" for n, c in
                sorted(cmap.items(), key=lambda x: -x[1])
            ),
        )
        # Routing memory: accumulate per-role credit so future runs
        # can prefer roles that historically contribute (role_stats).
        # The parent's department (domain pack) scopes the record so
        # a finance swarm's lesson steers future finance swarms.
        try:
            from .. import role_stats
            role_stats.record_credit(
                cmap, {c.name: c.role for c in children},
                domain=getattr(parent, "domain", None),
            )
        except Exception:  # pragma: no cover -- stats never block
            pass
        # Per-sub-agent trajectory capture: pair each contributor's
        # action sequence with its credit + learn-weight so the data
        # engine learns from real sub-trajectories, not just a credit
        # map on the goal record.
        _items = [
            (c.role, c.name, list(getattr(c, "_actions", []) or []))
            for c in children if c.name in contribs
        ]
        parent.ctx.last_subtrajectories = _credit.build_subtrajectories(
            _items, cmap,
        )
    except (_BE, _ks.Halted):
        raise
    except Exception:  # pragma: no cover -- CSCA must never break the loop
        pass


def _format_swarm_results(parent: Agent, children: list, results: list,
                          escalated: bool, dropped_specs: list | None = None) -> str:
    """Render the per-child swarm output, withholding sealed children's answers.

    Bounded: this string becomes the ``spawn_swarm`` tool result in the
    PARENT's message list, where it is re-sent on every subsequent turn — a
    wide fan-out of verbose children would otherwise dump N full answers into
    the orchestrator's window in one shot. Each child's answer is capped
    (MAVERICK_SWARM_CHILD_RESULT_CHARS, default 4000) and a total budget
    (MAVERICK_SWARM_RESULTS_TOTAL_CHARS, default 24000) elides the answers of
    trailing children once spent — every child keeps an identity line, and
    full answers remain in the run record.

    ``dropped_specs`` are the tail of a requested fan-out that got cut
    by the per-call cap. The cap is also posted to the blackboard, but a
    blackboard post is only ever rendered into the FIRST user turn
    (agent.py's ``bb.render(40)``) -- it never reaches the model again once
    that turn scrolls by. Without a notice HERE, in the tool result the
    model's own request produced, a swarm that silently ran fewer children
    than asked looks complete and the caller synthesizes an answer as if
    every sub-task ran.
    """
    from ..compaction import excerpt
    from ..env_setting import env_or_config_int
    child_cap = max(200, env_or_config_int(
        "MAVERICK_SWARM_CHILD_RESULT_CHARS", "swarm", "child_result_chars", 4000))
    total_cap = max(child_cap, env_or_config_int(
        "MAVERICK_SWARM_RESULTS_TOTAL_CHARS", "swarm", "results_total_chars", 24_000))
    parts: list[str] = []
    used = 0
    if dropped_specs:
        previews = "; ".join(
            f"{spec.get('role', '?')}: {str(spec.get('task', ''))[:80]!r}"
            for spec in dropped_specs[:10]
        )
        if len(dropped_specs) > 10:
            previews += f"; ...and {len(dropped_specs) - 10} more"
        parts.append(
            f"[swarm] NOTE: {len(dropped_specs)} of "
            f"{len(children) + len(dropped_specs)} requested agents were NOT "
            "run (fan-out cap reached). Dropped: "
            f"{previews}. Re-issue them in a later spawn_swarm call, or do "
            "them yourself -- do not treat this swarm as having covered them."
        )
    if escalated:
        parts.append(
            "[swarm] NOTE: the sub-agents disagreed substantially. Do not "
            "simply pick one answer -- reconcile the differences, and expect "
            "the FINAL to face stricter (ensemble) verification."
        )
    for child, res in zip(children, results, strict=False):
        if isinstance(res, Exception):
            parts.append(f"[{child.role}/{child.name}] EXCEPTION: {res}")
            continue
        # Containment Rung 1: withhold a sealed child's answer from the
        # parent (same leak render() closes for posts).
        notice = _sealed_notice(parent.ctx, child)
        if notice is not None:
            parts.append(f"[{child.role}/{child.name}] {notice}")
        elif res.final:
            answer = excerpt(res.final, child_cap,
                             "truncated; full answer in the run record")
            if used + len(answer) > total_cap and used:
                parts.append(
                    f"[{child.role}/{child.name}] [answer elided: "
                    f"{len(res.final)}B over the swarm result budget; full "
                    "answer in the run record]")
                continue
            used += len(answer)
            parts.append(f"[{child.role}/{child.name}] {answer}")
        elif res.blocked_on_user:
            parts.append(f"[{child.role}/{child.name}] BLOCKED_ON_USER")
        else:
            parts.append(f"[{child.role}/{child.name}] ERROR: {res.error}")
    return "\n\n".join(parts)


async def _run_swarm(parent: Agent, args: dict) -> str:
    from ..agent import Agent

    agents_spec = args.get("agents")
    _bad_spec = _validate_swarm_spec(agents_spec)
    if _bad_spec is not None:
        return _bad_spec

    if parent.depth + 1 > parent.ctx.max_depth:
        return f"ERROR: max depth {parent.ctx.max_depth} reached"

    # Synthesis reserve: once spend crosses (1 - reserve) of the cap,
    # refuse new fan-out so the budget the top-level goal needs to write its
    # answer isn't consumed by deeper research. Tell the agent to synthesize.
    _blocked = _synthesis_reserve_block(parent)
    if _blocked is not None:
        return _blocked

    # Cap per-call fan-out, DECAYING with depth so a recursive swarm can't
    # explode geometrically. An agent asking for 50 siblings on a
    # trivial sub-goal is almost always confused / under attack too.
    cap = _resolve_swarm_fanout(parent)
    dropped_specs: list = []
    if len(agents_spec) > cap:
        parent.ctx.blackboard.post(
            parent.name, "error",
            f"swarm fan-out capped: requested {len(agents_spec)}, "
            f"max {cap} at depth {parent.depth}",
        )
        dropped_specs = agents_spec[cap:]
        agents_spec = agents_spec[:cap]

    if not parent.ctx.try_reserve_spawns(len(agents_spec)):
        return (
            f"ERROR: per-goal spawn cap ({parent.ctx.max_total_spawns}) reached"
        )

    # Release the whole reservation if constructing any child raises -- none of
    # them ran, so the slots must go back (the gather() release below only
    # covers children that were built and then failed at run()).
    try:
        children = [
            Agent(
                ctx=parent.ctx,
                role=spec["role"],
                brief=spec["task"],
                depth=parent.depth + 1,
                parent=parent,
                max_steps=parent.max_steps,
                capability=_child_capability(
                    parent, spec["role"], parent.depth + 1, "spawn_swarm"
                ),
            )
            for spec in agents_spec
        ]
    except BaseException:
        parent.ctx.release_spawns(len(agents_spec))
        raise

    parent.ctx.blackboard.post(
        parent.name,
        "plan",
        f"spawning swarm of {len(children)}: "
        + ", ".join(f"{c.role}({c.name})" for c in children),
    )

    results = await asyncio.gather(*(c.run() for c in children), return_exceptions=True)
    _absorb_child_labels(parent, children)

    # Every child that RAISED never consumed its slot productively;
    # return those slots so a swarm with transient child failures doesn't
    # permanently erode the per-goal spawn cap. Children that returned
    # (even with result.error set) legitimately ran and keep their slot.
    n_failed = sum(1 for res in results if isinstance(res, BaseException))
    if n_failed:
        parent.ctx.release_spawns(n_failed)

    # A child hitting the budget cap or the killswitch is a STOP signal for
    # the whole swarm, not a per-child failure -- re-raise it instead of
    # folding it into the result string (matches agent.py's gather handler).
    from .. import killswitch as _ks
    from ..budget import BudgetExceeded as _BE
    for res in results:
        if isinstance(res, (_BE, _ks.Halted)):
            raise res

    # SubagentStop hooks: one per child that completed without raising.
    from ..hooks import HookEvent
    from ..hooks import emit as _emit_hook
    for child, res in zip(children, results, strict=False):
        if not isinstance(res, Exception):
            await _emit_hook(
                HookEvent.SUBAGENT_STOP,
                goal_id=parent.ctx.goal_id, agent_role=child.role,
                extra={"name": child.name, "final": res.final or ""},
            )

    # Measure disagreement across the children's
    # FINAL answers, record it on the blackboard, and escalate FINAL
    # verification (Loop 1) when the swarm diverged.
    escalated = _record_swarm_disagreement(parent, children, results)

    await _swarm_credit_assignment(parent, children, results)

    return _format_swarm_results(
        parent, children, results, escalated, dropped_specs=dropped_specs)


def spawn_swarm_tool(parent: Agent) -> Tool:
    async def fn(args: dict) -> str:
        return await _run_swarm(parent, args)

    return Tool(
        name="spawn_swarm",
        description=(
            "Spawn many sub-agents in PARALLEL and wait for all of them. "
            "Use when sub-tasks are independent (e.g., research three topics simultaneously). "
            "Each entry: {role, task}."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "agents": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "role": {
                                "type": "string",
                                "description": "Child specialist role; 'orchestrator' is reserved.",
                            },
                            "task": {"type": "string"},
                        },
                        "required": ["role", "task"],
                    },
                    "minItems": 1,
                }
            },
            "required": ["agents"],
        },
        fn=fn,
    )


def _suite_allowed(ctx: Any, suite: str | None) -> bool:
    """Whether this run may use a specialist suite."""
    if suite is None:
        return True
    allowed = getattr(ctx, "allowed_suites", None)
    return allowed is None or suite in allowed


def _visible_domains(domains: dict, ctx: Any | None) -> dict:
    """Filter specialist domains to the run's department-suite grant."""
    if ctx is None or getattr(ctx, "allowed_suites", None) is None:
        return domains
    from ..domain import suite_for

    return {
        name: profile for name, profile in domains.items()
        if _suite_allowed(ctx, suite_for(name))
        and _suite_allowed(ctx, suite_for(profile.name))
    }


def spawn_specialist_tool(parent: Agent) -> Tool:
    """Spawn a curated business-suite pack (a ``DomainProfile``) as a child.

    Unlike ``spawn_subagent`` (an ad-hoc free-text role), this runs one of the
    roster's specialists via ``domain.agent_from_profile`` -- so the child gets
    the pack's persona, its **compartment seal**, and its tool/risk **envelope**,
    attenuated against this parent's grant (a specialist can never out-scope the
    parent or its own pack). This is the bridge from the suite roster to the
    running fleet: the orchestrator deploys named specialists under itself.
    """
    async def fn(args: dict) -> str:
        from ..domain import agent_from_profile, enabled_domains, suite_for

        if "domain" not in args or "task" not in args:
            return "ERROR: spawn_specialist requires 'domain' and 'task'"
        domain = args["domain"]
        task = args["task"]
        if not isinstance(domain, str):
            return "ERROR: 'domain' must be a string (a specialist domain-pack name)"
        domains = enabled_domains()
        profile = domains.get(domain)
        if profile is None:
            from ..domain import rejected_workspace_domains

            if domain in rejected_workspace_domains():
                return (
                    f"ERROR: {domain!r} cannot start because its setup needs "
                    "review. Ask an administrator to check its permissions "
                    "and operating limits. No work was started."
                )
            sample = ", ".join(sorted(domains)[:30])
            return (
                f"ERROR: no enabled specialist domain {domain!r}. Call "
                f"list_specialists to see the roster. Some available: {sample}"
            )
        suite = suite_for(domain)
        if not _suite_allowed(parent.ctx, suite) or not _suite_allowed(
            parent.ctx, suite_for(profile.name)
        ):
            return f"ERROR: specialist domain {domain!r} is outside your department grant"
        if parent.depth + 1 > parent.ctx.max_depth:
            return f"ERROR: max depth {parent.ctx.max_depth} reached"
        _blocked = _synthesis_reserve_block(parent)
        if _blocked is not None:
            return _blocked
        if not parent.ctx.try_reserve_spawns(1):
            return f"ERROR: per-goal spawn cap ({parent.ctx.max_total_spawns}) reached"

        # Release the reserved slot if profile construction raises before run.
        try:
            child = agent_from_profile(
                profile, parent.ctx, task, parent=parent, depth=parent.depth + 1
            )
            # Inherit the parent's step budget (matches spawn_subagent);
            # agent_from_profile doesn't take max_steps, so apply it before run.
            child.max_steps = parent.max_steps
        except BaseException:
            parent.ctx.release_spawns(1)
            raise
        return await _run_child_and_report(parent, child)

    return Tool(
        name="spawn_specialist",
        description=(
            "Spawn a curated business-suite SPECIALIST (a domain pack) and block "
            "until it returns. Unlike spawn_subagent (an ad-hoc role), this runs a "
            "pack with its own persona, compartment seal, and tool/risk envelope "
            "(finance, legal, operations, sales/GTM, HR, IT-GRC, product/eng, "
            "strategy). Call list_specialists first to choose the domain."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Specialist domain-pack name, e.g. 'gtm_outbound_sdr' "
                                   "(see list_specialists).",
                },
                "task": {"type": "string", "description": "Concrete sub-goal for the specialist."},
            },
            "required": ["domain", "task"],
        },
        fn=fn,
    )


def list_specialists_tool(parent: Agent | None = None) -> Tool:
    """List the spawnable specialist domains, honoring the operator's suite toggles."""
    async def fn(args: dict) -> str:
        from collections import Counter

        from ..domain import enabled_domains, suite_for

        domains = _visible_domains(enabled_domains(), parent.ctx if parent is not None else None)
        flt = (args.get("suite") or "").strip()
        query = (args.get("query") or "").strip()
        # Query search: rank the WHOLE roster by relevance to the task, so an
        # ambiguous or cross-suite request doesn't require guessing the suite.
        if query:
            from ..domain_router import rank_specialists
            ranked = rank_specialists(query, k=12, domains=domains)
            if flt:  # optionally scope the search to one suite/prefix
                ranked = [(n, s) for n, s in ranked
                          if (suite_for(n) or "other") == flt or n.startswith(flt)]
            if not ranked:
                return (f"No specialists matched query {query!r}. Call "
                        "list_specialists (no arg) for the suites.")
            rows = [f"- {n}: {(domains[n].description or '').strip()}" for n, _ in ranked]
            return ("Most relevant specialists for the task (spawn the best fit with "
                    "spawn_specialist):\n" + "\n".join(rows))
        if not flt:
            counts = Counter(suite_for(n) or "other" for n in domains)
            lines = [f"- {s}: {c}" for s, c in sorted(counts.items())]
            return (
                "Specialist suites (search across all of them with "
                "list_specialists query=<the task>, or list one with suite=<name>, "
                "then spawn_specialist domain=<name>):\n" + "\n".join(lines)
            )
        rows = []
        for name in sorted(domains):
            if (suite_for(name) or "other") != flt and not name.startswith(flt):
                continue
            rows.append(f"- {name}: {(domains[name].description or '').strip()}")
        if not rows:
            return f"No specialist domains match {flt!r}. Call list_specialists (no arg) for suites."
        return f"Specialists in {flt!r} (spawn with spawn_specialist):\n" + "\n".join(rows)

    return Tool(
        name="list_specialists",
        description=(
            "List the business-suite specialist domains you can spawn with "
            "spawn_specialist. Pass query=<the task> to SEARCH the whole roster "
            "for the most relevant specialists (best for an ambiguous or cross-"
            "suite request). With no argument, returns each suite and its pack "
            "count; pass suite=<name> (e.g. 'finance', 'legal') or a name prefix "
            "(e.g. 'gtm_') to list that suite's packs with descriptions."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The task in your own words; ranks the most "
                                   "relevant specialists across all suites.",
                },
                "suite": {
                    "type": "string",
                    "description": "Optional: a suite name or pack-name prefix to filter by.",
                },
            },
        },
        fn=fn,
    )
