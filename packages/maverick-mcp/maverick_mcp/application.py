"""MCP application services with explicit authorization and storage seams."""
from __future__ import annotations

import json
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any

from .protocol import ProtocolError as _ProtocolError


@dataclass(frozen=True)
class ApplicationDependencies:
    world_factory: Callable[[], AbstractContextManager]
    shield: Any
    shield_scan_reason: Callable[..., Any]
    current_principal: Callable[[], str | None]
    goal_for_principal: Callable[..., Any]
    task_budget: Callable[..., Any]
    bounded_int: Callable[..., int]
    setting: Callable[..., Any]
    set_structured: Callable[[dict], None]


class MCPApplication:
    """Execute tools after the protocol layer has admitted the caller."""

    def __init__(self, dependencies: ApplicationDependencies):
        self.dependencies = dependencies

    def _tool_fleet_ingest(self, args: dict) -> str:
        from maverick import fleet_memory
        ok, reason = fleet_memory.ingest(dict(args), shield=self.dependencies.shield)
        result = {"ok": bool(ok), "reason": reason}
        self.dependencies.set_structured(result)
        return json.dumps(result)

    def _tool_fleet_recall(self, args: dict) -> str:
        from maverick import fleet_memory
        context, reason = fleet_memory.recall(
            str(args.get("query", "")),
            agent_id=str(args.get("agent_id", "")),
            vendor=str(args.get("vendor", "")),
            domain=str(args.get("domain", "") or "") or None,
            shield=self.dependencies.shield,
        )
        result = {"context": context, "reason": reason}
        self.dependencies.set_structured(result)
        return json.dumps(result)

    def _structured_result(self, name: str) -> dict | None:
        """Structured form of a query tool's result, matching its outputSchema.

        Re-derives from the world model so the text handlers in _dispatch_tool
        stay untouched; returns None for tools without an outputSchema."""
        if name == "maverick_status":
            with self.dependencies.world_factory() as w:
                owner = self.dependencies.current_principal()
                goals = (
                    w.list_goals(owner=owner)
                    if owner is not None else w.list_goals()
                )
                goal_ids = {goal.id for goal in goals}
                questions = [
                    question for question in w.open_questions()
                    if owner is None or question.goal_id in goal_ids
                ]
            return {
                "goals": [
                    {"id": g.id, "status": g.status, "title": g.title}
                    for g in goals[-10:]
                ],
                "open_questions": [
                    {"id": q.id, "goal_id": q.goal_id, "question": q.question}
                    for q in questions
                ],
            }
        if name == "maverick_skills_list":
            from maverick.skills import load_skills
            return {
                "skills": [
                    {"name": s.name, "triggers": list(s.triggers)}
                    for s in load_skills()
                ],
            }
        if name == "maverick_facts_get":
            if (self.dependencies.current_principal() or "").startswith("agent:"):
                raise PermissionError("tenant-wide facts require an operator")
            with self.dependencies.world_factory() as w:
                return {"facts": dict(w.get_facts())}
        return None

    def _tool_start(self, args: dict, *, capability=None) -> str:
        from maverick.deployment import require_enterprise_or_die
        require_enterprise_or_die()
        from maverick.llm import LLM
        from maverick.orchestrator import run_goal_sync
        from maverick.sandbox import build_sandbox
        title = args["title"]
        description = args.get("description", "")
        reasons = self.dependencies.shield_scan_reason(f"{title}\n{description}", output=False)
        if reasons is not None:
            return f"⚠ Blocked: {reasons}"
        # Clamp client-supplied limits to operator ceilings. Over the HTTP
        # transport the budget is 100% client-controlled, so without a cap
        # any authenticated caller could pass max_dollars=10000 and burn the
        # operator's provider spend. Ceilings come from env and default to
        # the schema defaults (so the common case is unchanged); raise them
        # with MAVERICK_MCP_MAX_DOLLARS / _MAX_WALL_SECONDS / _MAX_DEPTH.
        budget = self.dependencies.task_budget(args)
        max_depth = self.dependencies.bounded_int(
            args.get("max_depth", 3),
            default=3,
            ceiling=self.dependencies.setting("max_depth", "3"),
        )
        with self.dependencies.world_factory() as world:
            goal_id = world.create_goal(
                title,
                description,
                owner=self.dependencies.current_principal() or "",
            )
            llm = LLM()
            sandbox = build_sandbox()
            run_kwargs = {"sandbox": sandbox, "max_depth": max_depth}
            if capability is not None:
                run_kwargs["capability"] = capability
            answer = run_goal_sync(llm, world, budget, goal_id, **run_kwargs)
        self.dependencies.set_structured({"goal_id": goal_id, "answer": answer})
        return answer

    def _tool_status(self) -> str:
        with self.dependencies.world_factory() as w:
            owner = self.dependencies.current_principal()
            goals = (
                w.list_goals(owner=owner)
                if owner is not None else w.list_goals()
            )
            if not goals:
                return "no goals yet"
            lines = [f"#{g.id} [{g.status}] {g.title}" for g in goals[-10:]]
            goal_ids = {goal.id for goal in goals}
            questions = [
                question for question in w.open_questions()
                if owner is None or question.goal_id in goal_ids
            ]
            for q in questions:
                lines.append(
                    f"  open question #{q.id} (goal {q.goal_id}): {q.question}"
                )
            return "\n".join(lines)

    def _tool_resume(self, args: dict, *, capability=None) -> str:
        from maverick.llm import LLM
        from maverick.orchestrator import run_goal_sync
        from maverick.sandbox import build_sandbox
        with self.dependencies.world_factory() as w:
            owner = self.dependencies.current_principal()
            goal_id = args.get("goal_id")
            if goal_id is None:
                if owner is None:
                    g = w.active_goal()
                else:
                    active = [
                        goal for goal in w.list_goals(owner=owner)
                        if goal.status in ("active", "blocked")
                    ]
                    g = max(active, key=lambda goal: goal.updated_at, default=None)
                if not g:
                    return "no active or blocked goal to resume"
                goal_id = g.id
            else:
                try:
                    goal_id = int(goal_id)
                except (TypeError, ValueError, OverflowError):
                    raise _ProtocolError(
                        -32602, f"invalid goal_id: {goal_id!r}"
                    ) from None
            self.dependencies.goal_for_principal(w, goal_id, owner)
            # Clamp to the same operator ceilings as _tool_start. Over HTTP the
            # budget is client-controlled; a bare Budget() let a resume bypass
            # the MAVERICK_MCP_MAX_* caps that _tool_start enforces.
            budget = self.dependencies.task_budget(args)
            max_depth = self.dependencies.bounded_int(
                args.get("max_depth", 3),
                default=3,
                ceiling=self.dependencies.setting("max_depth", "3"),
            )
            run_kwargs = {"sandbox": build_sandbox(), "max_depth": max_depth}
            if capability is not None:
                run_kwargs["capability"] = capability
            answer = run_goal_sync(LLM(), w, budget, goal_id, **run_kwargs)
        self.dependencies.set_structured({"goal_id": goal_id, "answer": answer})
        return answer

    def _tool_answer(self, args: dict) -> str:
        # A bad id is an invalid-params protocol error (-32602), not a tool
        # execution error -- mirror _tool_resume so typed clients can tell them
        # apart (the old `int(...)` surfaced an isError tool result instead).
        try:
            qid = int(args["question_id"])
        except (TypeError, ValueError, OverflowError):
            raise _ProtocolError(-32602, f"invalid question_id: {args.get('question_id')!r}") from None
        answer = str(args["answer"])
        # An answer to an open question is fed straight back into the agent loop
        # as the user's reply -- equally attacker-influenced as a fact over the
        # network-reachable HTTP transport. Scan it like _tool_fact_set does.
        reasons = self.dependencies.shield_scan_reason(answer, output=False)
        if reasons is not None:
            return f"⚠ answer rejected by Shield: {reasons}"
        with self.dependencies.world_factory() as w:
            owner = self.dependencies.current_principal()
            answered = (
                w.answer(qid, answer, expected_owner=owner)
                if owner is not None else w.answer(qid, answer)
            )
        if not answered:
            raise _ProtocolError(-32602, "question not found")
        self.dependencies.set_structured({"question_id": qid})
        return f"answered #{qid}"

    def _tool_skill_install(self, args: dict) -> str:
        from maverick.skills import install_skill, url_install_allowed
        if not url_install_allowed():
            raise PermissionError("Skill installation is disabled by the server administrator")
        # MCP clients are external by definition, and the HTTP transport is
        # network-reachable behind only a shared bearer token. trusted_local
        # must be False so a bare local-path source (e.g. "/etc/passwd") is
        # rejected -- otherwise an authenticated client gets arbitrary host
        # file read, the exact hole the REST API was hardened against. Local
        # users install skills with `maverick skill install` (trusted there).
        s = install_skill(args["source"], trusted_local=False)
        self.dependencies.set_structured({"name": s.name, "path": str(s.path)})
        return f"installed: {s.name} -> {s.path}"

    def _tool_skills_list(self) -> str:
        from maverick.skills import load_skills
        items = load_skills()
        if not items:
            return "no skills installed"
        lines = [f"{s.name}: {', '.join(s.triggers[:3])}" for s in items[:100]]
        if len(items) > 100:
            lines.append(f"... ({len(items) - 100} more skills omitted)")
        return "\n".join(lines)

    def _tool_fact_set(self, args: dict) -> str:
        if (self.dependencies.current_principal() or "").startswith("agent:"):
            raise PermissionError("tenant-wide facts require an operator")
        # Facts are concatenated into the orchestrator's system brief on every
        # future run, so a malicious fact set over MCP is a persistent prompt
        # injection. Scan the value before storing (the orchestrator also
        # redacts/re-scans facts at read time as defense-in-depth).
        reasons = self.dependencies.shield_scan_reason(
            f"{args['key']}: {args['value']}", output=False)
        if reasons is not None:
            return f"⚠ fact rejected by Shield: {reasons}"
        # Memory Guard (OWASP ASI06): an MCP client is an untrusted author, so
        # stamp the fact TOOL-trust (not the upsert default of first-party) and
        # run it through the guard's injection tripwire before storing -- the
        # same screen kv_memory gets. Provenance is recorded even when the guard
        # is off, so enabling it later governs this fact.
        from maverick import memory_guard as _mg
        prov = _mg.Provenance(source="mcp:fact_set", trust=_mg.TrustTier.TOOL)
        decision = _mg.screen_write(args["value"], prov)
        _mg.audit_write(args["key"], prov, decision)
        if not decision.allowed:
            return f"⚠ fact rejected by Memory Guard: {decision.reason}"
        with self.dependencies.world_factory() as w:
            w.upsert_fact(
                args["key"], args["value"], source=prov.source,
                trust_tier=int(prov.trust), sensitivity=prov.sensitivity.value,
            )
        self.dependencies.set_structured({"key": args["key"]})
        return f"set {args['key']}"

    def _tool_facts_get(self) -> str:
        if (self.dependencies.current_principal() or "").startswith("agent:"):
            raise PermissionError("tenant-wide facts require an operator")
        with self.dependencies.world_factory() as w:
            facts = w.get_facts()
        if not facts:
            return "no facts known"
        # Bounded: this string re-enters the calling LLM's context, and the
        # fact store grows without limit. Newest first (get_facts order);
        # same knobs + truncation marker as the orchestrator brief's facts
        # block so the two renderers of one store can't drift.
        from maverick._envparse import env_int
        from maverick.compaction import excerpt
        max_n = max(1, env_int("MAVERICK_BRIEF_FACTS_MAX", 50))
        max_val = max(40, env_int("MAVERICK_BRIEF_FACT_VALUE_CHARS", 300))
        lines = [f"{k}: {excerpt(str(v), max_val)}"
                 for k, v in list(facts.items())[:max_n]]
        if len(facts) > max_n:
            lines.append(f"... ({len(facts) - max_n} more facts omitted)")
        return "\n".join(lines)
