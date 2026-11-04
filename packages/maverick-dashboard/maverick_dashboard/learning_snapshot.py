"""Owner-scoped learning status shared by the dashboard and API."""
from __future__ import annotations

import os


def _learning_components(subsystems: list[dict], on_by_key: dict) -> list[dict]:
    """One row per learning system for its own switch on the Learning page.

    ``on`` is the live state; ``wanted`` what this installation's settings ask
    for (it differs when a system waits on another one, ``waiting_on``);
    ``managed`` means a deployment variable decides and the switch is locked.
    """
    from maverick.config import governed_learning_default, load_config

    try:
        cfg = load_config() or {}
    except Exception:  # pragma: no cover -- the status view never 500s on config
        cfg = {}
    labels = {s["key"]: s["label"] for s in subsystems}
    rows = []
    for s in subsystems:
        on = bool(on_by_key.get(s["key"], False))
        managed = bool(s.get("env")) and s["env"] in os.environ
        section = cfg.get(s["section"]) if isinstance(cfg.get(s["section"]), dict) else {}
        raw = section.get(s["config_key"])
        wanted = on if managed else (raw if isinstance(raw, bool) else s.get("default", governed_learning_default()))
        needs = s.get("needs")
        waiting = bool(wanted and not on and needs and not on_by_key.get(needs, False))
        rows.append({
            "key": s["key"],
            "label": s["label"],
            "description": s.get("description", ""),
            "section": s["section"],
            "on": on,
            "wanted": bool(wanted),
            "managed": managed,
            "waiting_on": labels.get(needs, "") if waiting else "",
            "how": s["how"],
        })
    return rows


def learning_snapshot(request, *, world_factory, owner_filter, permission_check) -> dict:
    """Learning-engine status + accumulated learning. Shared by the JSON endpoint
    and the /learning page so both render identical numbers."""
    from maverick import (
        consequence,
        credit,
        data_engine,
        dreaming,
        evaluator_evolution,
        experience,
        factory_learning,
        failure_telemetry,
        jit_rl,
        operations_scientist,
        prm_guidance,
        reasoning_reward,
        reflexion,
        rehearsal,
        self_harness,
        self_improvement,
        self_learning,
        self_tuning_budget,
        trajectory_store,
    )
    from maverick.config import get_self_improvement
    from maverick.operating_record import assemble, stats
    from maverick.skill import distillation_local, synthesis

    from .settings_store import LEARNING_SUBSYSTEMS

    def _causal_promotion_on() -> bool:
        try:
            return bool(
                self_improvement.enabled() and get_self_improvement().get("causal_promotion", False)
            )
        except Exception:  # pragma: no cover - config never blocks the view
            return False

    # Live enabled() per subsystem key -- paired with the shared registry so the
    # label/how/config metadata stays single-sourced in settings_store.
    on_by_key = {
        "self_learning": self_learning.enabled(),
        "distill_local": distillation_local.enabled(),
        "failure_telemetry": failure_telemetry.enabled(),
        "budget_tuning": self_tuning_budget.enabled(),
        "consequence": consequence.enabled(),
        "reflexion": reflexion.enabled(),
        "dreaming": dreaming.enabled(),
        "experience": experience.enabled(),
        "skill_synthesis": synthesis.enabled(),
        "self_improvement": self_improvement.enabled(),
        "prm_guidance": prm_guidance.enabled(),
        "capture": trajectory_store.enabled(),
        "causal_promotion": _causal_promotion_on(),
        "factory_learning": factory_learning.enabled(),
        "evaluator_evolution": evaluator_evolution.enabled(),
        "self_harness": self_harness.enabled(),
        "data_engine": data_engine.enabled(),
        "operations_scientist": operations_scientist.enabled(),
        "rehearsal": rehearsal.enabled(),
        "credit": credit.enabled(),
        "reasoning_reward": reasoning_reward.enabled(),
        "reward_audit": reasoning_reward.audit_rewards_enabled(),
        "jit_rl": jit_rl.enabled(),
    }
    components = _learning_components(LEARNING_SUBSYSTEMS, on_by_key)

    w = world_factory()
    owner = owner_filter(request)
    st = stats(assemble(w, owner=owner))
    accumulated = {
        "decisions": st.n_records,
        "human_decisions": st.n_human_decisions,
        "approvals": st.n_approvals,
        "departments": len(st.departments),
    }
    # Learned skills and grounded outcomes are deployment-level assets (neither is
    # stored per-tenant), so only surface them on an unscoped/admin view -- a
    # single tenant must never see deployment-wide totals as if they were its own.
    if owner is None:
        try:
            # Count the ledger directly -- _learned_snapshot would also build
            # the whole harness/provenance/pending view just to be discarded.
            # The stat is a TOTAL, so don't inherit the page's display limit
            # (which would silently cap the count at 50).
            from maverick import self_learning

            learned_n = len(self_learning.history(limit=1_000_000, path=self_learning.LEARNED_PATH, owner=owner_filter(request)))
        except Exception:  # pragma: no cover - the learning view never 500s on a sub-read
            learned_n = 0
        accumulated["grounded_outcomes"] = consequence.count()
        accumulated["learned_capabilities"] = learned_n
        # Flows that improved themselves -- forward self-rewrites the loop enacted,
        # a tangible "your automations got better on their own" number.
        try:
            from maverick.flow import evolution_log

            improvements = evolution_log.improvement_count()
        except Exception:  # pragma: no cover -- the learning view never 500s on a sub-read
            improvements = 0
        if improvements:
            accumulated["flow_self_improvements"] = improvements
    # Autonomous flow self-improvement: its own opt-in, deliberately NOT folded
    # into the blanket "turn learning on" button -- autonomously rewriting a live
    # workflow is a heavier consequence than passive learning. Policy visibility
    # uses installation authority separately from private content ownership.
    can_manage = permission_check(request, "admin")
    flow_autonomy = None
    if can_manage:
        try:
            from maverick import flow as _flow_mod

            flow_autonomy = {
                "engine_on": _flow_mod.enabled(),
                "auto_evolve": _flow_mod.auto_evolve_enabled(),  # revert regressions
                "auto_apply": _flow_mod.auto_apply_enabled(),  # apply improvements
            }
        except Exception:  # pragma: no cover -- the learning view never 500s on a sub-read
            flow_autonomy = None
    dgm = None
    if can_manage:
        try:
            from maverick import self_modify

            dgm = self_modify.production_status()
        except Exception:  # pragma: no cover -- status is fail-closed in core
            dgm = None
    from .automation_queue import nightly_learning_status

    return {
        "overnight": nightly_learning_status() if can_manage else None,
        "components": components,
        "dgm": dgm,
        "flow_autonomy": flow_autonomy,
        "accumulated": accumulated,
        "components_on": sum(1 for c in components if c["on"]),
        "components_total": len(components),
    }
