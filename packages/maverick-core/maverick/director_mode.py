"""Director mode.

The director states an **outcome** and picks how much rope the swarm gets;
the mode assembles the run configuration from the controls that already
exist, instead of the operator hand-tuning five knobs per goal:

* **Outcome → goal**: the outcome statement becomes a plan-first goal (the
  plan-execute-reflect topology), titled and framed as a verifiable outcome
  ("Outcome: ...; done when the reflector accepts").
* **Autonomy profile → envelope**: three named profiles map to the existing
  controls — consent mode (``MAVERICK_CONSENT_MODE``), the review-checkpoint
  intervals (``review_checkpoint``), and a budget multiplier over the
  configured cap:

  ==============  ============  =======================  ================
  profile         consent       review checkpoint        budget multiple
  ==============  ============  =======================  ================
  ``supervised``  ask           every $2 / 25 calls      0.5×
  ``semi``        dashboard     every $10 / 100 calls    1.0×
  ``autonomous``  auto-approve  every $25 / 250 calls    2.0×
  ==============  ============  =======================  ================

:func:`direct` is pure assembly — it returns the goal spec + envelope (env
overrides, checkpoint policy, budget) and **starts nothing**; the caller
applies it. ``maverick start --director <profile> "<outcome>"`` does, for its
own one-goal process (the consent mode and checkpoints are process-wide, so a
shared server cannot apply them to one goal without a per-task consent
override). Profiles are overridable via ``[director.profiles.<name>]`` config
(Settings > All settings); unknown profiles are refused (an autonomy level
must never be guessed).
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

# Plain names for the start form's autonomy picker.
PROFILE_LABELS = {"supervised": "Supervised", "semi": "Partly on its own",
                  "autonomous": "On its own"}
# The goal event a dashboard start records its director envelope in. The run
# reads it back wherever the goal executes (in-process, queue worker, remote
# worker). Every part of it can only tighten, so a forged or stale record can
# never loosen a run: consent and review checkpoints tighten-only (see
# safety.consent.task_consent_mode / review_checkpoint.task_checkpoint_policy)
# and the spending cap is the smaller one.
EVENT_KIND = "director"
EVENT_AGENT = "dashboard"

PROFILES: dict[str, dict[str, Any]] = {
    "supervised": {
        "consent_mode": "ask",
        "checkpoint": {"dollars": 2.0, "tool_calls": 25},
        "budget_multiplier": 0.5,
    },
    "semi": {
        "consent_mode": "dashboard",
        "checkpoint": {"dollars": 10.0, "tool_calls": 100},
        "budget_multiplier": 1.0,
    },
    "autonomous": {
        "consent_mode": "auto-approve",
        "checkpoint": {"dollars": 25.0, "tool_calls": 250},
        "budget_multiplier": 2.0,
    },
}


class UnknownProfileError(ValueError):
    """An autonomy level must be one of the named profiles, never guessed."""


@dataclass(frozen=True)
class DirectorRun:
    """The assembled, not-yet-started run configuration."""

    goal_title: str
    goal_description: str
    profile: str
    consent_mode: str
    checkpoint: dict          # CheckpointPolicy kwargs
    max_dollars: float | None
    planning_mode: str = "plan_execute_reflect"
    env_overrides: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "goal_title": self.goal_title,
            "goal_description": self.goal_description,
            "profile": self.profile,
            "consent_mode": self.consent_mode,
            "checkpoint": dict(self.checkpoint),
            "max_dollars": self.max_dollars,
            "planning_mode": self.planning_mode,
            "env_overrides": dict(self.env_overrides),
        }


def _profile(name: str) -> dict[str, Any]:
    base = PROFILES.get(name)
    if base is None:
        raise UnknownProfileError(
            f"unknown autonomy profile {name!r}; expected one of "
            f"{sorted(PROFILES)}")
    merged = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
    try:
        from .config import load_config
        override = (((load_config() or {}).get("director") or {})
                    .get("profiles") or {}).get(name) or {}
        for key in ("consent_mode", "budget_multiplier"):
            if key in override:
                merged[key] = override[key]
        if isinstance(override.get("checkpoint"), dict):
            merged["checkpoint"].update(override["checkpoint"])
        # The All settings table stores each profile's checkpoint as flat
        # ``dollars`` / ``tool_calls`` cells.
        for key in ("dollars", "tool_calls"):
            if key in override:
                merged["checkpoint"][key] = override[key]
    except Exception:  # pragma: no cover -- config never blocks assembly
        pass
    return merged


def direct(outcome: str, *, profile: str = "supervised",
           base_max_dollars: float | None = None) -> DirectorRun:
    """Assemble a director run from an outcome statement + autonomy profile.

    ``base_max_dollars`` defaults to the configured budget cap; the profile's
    multiplier scales it (the hard Budget ceiling still applies at run time —
    this only sets the per-run cap, never bypasses ``budget.check()``).
    """
    outcome = (outcome or "").strip()
    if not outcome:
        raise ValueError("an outcome statement is required")
    p = _profile(profile)
    if base_max_dollars is None:
        from .budget import resolve_budget_caps
        base_max_dollars = resolve_budget_caps().get("max_dollars")
    title = outcome if len(outcome) <= 80 else outcome[:77] + "..."
    description = (
        f"Outcome: {outcome}\n\n"
        "Operate plan-first (plan -> execute -> reflect); the run is done "
        "when the reflector accepts the outcome as achieved, not when a step "
        "list is exhausted."
    )
    return DirectorRun(
        goal_title=title,
        goal_description=description,
        profile=profile,
        consent_mode=str(p["consent_mode"]),
        checkpoint=dict(p["checkpoint"]),
        max_dollars=(round(base_max_dollars * float(p["budget_multiplier"]), 2)
                     if base_max_dollars is not None else None),
        env_overrides={
            "MAVERICK_CONSENT_MODE": str(p["consent_mode"]),
            "MAVERICK_REVIEW_CHECKPOINT_DOLLARS": str(p["checkpoint"].get("dollars", "")),
            "MAVERICK_REVIEW_CHECKPOINT_TOOL_CALLS": str(p["checkpoint"].get("tool_calls", "")),
        },
    )


__all__ = ["PROFILES", "DirectorRun", "UnknownProfileError", "direct"]


_CONSENT_WORDS = {"ask": "asks a person", "dashboard": "waits on the Approvals page",
                  "auto-deny": "refuses actions that can't be undone",
                  "auto-approve": "allows actions that can't be undone"}


def profile_choices() -> list[dict[str, Any]]:
    """The autonomy levels for a start form, as configured now (plain words)."""
    out = []
    for name in PROFILES:
        p = _profile(name)
        consent = _CONSENT_WORDS.get(str(p["consent_mode"]), "asks a person")
        out.append({"value": name, "label": PROFILE_LABELS[name],
                    "summary": f"{consent}; up to {float(p['budget_multiplier']):g}x "
                               "the spending limit, never above it"})
    return out


def envelope(run: DirectorRun) -> dict[str, Any]:
    """What a run needs from ``run`` wherever it executes."""
    return {"profile": run.profile, "consent_mode": run.consent_mode,
            "checkpoint": dict(run.checkpoint), "max_dollars": run.max_dollars}


def record(world, goal_id: int, run: DirectorRun) -> None:
    """Record ``run``'s envelope on the goal before it is dispatched."""
    label = PROFILE_LABELS.get(run.profile, run.profile)
    world.append_event(goal_id, EVENT_AGENT, EVENT_KIND,
                       f"Director mode: {label} " + json.dumps(envelope(run), sort_keys=True))


def recorded_envelope(world, goal_id: int) -> dict[str, Any] | None:
    """The envelope a dashboard start recorded for ``goal_id``, if any."""
    try:
        events = world.goal_events(goal_id, since_id=0, limit=50)
    except Exception:  # an unreadable history leaves the run as configured
        return None
    for event in events:
        if event.kind != EVENT_KIND or event.agent != EVENT_AGENT:
            continue
        text = str(event.content or "")
        try:
            data = json.loads(text[text.index("{"):])
        except (ValueError, TypeError):
            continue
        if isinstance(data, dict) and data.get("profile") in PROFILES:
            return data
    return None


@contextmanager
def run_scope(env: dict[str, Any] | None) -> Iterator[None]:
    """Apply a recorded envelope's consent mode and review checkpoints to the
    run inside. Both only ever tighten what the installation allows."""
    if not env:
        yield
        return
    from .review_checkpoint import CheckpointPolicy, task_checkpoint_policy
    from .safety.consent import task_consent_mode

    cp = env.get("checkpoint") if isinstance(env.get("checkpoint"), dict) else {}

    def _positive(value: Any) -> float | None:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        return number if number > 0 else None

    calls = _positive(cp.get("tool_calls"))
    policy = CheckpointPolicy(dollars=_positive(cp.get("dollars")),
                              tool_calls=int(calls) if calls else None)
    with task_consent_mode(str(env.get("consent_mode") or "ask")), \
            task_checkpoint_policy(policy):
        yield


def spending_cap(env: dict[str, Any] | None, requested: float | None) -> float | None:
    """The smaller of the run's own cap and the envelope's."""
    try:
        cap = float(env["max_dollars"]) if env and env.get("max_dollars") is not None else None
    except (TypeError, ValueError):
        cap = None
    if cap is None:
        return requested
    return cap if requested is None else min(requested, cap)
