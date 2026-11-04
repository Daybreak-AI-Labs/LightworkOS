"""Risk-tier auto-classifier for GOALS.

:mod:`maverick.safety.tool_risk` classifies a *tool* (the instrument); this
module classifies a *goal* (the intent) **before it runs**, so autonomy and
approval policies can be set proportionally up front — a goal that says
"wire the vendor payment and deploy to production" should start life gated,
while "summarize last week's standup notes" should not, regardless of which
tools either ends up touching.

Deterministic and model-free by design: the tier feeds governance decisions
(:mod:`maverick.governance` REQUIRE_HUMAN gates, autonomy ceilings), and a
gate whose input changes between identical runs — or that needs a model call
before the run even starts — is not a gate an auditor can reason about. The
cost of that choice is bluntness: this is a lexical tripwire, not a judge,
and it errs toward flagging.

Scoring
=======
A documented signal table (:data:`SIGNALS`); each signal class fires **at
most once** per goal (so "delete delete delete" doesn't stack) and adds its
weight, in integer points, to the total. De-escalators (read-only verbs:
summarize / analyze / research / draft ...) subtract — "research payment
fraud patterns" is reading about money, not moving it. Points are integers
precisely so threshold comparisons are exact (no float-sum edge wobble);
``score`` is the clamped ``points / 100`` for callers that want 0..1.

Tiers (thresholds are documented constants):

  * ``high``   — points >= :data:`HIGH_THRESHOLD`  (60)
  * ``medium`` — points >= :data:`MEDIUM_THRESHOLD` (30)
  * ``low``    — otherwise

Config (all opt-in; env wins over ``[safety]``; fail-soft ``load_config``):

    [safety]
    goal_risk_floor = "medium"           # callers max() this with the tier
    goal_risk_require_human = "high"     # "high" | "medium" | "never"

``MAVERICK_GOAL_RISK_FLOOR`` / ``MAVERICK_GOAL_RISK_REQUIRE_HUMAN`` override
the table. Off by default: with nothing configured the floor is ``"low"`` (a
no-op) and no goal waits for a person. The orchestrator consults
:func:`start_check` before a goal starts; every goal's tier is recorded on its
start audit event. This is a lexical tripwire on the goal's words only: the
per-action gates (tool risk, governance, ``[actions] require_approval_at``)
still check every action whatever the goal was called.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .tool_risk import RISK_LEVELS, risk_rank

# Tier thresholds, in integer points (each signal weight below is points).
HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 30

# The signal table: (name, weight_points, compiled patterns). A signal fires
# when ANY of its patterns matches the lowercased "title\ndescription" text;
# it contributes its weight once. Weights are calibrated so one hard signal
# (money, destructive-infra) alone is "medium", a hard signal plus an
# irreversibility marker is "high", and a single soft signal with a read-only
# verb de-escalates back to "low".
def _rx(*words: str) -> re.Pattern[str]:
    """Word-boundary alternation over phrases (spaces match whitespace runs)."""
    parts = [r"\b" + re.escape(w).replace(r"\ ", r"\s+") + r"\b" for w in words]
    return re.compile("|".join(parts))


SIGNALS: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    # Money movement: paying, transferring, refunding — mistakes are spent.
    ("money", 45, _rx(
        "pay", "payment", "payout", "payroll", "transfer", "wire", "refund",
        "reimburse", "charge", "invoice", "purchase", "buy", "remit",
        "chargeback", "disburse",
    )),
    # Destructive / production infra verbs: deploys, deletes, migrations.
    ("infra_destruction", 45, _rx(
        "deploy", "delete", "drop", "truncate", "migrate", "decommission",
        "terminate", "shutdown", "shut down", "destroy", "wipe", "revoke",
        "rollback", "roll back", "uninstall",
    )),
    # Credential / secret handling: keys touched are keys exposable.
    ("credentials", 40, _rx(
        "credential", "credentials", "secret", "secrets", "api key",
        "api keys", "access key", "private key", "password", "passwords",
        "token", "tokens", "certificate", "keypair", "rotate keys",
    )),
    # Bulk outbound communication: one bad message times every recipient.
    ("bulk_outbound", 40, _rx(
        "email blast", "mass email", "bulk email", "mass dm", "mass message",
        "newsletter", "broadcast", "email all", "message all", "send to all",
        "email every", "notify all", "campaign send",
    )),
    # Regulated-advice domains: legal/medical/financial advice carries
    # liability and (EU AI Act) oversight duties.
    ("regulated_domain", 35, _rx(
        "legal advice", "medical advice", "financial advice", "diagnosis",
        "diagnose", "prescribe", "prescription", "tax advice",
        "investment advice", "contract review", "lawsuit", "litigation",
        "treatment plan",
    )),
    # PII processing verbs: collecting/exporting personal data.
    ("pii_processing", 30, _rx(
        "pii", "personal data", "personally identifiable", "ssn",
        "social security", "passport", "date of birth", "scrape emails",
        "export user data", "export customer data", "health record",
        "medical record",
    )),
    # Irreversibility markers: blast radius ("all users", "production") and
    # permanence ("permanently") amplify whatever else the goal does.
    ("irreversible", 25, _rx(
        "permanently", "permanent", "irreversible", "irreversibly",
        "cannot be undone", "can't be undone", "all users", "all customers",
        "every user", "every customer", "production", "prod environment",
        "live environment",
    )),
)

# De-escalators: read-only / draft-only verbs. Subtracted once. -25 lets a
# single soft signal (pii 30, regulated 35) fall back under MEDIUM, while a
# hard signal (45) stays at least borderline-low and two hard signals stay
# medium+ — researching a risky topic is fine; doing it is not.
DEESCALATE_WEIGHT = 25
_DEESCALATE = _rx(
    "summarize", "summarise", "analyze", "analyse", "research", "draft",
    "review", "read", "explain", "investigate", "compare", "plan",
    "estimate", "outline", "describe", "study", "propose",
)

_TIER_HIGH, _TIER_MEDIUM, _TIER_LOW = "high", "medium", "low"


@dataclass(frozen=True)
class GoalRisk:
    """The classified risk of one goal.

    ``tier`` is "low" / "medium" / "high"; ``score`` is the clamped 0..1
    points fraction; ``signals`` names every signal class that fired (a
    de-escalator appears as ``"deescalate:read_only"``) so the audit record
    shows *why*, not just *what*.
    """

    tier: str
    score: float
    signals: list[str]


def classify_goal(title: str, description: str = "") -> GoalRisk:
    """Score a goal's risk tier from its title + description.

    Deterministic: same input, same output — no model, no config, no clock.
    Matching is lowercased with word boundaries, so "buy" fires on "Buy the
    domain" but not inside "buyer" or "debuyt" — substrings of longer words
    never fire a signal.
    """
    text = f"{title or ''}\n{description or ''}".lower()
    points = 0
    fired: list[str] = []
    for name, weight, pattern in SIGNALS:
        if pattern.search(text):
            points += weight
            fired.append(name)
    if fired and _DEESCALATE.search(text):
        # De-escalation only ever softens a fired signal; a goal with no risk
        # signals is already 0 and listing the de-escalator would be noise.
        points -= DEESCALATE_WEIGHT
        fired.append("deescalate:read_only")
    points = max(0, min(100, points))
    if points >= HIGH_THRESHOLD:
        tier = _TIER_HIGH
    elif points >= MEDIUM_THRESHOLD:
        tier = _TIER_MEDIUM
    else:
        tier = _TIER_LOW
    return GoalRisk(tier=tier, score=points / 100.0, signals=fired)


def _safety_cfg() -> dict:
    try:
        from ..config import load_config
        return (load_config() or {}).get("safety") or {}
    except Exception:  # config must never block classification
        return {}


def config_floor() -> str:
    """The configured minimum tier every goal is treated as.

    ``MAVERICK_GOAL_RISK_FLOOR`` wins over ``[safety] goal_risk_floor``.
    Callers take ``max(classified, floor)`` by :func:`tool_risk.risk_rank`,
    so a cautious deployment can run everything as at-least-"medium" without
    touching the classifier. Unset / unrecognized -> ``"low"`` (a no-op).
    """
    env = os.environ.get("MAVERICK_GOAL_RISK_FLOOR", "").strip().lower()
    if env in RISK_LEVELS:
        return env
    val = str(_safety_cfg().get("goal_risk_floor", "")).strip().lower()
    return val if val in RISK_LEVELS else _TIER_LOW


def require_human_for(tier: str) -> bool:
    """Should a goal of ``tier`` pause for human sign-off before running?

    The knob ``[safety] goal_risk_require_human`` (env
    ``MAVERICK_GOAL_RISK_REQUIRE_HUMAN`` wins) is the *lowest* tier that
    requires a human: ``"high"``, ``"medium"`` (medium and high), or
    ``"never"``. Unset means ``"never"``: the pause is opt-in. A value that is
    set but unrecognized falls back to ``"high"`` — a typo in a safety knob
    must not silently disable a gate an administrator meant to turn on.
    """
    env = os.environ.get("MAVERICK_GOAL_RISK_REQUIRE_HUMAN", "").strip().lower()
    knob = env or str(_safety_cfg().get("goal_risk_require_human", "")).strip().lower()
    if knob in ("", "never"):
        return False
    if knob not in (_TIER_HIGH, _TIER_MEDIUM):
        knob = _TIER_HIGH
    return risk_rank(tier) >= risk_rank(knob)


def start_check(title: str, description: str = "") -> tuple[GoalRisk, str, bool]:
    """What the orchestrator consults before a goal starts.

    Returns ``(classified, effective_tier, needs_person)``: the effective tier
    is the classified tier raised to the configured floor, and
    ``needs_person`` applies :func:`require_human_for` to it (False unless an
    administrator turned the pause on)."""
    classified = classify_goal(title, description)
    floor = config_floor()
    effective = floor if risk_rank(floor) > risk_rank(classified.tier) else classified.tier
    return classified, effective, require_human_for(effective)


PLAIN_SIGNALS = {
    "money": "moves money",
    "infra_destruction": "deletes or deploys",
    "credentials": "handles passwords or keys",
    "bulk_outbound": "messages many people",
    "regulated_domain": "legal, medical or financial advice",
    "pii_processing": "personal data",
    "irreversible": "wide or permanent reach",
    "deescalate:read_only": "reading or drafting only",
}


def plain_reasons(signals: list[str]) -> str:
    """The fired signals in words a person reads (for labels and approvals)."""
    return ", ".join(PLAIN_SIGNALS.get(s, s.replace("_", " ")) for s in signals)


__all__ = [
    "GoalRisk",
    "PLAIN_SIGNALS",
    "classify_goal",
    "plain_reasons",
    "start_check",
    "config_floor",
    "require_human_for",
    "SIGNALS",
    "DEESCALATE_WEIGHT",
    "HIGH_THRESHOLD",
    "MEDIUM_THRESHOLD",
]
