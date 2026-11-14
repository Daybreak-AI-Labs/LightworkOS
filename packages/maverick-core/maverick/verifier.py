"""Verifier role: independent second-opinion pass on a proposer's answer.

The recursive multi-agent ceremony only earns its complexity if there's a
real verify step. The current ``revisor`` role exists in prompt strings
only -- no code actually runs a verifier pass before declaring FINAL.

This module gives the orchestrator a single function to call:

    verdict = await verify_proposal(brief, proposal, llm, budget)

The verifier is invoked with a different system prompt + a fresh
budget allocation so its output isn't anchored by the proposer's
context. The verdict is structured:

    verdict.confidence:   float in [0, 1]
    verdict.accepts:      bool (confidence >= threshold)
    verdict.critique:     str (always populated; empty string if accepts)
    verdict.issues:       list[str] (specific problems flagged)

The agent loop uses `accepts` to early-stop, and feeds `critique` back
to the proposer as a revision brief if it doesn't accept. `confidence`
is the disagreement signal that adaptive fanout reads (see
``maverick.tools.spawn``).
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field

from ._envparse import is_truthy
from .budget import Budget, BudgetExceeded
from .llm import LLM, model_for_role

log = logging.getLogger(__name__)


# Default disagreement entropy threshold. Above this, fan out to more
# proposers; below, accept the single answer. Tunable via env.
# Both are also settings ([verification] disagreement_high /
# confidence_accept) read once at startup; the environment still wins.
def _threshold_settings() -> tuple[float, float]:
    from .env_setting import env_or_config

    def _number(env: str, key: str, default: float) -> float:
        # An unreadable environment value still fails loudly, as it always did.
        raw = os.environ.get(env)
        if raw is not None and raw.strip():
            return float(raw)
        try:
            return float(env_or_config(env, "verification", key, str(default)) or default)
        except ValueError:
            return default

    return (_number("MAVERICK_DISAGREEMENT_HIGH", "disagreement_high", 0.5),
            _number("MAVERICK_VERIFIER_CONFIDENCE", "confidence_accept", 0.75))


DISAGREEMENT_HIGH, VERIFIER_CONFIDENCE_ACCEPT = _threshold_settings()


VERIFIER_SYSTEM = """You are an independent verifier reviewing another agent's answer to a goal.

You have access to no tools. Your job is to read the brief + the proposed final answer and decide:
1. Does the answer actually satisfy the brief? Be strict.
2. Are there factual errors, missing steps, or unsupported claims?
3. Would a careful human accept this?

Respond with a JSON object on a single line:

{"confidence": 0.0-1.0, "accepts": true|false, "critique": "<1-2 sentences>", "issues": ["<short issue>", ...]}

Confidence calibration:
- 0.9-1.0: The answer fully satisfies the brief, no meaningful issues.
- 0.7-0.9: Mostly correct; minor polish would help but it's defensible.
- 0.4-0.7: Significant gaps; a careful reviewer would want revisions.
- 0.0-0.4: Wrong direction or unsupported; reject.

`accepts` should be true iff confidence >= 0.75 AND issues is empty (or only nitpicks).
Output ONLY the JSON. No preamble, no markdown fence.
"""


@dataclass
class VerifierVerdict:
    confidence: float
    accepts: bool
    critique: str
    issues: list[str] = field(default_factory=list)
    raw: str = ""
    # When the structured rubric judge (maverick.reasoning_reward) produced this
    # verdict, its full to_audit_dict() -- the per-dimension rubric, reasoning,
    # and veto -- so a caller can record the legible reward in the learning
    # audit. None for the scalar verifier path.
    reward_audit: dict | None = None

    @classmethod
    def reject(cls, reason: str) -> VerifierVerdict:
        return cls(confidence=0.0, accepts=False, critique=reason, issues=[reason])

    @classmethod
    def accept_unconditionally(cls) -> VerifierVerdict:
        """For trivial cases where verification adds no value (e.g. empty
        brief, sub-second tasks). Skips the LLM call."""
        return cls(confidence=1.0, accepts=True, critique="", issues=[])


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse(text: str) -> VerifierVerdict:
    """Best-effort JSON extraction from the verifier's reply.

    Models sometimes wrap JSON in markdown fences or prefix with prose
    despite the system prompt. We extract the outermost {...} and parse
    it; on any failure we treat the verdict as low-confidence reject so
    the proposer is forced to revise.
    """
    if not text:
        return VerifierVerdict.reject("verifier returned empty response")
    m = _JSON_OBJECT_RE.search(text)
    if m is None:
        return VerifierVerdict.reject("verifier reply contained no JSON object")
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError as e:
        return VerifierVerdict.reject(f"verifier JSON parse failed: {e}")

    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    accepts_raw = data.get("accepts", False)
    if isinstance(accepts_raw, str):
        accepts = accepts_raw.lower() in ("true", "yes", "1")
    else:
        accepts = bool(accepts_raw)

    critique = str(data.get("critique", "") or "")
    issues_raw = data.get("issues", []) or []
    issues = [str(x) for x in issues_raw if x]

    # Enforce the confidence floor in code -- VERIFIER_CONFIDENCE_ACCEPT was
    # dead, so the model's raw `accepts` boolean was trusted verbatim. The
    # verifier is the last correctness gate before FINAL, so accepting a
    # low-confidence verdict is a fail-open a miscalibrated/jailbroken verifier
    # could exploit (accepts=true, confidence=0.1). Below the threshold the
    # verdict is forced to a reject with a revision brief.
    if accepts and confidence < VERIFIER_CONFIDENCE_ACCEPT:
        accepts = False
        critique = critique or (
            f"verifier confidence {confidence:.2f} is below the accept "
            f"threshold {VERIFIER_CONFIDENCE_ACCEPT:.2f}"
        )

    return VerifierVerdict(
        confidence=confidence,
        accepts=accepts,
        critique=critique,
        issues=issues,
        raw=text,
    )


async def verify_proposal(
    brief: str,
    proposal: str,
    llm: LLM,
    budget: Budget | None = None,
    *,
    max_tokens: int = 1024,
    proposer_model: str | None = None,
) -> VerifierVerdict:
    """Ask the verifier role to judge a proposer's final answer.

    Uses ``maverick.config`` per-role model routing under ``verifier``
    (falls back to MODEL_OPUS via ROLE_MODELS). Spend lands in the
    passed budget; callers should expect ~$0.005-$0.05 per call.

    The verdict is conservative: any parsing failure / empty response /
    JSON-without-required-fields → reject. This keeps the proposer
    honest -- a flaky verifier can only make the system MORE careful,
    not less.

    Cross-family guard: if the verifier model is in
    the same family as the proposer (e.g. both Anthropic), they can be
    jailbroken in lockstep (Anthropic's alignment-faking paper
    arxiv:2412.14093 and later deceptive-alignment work). When the
    proposer_model is passed and matches the verifier's family, we swap
    to a cross-family verifier — but ONLY when one is explicitly
    configured via ``MAVERICK_CROSS_FAMILY_VERIFIER`` (users own model
    choice; we never implicitly switch to a provider whose credentials
    the operator may not have). If no fallback is configured, the
    same-family verifier runs and we log the lockstep risk ONCE rather
    than silently pretending a cross-family swap happened.
    """
    if not proposal or not proposal.strip():
        return VerifierVerdict.reject("proposal is empty")

    model = model_for_role("verifier")
    if proposer_model and _same_family(proposer_model, model):
        cross = _cross_family_fallback(model)
        if cross is not None:
            model = cross
        else:
            _warn_same_family_verifier(model)

    user_msg = (
        f"GOAL BRIEF:\n{brief}\n\n"
        f"PROPOSED FINAL ANSWER:\n{proposal}\n\n"
        "Return the verdict JSON."
    )
    try:
        resp = await llm.complete_async(
            system=VERIFIER_SYSTEM,
            messages=[{"role": "user", "content": user_msg}],
            tools=None,
            budget=budget,
            max_tokens=max_tokens,
            model=model,
        )
    except BudgetExceeded:
        # Budget exhaustion is a control-flow signal for the budget
        # layer, not a verifier outcome — let it propagate.
        raise
    except Exception as e:  # pragma: no cover -- network errors
        # Fail CLOSED, per this module's contract ("any failure →
        # reject; a flaky verifier can only make the system MORE
        # careful, not less"). The previous fail-open (accepts=True)
        # silently disabled the safety gate exactly when the system was
        # least healthy.
        log.warning("verifier LLM call failed: %s; rejecting (fail-closed)", e)
        return VerifierVerdict.reject(f"verifier call failed: {e}")
    return _parse(resp.text)


def _provider_from_model(model: str) -> str:
    return model.split(":", 1)[0].strip()


def _routing_allowed_providers() -> set[str] | None:
    """Return the routing provider allowlist, or None when unrestricted.

    Installer-generated configs include this key when advanced routing or
    ensemble verification is enabled so verifier prompts do not leave the
    provider set the user selected in the wizard.
    """
    try:
        from .config import load_config
        routing = (load_config() or {}).get("routing") or {}
    except Exception:
        return None
    allowed = routing.get("allowed_providers")
    if not isinstance(allowed, list):
        return None
    return {str(p).strip() for p in allowed if str(p).strip()}


_DEFAULT_ENSEMBLE_PANEL = [
    "anthropic:claude-sonnet-4-6",
    "openai:gpt-5.4",
    "openrouter:deepseek-v4-pro",
]

_DEFAULT_ALLOWED_PROVIDER_MODELS = {
    "anthropic": "anthropic:claude-sonnet-4-6",
    "openai": "openai:gpt-5.4",
    "openrouter": "openrouter:deepseek-v4-pro",
    "deepseek": "deepseek:deepseek-v4-pro",
    "moonshot": "moonshot:moonshot-v1-128k",
    "xai": "xai:grok-4.5",
    "gemini": "gemini:gemini-3.5-flash",
}


def _filter_allowed_panel(panel: list[str], *, default_panel: bool) -> list[str]:
    allowed = _routing_allowed_providers()
    if allowed is None:
        return panel
    if default_panel:
        return [
            spec for provider, spec in _DEFAULT_ALLOWED_PROVIDER_MODELS.items()
            if provider in allowed
        ]
    return [model for model in panel if _provider_from_model(model) in allowed]


async def verify_proposal_ensemble(
    brief: str,
    proposal: str,
    llm: LLM,
    budget: Budget | None = None,
    *,
    proposer_model: str | None = None,
    panel: list[str] | None = None,
    weighted: bool = True,
) -> VerifierVerdict:
    """Run N verifiers across distinct model families and combine.

    Multi-Agent Verification (MAV, arxiv:2502.20379) shows that scaling
    the *verifier* axis -- multiple verifiers, weighted vote -- is
    orthogonally additive to scaling the *generator* axis (best-of-N).
    On agentic tasks MAV-3 beats single-verifier + best-of-8 at the
    same total compute budget.

    Panel: explicit model list, or None to use a curated cross-family
    default (Anthropic Sonnet + OpenAI GPT + DeepSeek). Same-family panel
    members are excluded when another allowed family remains.

    `weighted=True` uses each verdict's `confidence` as a weight in
    the final accept-vote; `weighted=False` is plain majority. The
    combined verdict's `confidence` is the *mean* confidence across the
    voters who agree with the winning side (a dissenting outlier is
    overruled, not averaged in).
    """
    if not proposal or not proposal.strip():
        return VerifierVerdict.reject("proposal is empty")

    default_panel = panel is None
    if panel is None:
        panel = list(_DEFAULT_ENSEMBLE_PANEL)
    allowed_panel = _filter_allowed_panel(panel, default_panel=default_panel)

    # Drop panel members in the proposer's family when possible, but never
    # replace an installer-constrained panel with an unselected provider. If
    # the only selected verifier is same-family, prefer that selected provider
    # over leaking the brief/proposal to an unselected cross-family fallback.
    panel = allowed_panel
    if proposer_model:
        cross_family_panel = [m for m in panel if not _same_family(proposer_model, m)]
        if cross_family_panel:
            panel = cross_family_panel
    if not panel:
        # Everything got filtered. Preserve the historical fallback only when
        # there is no routing allowlist; wizard-generated configs include an
        # allowlist and should fail closed instead of contacting third parties.
        if _routing_allowed_providers() is not None:
            return VerifierVerdict.reject("no allowed ensemble verifier providers configured")
        cross = _cross_family_fallback(proposer_model or "")
        if cross:
            panel = [cross]
        else:
            # Parity with the single-verifier path: when no cross-family
            # fallback is configured we fall back to a same-family verifier;
            # surface the lockstep-jailbreak risk ONCE instead of silently.
            fallback = model_for_role("verifier")
            if proposer_model and _same_family(proposer_model, fallback):
                _warn_same_family_verifier(fallback)
            panel = [fallback]

    import asyncio
    user_msg = (
        f"GOAL BRIEF:\n{brief}\n\n"
        f"PROPOSED FINAL ANSWER:\n{proposal}\n\n"
        "Return the verdict JSON."
    )

    async def _one(model: str) -> VerifierVerdict:
        try:
            resp = await llm.complete_async(
                system=VERIFIER_SYSTEM,
                messages=[{"role": "user", "content": user_msg}],
                tools=None,
                budget=budget,
                max_tokens=1024,
                model=model,
            )
            return _parse(resp.text)
        except BudgetExceeded:
            raise
        except Exception as e:  # pragma: no cover
            # Fail closed, same contract as verify_proposal. One panel
            # member erroring must not auto-accept.
            log.warning("MAV verifier %s failed: %s", model, e)
            return VerifierVerdict.reject(f"verifier {model} failed: {e}")

    # return_exceptions=True so a BudgetExceeded from ONE member doesn't
    # propagate out of gather mid-flight and leave the other _one coroutines
    # running orphaned (no awaiter) -- still spending tokens against an already
    # exhausted budget and producing late completions nobody reads. gather then
    # awaits all members; we re-raise the budget error once they've settled
    # (matches the kernel pattern in agent.py / tools/spawn.py).
    results = await asyncio.gather(*(_one(m) for m in panel), return_exceptions=True)
    for r in results:
        if isinstance(r, BudgetExceeded):
            raise r
    verdicts = [
        r if isinstance(r, VerifierVerdict)
        else VerifierVerdict.reject(f"verifier panel member crashed: {r}")
        for r in results
    ]
    return _combine(verdicts, weighted=weighted)


def _explicit_true(value: object) -> bool:
    """Return True only for explicit verifier-ensemble opt-in values."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return is_truthy(value)
    return False


def _ensemble_enabled() -> bool:
    """Opt-in gate for the adversarial multi-verifier panel.

    Off by default: a single cross-family verifier is the standard path.
    Flip on via ``MAVERICK_VERIFY_ENSEMBLE=1`` or ``[routing]
    verify_ensemble = true`` to run the MAV panel (stronger, ~Nx the
    verifier cost). Spend still lands in the run's Budget, so the cap is
    respected either way.
    """
    if _explicit_true(os.environ.get("MAVERICK_VERIFY_ENSEMBLE", "")):
        return True
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("routing") or {}
        return _explicit_true(cfg.get("verify_ensemble"))
    except Exception:
        return False


def _structured_verify_enabled() -> bool:
    """Whether the structured rubric judge (maverick.reasoning_reward) is on."""
    try:
        from . import reasoning_reward
        return bool(reasoning_reward.enabled())
    except Exception:  # pragma: no cover -- never let this gate a run
        return False


def _verdict_from_reward(reward: object) -> VerifierVerdict:
    """Map a structured ``ReasoningReward`` onto the ``VerifierVerdict`` contract.

    ``confidence`` = holistic score; ``accepts`` = the reward's own accept
    decision (holistic bar AND no vetoed dimension); ``issues`` surfaces the
    failing/vetoed facets; ``reward_audit`` carries the full rubric for the
    learning audit.
    """
    dims = getattr(reward, "dimensions", ()) or ()
    issues: list[str] = []
    for d in dims:
        if getattr(d, "vetoes", False) or getattr(d, "score", 1.0) < 0.5:
            crit = getattr(d, "critique", "") or ""
            issues.append(f"{d.name}: {crit}" if crit else str(getattr(d, "name", "")))
    return VerifierVerdict(
        confidence=float(getattr(reward, "score", 0.0)),
        accepts=bool(reward.accepts()),
        critique=str(getattr(reward, "critique", "") or ""),
        issues=[i for i in issues if i],
        raw=str(getattr(reward, "raw", "") or ""),
        reward_audit=reward.to_audit_dict(),
    )


async def verify_proposal_structured(
    brief: str,
    proposal: str,
    llm: LLM,
    budget: Budget | None = None,
    *,
    max_tokens: int = 1024,
    proposer_model: str | None = None,
) -> VerifierVerdict:
    """Verify with the structured rubric judge (Agent-RRM, reasoning_reward).

    Sends ``REASONING_REWARD_SYSTEM`` and parses a per-dimension rubric reward:
    a single failing dimension (e.g. ``safety`` below its veto floor) rejects
    even a high holistic score, and the full rubric is attached to the verdict
    for the learning audit. Any reply that is NOT a compliant rubric (no
    dimensions parsed) falls back to the scalar verifier parse, so this is a
    safe superset of :func:`verify_proposal` with the same VerifierVerdict
    contract and the same cross-family / fail-closed behaviour.
    """
    if not proposal or not proposal.strip():
        return VerifierVerdict.reject("proposal is empty")

    from . import reasoning_reward

    model = model_for_role("verifier")
    if proposer_model and _same_family(proposer_model, model):
        cross = _cross_family_fallback(model)
        if cross is not None:
            model = cross
        else:
            _warn_same_family_verifier(model)

    user_msg = (
        f"GOAL BRIEF:\n{brief}\n\n"
        f"PROPOSED FINAL ANSWER:\n{proposal}\n\n"
        "Return the rubric JSON."
    )
    try:
        resp = await llm.complete_async(
            system=reasoning_reward.REASONING_REWARD_SYSTEM,
            messages=[{"role": "user", "content": user_msg}],
            tools=None,
            budget=budget,
            max_tokens=max_tokens,
            model=model,
        )
    except BudgetExceeded:
        raise
    except Exception as e:  # pragma: no cover -- network errors
        log.warning("structured verifier LLM call failed: %s; rejecting (fail-closed)", e)
        return VerifierVerdict.reject(f"verifier call failed: {e}")

    reward = reasoning_reward.parse_structured(resp.text)
    if getattr(reward, "dimensions", ()):  # a compliant, complete rubric reply
        _maybe_audit_reward(reward)
        return _verdict_from_reward(reward)
    if reasoning_reward.looks_structured(resp.text):
        return VerifierVerdict.reject(
            "structured verifier returned an incomplete or invalid rubric"
        )
    # Non-rubric reply (or garbage): behave exactly like the scalar verifier.
    return _parse(resp.text)


def _maybe_audit_reward(reward: object) -> None:
    """Sign a structured reward into the tamper-evident audit chain when opted
    in (``[reasoning_reward] audit_rewards``) -- provable learning: the evidence
    the system learns from becomes a signed row, not just a mutable verdict.
    Best-effort: an audit write must never perturb a verification."""
    try:
        from . import reasoning_reward
        if not reasoning_reward.audit_rewards_enabled():
            return
        from .audit import EventKind, record
        record(EventKind.VERIFICATION_REWARD, agent="verifier",
               **reward.to_audit_summary())
    except Exception:  # pragma: no cover -- audit is best-effort, never blocks
        log.debug("verification-reward audit failed", exc_info=True)


async def verify_final(
    brief: str,
    proposal: str,
    llm: LLM,
    budget: Budget | None = None,
    *,
    proposer_model: str | None = None,
    force_ensemble: bool = False,
) -> VerifierVerdict:
    """Verify a FINAL answer using whichever verifier the operator chose.

    Single dispatch point for the live agent loop. Precedence: the adversarial
    cross-family ensemble when opted in (``_ensemble_enabled``) or escalated
    (``force_ensemble``); else the structured rubric judge when enabled
    (``reasoning_reward``, the default); else the scalar single cross-family
    verifier. Same signature + return type either way, so the call site is
    verifier-agnostic.
    """
    if force_ensemble or _ensemble_enabled():
        return await verify_proposal_ensemble(
            brief, proposal, llm, budget, proposer_model=proposer_model,
        )
    if _structured_verify_enabled():
        return await verify_proposal_structured(
            brief, proposal, llm, budget, proposer_model=proposer_model,
        )
    return await verify_proposal(
        brief, proposal, llm, budget, proposer_model=proposer_model,
    )


def _combine(verdicts: list[VerifierVerdict], *, weighted: bool) -> VerifierVerdict:
    """Combine N individual verdicts into one ensemble verdict."""
    if not verdicts:
        return VerifierVerdict.reject("no verifiers ran")
    if len(verdicts) == 1:
        return verdicts[0]

    if weighted:
        # ``confidence`` is each voter's confidence that the ANSWER is right,
        # so it measures the strength of an accept, and (1 - confidence) the
        # strength of a reject. Weighting rejects by their raw confidence let
        # one accept outvote failed members (reject() is confidence 0.0) and
        # ordinary rejects (0.0-0.4), contrary to the fail-closed contract.
        accept_weight = sum(v.confidence for v in verdicts if v.accepts)
        reject_weight = sum(1.0 - v.confidence for v in verdicts if not v.accepts)
        accepts = accept_weight > reject_weight
    else:
        accepts = sum(1 for v in verdicts if v.accepts) > len(verdicts) / 2

    # Conservative: combined confidence = mean of those who AGREE with
    # the majority. So if 2/3 accept at 0.9 and 1 rejects at 0.4, we
    # accept at 0.9 (the rejecting voter is overruled but not averaged in).
    side = [v for v in verdicts if v.accepts == accepts]
    confidence = sum(v.confidence for v in side) / len(side) if side else 0.0

    # Collect all unique issues + critiques across the panel.
    issues: list[str] = []
    seen: set[str] = set()
    for v in verdicts:
        for i in v.issues:
            if i and i not in seen:
                issues.append(i)
                seen.add(i)
    critiques = [v.critique for v in verdicts if v.critique]
    critique = " | ".join(critiques) if critiques else ""

    return VerifierVerdict(
        confidence=confidence, accepts=accepts,
        critique=critique, issues=issues,
    )


def _provider(model: str) -> str:
    """Extract the provider/family slug from a `provider:model-id` spec."""
    if ":" in model:
        return model.split(":", 1)[0].lower()
    # Bare ids: heuristic prefix match.
    m = model.lower()
    if m.startswith("claude"):
        return "anthropic"
    # OpenAI reasoning models are "o" plus a digit (o1, o3, o4-mini); a bare
    # "o" prefix also matched unrelated ids such as "ollama-..." or "olmo".
    if m.startswith("gpt") or re.match(r"o\d", m):
        return "openai"
    if m.startswith("gemini"):
        return "gemini"
    if m.startswith("deepseek"):
        return "deepseek"
    if m.startswith("qwen"):
        return "qwen"
    if m.startswith("grok"):
        return "xai"
    if m.startswith("llama"):
        return "meta"
    return "unknown"


def _same_family(a: str, b: str) -> bool:
    return _provider(a) == _provider(b)


_warned_same_family = False


def _warn_same_family_verifier(model: str) -> None:
    """Log the lockstep-jailbreak risk ONCE when the verifier shares the
    proposer's family and no cross-family fallback is configured.

    The contract promises a cross-family swap to defend against
    lockstep jailbreaks, but the swap only happens when
    ``MAVERICK_CROSS_FAMILY_VERIFIER`` is set. When it isn't, surface the
    residual risk instead of leaving the gap silent.
    """
    global _warned_same_family
    if _warned_same_family:
        return
    _warned_same_family = True
    log.warning(
        "verifier %s shares the proposer's family; set "
        "MAVERICK_CROSS_FAMILY_VERIFIER to a different-provider model to "
        "defend against lockstep jailbreaks (running same-family).",
        model,
    )


# Preferred cross-family verifier per source family. Read from env if
# the operator wants to override. The fallback chain ends with the
# original model (no swap) when no peer is configured.
def _cross_family_fallback(model: str) -> str | None:
    """Pick a verifier from a different provider family.

    Uses only the explicit ``MAVERICK_CROSS_FAMILY_VERIFIER`` override; no
    implicit provider swap is performed (users own model choice — we won't
    silently route to a provider whose credentials may be absent). Returns
    None when no cross-family peer is explicitly configured; callers that
    care about the lockstep risk should warn via
    ``_warn_same_family_verifier``.
    """
    from .env_setting import env_or_config

    explicit = env_or_config("MAVERICK_CROSS_FAMILY_VERIFIER", "verification", "cross_family_model")
    if explicit:
        return explicit

    return None
