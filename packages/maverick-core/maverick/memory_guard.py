"""Memory Guard -- governed reads/writes for agent memory (OWASP ASI06).

Persisting agent context creates a memory-poisoning surface: a malicious string
the agent ingested once (a web page, a tool result, an inbound message) can be
stored as "memory" and then replay as a standing instruction in every future
run. OWASP added this as **ASI06 -- Memory & Context Poisoning** to the 2026
Agentic Top 10. This module is Lightwork's screen between an agent and its memory
store. It does three things:

  1. **Provenance** -- stamp every memory write with who authored it
     (:class:`Provenance`: ``source`` + :class:`TrustTier` + :class:`Sensitivity`).
  2. **Write screening** -- run low-trust writes through an injection/poisoning
     tripwire (and the Shield, when wired) and quarantine the ones that look
     like smuggled instructions, so they never enter the store.
  3. **Trust-aware retrieval** -- keep low-trust memory out of the agent's
     standing brief (:func:`filter_facts`), with a stricter gate available for
     memory consulted right before an irreversible action
     (``filter_facts(high_risk=True)`` / :func:`allow_recall`).

Every decision is logged to the signed audit chain (:func:`audit_write`,
:func:`audit_recall`) so memory lineage is verifiable the same way tool calls
are. This is a *governance control*, not the whole defense: the deterministic,
LLM-free learning loops and the per-scope bulkheads are the structural defenses;
this is the ASI06 chokepoint on top.

OFF by default (``[memory_guard] enable`` / ``MAVERICK_MEMORY_GUARD=1``). When
off, writes are allowed unchanged and retrieval is unfiltered -- but provenance
columns are still recorded, so turning the guard on later governs existing
memory immediately.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum, IntEnum

from ._envparse import env_bool

log = logging.getLogger(__name__)


class TrustTier(IntEnum):
    """How much a piece of memory is trusted, by who authored it. Higher = more
    trusted. The ordering is the whole point: retrieval and write policy compare
    against a floor, so callers never hard-code tier semantics."""
    EXTERNAL = 0     # third-party / web / inbound-message / raw tool output
    TOOL = 1         # the agent itself, persisting its own working notes
    LEARNED = 2      # Lightwork's deterministic learning loops (dreaming, etc.)
    FIRST_PARTY = 3  # operator / config / human-authored


class Sensitivity(str, Enum):
    """Data-sensitivity label carried alongside a memory (for retention/export
    and future redaction policy). Stored as the string value."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass(frozen=True)
class Provenance:
    """Where a piece of memory came from. Defaults to first-party trust so an
    unstamped internal write is treated as trusted (backward-compatible)."""
    source: str = ""
    trust: TrustTier = TrustTier.FIRST_PARTY
    sensitivity: Sensitivity = Sensitivity.INTERNAL


@dataclass
class WriteDecision:
    """Outcome of :func:`screen_write`. ``allowed`` False = quarantine (do not
    store). ``markers`` are the tripwire labels that fired, for the audit line."""
    allowed: bool
    reason: str
    markers: list[str] = field(default_factory=list)


def enabled() -> bool:
    """Whether the Memory Guard is active. OFF by default.

    Turn on with ``MAVERICK_MEMORY_GUARD=1`` or ``[memory_guard] enable = true``.
    """
    if env_bool("MAVERICK_MEMORY_GUARD"):
        return True
    try:
        from .config import get_memory_guard
        return bool(get_memory_guard()["enable"])
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def min_recall_trust() -> int:
    """Trust floor for memory entering the agent's standing brief. Facts below
    this tier are dropped at retrieval. Default :attr:`TrustTier.TOOL` (1), i.e.
    drop only EXTERNAL/untrusted memory; raise to 2/3 to be stricter."""
    try:
        from .config import get_memory_guard
        return int(get_memory_guard()["min_recall_trust"])
    except Exception:  # pragma: no cover
        return int(TrustTier.TOOL)


# Injection / poisoning tripwire. These are the OWASP-ASI06 staples: smuggled
# role tags, "ignore previous instructions", instruction-override, secret
# exfiltration, and destructive-shell snippets. This is a deliberately small,
# high-signal list -- a heuristic that flags low-trust writes for quarantine,
# NOT a complete classifier. (label, pattern); matched case-insensitively.
_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (label, re.compile(rx, re.IGNORECASE))
    for label, rx in [
        ("ignore-previous",
         r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|earlier|"
         r"all)\b.{0,30}\b(instruction|message|context|prompt|rule)"),
        ("role-reassign", r"\byou\s+are\s+now\b"),
        ("from-now-on", r"\bfrom\s+now\s+on\b"),
        ("new-instructions",
         r"\bnew\s+(system\s+)?(instruction|prompt|directive|rule)"),
        ("fake-role-tag", r"</?\s*(system|assistant|developer)\s*>"),
        ("role-prefix-inject", r"\b(system|developer)\s*:\s*you\b"),
        ("reveal-secrets",
         r"\b(reveal|print|show|leak|exfiltrate)\b.{0,40}\b(system\s+prompt|"
         r"your\s+instruction|secret|api[\s_-]?key|password|token|credential)"),
        ("exfiltrate",
         r"\b(send|post|upload|exfiltrate|forward)\b.{0,40}"
         r"(https?://|ftp://|attacker|webhook)"),
        # curl/wget + a flag, a scheme, or a host.tld -- not prose like
        # "curl up on the couch".
        ("shell-fetch",
         r"\b(?:curl|wget)\s+(?:-{1,2}[a-z]|\w+://|[\w-]+\.[a-z]{2,})"),
        ("base64-decode", r"base64\b.{0,12}\b(decode|b64decode)"),
        # rm -rf, or an actual DROP TABLE/DATABASE ...; statement (terminated)
        # -- not a passing mention like "drop table talk and ship".
        ("destructive-shell",
         r"\brm\s+-rf\b|\bdrop\s+(?:table|database)\b[^;\n]{0,40};"),
        ("jailbreak", r"\b(jailbreak|dan\s+mode|developer\s+mode)\b"),
        ("conceal", r"\bdo\s*n[o']?t\s+(tell|inform|alert|notify)\b"),
        ("skip-approval",
         r"\bwithout\s+(asking|telling|notifying|approval|permission)\b"),
        ("override-safety",
         r"\boverride\b.{0,20}\b(safety|guard|shield|policy|governance)\b"),
    ]
]


def injection_markers(text: str) -> list[str]:
    """Tripwire labels that fired for ``text`` (empty = clean). Public so tests
    and other screens (knowledge ingest, fleet inbox) can reuse the same list."""
    if not text:
        return []
    return [label for label, rx in _INJECTION_PATTERNS if rx.search(text)]


def screen_write(text: str, prov: Provenance, *, shield=None) -> WriteDecision:
    """Decide whether ``text`` (authored per ``prov``) may enter memory.

    Trusted authors (operator/config = FIRST_PARTY, and the deterministic
    learning loops = LEARNED) are never quarantined -- an operator may
    legitimately store a note that trips a heuristic. Only low-trust writes
    (TOOL/EXTERNAL) are screened: if they carry injection markers, or the Shield
    flags them, they are quarantined. The Shield call is fail-open (kernel rule:
    a Shield error must never block the agent) -- a scan failure degrades to
    "allow", it never crashes the write path.

    When the guard is disabled this always allows (callers can screen
    unconditionally)."""
    if not enabled():
        return WriteDecision(True, "guard-disabled")
    if prov.trust >= TrustTier.LEARNED:
        return WriteDecision(True, "trusted-author")
    markers = injection_markers(text)
    if markers:
        return WriteDecision(
            False, "injection markers in low-trust memory: " + ",".join(markers),
            markers,
        )
    if shield is not None:
        try:
            verdict = shield.scan_input(text)
            if not getattr(verdict, "allowed", True):
                return WriteDecision(False, "shield-flagged low-trust memory",
                                     ["shield"])
        except Exception:  # pragma: no cover -- Shield must never block a write
            log.warning("memory_guard: shield scan failed; allowing write")
    return WriteDecision(True, "clean")


def _passes_floor(trust: int, floor: int, *, high_risk: bool) -> bool:
    """Trust-tier decision shared by :func:`allow_recall` and :func:`filter_facts`
    -- the latter precomputes ``floor`` once so its per-fact loop reads no config.
    """
    if trust < floor:
        return False
    if high_risk and trust < int(TrustTier.LEARNED):
        return False
    return True


def allow_recall(prov: Provenance, *, high_risk: bool = False,
                 min_trust: int | None = None) -> bool:
    """Whether a memory of provenance ``prov`` may be surfaced to the agent.

    Enforces the trust floor (``min_trust``, default :func:`min_recall_trust`),
    and -- when ``high_risk`` (the memory could drive an irreversible action) --
    requires at least LEARNED trust, so EXTERNAL/TOOL memory can suggest but
    never single-handedly authorize a destructive step. Allows everything when
    the guard is disabled."""
    if not enabled():
        return True
    floor = min_recall_trust() if min_trust is None else int(min_trust)
    return _passes_floor(int(prov.trust), floor, high_risk=high_risk)


def filter_facts(facts: dict[str, tuple[str, int]], *,
                 high_risk: bool = False) -> dict[str, str]:
    """Apply trust-aware retrieval to ``{key: (value, trust_tier)}`` (as returned
    by :meth:`maverick.world_model.WorldModel.get_facts_with_trust`) and return
    the kept ``{key: value}``.

    This is the production entry point. The trust floor is read ONCE (not per
    fact -- this runs on the brief-assembly hot path, and the config read is
    uncached file I/O), then applied to every fact; with ``high_risk=True`` the
    stricter irreversible-action gate applies. Every fact passes through
    unchanged when the guard is disabled."""
    if not enabled():
        return {k: v for k, (v, _tier) in facts.items()}
    floor = min_recall_trust()
    out: dict[str, str] = {}
    for k, (v, tier) in facts.items():
        try:
            trust = int(TrustTier(int(tier)))
        except ValueError:
            trust = int(TrustTier.EXTERNAL)  # unknown tier -> least trusted (safe)
        if _passes_floor(trust, floor, high_risk=high_risk):
            out[k] = v
    return out


def agent_fact_provenance() -> Provenance:
    """Provenance for a fact the agent persists via the kv_memory tool: TOOL
    trust (it authored it from its own work, not the operator), internal
    sensitivity. This is the memory-poisoning surface the guard screens."""
    return Provenance(source="agent:kv_memory", trust=TrustTier.TOOL,
                      sensitivity=Sensitivity.INTERNAL)


def audit_write(key: str, prov: Provenance, decision: WriteDecision, *,
                goal_id: int | None = None) -> None:
    """Log one memory write to the signed audit chain (fail-safe).

    No-op when the guard is disabled: a MEMORY_GUARD event records *guard
    activity*, so auditing every write while the guard is off is just noise (and
    needlessly logs the key, which may embed a subject identifier)."""
    if not enabled():
        return
    try:
        from . import audit
        audit.record(
            audit.EventKind.MEMORY_GUARD,
            goal_id=goal_id,
            action="write" if decision.allowed else "write_blocked",
            key=key,
            source=prov.source,
            trust=int(prov.trust),
            sensitivity=prov.sensitivity.value,
            reason=decision.reason,
            markers=",".join(decision.markers),
        )
    except Exception:  # pragma: no cover -- audit failures never crash the agent
        log.debug("memory_guard: audit_write failed", exc_info=True)


def audit_recall(*, kept: int, dropped: int, min_trust: int,
                 goal_id: int | None = None) -> None:
    """Log a trust-aware retrieval pass (how many memories were filtered)."""
    if dropped <= 0:
        return
    try:
        from . import audit
        audit.record(
            audit.EventKind.MEMORY_GUARD,
            goal_id=goal_id,
            action="recall_filter",
            kept=int(kept),
            dropped=int(dropped),
            min_trust=int(min_trust),
        )
    except Exception:  # pragma: no cover
        log.debug("memory_guard: audit_recall failed", exc_info=True)
