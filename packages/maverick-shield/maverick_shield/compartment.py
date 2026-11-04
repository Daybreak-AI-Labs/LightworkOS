"""Agent compartments: a swarm-shared threat ledger that turns one agent's
detection into immunity for the rest of the run.

Lightwork runs many agents off ONE shared Shield instance
(``SwarmContext.shield``). The base Shield is stateless -- every scan is a pure
function -- so a payload one agent's scan blocked is re-derived from scratch by
the next agent, and nothing carries "I already caught this" across the swarm.

This module adds the first compartment mechanism: *immunity*. When any
agent's scan BLOCKS, the offending payload's normalized fingerprint is recorded
in a run-scoped ``ThreatLedger``. Because the ledger lives inside the single
shared shield, every later scan -- by any agent, including ones spawned
afterward -- checks the fingerprint first and blocks the same attack instantly,
without re-deriving it. Trivial obfuscation variants (case, whitespace,
zero-width and fullwidth tricks) normalize to the same fingerprint, so they are
caught too.

Design constraints (kernel rules in CONTRIBUTING.md):
  * Off by default; opt in via ``[safety] compartments=true`` or
    ``MAVERICK_COMPARTMENTS=1``.
  * Fail-open. A ledger bug must never block a scan -- the base Shield is the
    security floor; the ledger only ever ADDS a block, never downgrades one.
  * In-memory and run-scoped. Persisting signatures across runs is a separate,
    opt-in decision (the immunity channel becomes a long-lived poisoning surface
    once it outlives the run) and is deliberately NOT done here.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass, field

from .cascade import normalize_for_probe
from .guard import ShieldVerdict

log = logging.getLogger(__name__)

_WHITESPACE_RE = re.compile(r"\s+")

# A fingerprint is only recorded/consulted for payloads at least this long
# (post-normalization). Short strings ("ok", "ls", "yes") collide across
# unrelated, benign content -- immunizing them would let one blocked call
# wrongly quarantine ordinary text everywhere. The threat payloads we care
# about (injection blocks, exfil markers, shell one-liners) are comfortably
# longer than this floor.
_MIN_FINGERPRINT_CHARS = 12


def _normalize(text: str) -> str:
    """Collapse a payload to a comparison form.

    NFKC + invisible/tag-block stripping (shared with the cheap probe) folds the
    Unicode smuggling tricks; casefold + whitespace-collapse folds the cheap
    textual variants. Two payloads that differ only by those tricks therefore
    share one fingerprint, so immunity survives light mutation.
    """
    folded = normalize_for_probe(text)
    return _WHITESPACE_RE.sub(" ", folded).strip().casefold()


def fingerprint(text: str) -> str | None:
    """Stable fingerprint of a payload, or None if too short to be meaningful."""
    if not isinstance(text, str):
        return None
    norm = _normalize(text)
    if len(norm) < _MIN_FINGERPRINT_CHARS:
        return None
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


@dataclass
class _Signature:
    severity: str
    reasons: list[str]
    hits: int = 1


@dataclass
class ThreatLedger:
    """Run-scoped, swarm-shared registry of blocked-payload fingerprints.

    Thread-safe: a swarm runs children concurrently on one event loop, but the
    lock also covers the rare cross-thread caller. Bounded: a flood of distinct
    payloads evicts oldest-first rather than growing without limit.
    """
    max_entries: int = 2048
    _sigs: OrderedDict[str, _Signature] = field(default_factory=OrderedDict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, text: str, verdict: ShieldVerdict, surface: str = "") -> str | None:
        """Quarantine the payload behind a blocking verdict. No-op if allowed.

        ``surface`` scopes the fingerprint to the scan surface it was blocked on
        (input / output / tool_call): a string blocked as an untrusted INPUT
        must not auto-block the same text legitimately QUOTED in an agent's
        output. Returns the bare fingerprint (or None)."""
        if getattr(verdict, "allowed", True):
            return None
        fp = fingerprint(text)
        if fp is None:
            return None
        key = f"{surface}|{fp}"
        with self._lock:
            existing = self._sigs.get(key)
            if existing is not None:
                existing.hits += 1
                self._sigs.move_to_end(key)
                return fp
            self._sigs[key] = _Signature(
                severity=getattr(verdict, "severity", "high") or "high",
                reasons=list(getattr(verdict, "reasons", []) or []),
            )
            while len(self._sigs) > self.max_entries:
                self._sigs.popitem(last=False)  # evict oldest
        return fp

    def check(self, text: str, surface: str = "") -> _Signature | None:
        """Return the stored signature if this payload was quarantined on the
        same ``surface`` (see :meth:`record`)."""
        fp = fingerprint(text)
        if fp is None:
            return None
        key = f"{surface}|{fp}"
        with self._lock:
            sig = self._sigs.get(key)
            if sig is not None:
                self._sigs.move_to_end(key)
            return sig

    def __len__(self) -> int:  # observability
        return len(self._sigs)


@dataclass
class ImmunizingShield:
    """Wraps a base Shield with a swarm-shared ThreatLedger (the immunity compartment).

    Mirrors ``CascadedShield``: a thin wrapper exposing the same
    ``scan_input`` / ``scan_tool_call`` / ``scan_output`` surface plus
    ``backend`` / ``enabled``. The base scan ALWAYS runs and is the security
    floor; the ledger only adds an early block on a previously-seen payload and
    records new blocks. Never weaker than the base it wraps.
    """
    base: object
    ledger: ThreatLedger = field(default_factory=ThreatLedger)

    @classmethod
    def from_config(cls) -> ImmunizingShield:
        from .guard import Shield  # local import to avoid cycle
        return cls(base=Shield.from_config())

    @property
    def backend(self) -> str:
        return f"immunizing({getattr(self.base, 'backend', 'unknown')})"

    @property
    def enabled(self) -> bool:
        return getattr(self.base, "enabled", True)

    def _quarantine_verdict(self, sig: _Signature) -> ShieldVerdict:
        reasons = [f"compartment-quarantine: {r}" for r in sig.reasons] or [
            "compartment-quarantine"
        ]
        return ShieldVerdict(allowed=False, severity=sig.severity, reasons=reasons)

    def _guard(self, text: str, base_scan, surface: str):
        """Ledger-check -> base scan -> record, scoped to ``surface``. Fail-open
        on ledger errors. Immunity is per-surface so a block on one surface
        never auto-quarantines the same text on another (a different trust
        context); the base scan still runs as the floor on every surface."""
        try:
            hit = self.ledger.check(text, surface)
        except Exception:  # pragma: no cover -- ledger must never break a scan
            hit = None
        if hit is not None:
            return self._quarantine_verdict(hit)
        verdict = base_scan()
        try:
            if not getattr(verdict, "allowed", True):
                self.ledger.record(text, verdict, surface)
        except Exception:  # pragma: no cover -- recording must never break a scan
            pass
        return verdict

    def scan_input(self, text: str):
        return self._guard(text, lambda: self.base.scan_input(text), "input")

    def scan_output(self, text: str, known_prompt: str | None = None):
        return self._guard(
            text, lambda: self.base.scan_output(text, known_prompt=known_prompt),
            "output",
        )

    def scan_tool_call(self, tool_name: str, args: dict):
        # Build the same payload string the base scanner inspects so a tool call
        # blocked once is recognized again by fingerprint.
        try:
            from .guard import _collect_arg_strings
            payload = "\n".join([f"tool={tool_name}", *_collect_arg_strings(args)])
        except Exception:  # pragma: no cover
            payload = f"tool={tool_name}"
        return self._guard(
            payload, lambda: self.base.scan_tool_call(tool_name, args), "tool_call"
        )


def compartments_enabled() -> bool:
    """True if agent compartments (the shared threat ledger) are turned on."""
    env = os.environ.get("MAVERICK_COMPARTMENTS", "")
    if env.strip().lower() in ("1", "true", "yes", "on"):
        return True
    try:
        from maverick.config import get_safety
        return bool(get_safety().get("compartments", False))
    except Exception:
        return False
