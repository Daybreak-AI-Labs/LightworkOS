"""Negative knowledge -- executable guardrails mined from causally-triaged failures.

The Cognitive Data Engine's fix-mining stage:
governance that gets *smarter from every incident* instead of ossifying into
static, hand-written ACLs. A triaged :class:`~maverick.data_engine.FailureClass`
(an action that *provably* lowers outcomes) becomes a :class:`Guardrail`: a
learned, reversible rule that discourages that action -- and unlike a deny-list,
each guardrail carries the **causal effect that justifies it**, so it can be
explained, ranked, and *dropped* automatically when re-triage shows the harm is
gone. Negative knowledge that compounds.

The registry persists the learned guardrails; ``consult`` is the read side an
agent (or the rehearsal gate) checks before acting. Pure + OFF by default: mining
only runs on an opt-in triaged corpus, and ``consult`` on an empty registry
returns ``None`` (no behaviour change).
"""
from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path

from .file_lock import atomic_read_text, atomic_write_text, ensure_private_file

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Guardrail:
    """A learned, causally-justified rule that an action hurts outcomes."""

    action: str
    severity: float     # |causal effect| -- how much the action lowers outcome
    ci_high: float      # the effect's upper confidence bound (< 0 == confidently harmful)
    rule: str           # human-readable justification

    @property
    def justified(self) -> bool:
        """Confidently harmful -- the evidence clears the bar to act on it."""
        return self.ci_high < 0.0

    def to_dict(self) -> dict:
        return {"action": self.action, "severity": self.severity,
                "ci_high": self.ci_high, "rule": self.rule}


def mine(failure_classes) -> list[Guardrail]:
    """Turn triaged failure classes into guardrails, strongest harm first.

    Only **trustworthy, confidently-harmful** classes (``ci_high < 0``) become
    guardrails -- a merely-frequent or shaky failure never hardens into a rule.
    """
    rails: list[Guardrail] = []
    for fc in failure_classes:
        if not getattr(fc, "trustworthy", False) or fc.ci_high >= 0.0:
            continue
        sev = abs(fc.causal_effect)
        rails.append(Guardrail(
            action=fc.action, severity=sev, ci_high=fc.ci_high,
            rule=(f"avoid '{fc.action}': it causally lowers task outcome by "
                  f"~{sev:.2f} (95% CI upper bound {fc.ci_high:.2f} < 0)"),
        ))
    rails.sort(key=lambda g: g.severity, reverse=True)
    return rails


@dataclass
class GuardrailRegistry:
    """Append/replace store of learned guardrails (atomic, 0600), keyed by action."""

    path: Path | None = None
    _rails: dict = None  # type: ignore[assignment]
    _lock: threading.Lock = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._lock is None:
            self._lock = threading.Lock()
        if self._rails is None:
            self._rails = {}
        if self.path is not None:
            self._load()

    def update(self, guardrails, *, strict: bool = False, before_write=None) -> None:
        """Replace the learned set with a freshly-mined one (re-triage drops the
        rules whose harm is gone -- guardrails don't accumulate forever)."""
        from .learning_store import derived_guidance_fence

        with derived_guidance_fence(), self._lock:
            if before_write is not None:
                before_write()
            previous = self._rails
            self._rails = {g.action: g for g in guardrails}
            try:
                self._save(strict=strict, before_write=before_write)
            except Exception:
                self._rails = previous
                raise

    def consult(self, action: str) -> Guardrail | None:
        """The guardrail flagging ``action``, or None. The read side for an agent
        / the rehearsal gate; None on an empty registry (no behaviour change)."""
        with self._lock:
            self._refresh()
            return self._rails.get(action)

    def all(self) -> list[Guardrail]:
        with self._lock:
            self._refresh()
            return sorted(self._rails.values(), key=lambda g: g.severity, reverse=True)

    def _refresh(self) -> None:
        # A rollback can come from another process. Existing objects must read
        # current retained guidance, including a restored empty boundary.
        if self.path is not None:
            self._rails.clear()
            if Path(self.path).exists():
                self._load()

    def _load(self) -> None:
        try:
            path = ensure_private_file(Path(self.path))
            raw = json.loads(atomic_read_text(path))
        except (OSError, ValueError):
            return
        if not isinstance(raw, list):
            return
        for d in (raw or []):
            try:
                g = Guardrail(action=str(d["action"]), severity=float(d["severity"]),
                              ci_high=float(d["ci_high"]), rule=str(d.get("rule", "")))
                self._rails[g.action] = g
            except (KeyError, TypeError, ValueError):
                continue

    def _save(self, *, strict: bool = False, before_write=None) -> None:
        if self.path is None:
            return
        try:
            atomic_write_text(
                Path(self.path),
                json.dumps(
                    [g.to_dict() for g in self._rails.values()], sort_keys=True,
                ),
                **({"effect_guard": before_write} if before_write is not None else {}),
            )
        except Exception:  # pragma: no cover -- persistence is best-effort
            if strict:
                raise
            log.debug("guardrail registry save failed", exc_info=True)


_shared: dict = {}
_shared_lock = threading.Lock()


def shared() -> GuardrailRegistry:
    from .file_lock import ensure_private_directory
    from .paths import data_dir

    path = data_dir("guardrails.json")
    with _shared_lock:
        reg = _shared.get(path)
        if reg is None:
            # The default data root is Lightwork-owned.  Explicit registry
            # paths retain their caller-managed parent ACL.
            ensure_private_directory(path.parent)
            reg = GuardrailRegistry(path=path)
            _shared[path] = reg
        return reg


def reset_shared() -> None:
    with _shared_lock:
        _shared.clear()


def refresh_shared() -> None:
    """Refresh the active tenant's existing objects after native restoration."""
    from .paths import data_dir

    with _shared_lock:
        reg = _shared.get(data_dir("guardrails.json"))
        if reg is not None:
            with reg._lock:
                reg._refresh()


__all__ = ["Guardrail", "mine", "GuardrailRegistry", "shared", "reset_shared"]
