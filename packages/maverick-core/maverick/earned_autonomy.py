"""Record and reconcile action-level outcome evidence.

Action-wide predictions do not identify an authorized recipient, destination,
or exact operation. Graduation is advisory and never grants standing consent.
Shadow executions continue to require the supplied human approval callback.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .config import env_flag

log = logging.getLogger(__name__)

_GENESIS = "0" * 64
_MAX_ROWS = 100_000
_MAX_TEXT = 300

#: Card sources whose ``reversible`` flag was *demonstrated* rather than
#: asserted. Only the shadow-mode path qualifies today: it reads the flag off a
#: preview the connector adapter actually produced. ``"rehearsal"`` takes the
#: caller's word for it and ``"declared"`` is the dataclass default, so neither
#: is evidence. Add a source here only when the adapter behind it round-trips
#: the write -- this set is what separates a proven undo from a claimed one.
EARNED_REVERSIBILITY_SOURCES = frozenset({"simulate"})


def enabled() -> bool:
    """Whether earned autonomy records evidence / decides. OFF by default."""
    _v = env_flag("MAVERICK_EARNED_AUTONOMY")
    if _v is not None:
        return _v
    try:
        from .config import get_earned_autonomy

        return bool(get_earned_autonomy().get("enable", False))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def _clamp01(value: float) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(v):
        return 0.0
    return max(0.0, min(1.0, v))


def _safe_text(value: object, *, max_len: int = _MAX_TEXT) -> str:
    """Bound + secret-redact free text before it reaches a durable card."""
    text = str(value or "")
    try:
        from .safety.secret_detector import redact

        text, _matches = redact(text)
    except Exception:  # pragma: no cover -- redactor optional; keep it bounded
        pass
    return str(text)[:max_len]


# ---------------------------------------------------------------------------
# hash-chained append-only NDJSON log (the shared shape of both stores)
# ---------------------------------------------------------------------------


class _ChainedLog:
    """Append-only NDJSON rows, each carrying ``prev``/``hash`` sha256 links.

    The tamper-evident spine both the card store and the trust ledger sit on:
    genesis is 64 zeros, each row's hash covers all its fields plus the
    previous hash (the :mod:`maverick.governed_actions` lineage recipe).
    Multi-writer safe: every persisted append happens under the file's
    :func:`maverick.file_lock.cross_process_lock` and re-reads any rows other
    writers appended first, so the on-disk chain never forks. ``path=None``
    keeps the chain in memory (tests / ephemeral runs). Appends never raise;
    they return False on any persistence/lock failure. ``force=True`` lets a
    safety-critical row (a demotion/revocation) through even at capacity --
    the bound is a growth guard, never a reason to keep stale authority.
    """

    def __init__(self, path: Path | None = None, *, max_rows: int = _MAX_ROWS) -> None:
        self.path = Path(path) if path is not None else None
        self.max_rows = max_rows
        self._rows: list[dict] = []
        self._size = -1
        self._lock = threading.RLock()
        if self.path is not None:
            with self._lock:
                self._refresh_unlocked()

    @staticmethod
    def _row_hash(fields: dict, prev: str) -> str:
        material = json.dumps({**fields, "prev": prev}, sort_keys=True, default=str)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _refresh_unlocked(self) -> None:
        """Re-read the file when another writer grew it (fork-free chaining)."""
        if self.path is None:
            return
        try:
            size = self.path.stat().st_size
        except OSError:
            return
        if size == self._size:
            return
        try:
            with open(self.path, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError:
            return
        rows: list[dict] = []
        for raw in lines:
            try:
                row = json.loads(raw)
            except ValueError:
                continue
            if isinstance(row, dict) and "hash" in row:
                rows.append(row)
        self._rows = rows
        self._size = size

    def _append_unlocked(self, fields: dict, *, force: bool) -> bool:
        if len(self._rows) >= self.max_rows and not force:
            log.warning("earned-autonomy log at capacity; row dropped")
            return False
        prev = self._rows[-1]["hash"] if self._rows else _GENESIS
        row = dict(fields)
        row["prev"] = prev
        row["hash"] = self._row_hash(fields, prev)
        if self.path is not None:
            line = json.dumps(row, sort_keys=True) + "\n"
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(
                    os.open(self.path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600),
                    "a", encoding="utf-8",
                ) as fh:
                    fh.write(line)
            except Exception:  # pragma: no cover -- best-effort persistence
                log.debug("earned-autonomy append failed", exc_info=True)
                return False
            self._size += len(line.encode("utf-8"))
        self._rows.append(row)
        return True

    def append(self, fields: dict, *, force: bool = False) -> bool:
        with self._lock:
            if self.path is None:
                return self._append_unlocked(fields, force=force)
            try:
                from .file_lock import cross_process_lock

                with cross_process_lock(self.path):
                    self._refresh_unlocked()
                    return self._append_unlocked(fields, force=force)
            except Exception:
                # No lock -> no unserialized write: a refused append is safe,
                # a forked chain is not.
                log.warning("earned-autonomy append refused (no lock)", exc_info=True)
                return False

    def rows(self) -> list[dict]:
        with self._lock:
            self._refresh_unlocked()
            return list(self._rows)

    def verify(self) -> str:
        """Recompute the chain: ``VALID: ...`` or ``BROKEN: link i ...``."""
        with self._lock:
            self._refresh_unlocked()
            prev = _GENESIS
            for i, row in enumerate(self._rows):
                fields = {k: v for k, v in row.items() if k not in ("prev", "hash")}
                if row.get("prev") != prev:
                    return f"BROKEN: link {i} prev_hash mismatch"
                if row.get("hash") != self._row_hash(fields, prev):
                    return f"BROKEN: link {i} content hash mismatch"
                prev = row["hash"]
            head = prev[:12] if self._rows else _GENESIS[:12]
            return f"VALID: {len(self._rows)} link(s), head {head}"


# ---------------------------------------------------------------------------
# consequence cards: the persisted prediction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConsequenceCard:
    """One pinned prediction for a high-stakes action, made BEFORE it ran.

    ``predicted_outcome`` is the [0, 1] result the system committed to (from
    the rehearsal twin or a simulation); ``reversible`` declares whether the
    action ships an inverse (a saga/compensation path). ``params_sha256``
    pins *what* was predicted without persisting raw arguments. The
    ``(goal_id, episode_id)`` key is the join back to reality via
    :func:`maverick.consequence.resolve`. ``principal`` records who acted
    (provenance); trust itself accrues to the action type. ``risk`` is the
    recorder's label, kept for the audit trail -- graduation recomputes the
    action's live risk and never trusts this field.
    """

    principal: str
    action: str
    risk: str
    predicted_outcome: float
    goal_id: int
    episode_id: int
    effect: str = ""
    exposure_dollars: float | None = None
    reversible: bool = False
    source: str = "declared"
    params_sha256: str = ""
    ts: float = 0.0
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_row(self) -> dict:
        return {
            "id": self.id, "ts": self.ts, "principal": self.principal,
            "action": self.action, "risk": self.risk,
            "predicted_outcome": self.predicted_outcome,
            "goal_id": self.goal_id, "episode_id": self.episode_id,
            "effect": self.effect, "exposure_dollars": self.exposure_dollars,
            "reversible": self.reversible, "source": self.source,
            "params_sha256": self.params_sha256,
        }


@dataclass
class CardStore:
    """Hash-chained store of consequence cards. ``path=None`` = in-memory."""

    path: Path | None = None
    max_rows: int = _MAX_ROWS
    _log: _ChainedLog = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._log is None:
            self._log = _ChainedLog(self.path, max_rows=self.max_rows)

    def append(self, card: ConsequenceCard) -> bool:
        return self._log.append(card.to_row())

    def cards(self) -> list[dict]:
        """All recorded cards, oldest first."""
        return self._log.rows()

    def verify(self) -> str:
        return self._log.verify()


# ---------------------------------------------------------------------------
# trust ledger: hit/miss evidence and graduation state per action type
# ---------------------------------------------------------------------------

_SCORING_KINDS = ("hit", "miss", "superseded")
_EVENT_KINDS = _SCORING_KINDS + ("graduate", "demote", "revoke")
# Losing authority must never be blocked by a full ledger.
_FORCED_KINDS = frozenset({"demote", "revoke"})


@dataclass(frozen=True)
class TrustState:
    """Reduced evidence for one action type (deployment-wide)."""

    action: str
    hits: int = 0
    misses: int = 0
    streak: int = 0
    graduated: bool = False
    ever_graduated: bool = False
    last_event_ts: float = 0.0

    @property
    def samples(self) -> int:
        return self.hits + self.misses

    @property
    def accuracy(self) -> float:
        return self.hits / self.samples if self.samples else 0.0


@dataclass
class TrustLedger:
    """Event-sourced, hash-chained record of scoring and graduation events.

    Events: ``hit`` / ``miss`` (a card scored against reality),
    ``superseded`` (a same-episode duplicate collapsed into the scored card
    -- enters the idempotency set, never the counts), ``graduate``
    (evidence qualified), ``demote`` (a miss removed qualification), and
    ``revoke`` (an operator cleared it). Trust state is a pure reduction over
    the chain keyed by ACTION TYPE, with each
    event keeping the acting agent for provenance. Demote/revoke rows append
    even at capacity (``force``): shedding authority is never rate-limited.
    """

    path: Path | None = None
    max_rows: int = _MAX_ROWS
    _log: _ChainedLog = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._log is None:
            self._log = _ChainedLog(self.path, max_rows=self.max_rows)

    def record_event(self, kind: str, action: str, *, principal: str = "",
                     card_id: str = "", predicted: float | None = None,
                     actual: float | None = None, reason: str = "",
                     ts: float | None = None) -> bool:
        if kind not in _EVENT_KINDS:
            return False
        row = {
            "kind": kind, "action": str(action)[:120],
            "principal": str(principal)[:120], "card_id": str(card_id)[:32],
            "ts": ts if ts is not None else time.time(),
            "reason": _safe_text(reason, max_len=200),
        }
        if predicted is not None:
            row["predicted"] = _clamp01(predicted)
        if actual is not None:
            row["actual"] = _clamp01(actual)
        return self._log.append(row, force=kind in _FORCED_KINDS)

    def scored_ids(self) -> frozenset[str]:
        """Card ids already consumed -- the reconcile idempotency set."""
        return frozenset(
            r["card_id"] for r in self._log.rows()
            if r.get("kind") in _SCORING_KINDS and r.get("card_id"))

    def state(self, action: str) -> TrustState:
        return self.states().get(str(action), TrustState(action=str(action)))

    def states(self) -> dict[str, TrustState]:
        """Reduce the event chain to per-action trust state. Never raises on
        type-corrupt rows -- a bad row is skipped, not a crash."""
        out: dict[str, TrustState] = {}
        for r in self._log.rows():
            try:
                action = str(r.get("action", ""))
                kind = r.get("kind")
                ts = float(r.get("ts", 0.0) or 0.0)
            except (TypeError, ValueError):
                continue
            if not action or kind not in _EVENT_KINDS:
                continue
            s = out.get(action) or TrustState(action=action)
            if kind == "hit":
                s = TrustState(action, s.hits + 1, s.misses, s.streak + 1,
                               s.graduated, s.ever_graduated, ts)
            elif kind == "miss":
                s = TrustState(action, s.hits, s.misses + 1, 0,
                               s.graduated, s.ever_graduated, ts)
            elif kind == "graduate":
                s = TrustState(action, s.hits, s.misses, s.streak,
                               True, True, ts)
            elif kind == "demote":
                s = TrustState(action, s.hits, s.misses, s.streak,
                               False, s.ever_graduated, ts)
            elif kind == "revoke":
                # An operator revoke restarts the streak, so the next accurate
                # prediction cannot re-graduate the action straight away.
                s = TrustState(action, s.hits, s.misses, 0,
                               False, s.ever_graduated, ts)
            else:  # superseded: idempotency only, no evidence weight
                s = TrustState(action, s.hits, s.misses, s.streak,
                               s.graduated, s.ever_graduated, ts)
            out[action] = s
        return out

    def verify(self) -> str:
        return self._log.verify()


# ---------------------------------------------------------------------------
# graduation policy + gates (pure, controller-style: every gate fails closed)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GraduationPolicy:
    """The evidence bar an action type must clear to qualify.

    Deliberately stricter than :mod:`maverick.predictive_approvals` (which
    only ever *suggests*, and never for high risk): this policy *decides*, so
    it demands a consecutive-hit streak against ground truth, not just a
    lopsided approval history. ``armed`` is the operator's authority-widening
    evidence qualification switch (``[earned_autonomy] auto_graduate``).
    """

    min_streak: int = 10
    min_samples: int = 10
    min_accuracy: float = 0.9
    tolerance: float = 0.25
    max_auto_risk: str = "medium"
    require_reversible: bool = True
    armed: bool = False


def policy_from_config() -> GraduationPolicy:
    """The configured policy; malformed config degrades to the strict default."""
    try:
        from .config import get_earned_autonomy

        cfg = get_earned_autonomy()
        return GraduationPolicy(
            min_streak=int(cfg["min_streak"]), min_samples=int(cfg["min_samples"]),
            min_accuracy=float(cfg["min_accuracy"]), tolerance=float(cfg["tolerance"]),
            max_auto_risk=str(cfg["max_auto_risk"]),
            require_reversible=bool(cfg["require_reversible"]),
            armed=bool(cfg["auto_graduate"]),
        )
    except Exception:  # pragma: no cover -- policy loss must not widen authority
        return GraduationPolicy()


@dataclass(frozen=True)
class GateResult:
    gate: str
    ok: bool
    reason: str = ""


@dataclass(frozen=True)
class EarnedVerdict:
    """Whether one action type may graduate. AND of all gates."""

    action: str
    graduate: bool
    gates: tuple[GateResult, ...]
    blocking_reason: str = ""


def _ceiling_rank(level: str) -> int:
    """Rank of the ``max_auto_risk`` ceiling; unknown = below every level.

    Mirrors ``self_improvement._ceiling_rank``: a typo ceiling must be the
    MOST restrictive (nothing graduates), never silently permissive.
    """
    try:
        from .safety.tool_risk import RISK_LEVELS

        return RISK_LEVELS.index(str(level))
    except ValueError:
        return -1


def _action_risk_rank(risk: str) -> int:
    """Rank of an action's risk; unknown = ABOVE every ceiling (fail closed).

    Deliberately not ``tool_risk.risk_rank`` -- that helper maps an unknown
    level to ``medium``, which would let a mislabeled or novel level (e.g.
    ``critical``) slip under a ``medium`` ceiling.
    """
    try:
        from .safety.tool_risk import RISK_LEVELS
    except Exception:  # pragma: no cover -- taxonomy gone: fail closed (high)
        return 99
    try:
        return RISK_LEVELS.index(str(risk))
    except ValueError:
        return len(RISK_LEVELS)


def evaluate_graduation(state: TrustState, *, risk: str, reversible_share: float,
                        policy: GraduationPolicy, frozen: bool) -> EarnedVerdict:
    """Run every graduation gate; all must pass, each fails closed."""
    gates: list[GateResult] = []

    gates.append(GateResult(
        "armed", policy.armed,
        "" if policy.armed else "auto_graduate is not armed by the operator"))

    valid = (
        isinstance(policy.min_streak, int) and policy.min_streak >= 1
        and isinstance(policy.min_samples, int) and policy.min_samples >= 1
        and math.isfinite(float(policy.min_accuracy))
        and 0.0 <= float(policy.min_accuracy) <= 1.0
    )
    if not valid:
        gates.append(GateResult("evidence", False, "invalid graduation policy"))
    else:
        ok = (state.samples >= policy.min_samples
              and state.streak >= policy.min_streak
              and state.accuracy >= policy.min_accuracy)
        reason = ""
        if state.samples < policy.min_samples:
            reason = f"insufficient evidence: {state.samples} < {policy.min_samples} outcomes"
        elif state.streak < policy.min_streak:
            reason = f"streak {state.streak} < {policy.min_streak} consecutive accurate predictions"
        elif state.accuracy < policy.min_accuracy:
            reason = f"accuracy {state.accuracy:.2f} < {policy.min_accuracy:.2f}"
        gates.append(GateResult("evidence", ok, reason))

    risk_ok = _action_risk_rank(risk) <= _ceiling_rank(policy.max_auto_risk)
    gates.append(GateResult(
        "risk_ceiling", risk_ok,
        "" if risk_ok else
        f"{risk!r}-risk action type is above the max_auto_risk "
        f"ceiling ({policy.max_auto_risk!r})"))

    if policy.require_reversible:
        rev_ok = reversible_share >= 1.0
        gates.append(GateResult(
            "reversibility", rev_ok,
            "" if rev_ok else
            "action type has cards whose undo was never demonstrated by a "
            "preview adapter; a guaranteed undo -- not an asserted one -- is "
            "required until autonomy is earned"))
    else:
        gates.append(GateResult("reversibility", True, ""))

    gates.append(GateResult(
        "calibration", not frozen,
        "" if not frozen else "learning frozen: a drifting verifier cannot mint autonomy"))

    failing = [g for g in gates if not g.ok]
    return EarnedVerdict(
        state.action, not failing, tuple(gates),
        failing[0].reason if failing else "")


# ---------------------------------------------------------------------------
# the engine: record -> reconcile -> graduate/demote -> decide
# ---------------------------------------------------------------------------


def _default_frozen_fn() -> bool:
    from .calibration import learning_frozen

    return bool(learning_frozen())


def _default_audit_fn(kind: str, **payload) -> None:
    try:
        from .audit import record

        goal_id = payload.pop("goal_id", None)
        record(kind, agent="earned_autonomy", goal_id=goal_id, **payload)
    except Exception:  # pragma: no cover -- audit is best-effort, never blocks
        log.debug("earned-autonomy audit skipped", exc_info=True)


def _default_grant_fn(action: str) -> None:
    # Evidence is aggregated by action type and does not identify an approved
    # target or operation. Graduation is advisory until evidence is scoped.
    del action


def _default_revoke_fn(action: str) -> None:
    # Earned autonomy no longer owns standing grants. Do not revoke a manual
    # operator grant that happens to share the same action and empty scope.
    del action


def _live_risk(action: str) -> str | None:
    """The action's CURRENT risk class, or None when it can't be resolved.

    Graduation and decisions consult the live classification -- never a
    card-declared label -- so a mislabeled recorder can't sneak an action
    under the ceiling. Unresolvable risk keeps the human.
    """
    try:
        from .safety.tool_risk import tool_risk

        return tool_risk(action)
    except Exception:
        return None


@dataclass(frozen=True)
class EarnedDecision:
    """The dial's answer for one action right now."""

    auto: bool
    reason: str = ""


@dataclass(frozen=True)
class ReconcileReport:
    scored: int = 0
    hits: int = 0
    misses: int = 0
    superseded: int = 0
    graduated: tuple[str, ...] = ()
    demoted: tuple[str, ...] = ()


@dataclass
class EarnedAutonomyEngine:
    """Record and evaluate prediction evidence without granting authority.

    Legacy callback fields remain for construction compatibility but are not
    invoked: action-wide evidence cannot authorize or revoke consent grants.
    """

    cards: CardStore = field(default_factory=CardStore)
    ledger: TrustLedger = field(default_factory=TrustLedger)
    policy: GraduationPolicy | None = None
    frozen_fn: Callable[[], bool] = _default_frozen_fn
    audit_fn: Callable[..., None] = _default_audit_fn
    grant_fn: Callable[[str], None] = _default_grant_fn
    revoke_fn: Callable[[str], None] = _default_revoke_fn
    now: Callable[[], float] = time.time
    _reconcile_lock: threading.Lock = field(default_factory=threading.Lock)

    def _policy(self) -> GraduationPolicy:
        return self.policy if self.policy is not None else policy_from_config()

    def _frozen(self) -> bool:
        try:
            return bool(self.frozen_fn())
        except Exception:
            return True  # can't confirm the judge is honest -> fail closed

    def _audit(self, kind: str, **payload) -> None:
        try:
            self.audit_fn(kind, **payload)
        except Exception:  # pragma: no cover -- audit sink must never block
            log.debug("earned-autonomy audit sink failed", exc_info=True)

    def _revoke_grant(self, action: str) -> bool:
        """There is no earned consent authority to withdraw."""
        del action
        return True

    # -- recording ---------------------------------------------------------

    def record_card(self, *, principal: str, action: str, risk: str,
                    predicted_outcome: float, goal_id: int, episode_id: int,
                    effect: str = "", exposure_dollars: float | None = None,
                    reversible: bool = False, source: str = "declared",
                    params_sha256: str = "", ts: float | None = None) -> str | None:
        """Pin one prediction. Returns the card id, or None when not recorded."""
        if not enabled():
            return None
        from .learning_guard import learning_write_allowed

        if not learning_write_allowed("earned_autonomy", "record_card"):
            return None
        card = ConsequenceCard(
            principal=str(principal)[:120], action=str(action)[:120],
            risk=str(risk), predicted_outcome=_clamp01(predicted_outcome),
            goal_id=int(goal_id), episode_id=int(episode_id),
            effect=_safe_text(effect), exposure_dollars=exposure_dollars,
            reversible=bool(reversible), source=str(source)[:32],
            params_sha256=str(params_sha256)[:64],
            ts=ts if ts is not None else self.now(),
        )
        if not self.cards.append(card):
            return None
        from .audit import EventKind

        self._audit(EventKind.CONSEQUENCE_CARD, goal_id=card.goal_id,
                    card=card.id, principal=card.principal, action=card.action,
                    risk=card.risk, predicted=card.predicted_outcome,
                    episode_id=card.episode_id, reversible=card.reversible,
                    source=card.source)
        return card.id

    # -- the join ----------------------------------------------------------

    @staticmethod
    def _card_key(row: dict) -> tuple[int, int, str] | None:
        """The (goal, episode, action) join group, or None when unjoinable."""
        try:
            goal_id = int(row.get("goal_id", 0) or 0)
            episode_id = int(row.get("episode_id", 0) or 0)
        except (TypeError, ValueError):
            return None
        action = str(row.get("action", ""))
        if episode_id <= 0 or not action:
            return None
        return (goal_id, episode_id, action)

    def _unscored_groups(self, scored_ids: frozenset[str]) -> dict:
        """Unscored cards grouped by join key; each group sorted oldest-first."""
        groups: dict[tuple[int, int, str], list[dict]] = {}
        for row in self.cards.cards():
            if not row.get("id") or row.get("id") in scored_ids:
                continue
            key = self._card_key(row)
            if key is None:
                continue
            groups.setdefault(key, []).append(row)
        for rows in groups.values():
            rows.sort(key=lambda r: float(r.get("ts", 0.0) or 0.0)
                      if isinstance(r.get("ts", 0.0), (int, float)) else 0.0)
        return groups

    def reconcile(self, *, resolve: Callable[[int, int], float | None] | None = None,
                  ) -> ReconcileReport:
        """Score unscored cards against reality; graduate/demote on the result.

        ``resolve(goal_id, episode_id) -> actual | None`` defaults to the
        Consequence Engine's grounded-outcome join. One episode outcome grades
        ONE prediction per action type: the latest card of a same-episode
        group is scored, earlier duplicates are recorded ``superseded`` (they
        enter the idempotency set with no evidence weight). Idempotent, and
        serialized against concurrent reconciles (in-process lock plus the
        ledger file's cross-process lock) so evidence is never double-counted.
        """
        if not enabled():
            return ReconcileReport()
        from .learning_guard import learning_write_allowed

        if not learning_write_allowed("earned_autonomy", "reconcile"):
            return ReconcileReport()
        with self._reconcile_lock:
            if self.ledger.path is not None:
                try:
                    from .file_lock import cross_process_lock

                    with cross_process_lock(self.ledger.path):
                        return self._reconcile_locked(resolve)
                except Exception:
                    log.warning("earned-autonomy reconcile refused (no lock)",
                                exc_info=True)
                    return ReconcileReport()
            return self._reconcile_locked(resolve)

    def _reconcile_locked(self, resolve) -> ReconcileReport:
        if resolve is None:
            from .consequence import resolve as _resolve

            resolve = _resolve
        policy = self._policy()
        touched: set[str] = set()
        scored = hits = misses = superseded = 0
        demoted: list[str] = []
        groups = self._unscored_groups(self.ledger.scored_ids())
        for (goal_id, episode_id, action), rows in groups.items():
            try:
                actual = resolve(goal_id, episode_id)
            except Exception:  # pragma: no cover -- a broken join scores nothing
                continue
            if actual is None:
                continue
            row = rows[-1]  # the latest prediction is the one reality grades
            principal = str(row.get("principal", ""))
            hit = abs(_clamp01(row.get("predicted_outcome", 0.0)) - _clamp01(actual)
                      ) <= policy.tolerance
            if not self.ledger.record_event(
                    "hit" if hit else "miss", action, principal=principal,
                    card_id=str(row.get("id", "")),
                    predicted=row.get("predicted_outcome"), actual=actual,
                    ts=self.now()):
                # Evidence that can't be persisted is not evidence; the card
                # stays unscored and is retried next pass. A miss still sheds
                # authority NOW -- the demote row is forced, so it lands even
                # when the ledger is at capacity and the miss row was dropped.
                if not hit:
                    self._demote(action, principal=principal,
                                 card_id=str(row.get("id", "")), demoted=demoted)
                continue
            for extra in rows[:-1]:
                if self.ledger.record_event(
                        "superseded", action, principal=str(extra.get("principal", "")),
                        card_id=str(extra.get("id", "")),
                        reason="same-episode duplicate; one outcome grades one prediction",
                        ts=self.now()):
                    superseded += 1
            scored += 1
            hits += int(hit)
            misses += int(not hit)
            touched.add(action)
            if not hit:
                self._demote(action, principal=principal,
                             card_id=str(row.get("id", "")), demoted=demoted)
        graduated = self._graduate_touched(touched, policy)
        self._sweep_stale_grants()
        return ReconcileReport(scored=scored, hits=hits, misses=misses,
                               superseded=superseded, graduated=tuple(graduated),
                               demoted=tuple(demoted))

    def _demote(self, action: str, *, principal: str, card_id: str,
                demoted: list[str]) -> None:
        """One missed prediction clears the action type's qualification.

        The revoke is attempted on EVERY miss (not only while the ledger says
        graduated) so a previously failed withdrawal is retried, and it runs
        before the demote event -- authority sheds first, evidence follows.
        """
        self._revoke_grant(action)
        if not self.ledger.state(action).graduated:
            return
        if not self.ledger.record_event(
                "demote", action, principal=principal, card_id=card_id,
                reason="prediction missed reality; trust is withdrawn on one miss",
                ts=self.now()):
            log.warning("earned-autonomy demote event not persisted for %s", action)
        demoted.append(action)
        from .audit import EventKind

        self._audit(EventKind.AUTONOMY_GRADUATION, decision="demote",
                    principal=principal, action=action, card=card_id)

    def _graduate_touched(self, touched: set[str],
                          policy: GraduationPolicy) -> list[str]:
        """Evaluate each touched action; record qualifying evidence only."""
        graduated: list[str] = []
        frozen = self._frozen()
        for action in sorted(touched):
            state = self.ledger.state(action)
            if state.graduated:
                continue
            risk = _live_risk(action)
            if risk is None:
                continue  # can't classify -> keep the human
            verdict = evaluate_graduation(
                state, risk=risk,
                reversible_share=self._reversible_share(action),
                policy=policy, frozen=frozen)
            if not verdict.graduate:
                continue
            if not self.ledger.record_event(
                    "graduate", action,
                    reason=f"{state.streak} consecutive accurate predictions "
                           f"({state.hits}/{state.samples} overall)",
                    ts=self.now()):
                continue
            graduated.append(action)
            from .audit import EventKind

            self._audit(EventKind.AUTONOMY_GRADUATION, decision="graduate",
                        action=action, streak=state.streak,
                        hits=state.hits, misses=state.misses)
        return graduated

    def _sweep_stale_grants(self) -> None:
        """Compatibility hook; earned evidence no longer owns consent grants."""

    def _reversible_share(self, action: str) -> float:
        """Share of cards whose undo was *demonstrated*, not merely asserted.

        The reversibility gate exists to require a guaranteed undo before an
        action type earns autonomy. Only a preview adapter that actually round-
        tripped the write can establish that; ``source="rehearsal"`` carries a
        flag the caller passed in, and ``"declared"`` -- the dataclass default,
        so also what any direct ``record_card`` gets -- is a bare assertion.

        Counting those toward the share let a self-declaration satisfy a gate
        whose own failure text promises "a guaranteed undo", and the resulting
        number would have been shown to an auditor as evidence. Unearned cards
        stay in the denominator rather than being filtered out, so they push the
        share below 1.0 and hold the human in place: an action type we cannot
        prove is reversible must not graduate on the strength of being *said* to
        be reversible.
        """
        rows = [r for r in self.cards.cards() if r.get("action") == action]
        if not rows:
            return 0.0
        earned = sum(
            1 for r in rows
            if r.get("reversible") is True
            and str(r.get("source") or "") in EARNED_REVERSIBILITY_SOURCES)
        return earned / len(rows)

    # -- deciding ----------------------------------------------------------

    def decide(self, action: str, *, risk: str | None = None) -> EarnedDecision:
        """May ``action`` auto-run right now?

        Read-only; every uncertainty resolves to "keep the human". The live
        evidence is advisory and never creates a consent-ledger grant. When
        ``risk`` is omitted the action's live classification is used; an
        unresolvable or unknown risk level keeps the human.
        """
        if not enabled():
            return EarnedDecision(False, "earned autonomy disabled")
        policy = self._policy()
        if not policy.armed:
            return EarnedDecision(False, "auto_graduate is not armed")
        try:
            from . import killswitch

            if killswitch.is_active():
                return EarnedDecision(False, "operational halt active")
        except Exception:
            return EarnedDecision(False, "halt state unavailable")
        if self._frozen():
            return EarnedDecision(False, "learning frozen: autonomy suspended")
        if risk is None:
            risk = _live_risk(action)
            if risk is None:
                return EarnedDecision(False, "action risk unavailable")
        if _action_risk_rank(risk) > _ceiling_rank(policy.max_auto_risk):
            return EarnedDecision(
                False, f"{risk!r} risk is above the max_auto_risk ceiling")
        state = self.ledger.state(action)
        if not state.graduated:
            return EarnedDecision(
                False, f"not graduated: streak {state.streak}, "
                       f"{state.hits}/{state.samples} accurate")
        return EarnedDecision(
            False, "action-level evidence is advisory; a human decision is required")

    def revoke(self, action: str, *, reason: str = "operator revoke",
               principal: str = "operator") -> bool:
        """Demote action evidence without revoking manual consent grants.

        Works even while evidence collection is disabled. The audit records
        whether the local revocation was recorded.
        """
        revoked = self._revoke_grant(action)
        ok = self.ledger.record_event("revoke", action, principal=principal,
                                      reason=reason, ts=self.now())
        from .audit import EventKind

        self._audit(EventKind.AUTONOMY_GRADUATION, decision="revoke",
                    principal=principal, action=action, reason=_safe_text(reason),
                    withdrawal_confirmed=False, local_revocation_recorded=ok,
                    authority_scope="advisory_evidence_only")
        return revoked and ok

    def status(self) -> list[TrustState]:
        """Every action type's trust state, most-proven first."""
        return sorted(self.ledger.states().values(),
                      key=lambda s: (-int(s.graduated), -s.streak, -s.hits))


# ---------------------------------------------------------------------------
# compensating-action saga: every action ships its inverse
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SagaStep:
    """One consequential step and the inverse that undoes it."""

    name: str
    do: Callable[[], str]
    undo: Callable[[], str] | None = None


@dataclass(frozen=True)
class StepResult:
    step: str
    phase: str  # "do" | "undo"
    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class SagaResult:
    """``committed`` iff every step succeeded; else the prefix was rolled back."""

    committed: bool
    results: tuple[StepResult, ...] = ()
    compensated: tuple[StepResult, ...] = ()
    reason: str = ""


def _run_step(fn: Callable[[], str], name: str, phase: str) -> StepResult:
    try:
        return StepResult(name, phase, True, _safe_text(fn()))
    except Exception as exc:
        return StepResult(name, phase, False,
                          _safe_text(f"{type(exc).__name__}: {exc}"))


def run_saga(steps: list[SagaStep] | tuple[SagaStep, ...], *,
             allow_irreversible: bool = False) -> SagaResult:
    """Execute steps in order; roll the completed prefix back on any failure.

    Fail-closed BEFORE any effect: unless ``allow_irreversible`` is set, every
    step must declare an inverse -- an action without an undo never starts.
    Compensation runs the completed steps' inverses in reverse order; a failed
    inverse is recorded (never silently swallowed) and the remaining inverses
    still run. The result is the caller's receipt: ``committed`` means all
    effects stand, otherwise none should (any failed compensation is listed).
    """
    steps = tuple(steps)
    if not allow_irreversible:
        missing = [s.name for s in steps if s.undo is None]
        if missing:
            return SagaResult(
                False, reason=(
                    "refused before any effect: step(s) without an inverse: "
                    + ", ".join(missing)))
    done: list[tuple[SagaStep, StepResult]] = []
    for step in steps:
        result = _run_step(step.do, step.name, "do")
        done.append((step, result))
        if not result.ok:
            compensated = tuple(
                _run_step(s.undo, s.name, "undo")
                for s, _r in reversed(done[:-1])
                if s.undo is not None
            )
            return SagaResult(
                False, results=tuple(r for _, r in done), compensated=compensated,
                reason=f"step {step.name!r} failed; rolled back {len(compensated)} step(s)")
    return SagaResult(True, results=tuple(r for _, r in done))


# ---------------------------------------------------------------------------
# Shadow Mode: preview the irreversible action, gate on the simulated outcome,
# execute inside the compensating saga, sign the sim -> approve -> execute chain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConsequencePreview:
    """A dry-run's forecast of one high-stakes action, made BEFORE it runs.

    Built from a governed connector's ``preview_write`` (the existing
    no-side-effect seam, :mod:`maverick.governed_connectors`) or a simulator.
    ``effect`` is the human-readable forecast ("would wire $240k to ACME"),
    ``exposure_dollars`` the magnitude at stake, ``entities`` the records it
    would touch ("close these 3 tickets"), and ``predicted_outcome`` the [0, 1]
    confidence the action ends well -- the exact number reality later grades.
    ``reversible`` declares whether the action ships an inverse.
    """

    action: str
    predicted_outcome: float
    effect: str = ""
    exposure_dollars: float | None = None
    entities: tuple[str, ...] = ()
    reversible: bool = False
    params_sha256: str = ""
    risk: str = ""

    def card_view(self) -> dict:
        """The bounded, side-effect-free summary a human/policy approves."""
        return {
            "action": _safe_text(self.action, max_len=120),
            "risk": _safe_text(self.risk, max_len=32),
            "effect": _safe_text(self.effect),
            "exposure_dollars": self.exposure_dollars,
            "entities": [_safe_text(e, max_len=120) for e in self.entities[:32]],
            "reversible": self.reversible,
            "predicted_outcome": _clamp01(self.predicted_outcome),
        }


@dataclass(frozen=True)
class ShadowResult:
    """The receipt of one shadow-mode preview -> gate -> execute cycle."""

    action: str
    approved: bool
    auto_approved: bool
    executed: bool
    committed: bool
    reason: str = ""
    card_id: str | None = None
    saga: SagaResult | None = None


def _safe_approve(approve: Callable[[dict], bool], card_view: dict) -> bool:
    """Resolve the human/policy approval gate. Any error is a denial."""
    try:
        return bool(approve(card_view))
    except Exception:
        log.warning("shadow-mode approval callback failed; treating as denied",
                    exc_info=True)
        return False


def _shadow_kind() -> str:
    try:
        from .audit import EventKind

        return EventKind.SHADOW_EXECUTION
    except Exception:  # pragma: no cover -- audit is best-effort
        return "shadow_execution"


def shadow_execute(preview: ConsequencePreview,
                   steps: list[SagaStep] | tuple[SagaStep, ...], *,
                   principal: str, goal_id: int, episode_id: int,
                   approve: Callable[[dict], bool],
                   allow_irreversible: bool = False,
                   engine: EarnedAutonomyEngine | None = None) -> ShadowResult:
    """Preview an irreversible action, gate it, then execute under the saga.

    The centerpiece of earned autonomy, composed from the pieces the engine already owns:

    1. **Gate.** ``approve(card_view)`` must return truthy for this operation.
       Action-level evidence does not authorize a particular target or effect.
       Any approval error is a denial (fail-closed).
    2. **Guaranteed undo.** Execution runs through :func:`run_saga`, which
       refuses before any effect unless every step declares an inverse (pass
       ``allow_irreversible=True`` only when the caller accepts no rollback),
       and rolls the completed prefix back on any failure.
    3. **Evidence, only when the effect stands.** A consequence card (source
       ``simulate``) is pinned ONLY when the saga commits -- a denied, refused,
       or rolled-back action never becomes a prediction reality would mis-grade
       against the episode's outcome (the same rule as a held rehearsal
       verdict).
    4. **Provenance.** The gate decision and the execution outcome are signed
       into the audit chain (``shadow_execution``).

    Every action routes through ``approve``. The
    preview/gate/execute/sign flow itself is valuable standalone and is NOT
    gated by ``[earned_autonomy] enable`` -- only the card evidence is (a
    disabled engine simply records no card).
    """
    engine = engine or shared()
    action = str(getattr(preview, "action", ""))
    risk = str(getattr(preview, "risk", "") or "")
    view = preview.card_view()
    kind = _shadow_kind()

    # Evidence is action-wide, so it cannot authorize this exact effect.
    # Keep the human decision even for legacy graduated states or a custom
    # engine implementation.
    decision = engine.decide(action)
    auto = False
    approved = _safe_approve(approve, view)
    if not approved:
        engine._audit(kind, decision="denied", action=action, goal_id=goal_id,
                      exposure=view.get("exposure_dollars"), auto=auto)
        return ShadowResult(
            action, approved=False, auto_approved=auto, executed=False,
            committed=False,
            reason=("approval withheld" if not auto else decision.reason))

    steps = tuple(steps)
    if not steps:
        engine._audit(kind, decision="auto" if auto else "approved",
                      action=action, goal_id=goal_id, card=None,
                      exposure=view.get("exposure_dollars"),
                      committed=False, auto=auto)
        return ShadowResult(action, approved=True, auto_approved=auto,
                            executed=False, committed=False,
                            reason="no execution steps supplied")

    # 2. Execute under the compensating saga (refuses irreversible-without-undo
    #    before any effect; rolls back the prefix on failure).
    saga = run_saga(steps, allow_irreversible=allow_irreversible)

    # 3. Pin the card ONLY when the effect stands, so a refused/rolled-back
    #    action is never graded against the episode outcome it didn't produce.
    #    Evidence is best-effort: a committed effect must never surface a
    #    card-recording error to the caller (the action already happened).
    card_id: str | None = None
    if saga.committed:
        try:
            card_id = engine.record_card(
                principal=principal, action=action, risk=risk or "high",
                predicted_outcome=float(getattr(preview, "predicted_outcome", 0.0)),
                goal_id=goal_id, episode_id=episode_id,
                effect=getattr(preview, "effect", ""),
                exposure_dollars=getattr(preview, "exposure_dollars", None),
                reversible=bool(getattr(preview, "reversible", False)),
                source="simulate",
                params_sha256=str(getattr(preview, "params_sha256", "")))
        except Exception:  # pragma: no cover -- evidence never breaks execution
            log.warning("shadow-mode card recording failed after commit for %s",
                        action, exc_info=True)

    # 4. Sign the sim -> approve -> execute chain.
    engine._audit(kind, decision="auto" if auto else "approved", action=action,
                  goal_id=goal_id, card=card_id,
                  exposure=view.get("exposure_dollars"),
                  committed=saga.committed, auto=auto)
    return ShadowResult(
        action, approved=True, auto_approved=auto,
        executed=bool(saga.results), committed=saga.committed,
        reason=saga.reason, card_id=card_id, saga=saga)


# ---------------------------------------------------------------------------
# run-path wiring
# ---------------------------------------------------------------------------

_shared: dict = {}
_shared_lock = threading.Lock()


def shared() -> EarnedAutonomyEngine:
    from .paths import data_dir

    cards_path = data_dir("consequence_cards.ndjson")
    with _shared_lock:
        engine = _shared.get(cards_path)
        if engine is None:
            engine = EarnedAutonomyEngine(
                cards=CardStore(path=cards_path),
                ledger=TrustLedger(path=data_dir("earned_autonomy.ndjson")))
            _shared[cards_path] = engine
        return engine


def reset_shared() -> None:
    with _shared_lock:
        _shared.clear()


def capture_prediction(verdict, *, principal: str, action: str, risk: str,
                       goal_id: int, episode_id: int, reversible: bool = False,
                       engine: EarnedAutonomyEngine | None = None) -> str | None:
    """Pin a rehearsal verdict as a consequence card. Never raises.

    The default-off hook the agent loop calls after the rehearsal twin speaks.
    Only a PROCEED verdict the model actually vouched for (``known``) becomes
    evidence: the disabled/no-support placeholder (predicted 0.5,
    ``known=False``) is filtered so sentinels can't launder into accuracy,
    and a held (BLOCK/ESCALATE) action never executes, so its prediction was
    never tested by reality and must not be graded by the episode's outcome.
    """
    try:
        if not enabled() or not getattr(verdict, "known", False):
            return None
        if str(getattr(verdict, "decision", "")) != "proceed":
            return None
        return (engine or shared()).record_card(
            principal=principal, action=action, risk=risk,
            predicted_outcome=float(verdict.predicted_outcome),
            goal_id=goal_id, episode_id=episode_id,
            effect=getattr(verdict, "reason", ""), reversible=reversible,
            source="rehearsal")
    except Exception:  # pragma: no cover -- capture must never break the loop
        log.debug("consequence-card capture skipped", exc_info=True)
        return None


__all__ = [
    "CardStore",
    "ConsequenceCard",
    "ConsequencePreview",
    "EarnedAutonomyEngine",
    "EarnedDecision",
    "EarnedVerdict",
    "GateResult",
    "GraduationPolicy",
    "ReconcileReport",
    "SagaResult",
    "SagaStep",
    "ShadowResult",
    "StepResult",
    "TrustLedger",
    "TrustState",
    "capture_prediction",
    "enabled",
    "evaluate_graduation",
    "policy_from_config",
    "reset_shared",
    "run_saga",
    "shadow_execute",
    "shared",
]
