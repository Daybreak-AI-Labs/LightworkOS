"""Anchor-gated evaluator co-evolution: let the *judge* improve, safely.

Lightwork's learning loop already defends against a rotting evaluator by
*freezing* (:mod:`maverick.calibration`): when the verifier stops discriminating
correct from incorrect, learning halts. That is the conservative half of the
story. The aggressive half -- recently formalised by the Red Queen Gödel Machine
(*Co-Evolving Agents and Their Evaluators*, arXiv 2606.26294) -- is that a fixed
evaluator eventually stops giving an informative signal at all, so capability
plateaus: agents saturate the judge and the only safe move left is to freeze.
The fix is to *promote a better judge* instead of merely pausing.

This module is the bridge from freeze-on-drift to promote-on-drift, built on the
existing governance spine (:mod:`maverick.self_improvement`) rather than beside
it. The mechanism, following the paper's *controlled utility evolution*:

* **Anchor.** Every evaluator role is tied to a fixed, held-out ground-truth set
  (:class:`Anchor`) -- e.g. operator-labelled accept/reject decisions. An
  evaluator is scored by its *agreement* with the anchor, never by self-report.
* **epsilon-best-belief promotion.** A challenger replaces the incumbent only when its
  anchor agreement, measured by the conservative epsilon-best-belief lower bound
  (:func:`best_belief`, the epsilon-quantile of the Beta posterior the paper uses for
  agent selection), beats the incumbent's. Ties favour the incumbent.
* **Selective erasure.** On a swap, only the learning records the displaced
  evaluator produced are discarded (:func:`selective_erasure`); anchor evidence
  and records from other slots survive. Each evaluator change advances the
  slot's *epoch*, so the within-epoch signal stays stationary.
* **The anchor is the guardrail, so the anchor is governed.** The paper is
  explicit that a weak, mutable, or poisoned anchor turns "provable learning"
  into laundered drift. We pin every released anchor's checksum in a committed
  lock (:func:`write_lock`) and *refuse to promote* against an anchor whose
  checksum no longer matches (:func:`verify_anchor_integrity`). Released anchors
  are immutable, exactly as released world-model migrations are
  (:mod:`maverick.migration_governance`). Surfaced as a CI gate:
  ``python -m maverick.evaluator_evolution --ci`` (``--regen`` to re-bake the
  lock after an intentional anchor addition).

Posture: ON by default with governed self-improvement and a no-op while off.
Promotion runs only when ``[self_improvement] enable`` AND
``[self_improvement] evaluator_evolution`` are set, and then it inherits *every* self-improvement
gate -- the calibration freeze, the evidence floor, reversibility, and the
signed audit -- on a dedicated ``evaluator`` rung. An evaluator scores; it never
grants a tool or executes code, so it cannot widen the capability envelope, but
it reshapes the entire learning signal, so by default it sits above
``max_auto_rung`` and a swap requires human approval until an operator raises the
ceiling to ``evaluator``.

Pure + dependency-injected: this module never *calls* an evaluator agent (those
are agentic/LLM and live elsewhere). The caller supplies each evaluator's
verdicts on the anchor items; everything here is deterministic and testable
without a live model.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

# The slot risk rung in the self-improvement ladder (see self_improvement.RUNGS).
RUNG = "evaluator"

# Default confidence level for the epsilon-best-belief lower bound, matching the
# paper's agent-selection default. A promoted evaluator's true anchor agreement
# exceeds its best-belief score with probability 1 - eps.
DEFAULT_EPS = 0.05


# --------------------------------------------------------------------------- #
# epsilon-best-belief: the eps-quantile of a Beta(1+S, 1+F) posterior.
#
# There is no scipy in this tree and no other Beta-quantile helper, so we carry a
# small dependency-free regularized-incomplete-beta (Lentz continued fraction)
# and invert it by bisection. I_x(a,b) is monotone increasing in x, so bisection
# converges cleanly.
# --------------------------------------------------------------------------- #


def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta (Numerical Recipes / Lentz)."""
    maxit = 200
    eps = 3.0e-12
    fpmin = 1.0e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, maxit + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def _betainc(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta I_x(a, b) in [0, 1]."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(lbeta + a * math.log(x) + b * math.log1p(-x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def best_belief(successes: int, failures: int, eps: float = DEFAULT_EPS) -> float:
    """epsilon-best-belief score: the eps-quantile of Beta(1+S, 1+F).

    A conservative lower bound on the underlying success rate that the true rate
    exceeds with probability ``1 - eps``. More evidence at the same ratio raises
    the bound toward the mean; with no evidence (S=F=0) it is just ``eps``
    (the eps-quantile of the uniform). This is the same selection statistic the
    paper uses for both agent selection and evaluator replacement.
    """
    s = max(0, int(successes))
    f = max(0, int(failures))
    e = min(max(float(eps), 1e-6), 1.0 - 1e-6)
    a, b = 1.0 + s, 1.0 + f
    lo, hi = 0.0, 1.0
    for _ in range(100):
        mid = 0.5 * (lo + hi)
        if _betainc(a, b, mid) < e:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


# --------------------------------------------------------------------------- #
# Anchor: the fixed ground-truth set an evaluator is scored against.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AnchorItem:
    """One held-out ground-truth datum: ``label`` is the correct verdict.

    For a paper reviewer the label is the human accept/reject; for a grader, a
    pass/fail at the reference grade. ``prompt`` is evaluator input, so it is part
    of the checksum-relevant identity together with ``id`` and ``label``. Editing
    any of those fields changes the released measurement and must fail integrity.
    """

    id: str
    label: bool
    prompt: str = ""


@dataclass(frozen=True)
class Anchor:
    """A role's fixed, checksum-pinned ground-truth set."""

    role: str
    items: tuple[AnchorItem, ...]
    _source_valid: bool = field(default=True, repr=False, compare=False)

    def __len__(self) -> int:
        return len(self.items)

    def checksum(self) -> str:
        """Stable SHA-256 over every evaluator-visible released anchor field."""
        payload = {
            "schema": "maverick-evaluator-anchor-v2",
            "role": self.role,
            "items": sorted(
                ([it.id, bool(it.label), it.prompt] for it in self.items),
                key=lambda r: r[0],
            ),
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def load_anchor(path: Path | str, role: str) -> Anchor:
    """Read an NDJSON anchor file (``{"id":..., "label":..., "prompt":...}``).

    Never raises: malformed rows are skipped, a missing file yields an empty
    anchor (which the promotion path treats as "not enough evidence").
    """
    p = Path(path)
    items: list[AnchorItem] = []
    source_valid = True
    if p.exists():
        try:
            with open(p, encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        d = json.loads(raw)
                        if not isinstance(d, dict) or "id" not in d or "label" not in d:
                            source_valid = False
                            continue
                        item_id = d["id"]
                        label = d["label"]
                        prompt = d.get("prompt", "")
                        if (not isinstance(item_id, str) or not item_id.strip()
                                or not isinstance(label, bool)
                                or not isinstance(prompt, str)):
                            source_valid = False
                            continue
                        items.append(AnchorItem(
                            id=item_id, label=label, prompt=prompt))
                    except (json.JSONDecodeError, TypeError, ValueError):
                        source_valid = False
                        continue
        except OSError:
            return Anchor(role=role, items=(), _source_valid=False)
    return Anchor(role=role, items=tuple(items), _source_valid=source_valid)


def score_on_anchor(
    verdicts: Mapping[str, bool], anchor: Anchor,
) -> tuple[int, int]:
    """Score an evaluator by agreement with the anchor: ``(successes, failures)``.

    ``verdicts`` maps anchor item id -> the evaluator's predicted label. An item
    with no verdict counts as a failure (an evaluator that abstains on ground
    truth is not agreeing with it). Only items present in the anchor are judged.
    """
    s = f = 0
    for it in anchor.items:
        if it.id in verdicts and bool(verdicts[it.id]) == bool(it.label):
            s += 1
        else:
            f += 1
    return s, f


# --------------------------------------------------------------------------- #
# Anchor governance: released anchors are immutable (the guardrail must hold).
# --------------------------------------------------------------------------- #


def anchor_lock_path() -> Path:
    """The committed lock manifest, next to this module."""
    return Path(__file__).with_name("evaluator_anchors.lock.json")


def default_anchor_dir() -> Path:
    """Where deployments keep their committed anchor NDJSON files.

    ``MAVERICK_EVALUATOR_ANCHOR_DIR`` overrides it. The default lives under the
    package so a repo that commits anchors can govern them in CI; deployments
    point it at their own anchor directory.
    """
    env = os.environ.get("MAVERICK_EVALUATOR_ANCHOR_DIR", "").strip()
    if env:
        return Path(env).expanduser()
    return Path(__file__).with_name("evaluator_anchors")


def discover_anchors(anchor_dir: Path | None = None) -> dict[str, Anchor]:
    """Load every ``*.ndjson`` anchor in ``anchor_dir`` keyed by role (the stem)."""
    d = Path(anchor_dir) if anchor_dir is not None else default_anchor_dir()
    out: dict[str, Anchor] = {}
    if not d.exists():
        return out
    for p in sorted(d.glob("*.ndjson")):
        role = p.stem
        out[role] = load_anchor(p, role)
    return out


def anchor_fingerprint(anchors: Mapping[str, Anchor]) -> dict:
    """Manifest of ``role -> {checksum, n}`` for the lock."""
    return {
        "checksums": {role: a.checksum() for role, a in sorted(anchors.items())},
        "sizes": {role: len(a) for role, a in sorted(anchors.items())},
    }


def _anchor_well_formed(anchor: object) -> bool:
    if not isinstance(anchor, Anchor):
        return False
    if (not isinstance(anchor.role, str) or not anchor.role.strip()
            or len(anchor.role) > 128 or not anchor.items
            or anchor._source_valid is not True):
        return False
    ids: set[str] = set()
    for item in anchor.items:
        if (not isinstance(item, AnchorItem)
                or not isinstance(item.id, str) or not item.id.strip()
                or len(item.id) > 512 or item.id in ids
                or not isinstance(item.label, bool)
                or not isinstance(item.prompt, str)
                or len(item.prompt) > 1_000_000):
            return False
        ids.add(item.id)
    return True


def _lock_maps(lock: object) -> tuple[dict[str, str], dict[str, int]] | None:
    if not isinstance(lock, dict):
        return None
    checksums = lock.get("checksums")
    sizes = lock.get("sizes")
    if not isinstance(checksums, dict) or not isinstance(sizes, dict):
        return None
    if set(checksums) != set(sizes):
        return None
    normalized_checksums: dict[str, str] = {}
    normalized_sizes: dict[str, int] = {}
    for role, checksum in checksums.items():
        size = sizes.get(role)
        if (not isinstance(role, str) or not role.strip() or len(role) > 128
                or not isinstance(checksum, str) or len(checksum) != 64
                or any(ch not in "0123456789abcdef" for ch in checksum)
                or isinstance(size, bool) or not isinstance(size, int) or size < 0):
            return None
        normalized_checksums[role] = checksum
        normalized_sizes[role] = size
    return normalized_checksums, normalized_sizes


def load_lock() -> dict | None:
    """The committed lock; None only when it does not exist.

    A lock that exists but cannot be read or parsed is returned as a
    non-empty object with no checksums, so it reports an invalid schema
    (which ``--regen`` refuses) instead of looking absent.
    """
    try:
        return json.loads(anchor_lock_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {"unreadable": True}


def write_lock(anchors: Mapping[str, Anchor] | None = None) -> Path:
    """Re-bake the committed lock from the current anchors (the ``--regen`` path)."""
    anchors = discover_anchors() if anchors is None else anchors
    if any(
        role != getattr(anchor, "role", None) or not _anchor_well_formed(anchor)
        for role, anchor in anchors.items()
    ):
        raise ValueError("cannot lock an invalid evaluator anchor")
    payload = anchor_fingerprint(anchors)
    payload["_comment"] = (
        "Committed fingerprint of the evaluator ground-truth anchors. Generated "
        "by `python -m maverick.evaluator_evolution --regen`. Do not hand-edit; "
        "a changed checksum on a released anchor fails CI. A weak or mutable "
        "anchor turns provable learning into laundered drift (arXiv 2606.26294)."
    )
    path = anchor_lock_path()
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def lock_problems(
    lock: dict | None, anchors: Mapping[str, Anchor] | None = None,
) -> list[str]:
    """Immutability checks against the committed lock.

    A changed checksum on a role present in the lock = an edited released anchor
    (hard fail: every evaluator promotion judged against the old labels is now
    invalid). A new role is allowed but must be locked so the addition is
    reviewed. A role removed from the lock fails -- released anchors may not
    silently disappear.
    """
    anchors = discover_anchors() if anchors is None else anchors
    malformed = [
        role for role, anchor in anchors.items()
        if role != getattr(anchor, "role", None) or not _anchor_well_formed(anchor)
    ]
    if malformed:
        return [
            "invalid evaluator anchor(s): " + ", ".join(sorted(map(str, malformed)))
        ]
    if not anchors and not lock:
        return []  # nothing committed to govern (a clean default deployment)
    fp = anchor_fingerprint(anchors)
    if not lock:
        return ["no evaluator_anchors.lock.json -- run `--regen` to create the baseline"]
    maps = _lock_maps(lock)
    if maps is None:
        return ["evaluator_anchors.lock.json has an invalid schema"]
    locked, locked_sizes = maps
    current = fp["checksums"]
    problems: list[str] = []
    pending_regen = False
    for role, cksum in current.items():
        if role in locked:
            if locked[role] != cksum or locked_sizes[role] != fp["sizes"][role]:
                problems.append(
                    f"anchor {role!r} checksum changed or size changed "
                    f"({locked[role]}/{locked_sizes[role]} -> "
                    f"{cksum}/{fp['sizes'][role]}) "
                    "-- a released anchor was edited; anchors are immutable once "
                    "released (add a new anchor or version instead)")
        else:
            pending_regen = True
    for role in locked:
        if role not in current:
            problems.append(
                f"anchor {role!r} is in the lock but gone from the anchor dir -- "
                "released anchors may not be removed")
    if pending_regen and not problems:
        problems.append(
            "new anchor(s) detected -- run `--regen` and commit "
            "evaluator_anchors.lock.json so the addition is reviewed")
    return problems


def verify_anchor_integrity(anchor: Anchor, lock: dict | None = None) -> bool:
    """Runtime guard: does this anchor match its locked checksum?

    Used inside the promotion path. Evaluation against an unregistered role or a
    missing/malformed lock fails closed: an unlocked anchor is development input,
    not a released measurement. Checksum and size must both match before scoring.
    """
    if lock is None:
        lock = load_lock()
    maps = _lock_maps(lock)
    if maps is None or not _anchor_well_formed(anchor):
        return False
    checksums, sizes = maps
    return (
        anchor.role in checksums
        and checksums[anchor.role] == anchor.checksum()
        and sizes[anchor.role] == len(anchor)
    )


def validate(anchor_dir: Path | None = None) -> list[str]:
    anchors = discover_anchors(anchor_dir)
    return lock_problems(load_lock(), anchors)


# --------------------------------------------------------------------------- #
# Epochs + selective erasure.
# --------------------------------------------------------------------------- #


@dataclass
class EvaluatorSlot:
    """A replaceable evaluator position for one role and its epoch index.

    ``epoch`` counts replacements: it starts at 1 and advances on every promote.
    Within an epoch the frozen evaluator gives a stationary signal; the utility
    may change only at an epoch boundary (a promote).
    """

    role: str
    evaluator_id: str
    epoch: int = 1


@dataclass(frozen=True)
class EvaluatorRecord:
    """A learning record stamped with the evaluator that produced its score."""

    record_id: str
    evaluator_id: str
    payload: object = None


def selective_erasure(
    records: list[EvaluatorRecord], displaced_evaluator_id: str,
) -> tuple[list[EvaluatorRecord], list[EvaluatorRecord]]:
    """Partition records into ``(kept, erased)``.

    Only records scored by the displaced evaluator are erased; everything else --
    anchor evidence, records from other slots/evaluators -- is preserved. Keeping
    stale records would mix evidence from two different utility functions and
    break the per-epoch stationarity the guarantees rely on.
    """
    kept: list[EvaluatorRecord] = []
    erased: list[EvaluatorRecord] = []
    for rec in records:
        (erased if rec.evaluator_id == displaced_evaluator_id else kept).append(rec)
    return kept, erased


def choose_challenger(
    incumbent_bb: float, challengers: list[tuple[str, float]],
) -> tuple[str | None, float]:
    """Pick the challenger with the highest best-belief that beats the incumbent.

    Ties favour the incumbent (returns ``(None, incumbent_bb)``) to avoid
    unnecessary erasures, exactly as the paper specifies.
    """
    best_id: str | None = None
    best_bb = incumbent_bb
    for cid, bb in challengers:
        if bb > best_bb:
            best_id, best_bb = cid, bb
    return best_id, best_bb


# --------------------------------------------------------------------------- #
# Enablement + the governed promotion entry point.
# --------------------------------------------------------------------------- #


def enabled() -> bool:
    """Whether default-on evaluator co-evolution may run.

    Requires self-improvement enabled AND the ``evaluator_evolution`` sub-toggle;
    ``MAVERICK_EVALUATOR_EVOLUTION=0`` opts out. Promotion remains above the
    default auto-rung ceiling and therefore requires approval.
    """
    try:
        from .self_improvement import enabled as si_enabled
        if not si_enabled():
            return False
    except Exception:  # pragma: no cover -- if we can't confirm, stay off
        return False
    from .config import governed_learning_env_flag
    ov = governed_learning_env_flag("MAVERICK_EVALUATOR_EVOLUTION")
    if ov is not None:
        return ov
    try:
        from .config import get_self_improvement
        return bool(get_self_improvement().get("evaluator_evolution", False))
    except Exception:  # pragma: no cover
        return False


def _eps() -> float:
    try:
        from .config import get_self_improvement
        return float(get_self_improvement().get("evaluator_eps", DEFAULT_EPS))
    except Exception:  # pragma: no cover
        return DEFAULT_EPS


def _audit(content: str, **fields: object) -> None:
    try:
        from .audit import EventKind, record
        record(EventKind.LEARNING_UPDATE, agent="evaluator_evolution",
               content=content, **fields)
    except Exception:  # pragma: no cover -- audit is best-effort, never blocks
        log.debug("evaluator-evolution audit failed", exc_info=True)


@dataclass(frozen=True)
class PromotionResult:
    """Outcome of a co-evolution step (a no-op when nothing was promoted)."""

    role: str
    promoted: bool
    incumbent_id: str
    challenger_id: str | None
    incumbent_bb: float
    challenger_bb: float
    new_epoch: int
    kept: tuple[EvaluatorRecord, ...] = ()
    erased: tuple[EvaluatorRecord, ...] = ()
    reason: str = ""


def consider_promotion(
    slot: EvaluatorSlot,
    incumbent_verdicts: Mapping[str, bool],
    challenger_verdicts: Mapping[str, Mapping[str, bool]],
    anchor: Anchor,
    records: list[EvaluatorRecord],
    *,
    eps: float | None = None,
    approved: bool = False,
    lock: dict | None = None,
    controller: object | None = None,
) -> PromotionResult:
    """Score incumbent + challengers on the anchor and promote through the gate.

    The whole step is a safe no-op (``promoted=False``) when the engine is off,
    the anchor fails its integrity check, no challenger beats the incumbent, or
    any self-improvement gate refuses the swap. Only on a real promotion does it
    mutate ``slot`` (advance the epoch, install the challenger) and return the
    surviving records after selective erasure.
    """
    e = _eps() if eps is None else eps
    base = PromotionResult(
        role=slot.role, promoted=False, incumbent_id=slot.evaluator_id,
        challenger_id=None, incumbent_bb=0.0, challenger_bb=0.0,
        new_epoch=slot.epoch, kept=tuple(records),
    )
    if not enabled():
        return _replace(base, reason="evaluator evolution disabled")
    if anchor.role != slot.role or not verify_anchor_integrity(anchor, lock):
        _audit("evaluator_anchor_integrity_failed", role=slot.role)
        return _replace(base, reason="anchor integrity check failed")

    s_inc, f_inc = score_on_anchor(incumbent_verdicts, anchor)
    inc_bb = best_belief(s_inc, f_inc, e)
    scored: list[tuple[str, float]] = []
    for cid, verdicts in challenger_verdicts.items():
        cs, cf = score_on_anchor(verdicts, anchor)
        scored.append((cid, best_belief(cs, cf, e)))

    winner_id, winner_bb = choose_challenger(inc_bb, scored)
    base = _replace(base, incumbent_bb=inc_bb, challenger_bb=winner_bb,
                    challenger_id=winner_id)
    if winner_id is None:
        return _replace(base, reason="no challenger beats the incumbent anchor best-belief")

    # Route through the governance spine on the dedicated evaluator rung: it
    # inherits the calibration freeze, the evidence floor, reversibility, human
    # approval (above max_auto_rung), and the signed audit.
    from .self_improvement import Candidate, consider
    cand = Candidate(
        rung=RUNG,
        summary=f"evaluator swap for role {slot.role!r}: {slot.evaluator_id} -> {winner_id}",
        baseline_score=inc_bb,
        candidate_score=winner_bb,
        samples=len(anchor),
        approved=approved,
        rollback={"role": slot.role, "displaced": slot.evaluator_id, "epoch": slot.epoch},
        provenance={"anchor_role": slot.role, "anchor_checksum": anchor.checksum(),
                    "eps": e},
    )
    verdict = consider(cand, controller=controller)  # type: ignore[arg-type]
    if not getattr(verdict, "ok", False):
        return _replace(base, reason=getattr(verdict, "blocking_reason", "promotion refused"))

    displaced = slot.evaluator_id
    kept, erased = selective_erasure(records, displaced)
    slot.evaluator_id = winner_id
    slot.epoch += 1
    _audit("evaluator_records_erased", role=slot.role, displaced=displaced,
           promoted=winner_id, epoch=slot.epoch, erased=len(erased))
    return _replace(base, promoted=True, new_epoch=slot.epoch,
                    kept=tuple(kept), erased=tuple(erased),
                    reason="promoted")


def _replace(result: PromotionResult, **changes: object) -> PromotionResult:
    from dataclasses import replace
    return replace(result, **changes)  # type: ignore[arg-type]


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(
        prog="maverick.evaluator_evolution",
        description="Govern evaluator ground-truth anchors (immutability of "
                    "released anchors). A weak or mutable anchor turns provable "
                    "learning into laundered drift (arXiv 2606.26294).")
    p.add_argument("--ci", action="store_true",
                   help="exit 1 on any anchor governance violation")
    p.add_argument("--regen", action="store_true",
                   help="rewrite evaluator_anchors.lock.json from the current anchors")
    p.add_argument("--force", action="store_true",
                   help="deprecated compatibility flag; released anchors still "
                        "cannot be re-locked after a checksum change")
    args = p.parse_args(argv)

    if args.regen:
        current_problems = lock_problems(load_lock())
        changed = [
            prob for prob in current_problems if "checksum changed" in prob
        ]
        hard_failures = [
            prob for prob in current_problems
            if ("gone from the anchor dir" in prob
                or "invalid evaluator anchor" in prob
                or "invalid schema" in prob)
        ]
        if hard_failures:
            print("evaluator-anchor governance: refusing to --regen")
            for prob in hard_failures:
                print(f"  - {prob}")
            print("  repair the release lock/anchor set or add a separately "
                  "versioned anchor; regeneration cannot erase released history.")
            return 1
        if changed:
            print("evaluator-anchor governance: refusing to --regen")
            for prob in changed:
                print(f"  - {prob}")
            print("  a released anchor was edited on disk; regenerating the lock "
                  "now would silently launder that edit. Add a new anchor/version "
                  "instead; released IDs cannot be re-locked, including with "
                  "--force.")
            return 1
        try:
            path = write_lock()
        except ValueError as exc:
            print(f"evaluator-anchor governance: refusing to --regen: {exc}")
            return 1
        print(f"wrote {path}")
        return 0

    problems = validate()
    if problems:
        print("evaluator-anchor governance: PROBLEMS")
        for prob in problems:
            print(f"  - {prob}")
    else:
        anchors = discover_anchors()
        lock = load_lock() or {}
        locked = len(lock.get("checksums") or {})
        # Anti-vacuity. With no anchors committed and an empty lock this printed
        # "OK / 0 anchor(s)" and exited 0 -- a governance gate reporting success
        # over nothing, next to migration_governance whose lock carries real
        # checksums. "Nothing to govern" is a legitimate state, but it must not
        # be spelled the same way as "everything checks out": an operator
        # skimming a green column cannot tell them apart, and that is exactly
        # how a ratchet protecting nothing survives review.
        if not anchors and not locked:
            print("evaluator-anchor governance: NO ANCHORS COMMITTED")
            print("  0 anchors on disk and 0 in the lock, so this gate is "
                  "currently governing nothing. That is a valid state for a "
                  "deployment that has not released an evaluator anchor -- but "
                  "it is not evidence that anchor immutability is enforced.")
        else:
            print("evaluator-anchor governance: OK")
            print(f"  {len(anchors)} anchor(s) on disk, {locked} locked: "
                  + ", ".join(f"{r}({len(a)})" for r, a in sorted(anchors.items())))
        # A lock with entries but nothing on disk means the released anchors
        # were deleted -- the exact laundering the ratchet exists to catch, and
        # `validate()` cannot see it if it only walks what is present.
        if locked and not anchors:
            print(f"evaluator-anchor governance: PROBLEM -- {locked} anchor(s) "
                  "are locked but none are on disk; released anchors were "
                  "removed.", file=sys.stderr)
            return 1 if args.ci else 0
    if args.ci and problems:
        return 1
    return 0


__all__ = [
    "RUNG", "DEFAULT_EPS", "best_belief",
    "AnchorItem", "Anchor", "load_anchor", "score_on_anchor",
    "anchor_lock_path", "default_anchor_dir", "discover_anchors",
    "anchor_fingerprint", "load_lock", "write_lock", "lock_problems",
    "verify_anchor_integrity", "validate",
    "EvaluatorSlot", "EvaluatorRecord", "selective_erasure", "choose_challenger",
    "enabled", "PromotionResult", "consider_promotion", "main",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
