"""Verifier calibration: keep the evaluator honest before the system learns.

Self-improvement closes the loop between the evaluator and the policy. The
verifier's confidence is the *label* the trajectory-donation flywheel
(:func:`maverick.donation.should_donate`) and the skill distiller learn from.
If the verifier drifts -- starts assigning high confidence to wrong answers --
the system trains on its own mistakes and compounds them (reward hacking /
model collapse). The single most important guardrail for safe self-improvement
is therefore: the evaluator must keep *discriminating* correct from incorrect,
and learning must FREEZE if it stops.

This module is that interlock. It mirrors the standard "judge calibration set"
pattern: hold a set of ``(verifier_confidence, ground_truth)`` samples and
require that the verifier's mean confidence on correct answers exceeds its mean
on incorrect answers by a margin, over enough samples. When an assessment finds
the verifier inadequate, :func:`learning_frozen` returns True and
``donation.write_record`` refuses to harvest new trajectories.

Samples come from a labeled set the operator feeds (``maverick calibrate
--sample ...``) or any ground-truth source (e.g. coding-mode test outcomes
paired with the verifier's confidence). The producer is deliberately decoupled
from the consumer so any ground-truth signal can drive it.

OFF by default and fail-open (kernel rule 1): the freeze only engages when
enforcement is enabled AND an assessment has actually run and found the
verifier inadequate. Any error here leaves learning exactly as it was -- this
gate can only make the system MORE cautious about what it learns, never a new
way to block a run.
"""
from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .config import env_flag
from .paths import data_dir

log = logging.getLogger(__name__)

# Legacy/global fallback locations (single-tenant). Multi-tenant deployments
# resolve these per-tenant at call time via :func:`_samples_path`/:func:`_verdict_path`
# so one tenant's calibration samples and learning-freeze verdict never bleed
# into another's self-improvement loop. With no active tenant these resolve to
# exactly the historical paths below (single-tenant behaviour unchanged).
SAMPLES_PATH = data_dir("calibration.ndjson")
VERDICT_PATH = data_dir("calibration_verdict.json")
RISK_VERDICT_PATH = data_dir("self_harness_calibration_receipt.json")


def _samples_path() -> Path:
    """Tenant-scoped calibration-sample ledger (legacy root when no tenant active)."""
    try:
        from .paths import data_dir
        return data_dir("calibration.ndjson")
    except Exception:  # pragma: no cover -- never let path resolution block a run
        return SAMPLES_PATH


def _verdict_path() -> Path:
    """Tenant-scoped learning-freeze verdict (legacy root when no tenant active)."""
    try:
        from .paths import data_dir
        return data_dir("calibration_verdict.json")
    except Exception:  # pragma: no cover -- never let path resolution block a run
        return VERDICT_PATH


def _risk_verdict_path() -> Path:
    """Tenant-scoped, evaluator-bound Self-Harness promotion receipt.

    Kept separate from the general learning-freeze verdict: a narrow current-
    cycle assessment that is intentionally inadequate until enough judge calls
    complete must not overwrite the broader donation interlock's state.
    """
    try:
        return data_dir("self_harness_calibration_receipt.json")
    except Exception:  # pragma: no cover -- path resolution cannot block a run
        return RISK_VERDICT_PATH

# Last-resort defaults; live values come from ``[calibration]`` (config.get_calibration).
_DEFAULTS = {
    "enforce": False,
    "min_samples": 20,
    "min_discrimination": 0.15,
    "collect_from_coding": False,
    # Reward-laundering interlock. 0.0 = advisory (measured + audited, never
    # freezes); >0 freezes learning when the verifier still separates natural
    # traffic but its edge on ADVERSARIAL probes has collapsed below this
    # fraction (see ``assess`` / ``resistance``). Off by default.
    "min_resistance": 0.0,
}

_lock = threading.RLock()


def _settings(*, config: dict | None = None) -> dict:
    """``config`` is only ever forwarded when actually given one, so the
    many existing test doubles for this function (a zero-argument
    ``lambda: {...}``) keep working when this is called the old, plain
    way -- only ``learning_frozen``'s config-reuse path passes one."""
    try:
        from .config import get_calibration
        return get_calibration() if config is None else get_calibration(config=config)
    except Exception:  # pragma: no cover -- config must never block a run
        return dict(_DEFAULTS)


def collect_from_coding_enabled() -> bool:
    """Whether to auto-record calibration samples from coding-mode runs.

    When a coding-mode run has ground truth (tests pass/fail), the agent loop
    can also ask the LLM verifier and record ``(confidence, correct)`` so the
    interlock learns whether the judge still tracks reality -- without an
    operator hand-feeding a labeled set. Off by default (it costs one extra
    verifier call per coding FINAL). ``MAVERICK_CALIBRATION_COLLECT_CODING``
    overrides ``[calibration] collect_from_coding``.
    """
    _v = env_flag("MAVERICK_CALIBRATION_COLLECT_CODING")
    if _v is not None:
        return _v
    return bool(_settings().get("collect_from_coding", False))


@dataclass
class CalibrationSample:
    confidence: float
    correct: bool
    ts: float = 0.0
    source: str = ""
    # Stable identity of the evaluator implementation that emitted this
    # confidence (model + judge protocol/configuration).  Empty preserves
    # legacy/general calibration samples, but a risk-limited promotion requires
    # an exact non-empty match so one verifier's receipt cannot authorize
    # another verifier after a model or prompt-protocol change.
    evaluator_id: str = ""
    # An ADVERSARIAL probe: a crafted plausible-but-wrong (or ugly-but-correct)
    # case whose ground truth is known. Natural samples measure drift; probes
    # measure whether the judge is being *gamed* (reward laundering) -- a
    # verifier can look calibrated on everyday traffic while its edge on
    # adversarial pairs quietly collapses. See ``assess``.
    adversarial: bool = False


@dataclass
class CalibrationReport:
    """The outcome of assessing a set of calibration samples.

    ``discrimination`` is mean(confidence | correct) - mean(confidence |
    incorrect): how much higher the verifier scores answers that were actually
    right (measured on NATURAL traffic when adversarial probes are present).
    ``brier`` is the mean squared error of confidence vs. outcome (lower is
    better). ``adequate`` is the verdict the freeze gate reads.

    ``adversarial_discrimination`` is the same edge measured only over crafted
    adversarial probes, and ``resistance`` =
    adversarial_discrimination / discrimination in [0, ~1]: 1.0 means the judge
    is as sharp on adversarial pairs as on easy ones; toward 0 means it looks
    calibrated on natural traffic but is being gamed (reward laundering). Both
    are ``None`` when no probes of both classes were supplied.
    """
    n: int
    n_correct: int
    n_incorrect: int
    discrimination: float
    brier: float
    adequate: bool
    reason: str = ""
    adversarial_discrimination: float | None = None
    resistance: float | None = None

    def to_dict(self) -> dict:
        return {
            "ts": time.time(),
            "n": self.n,
            "n_correct": self.n_correct,
            "n_incorrect": self.n_incorrect,
            "discrimination": round(self.discrimination, 4),
            "brier": round(self.brier, 4),
            "adequate": self.adequate,
            "reason": self.reason,
            "adversarial_discrimination": (
                round(self.adversarial_discrimination, 4)
                if self.adversarial_discrimination is not None else None),
            "resistance": (
                round(self.resistance, 4) if self.resistance is not None else None),
        }


def assess(
    samples: list[CalibrationSample],
    *,
    min_samples: int | None = None,
    min_discrimination: float | None = None,
    min_resistance: float | None = None,
) -> CalibrationReport:
    """Assess whether verifier confidence still discriminates correct answers.

    Adequate requires: at least ``min_samples`` total, BOTH classes present in
    the scored set (you cannot judge discrimination with only correct or only
    incorrect samples), ``discrimination >= min_discrimination``, AND -- when
    adversarial probes are supplied and ``min_resistance > 0`` --
    ``resistance >= min_resistance`` (the reward-laundering interlock). The
    thresholds default to the ``[calibration]`` config.

    When any sample is tagged ``adversarial``, drift discrimination is measured
    on the NATURAL subset only (probes are deliberately hard and would otherwise
    depress the everyday-calibration number); with no probes the behaviour is
    exactly the historical all-sample measurement.
    """
    s = _settings()
    min_n = s["min_samples"] if min_samples is None else min_samples
    min_disc = s["min_discrimination"] if min_discrimination is None else min_discrimination
    if min_resistance is None:
        min_resistance = float(s.get("min_resistance", 0.0))

    n = len(samples)
    adversarial = [x for x in samples if getattr(x, "adversarial", False)]
    natural = [x for x in samples if not getattr(x, "adversarial", False)]
    # The drift gate reads discrimination on natural traffic. With no probes,
    # `natural` already contains every sample, so this is the historical
    # all-sample measurement unchanged.
    base = natural

    def _disc(xs: list[CalibrationSample]) -> float | None:
        c = [x for x in xs if x.correct]
        i = [x for x in xs if not x.correct]
        if not c or not i:
            return None
        mean_c = sum(_clamp01(x.confidence) for x in c) / len(c)
        mean_i = sum(_clamp01(x.confidence) for x in i) / len(i)
        return mean_c - mean_i

    discrimination = _disc(base)
    disc_val = discrimination if discrimination is not None else 0.0
    brier = (
        sum((_clamp01(x.confidence) - (1.0 if x.correct else 0.0)) ** 2 for x in samples) / n
        if n else 1.0
    )

    adv_disc = _disc(adversarial)
    resistance: float | None = None
    if adv_disc is not None and disc_val > 0:
        resistance = adv_disc / disc_val

    nc = sum(1 for x in base if x.correct)
    ni = sum(1 for x in base if not x.correct)

    def _report(adequate: bool, reason: str) -> CalibrationReport:
        return CalibrationReport(
            n=n, n_correct=nc, n_incorrect=ni, discrimination=disc_val, brier=brier,
            adequate=adequate, reason=reason,
            adversarial_discrimination=adv_disc, resistance=resistance,
        )

    if n < min_n:
        return _report(False, f"not enough samples ({n} < {min_n}); cannot assess calibration")
    if nc == 0 or ni == 0:
        return _report(
            False, "need both correct and incorrect samples to judge discrimination")
    if disc_val < min_disc:
        return _report(False, (
            f"verifier discrimination {disc_val:.2f} below floor {min_disc:.2f}: "
            "confidence no longer separates correct from incorrect; learning frozen"))
    if resistance is not None and min_resistance > 0 and resistance < min_resistance:
        return _report(False, (
            f"reward-laundering resistance {resistance:.2f} below floor "
            f"{min_resistance:.2f}: the verifier still separates natural samples "
            f"(disc {disc_val:.2f}) but its edge on adversarial probes has collapsed "
            f"(disc {adv_disc:.2f}) -- the judge is being gamed; learning frozen"))
    tail = f"; laundering resistance {resistance:.2f}" if resistance is not None else ""
    return _report(
        True, f"verifier discriminates by {disc_val:.2f} over {n} samples{tail}")


def _clamp01(v: float) -> float:
    try:
        return max(0.0, min(1.0, float(v)))
    except (TypeError, ValueError):
        return 0.0


def record_sample(
    confidence: float, correct: bool, *, source: str = "",
    adversarial: bool = False, evaluator_id: str = "",
    path: Path | None = None, before_effect=None,
) -> bool:
    """Append one ``(confidence, ground_truth)`` calibration sample.

    Set ``adversarial=True`` for a crafted probe whose known outcome tests
    whether the judge is being gamed (see :func:`record_probe`). Legacy callers
    remain best-effort; an explicit effect guard preserves refusal/errors."""
    if path is None:
        path = _samples_path()
    entry = CalibrationSample(
        confidence=_clamp01(confidence), correct=bool(correct),
        ts=time.time(), source=str(source or "")[:120],
        evaluator_id=str(evaluator_id or "").strip()[:240],
        adversarial=bool(adversarial),
    )
    from .file_lock import cross_process_lock

    with _lock, cross_process_lock(path, strict=before_effect is not None):
        if before_effect is not None:
            before_effect()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                if before_effect is not None:
                    before_effect()
                f.write(json.dumps(entry.__dict__) + "\n")
                if before_effect is not None:
                    f.flush()
                    os.fsync(f.fileno())
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return True
        except OSError as e:
            if before_effect is not None:
                raise
            log.warning("calibration: sample write failed: %s", e)
            return False


def record_probe(
    confidence: float, correct: bool, *, source: str = "",
    evaluator_id: str = "", path: Path | None = None,
) -> bool:
    """Append one ADVERSARIAL calibration probe: a crafted case (plausible but
    wrong, or ugly but correct) with known ground truth, tagged so
    :func:`assess` can measure reward-laundering resistance. Same ledger as
    natural samples. Never raises.

    The probe corpus is exactly the fixed ground truth a governed platform
    should hold immutable (cf. the evaluator anchors): a proposer or co-evolving
    evaluator that games the judge shows up as adversarial discrimination
    collapsing while natural discrimination stays healthy."""
    return record_sample(
        confidence, correct, source=source, adversarial=True,
        evaluator_id=evaluator_id, path=path)


def current_resistance(path: Path | None = None) -> float | None:
    """The latest reward-laundering resistance over the sample ledger, or None
    when no adversarial probes of both classes are present. A read-only summary
    for dashboards / the evaluator co-evolution gate -- it does not persist a
    verdict (that is :func:`run_assessment`)."""
    return assess(load_samples(path)).resistance


def load_samples(path: Path | None = None, *, strict: bool = False) -> list[CalibrationSample]:
    """Read the calibration-sample ledger (most recent last). Never raises."""
    if path is None:
        path = _samples_path()
    if strict:
        from .file_lock import cross_process_lock, open_private_read

        with _lock, cross_process_lock(path, strict=True):
            try:
                with os.fdopen(open_private_read(path), "rb") as handle:
                    raw = handle.read(32 * 1024 * 1024 + 1)
            except FileNotFoundError:
                return []
            if len(raw) > 32 * 1024 * 1024:
                raise ValueError("The complete checker record exceeds its supported reading size")
            result = []
            for line in raw.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                value = json.loads(line)
                if (not isinstance(value, dict)
                        or type(value.get("confidence")) not in {int, float}
                        or not math.isfinite(value["confidence"]) or not 0 <= value["confidence"] <= 1
                        or type(value.get("correct")) is not bool
                        or type(value.get("ts")) not in {int, float}
                        or not math.isfinite(value["ts"]) or value["ts"] < 0
                        or not isinstance(value.get("source", ""), str)
                        or not isinstance(value.get("evaluator_id", ""), str)
                        or type(value.get("adversarial", False)) is not bool):
                    raise ValueError("The complete checker record cannot be verified")
                result.append(CalibrationSample(**value))
            return result
    if not path.exists():
        return []
    out: list[CalibrationSample] = []
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                try:
                    d = json.loads(raw)
                    if not isinstance(d, dict):
                        continue
                    out.append(CalibrationSample(
                        confidence=float(d.get("confidence", 0.0)),
                        correct=bool(d.get("correct", False)),
                        ts=float(d.get("ts", 0.0) or 0.0),
                        source=str(d.get("source", "")),
                        evaluator_id=str(d.get("evaluator_id", "")),
                        adversarial=bool(d.get("adversarial", False)),
                    ))
                except (json.JSONDecodeError, TypeError, ValueError):
                    continue
    except OSError:
        return []
    return out


def run_assessment(
    *, samples_path: Path | None = None, verdict_path: Path | None = None,
    evaluator_id: str | None = None, since: float | None = None,
    sources: set[str] | None = None, strict: bool = False, before_effect=None,
    min_samples: int | None = None, min_discrimination: float | None = None,
) -> CalibrationReport:
    """Assess the ledger and persist the verdict that :func:`learning_frozen` reads.

    ``evaluator_id`` and ``since`` form the risk-limited receipt boundary.  When
    supplied, only samples from that exact evaluator at or after ``since`` are
    eligible, and the persisted verdict records both the identity and evidence
    timestamps.  Re-running an assessment over old or differently configured
    judge evidence therefore cannot mint a fresh authorization receipt.  With
    both omitted, historical all-sample calibration behavior is unchanged.
    """
    if samples_path is None:
        samples_path = _samples_path()
    if verdict_path is None:
        verdict_path = _verdict_path()
    if before_effect is not None:
        before_effect()
    samples = load_samples(samples_path, strict=True) if strict else load_samples(samples_path)
    if sources is not None:
        samples = [sample for sample in samples if sample.source in sources]
    bound_id: str | None = None
    if evaluator_id is not None:
        bound_id = str(evaluator_id or "").strip()[:240]
        samples = [sample for sample in samples
                   if bound_id and sample.evaluator_id == bound_id]
    evidence_since: float | None = None
    if since is not None:
        try:
            evidence_since = float(since)
        except (TypeError, ValueError, OverflowError):
            evidence_since = float("nan")
        if not math.isfinite(evidence_since) or evidence_since < 0:
            samples = []
        else:
            samples = [sample for sample in samples
                       if math.isfinite(sample.ts) and sample.ts >= evidence_since]
    report = assess(samples, min_samples=min_samples, min_discrimination=min_discrimination)
    payload = report.to_dict()
    if evaluator_id is not None or since is not None:
        timestamps = [sample.ts for sample in samples
                      if math.isfinite(sample.ts) and sample.ts >= 0]
        payload.update({
            "schema": "maverick-calibration-receipt-v2",
            "evaluator_id": bound_id or "",
            "evidence_since": evidence_since,
            "sample_min_ts": min(timestamps) if timestamps else None,
            "sample_max_ts": max(timestamps) if timestamps else None,
        })
    with _lock:
        try:
            if strict or before_effect is not None:
                from .file_lock import atomic_write_text, cross_process_lock

                with cross_process_lock(verdict_path, strict=True):
                    if before_effect is not None:
                        before_effect()
                    atomic_write_text(verdict_path, json.dumps(payload, indent=2),
                                      mode=0o600, effect_guard=before_effect)
                return report
            verdict_path.parent.mkdir(parents=True, exist_ok=True)
            verdict_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            try:
                os.chmod(verdict_path, 0o600)
            except OSError:
                pass
        except OSError as e:  # pragma: no cover -- persistence is best-effort
            if strict or before_effect is not None:
                raise
            log.warning("calibration: verdict write failed: %s", e)
    return report


def _load_verdict(path: Path | None = None) -> dict | None:
    if path is None:
        path = _verdict_path()
    if not path.exists():
        return None
    try:
        verdict = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return verdict if isinstance(verdict, dict) else None


def learning_frozen(
    *, verdict_path: Path | None = None, config: dict | None = None,
) -> bool:
    """Whether self-improvement should be frozen because the verifier drifted.

    True only when enforcement is enabled AND a persisted assessment exists and
    found the verifier inadequate. With enforcement off, or no assessment yet,
    returns False (learning proceeds as today). Fail-open.

    The verdict is resolved per-tenant: a freeze raised by one tenant's drifting
    verifier does not freeze learning for other tenants.

    ``MAVERICK_LEARNING_FROZEN`` is a hard override used by the learning-proof
    A/B harness to force a clean control arm independent of verifier drift:
    ``1/true/on`` forces frozen (no learning), ``0/false/off`` forces unfrozen,
    anything else falls through to the calibration logic below.

    ``config`` lets a caller that already loaded config reuse that snapshot
    for the ``[calibration]`` lookup; only forwarded when actually given one,
    so the many existing ``_settings`` test doubles (zero-argument) keep
    working when this is called the old, plain way.
    """
    override = os.environ.get("MAVERICK_LEARNING_FROZEN", "").strip().lower()
    if override in {"1", "true", "yes", "on"}:
        return True
    if override in {"0", "false", "no", "off"}:
        return False
    s = _settings() if config is None else _settings(config=config)
    if not s["enforce"]:
        return False
    if verdict_path is None:
        verdict_path = _verdict_path()
    verdict = _load_verdict(verdict_path)
    if verdict is None:
        # No assessment has run: we have no evidence of drift, so don't freeze.
        return False
    return not bool(verdict.get("adequate", True))


def learning_frozen_safe(*, config: dict | None = None) -> bool:
    """``learning_frozen()``, but never raises into a caller that can't afford
    to: an interlock deciding whether to distill/consolidate/rehearse must
    fail OPEN (not frozen) rather than crash the learning loop if calibration
    itself is unavailable or its state is unreadable.

    Three call sites (``dreaming.rehearse``, ``dreaming._consolidate_learning``,
    ``orchestrator``'s per-run skill distillation gate) each independently
    wrapped ``learning_frozen()`` in this exact
    ``try: ... except Exception: return False`` shape; sharing it here means a
    future change to what "fail open" should mean here only has one place to
    change. Deliberately drops ``verdict_path`` -- no call site has ever
    needed a custom one. ``config`` exists ONLY so orchestrator's per-run
    gate (the one call site that also checks ``distillation_local.enabled()``
    in the same breath) can load config once for both checks; it is never
    forwarded unless actually given, so every existing zero-argument test
    double for ``learning_frozen`` keeps working when this is called the
    old, plain way."""
    try:
        return bool(learning_frozen() if config is None else learning_frozen(config=config))
    except Exception:  # pragma: no cover -- interlock absent = not frozen
        return False


__all__ = [
    "CalibrationSample",
    "CalibrationReport",
    "assess",
    "collect_from_coding_enabled",
    "record_sample",
    "record_probe",
    "current_resistance",
    "load_samples",
    "run_assessment",
    "learning_frozen",
    "learning_frozen_safe",
    "SAMPLES_PATH",
    "VERDICT_PATH",
    "RISK_VERDICT_PATH",
]
