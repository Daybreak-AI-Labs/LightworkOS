"""A self-improving agent factory: learn from what the packs we make get wrong.

The factory drafts packs (intake, demonstration) and provisioning reveals where
those drafts fall short -- a tool the pack declared but didn't exist, a skill
its workflow needed but wasn't installed, an envelope a human had to widen at
approval. Today that signal dies in a log. This module closes the loop back
onto *generation quality*:

    record provisioning/approval outcomes  (attributed to suite + signal)
        --> mine recurring shortfalls into proposer CORRECTIONS
        --> promote each through the self_improvement gate  (the ``prompt`` rung)
        --> augment the generator's system prompt with the promoted guidance

So the NEXT finance pack the factory writes already knows that finance packs
typically need ``web_search``, because the last several needed it and the gate
agreed the pattern is real.

Posture: ON by default with governed self-improvement and a no-op while off.
Before enough governed evidence accumulates, recording/mining cannot change the
generator. Set ``[self_improvement] factory_learning = false`` or
``MAVERICK_FACTORY_LEARNING=0`` to keep it static. Promotion reuses
``SelfImprovementController`` so a
correction only takes effect if it beats its baseline with enough support and
the verifier isn't drifting. Ordinary tool/skill guidance cannot grant tools;
an envelope-widening signal is deliberately excluded from automatic promotion
because that change requires a separate, explicit authority review. Outcome
identifiers are secret-redacted and shape-validated before they are persisted.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import stat
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import governed_learning_env_flag
from .file_lock import (
    atomic_read_bytes,
    atomic_read_text,
    atomic_write_bytes,
    atomic_write_text,
    cross_process_lock,
    ensure_private_file,
)
from .learning_guard import Halted, check_learning_halt
from .paths import data_dir

log = logging.getLogger(__name__)


def outcomes_path() -> Path:
    """The active tenant's factory-outcome ledger."""
    return data_dir("factory_outcomes.ndjson")


def corrections_path() -> Path:
    """The active tenant's promoted-correction ledger."""
    return data_dir("factory_corrections.ndjson")


def __getattr__(name: str) -> Path:
    """Dynamically resolve legacy path attributes for compatibility.

    A module-level path would be frozen under the tenant active at import time.
    Attribute access remains available without pinning subsequent requests to
    that tenant.
    """
    if name == "OUTCOMES_PATH":
        return outcomes_path()
    if name == "PROMOTED_PATH":
        return corrections_path()
    raise AttributeError(name)

# Signals we attribute to a generated pack's *making*, not its running.
SIGNAL_TOOL_MISSING = "tool_declared_but_missing"   # provisioning had to synthesize it
SIGNAL_SKILL_GAP = "workflow_skill_gap"             # provisioning installed a catalog skill
SIGNAL_ENVELOPE_WIDENED = "envelope_widened"        # a human widened the clamp at approval
_VALID_SIGNALS = frozenset({SIGNAL_TOOL_MISSING, SIGNAL_SKILL_GAP, SIGNAL_ENVELOPE_WIDENED})

_lock = threading.Lock()
# A correction targeting the whole roster (no suite prefix) uses this scope.
_GLOBAL_SCOPE = "*"
_MAX_GUIDANCE_ITEMS = 8
# Bound the outcomes ledger the way trajectory_store bounds its capture: oldest
# rows roll off so a long-lived deployment can't grow it without limit (and the
# whole-file re-read in mining/promotion stays cheap). The promoted ledger is
# self-bounding (deduped on read, one entry per distinct correction).
_MAX_OUTCOME_ROWS = 50_000
# Rotate (read + rewrite, keeping the newest rows) once the file exceeds this many
# bytes. Sized comfortably above the worst-case row (pack + 200-char detail + json
# overhead ~= 320 B) * the row cap, so the expensive rewrite runs rarely and the
# ledger settles just above the cap rather than oscillating on every append.
_ROTATE_BYTES = _MAX_OUTCOME_ROWS * 320

# Factory telemetry becomes generator prompt text after promotion.  Treat its
# identity fields as identifiers, never free-form prose: this blocks newlines,
# prompt delimiters, Unicode confusables, path traversal, and unbounded payloads
# from entering the evidence/prompt pipeline.  Tool and catalog-skill
# names legitimately use ``_``, ``-``, ``.``, ``:``, ``/``, ``@``, and ``+``.
_PACK_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,95}$")
_SUITE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_DETAIL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+\-]{0,127}$")
_EVIDENCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/\-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CORRECTION_ARTIFACT_VERSION = 2
_EVIDENCE_PROVENANCE_HASHES = (
    "dataset_sha256",
    "split_sha256",
    "evaluator_sha256",
    "model_sha256",
    "prompt_sha256",
)


def enabled() -> bool:
    """Whether the default-on factory-learning loop is active.

    Rides on the self-improvement master switch (the gate it promotes through),
    with a dedicated ``[self_improvement] factory_learning`` sub-toggle (default
    on) so an operator can keep the generator static while other rungs learn.
    ``MAVERICK_FACTORY_LEARNING`` overrides both.
    """
    v = governed_learning_env_flag("MAVERICK_FACTORY_LEARNING")
    if v is not None:
        return v
    try:
        from .self_improvement import enabled as si_enabled
        if not si_enabled():
            return False
        from .config import get_self_improvement
        return bool(get_self_improvement().get("factory_learning", True))
    except Exception:  # pragma: no cover -- never block a run
        return False


def _redact(text: str) -> str:
    try:
        from .safety.secret_detector import redact
        return redact(str(text or ""))[0]
    except Exception:  # pragma: no cover
        # Learning is optional; if its redaction boundary is unavailable, drop
        # the signal instead of persisting potentially sensitive prompt input.
        return ""


def _safe_pack(value: object) -> str | None:
    raw = str(value or "")
    return raw if _PACK_RE.fullmatch(raw) else None


def _safe_suite(value: object, *, allow_empty: bool = True) -> str | None:
    raw = str(value or "")
    if not raw and allow_empty:
        return ""
    return raw if _SUITE_RE.fullmatch(raw) else None


def _safe_detail(value: object) -> str | None:
    # Redaction happens before shape validation. Reject rather than truncate so
    # two attacker-controlled long values cannot collapse onto one evidence key.
    raw = _redact(str(value or ""))
    if ".." in raw or "//" in raw:
        return None
    return raw if _DETAIL_RE.fullmatch(raw) else None


# --------------------------------------------------------------------------
# outcome ledger
# --------------------------------------------------------------------------
@dataclass
class FactoryOutcome:
    ts: float
    pack: str
    suite: str          # business suite, or "" for legacy/generic packs
    signal: str
    detail: str = ""    # the tool / skill / risk involved

    def to_dict(self) -> dict:
        return {"ts": self.ts, "pack": self.pack, "suite": self.suite,
                "signal": self.signal, "detail": self.detail}


def _validated_outcome(
    *, ts: object, pack: object, suite: object, signal: object, detail: object,
) -> FactoryOutcome | None:
    """Return a canonical safe outcome, or ``None`` for poisoned/corrupt input."""
    safe_pack = _safe_pack(pack)
    safe_suite = _safe_suite(suite)
    safe_signal = str(signal or "")
    safe_detail = _safe_detail(detail)
    if (safe_pack is None or safe_suite is None or safe_detail is None
            or safe_signal not in _VALID_SIGNALS):
        return None
    try:
        safe_ts = float(ts)
    except (TypeError, ValueError):
        return None
    # NaN is the only float unequal to itself; infinities are rejected by the
    # finite timestamp bound. Avoid importing math on this hot append path.
    if safe_ts != safe_ts or safe_ts < 0 or safe_ts == float("inf"):
        return None
    return FactoryOutcome(
        ts=safe_ts, pack=safe_pack, suite=safe_suite,
        signal=safe_signal, detail=safe_detail,
    )


def record_outcome(
    pack: str, signal: str, *, detail: str = "", suite: str | None = None,
    path: Path | None = None,
) -> bool:
    """Append one factory outcome. No-op (returns False) while disabled or for
    an unknown signal. Never raises -- a ledger write must not break onboarding.
    """
    if not enabled() or signal not in _VALID_SIGNALS:
        return False
    from .learning_guard import learning_write_allowed
    if not learning_write_allowed("factory_learning"):
        return False
    safe_pack = _safe_pack(pack)
    if safe_pack is None:
        return False
    if suite is None:
        try:
            from .domain import suite_for
            suite = suite_for(safe_pack) or ""
        except Exception:  # pragma: no cover
            suite = ""
    entry = _validated_outcome(
        ts=time.time(), pack=safe_pack, suite=suite,
        signal=signal, detail=detail,
    )
    if entry is None:
        return False
    path = path if path is not None else outcomes_path()
    with _lock:
        try:
            # Serialize append + possible rotation as one transaction. A stable
            # sidecar lock survives the rotation's os.replace across processes.
            with cross_process_lock(path):
                path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
                with open(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
                _maybe_rotate(path)
            return True
        except (OSError, RuntimeError) as e:
            log.warning("factory_learning: outcome write failed: %s", e)
            return False


def _maybe_rotate(path: Path) -> None:
    """Keep only the newest rows. Called under both process + file locks.

    Triggered by the file's actual SIZE, not a process-local counter: in the CLI
    a fresh process records only a few rows, so a counter would never trip and
    the cap would be a no-op. A cheap ``stat`` on each append, with the expensive
    read+rewrite only once the file is clearly oversized, bounds the ledger
    regardless of how many short-lived processes write it.
    """
    try:
        if path.stat().st_size < _ROTATE_BYTES:
            return
        lines = atomic_read_text(path).splitlines(keepends=True)
        if len(lines) <= _MAX_OUTCOME_ROWS:
            return
        atomic_write_text(path, "".join(lines[-_MAX_OUTCOME_ROWS:]), mode=0o600)
    except OSError:  # pragma: no cover -- rotation is best-effort
        pass


def load_outcomes(*, path: Path | None = None, strict: bool = False) -> list[FactoryOutcome]:
    path = path if path is not None else outcomes_path()
    if not path.exists():
        return []
    out: list[FactoryOutcome] = []
    try:
        with cross_process_lock(path):
            rows = atomic_read_text(path).splitlines()
        for raw in rows:
            try:
                d = json.loads(raw)
                if not isinstance(d, dict):  # a bare int/str/array/null line
                    if strict:
                        raise ValueError("factory outcome record is invalid")
                    continue
                entry = _validated_outcome(
                    ts=d.get("ts"), pack=d.get("pack"), suite=d.get("suite"),
                    signal=d.get("signal"), detail=d.get("detail"),
                )
                if entry is not None:
                    out.append(entry)
                elif strict:
                    raise ValueError("factory outcome record is invalid")
            except (json.JSONDecodeError, TypeError, ValueError):
                if strict:
                    raise
                continue
    except (OSError, RuntimeError):
        if strict:
            raise
        return []
    return out


def record_provisioning(profile, plan, result) -> int:
    """Attribute a pack's provisioning gaps to its making. Best-effort.

    Called after ``provision.apply_plan``: a synthesized tool means the pack
    declared a tool that didn't exist (the generator should have known better
    or the tool belongs in the catalog); an installed skill means its workflow
    needed know-how the draft lacked. Returns the number of outcomes recorded
    (0 while disabled).
    """
    if not enabled():
        return 0
    pack = getattr(profile, "name", "") or ""
    n = 0
    # The making-time signal is "the pack DECLARED a tool that didn't exist",
    # keyed by the declared name (``gap.need``). Record it from the plan's
    # tool-gaps -- which captures every such tool whether or not synthesis later
    # succeeded -- and NOT also from ``result.generated`` (the post-synthesis
    # SANITIZED name): recording both would double-count and, worse, fragment
    # mining across two different spellings of the same tool.
    seen_tools: set[str] = set()
    for gap in getattr(plan, "tool_gaps", []) or []:
        if getattr(gap, "resolution", "") == "generate_tool" and gap.need not in seen_tools:
            seen_tools.add(gap.need)
            n += bool(record_outcome(pack, SIGNAL_TOOL_MISSING, detail=gap.need))
    for skill_name in getattr(result, "acquired", []) or []:
        n += bool(record_outcome(pack, SIGNAL_SKILL_GAP, detail=skill_name))
    return n


# --------------------------------------------------------------------------
# mining: recurring outcomes -> proposer corrections
# --------------------------------------------------------------------------
@dataclass
class ProposerCorrection:
    """A guidance hint to fold into the generator's system prompt."""

    scope: str          # suite key, or "*" for the whole roster
    signal: str
    detail: str
    support: int        # how many distinct packs exhibited it
    guidance: str       # the sentence appended to the proposer prompt

    def key(self) -> str:
        return f"{self.scope}|{self.signal}|{self.detail}"


def _guidance_for(signal: str, detail: str, scope: str) -> str:
    where = "packs" if scope == _GLOBAL_SCOPE else f"{scope} packs"
    if signal == SIGNAL_TOOL_MISSING:
        return (f"{where} commonly need the {detail!r} tool but recent drafts "
                f"omitted it or named a tool that doesn't exist -- include a real, "
                f"catalog tool for this need.")
    if signal == SIGNAL_SKILL_GAP:
        return (f"{where} typically need the {detail!r} skill -- reflect that "
                f"capability in the workflow.")
    if signal == SIGNAL_ENVELOPE_WIDENED:
        return (f"{where} were repeatedly approved only after widening the "
                f"{detail!r} envelope -- size the envelope for this need up front.")
    return ""  # pragma: no cover -- unknown signal never mined


def _validated_correction(
    *, scope: object, signal: object, detail: object, support: object,
) -> ProposerCorrection | None:
    """Canonicalize persisted/mined correction metadata and rebuild its prompt.

    ``guidance`` is intentionally not accepted as input: it is derived from the
    validated identifiers, so tampering with an NDJSON row cannot inject prompt
    instructions through the stored free-form sentence.
    """
    raw_scope = str(scope or _GLOBAL_SCOPE)
    safe_scope = (
        _GLOBAL_SCOPE if raw_scope == _GLOBAL_SCOPE
        else _safe_suite(raw_scope, allow_empty=False)
    )
    safe_signal = str(signal or "")
    safe_detail = _safe_detail(detail)
    try:
        safe_support = int(support)
    except (TypeError, ValueError):
        return None
    if (safe_scope is None or safe_signal not in _VALID_SIGNALS
            or safe_detail is None or not 1 <= safe_support <= _MAX_OUTCOME_ROWS):
        return None
    # Expanding an authority envelope cannot ride the automatic prompt rung.
    if safe_signal == SIGNAL_ENVELOPE_WIDENED:
        return None
    return ProposerCorrection(
        scope=safe_scope, signal=safe_signal, detail=safe_detail,
        support=safe_support,
        guidance=_guidance_for(safe_signal, safe_detail, safe_scope),
    )


def mine_corrections(
    outcomes: list[FactoryOutcome] | None = None, *, min_support: int = 3,
) -> list[ProposerCorrection]:
    """Aggregate recurring outcomes into corrections meeting ``min_support``.

    Support counts DISTINCT packs (one pack that hit the same gap five times is
    one data point, not five), grouped by (suite-scope, signal, detail). Pure
    and deterministic -- the same ledger always mines the same corrections,
    ordered by support then key for a stable promotion sequence.
    """
    outcomes = load_outcomes() if outcomes is None else outcomes
    packs: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for o in outcomes:
        safe = _validated_outcome(
            ts=getattr(o, "ts", None), pack=getattr(o, "pack", None),
            suite=getattr(o, "suite", None), signal=getattr(o, "signal", None),
            detail=getattr(o, "detail", None),
        )
        if safe is None:
            continue
        scope = safe.suite or _GLOBAL_SCOPE
        packs[(scope, safe.signal, safe.detail)].add(safe.pack)
    corrections: list[ProposerCorrection] = []
    for (scope, signal, detail), pset in packs.items():
        if len(pset) < max(1, min_support):
            continue
        corrections.append(ProposerCorrection(
            scope=scope, signal=signal, detail=detail, support=len(pset),
            guidance=_guidance_for(signal, detail, scope),
        ))
    corrections.sort(key=lambda c: (-c.support, c.key()))
    return corrections


# --------------------------------------------------------------------------
# promotion: gate measured corrections through the self_improvement controller
# --------------------------------------------------------------------------
def _evidence_json(raw: str) -> object:
    """Decode evidence while rejecting duplicate object keys and NaN/Infinity."""
    def _constant(value: str):
        raise ValueError(f"non-finite number {value!r}")

    def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate evidence key {key!r}")
            out[key] = value
        return out

    return json.loads(
        raw,
        parse_constant=_constant,
        object_pairs_hook=_object,
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _valid_sha256(value: object) -> str:
    digest = str(value or "")
    if not _SHA256_RE.fullmatch(digest):
        raise ValueError("hashes must be 64 lowercase hexadecimal characters")
    return digest


def _bounded_label(value: object, *, field_name: str, max_length: int = 512) -> str:
    label = str(value or "")
    if (not label or len(label) > max_length
            or any(ord(char) < 32 for char in label)):
        raise ValueError(f"evidence provenance {field_name} is invalid")
    return label


def _score(value: object, *, key: str, arm: str) -> float:
    if (not isinstance(value, (int, float)) or isinstance(value, bool)):
        raise ValueError(f"{key}: {arm} scores must be numeric")
    score = float(value)
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise ValueError(f"{key}: {arm} scores must be finite in [0,1]")
    return score


def _paired_effect_lcb(
    baseline: list[float], candidate: list[float], *, alpha: float = 0.05,
) -> float:
    """Distribution-free one-sided lower bound for the paired mean effect.

    Scores are bounded in [0, 1], so paired differences are bounded in [-1, 1].
    The empirical-Bernstein radius uses the observed paired variance plus its
    finite-sample range penalty.  It is intentionally more conservative than a
    normal/t approximation and remains valid for skewed or binary evaluators.
    """
    if len(baseline) != len(candidate) or len(baseline) < 2:
        raise ValueError("paired effect confidence bound requires at least two cases")
    differences = [right - left for left, right in zip(baseline, candidate, strict=True)]
    count = len(differences)
    mean = sum(differences) / count
    variance = sum((value - mean) ** 2 for value in differences) / (count - 1)
    log_term = math.log(2.0 / alpha)
    radius = (
        math.sqrt(2.0 * variance * log_term / count)
        + (7.0 * 2.0 * log_term) / (3.0 * (count - 1))
    )
    return max(-1.0, min(1.0, mean - radius))


@dataclass(frozen=True)
class FactoryEvidenceResult:
    baseline_score: float
    candidate_score: float
    samples: int
    effect_ci_low: float | None
    evidence_sha256: str
    source_sha256: str
    provenance: dict[str, Any]


@dataclass(frozen=True)
class MeasuredFactoryEvidence:
    """Parsed evidence bundle. Only self-digested v2 is live-promotable."""

    version: int
    evidence_sha256: str
    source_sha256: str
    provenance: dict[str, Any]
    rows: dict[str, FactoryEvidenceResult]

    @property
    def live_eligible(self) -> bool:
        return self.version == 2

    def __call__(
        self, correction: ProposerCorrection, _total_packs: int = 0,
    ) -> FactoryEvidenceResult:
        try:
            return self.rows[correction.key()]
        except KeyError as exc:
            raise ValueError(
                f"no paired held-out evidence for {correction.key()!r}") from exc


def _correction_evidence_key(raw_key: object) -> str:
    if not isinstance(raw_key, str):
        raise ValueError("factory correction evidence keys must be strings")
    parts = raw_key.split("|")
    if len(parts) != 3 or _validated_correction(
        scope=parts[0], signal=parts[1], detail=parts[2], support=1,
    ) is None:
        raise ValueError(f"invalid factory correction evidence key {raw_key!r}")
    return raw_key


def _load_v1_evidence(
    doc: dict[str, object], *, source_sha256: str,
) -> MeasuredFactoryEvidence:
    """Parse legacy evidence for dry-run inspection, never live promotion."""
    if set(doc) != {"version", "corrections"}:
        raise ValueError("factory evidence v1 contains unexpected fields")
    rows = doc.get("corrections")
    if not isinstance(rows, dict) or not rows or len(rows) > 10_000:
        raise ValueError("factory evidence corrections must be a non-empty object")
    digest = _sha256_bytes(_canonical_json(doc).encode("utf-8"))
    measured: dict[str, FactoryEvidenceResult] = {}
    for raw_key, value in rows.items():
        key = _correction_evidence_key(raw_key)
        if not isinstance(value, dict) or set(value) != {"baseline", "candidate"}:
            raise ValueError(f"{key}: v1 evidence row is invalid")
        baseline_raw, candidate_raw = value["baseline"], value["candidate"]
        if (not isinstance(baseline_raw, list) or not isinstance(candidate_raw, list)
                or not 1 <= len(baseline_raw) <= 10_000
                or len(baseline_raw) != len(candidate_raw)):
            raise ValueError(f"{key}: baseline and candidate must be paired equally")
        baseline = [_score(item, key=key, arm="baseline") for item in baseline_raw]
        candidate = [_score(item, key=key, arm="candidate") for item in candidate_raw]
        measured[key] = FactoryEvidenceResult(
            baseline_score=sum(baseline) / len(baseline),
            candidate_score=sum(candidate) / len(candidate),
            samples=len(baseline), effect_ci_low=None,
            evidence_sha256=digest, source_sha256=source_sha256,
            provenance={"legacy_version": 1},
        )
    return MeasuredFactoryEvidence(
        version=1, evidence_sha256=digest, source_sha256=source_sha256,
        provenance={"legacy_version": 1}, rows=measured,
    )


def load_measured_evidence(path: str | Path) -> MeasuredFactoryEvidence:
    """Load strict, paired factory evidence.

    Version 2 binds the exact payload with ``evidence_sha256`` and requires
    immutable dataset/split/evaluator/model/prompt hashes plus run provenance.
    Each correction carries unique case IDs and baseline/candidate scores for
    the same cases. Version 1 remains parseable for dry-run analysis, but
    :func:`review_and_promote` refuses it for a live transition.
    """
    try:
        raw_bytes = atomic_read_bytes(Path(path))
        raw = raw_bytes.decode("utf-8")
        doc = _evidence_json(raw)
    except (OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"factory evidence is unreadable or invalid: {exc}") from exc
    if not isinstance(doc, dict) or isinstance(doc.get("version"), bool):
        raise ValueError("factory evidence must be a versioned object")
    source_sha256 = _sha256_bytes(raw_bytes)
    if doc.get("version") == 1:
        return _load_v1_evidence(doc, source_sha256=source_sha256)
    if doc.get("version") != 2:
        raise ValueError("factory evidence must use version 2 for live promotion")
    if set(doc) != {"version", "provenance", "corrections", "evidence_sha256"}:
        raise ValueError("factory evidence v2 contains missing or unexpected fields")

    claimed_digest = _valid_sha256(doc["evidence_sha256"])
    payload = {
        "version": doc["version"],
        "provenance": doc["provenance"],
        "corrections": doc["corrections"],
    }
    actual_digest = _sha256_bytes(_canonical_json(payload).encode("utf-8"))
    if claimed_digest != actual_digest:
        raise ValueError("factory evidence digest mismatch (evidence was tampered)")

    raw_provenance = doc["provenance"]
    required_provenance = {
        *_EVIDENCE_PROVENANCE_HASHES, "run_id", "producer", "source",
    }
    if not isinstance(raw_provenance, dict) or set(raw_provenance) != required_provenance:
        raise ValueError("factory evidence provenance is incomplete or contains unknown fields")
    provenance: dict[str, Any] = {
        field_name: _valid_sha256(raw_provenance[field_name])
        for field_name in _EVIDENCE_PROVENANCE_HASHES
    }
    for field_name in ("run_id", "producer"):
        label = _bounded_label(
            raw_provenance[field_name], field_name=field_name, max_length=128)
        if not _EVIDENCE_ID_RE.fullmatch(label):
            raise ValueError(f"evidence provenance {field_name} is invalid")
        provenance[field_name] = label
    provenance["source"] = _bounded_label(
        raw_provenance["source"], field_name="source", max_length=512)

    raw_rows = doc["corrections"]
    if not isinstance(raw_rows, dict) or not raw_rows or len(raw_rows) > 10_000:
        raise ValueError("factory evidence corrections must be a non-empty object")
    # Control the family-wise false-promotion rate across every correction in
    # this evidence bundle, not merely the per-candidate error rate.
    bound_alpha = 0.05 / len(raw_rows)
    measured: dict[str, FactoryEvidenceResult] = {}
    for raw_key, value in raw_rows.items():
        key = _correction_evidence_key(raw_key)
        expected_row_fields = {
            "cases", "baseline_prompt_sha256", "candidate_prompt_sha256",
        }
        if not isinstance(value, dict) or set(value) != expected_row_fields:
            raise ValueError(f"{key}: evidence row contains missing or unexpected fields")
        baseline_prompt = _valid_sha256(value["baseline_prompt_sha256"])
        candidate_prompt = _valid_sha256(value["candidate_prompt_sha256"])
        if baseline_prompt == candidate_prompt:
            raise ValueError(f"{key}: candidate prompt hash must differ from baseline")
        cases = value["cases"]
        if not isinstance(cases, list) or not 2 <= len(cases) <= 10_000:
            raise ValueError(f"{key}: cases must contain 2..10000 paired results")
        case_ids: list[str] = []
        seen_ids: set[str] = set()
        baseline: list[float] = []
        candidate: list[float] = []
        for case in cases:
            if not isinstance(case, dict) or set(case) != {
                "case_id", "baseline", "candidate",
            }:
                raise ValueError(f"{key}: each paired case must have case_id/baseline/candidate")
            case_id = str(case["case_id"] or "")
            if (not _EVIDENCE_ID_RE.fullmatch(case_id)
                    or case_id in seen_ids or ".." in case_id or "//" in case_id):
                raise ValueError(f"{key}: case IDs must be unique safe identifiers")
            seen_ids.add(case_id)
            case_ids.append(case_id)
            baseline.append(_score(case["baseline"], key=key, arm="baseline"))
            candidate.append(_score(case["candidate"], key=key, arm="candidate"))
        result_provenance = {
            **provenance,
            "baseline_prompt_sha256": baseline_prompt,
            "candidate_prompt_sha256": candidate_prompt,
            "case_ids_sha256": _sha256_bytes(
                _canonical_json(case_ids).encode("utf-8")),
            "effect_bound": {
                "method": "paired_empirical_bernstein",
                "family_size": len(raw_rows),
                "alpha": bound_alpha,
            },
        }
        measured[key] = FactoryEvidenceResult(
            baseline_score=sum(baseline) / len(baseline),
            candidate_score=sum(candidate) / len(candidate),
            samples=len(baseline),
            effect_ci_low=_paired_effect_lcb(
                baseline, candidate, alpha=bound_alpha),
            evidence_sha256=actual_digest,
            source_sha256=source_sha256,
            provenance=result_provenance,
        )
    return MeasuredFactoryEvidence(
        version=2, evidence_sha256=actual_digest, source_sha256=source_sha256,
        provenance=provenance, rows=measured,
    )


@dataclass(frozen=True)
class _CorrectionArtifact:
    entries: dict[str, dict[str, Any]]
    generation: int
    raw: bytes | None
    version: str


def _artifact_evidence(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    expected = {
        "evidence_sha256", "source_sha256", "effect_ci_low", "samples", "provenance",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("correction artifact evidence metadata is invalid")
    evidence_digest = _valid_sha256(value["evidence_sha256"])
    source_digest = _valid_sha256(value["source_sha256"])
    samples = value["samples"]
    effect_ci_low = value["effect_ci_low"]
    if (not isinstance(samples, int) or isinstance(samples, bool)
            or not 1 <= samples <= 10_000):
        raise ValueError("correction artifact evidence sample count is invalid")
    if (not isinstance(effect_ci_low, (int, float))
            or isinstance(effect_ci_low, bool)
            or not math.isfinite(float(effect_ci_low))
            or not -1.0 <= float(effect_ci_low) <= 1.0):
        raise ValueError("correction artifact evidence confidence bound is invalid")
    provenance = value["provenance"]
    if not isinstance(provenance, dict):
        raise ValueError("correction artifact evidence provenance is invalid")
    canonical_provenance = _canonical_json(provenance)
    if len(canonical_provenance.encode("utf-8")) > 32_768:
        raise ValueError("correction artifact evidence provenance is too large")
    return {
        "evidence_sha256": evidence_digest,
        "source_sha256": source_digest,
        "effect_ci_low": float(effect_ci_low),
        "samples": samples,
        "provenance": json.loads(canonical_provenance),
    }


def _artifact_entry(value: object, *, canonical: bool) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    allowed = {"scope", "signal", "detail", "support", "evidence"}
    if canonical and not set(value) <= allowed:
        return None
    correction = _validated_correction(
        scope=value.get("scope"), signal=value.get("signal"),
        detail=value.get("detail"), support=value.get("support"),
    )
    if correction is None:
        return None
    entry: dict[str, Any] = {
        "scope": correction.scope,
        "signal": correction.signal,
        "detail": correction.detail,
        "support": correction.support,
    }
    if canonical and "evidence" in value:
        try:
            evidence = _artifact_evidence(value["evidence"])
        except (TypeError, ValueError):
            return None
        if evidence is not None:
            entry["evidence"] = evidence
    return entry


def _entry_correction(entry: dict[str, Any]) -> ProposerCorrection | None:
    return _validated_correction(**{
        name: entry[name] for name in ("scope", "signal", "detail", "support")
    })


def _parse_canonical_correction_artifact(
    doc: dict[str, object], raw: bytes, *, strict: bool,
) -> tuple[dict[str, dict[str, Any]], int, str]:
    if set(doc) != {"artifact_version", "generation", "corrections"}:
        if strict:
            raise ValueError("correction artifact contains unexpected fields")
        return {}, 0, f"corrupt:{_sha256_bytes(raw)}"
    generation = doc["generation"]
    rows = doc["corrections"]
    if (not isinstance(generation, int) or isinstance(generation, bool)
            or generation < 1 or not isinstance(rows, list)
            or len(rows) > _MAX_OUTCOME_ROWS):
        if strict:
            raise ValueError("correction artifact metadata is invalid")
        return {}, 0, f"corrupt:{_sha256_bytes(raw)}"
    entries: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = _artifact_entry(row, canonical=True)
        correction = _entry_correction(entry) if entry is not None else None
        if correction is None:
            if strict:
                raise ValueError("correction artifact contains an invalid correction")
            continue
        if correction.key() in entries:
            if strict:
                raise ValueError("correction artifact contains duplicate corrections")
            continue
        entries[correction.key()] = entry
    return entries, generation, f"v2:{generation}"


def _parse_legacy_correction_artifact(
    text: str, raw: bytes, *, strict: bool,
) -> tuple[dict[str, dict[str, Any]], int, str]:
    entries: dict[str, dict[str, Any]] = {}
    saw_line = False
    for line in text.splitlines():
        if not line.strip():
            continue
        saw_line = True
        try:
            row = _evidence_json(line)
        except (json.JSONDecodeError, TypeError, ValueError):
            row = None
        entry = _artifact_entry(row, canonical=False)
        correction = _entry_correction(entry) if entry is not None else None
        if correction is None:
            if strict:
                raise ValueError("legacy correction artifact contains an invalid row")
            continue
        entries[correction.key()] = entry
    if not saw_line and strict:
        raise ValueError("existing correction artifact is empty")
    return entries, 0, f"legacy:{_sha256_bytes(raw)}"


def _parse_correction_artifact(
    raw: bytes | None, *, strict: bool,
) -> tuple[dict[str, dict[str, Any]], int, str]:
    if raw is None:
        return {}, 0, "absent:0"
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        if strict:
            raise ValueError("correction artifact is not UTF-8") from exc
        return {}, 0, f"corrupt:{_sha256_bytes(raw)}"
    try:
        doc = _evidence_json(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        doc = None
    if isinstance(doc, dict) and doc.get("artifact_version") == _CORRECTION_ARTIFACT_VERSION:
        return _parse_canonical_correction_artifact(doc, raw, strict=strict)

    # Backward-compatible reader for the historical NDJSON artifact.  A live
    # mutation treats any malformed legacy line as corruption and refuses to
    # overwrite it; the prompt read path remains fail-soft and drops bad rows.
    return _parse_legacy_correction_artifact(text, raw, strict=strict)


def _load_correction_artifact(path: Path, *, strict: bool) -> _CorrectionArtifact:
    try:
        info = path.lstat()
    except FileNotFoundError:
        entries, generation, version = _parse_correction_artifact(None, strict=strict)
        return _CorrectionArtifact(entries, generation, None, version)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("correction artifact must be a regular file")
    ensure_private_file(path)
    raw = atomic_read_bytes(path)
    entries, generation, version = _parse_correction_artifact(raw, strict=strict)
    return _CorrectionArtifact(entries, generation, raw, version)


def _artifact_revision(path: Path, state: _CorrectionArtifact):
    from .self_improvement import ArtifactRevision

    identity = f"factory-corrections:{os.path.normcase(os.path.abspath(path))}"
    return ArtifactRevision(
        identity=identity,
        sha256=_sha256_bytes(state.raw or b""),
        version=state.version,
    )


def _serialize_correction_artifact(
    entries: dict[str, dict[str, Any]], *, generation: int,
) -> bytes:
    doc = {
        "artifact_version": _CORRECTION_ARTIFACT_VERSION,
        "generation": generation,
        "corrections": [entries[key] for key in sorted(entries)],
    }
    return (_canonical_json(doc) + "\n").encode("utf-8")


def _next_artifact(
    before: _CorrectionArtifact, correction: ProposerCorrection,
    evidence: FactoryEvidenceResult | None,
) -> _CorrectionArtifact:
    entries = dict(before.entries)
    entry: dict[str, Any] = {
        "scope": correction.scope,
        "signal": correction.signal,
        "detail": correction.detail,
        "support": correction.support,
    }
    if evidence is not None:
        entry["evidence"] = {
            "evidence_sha256": evidence.evidence_sha256,
            "source_sha256": evidence.source_sha256,
            "effect_ci_low": evidence.effect_ci_low,
            "samples": evidence.samples,
            "provenance": evidence.provenance,
        }
    entries[correction.key()] = entry
    generation = max(0, before.generation) + 1
    raw = _serialize_correction_artifact(entries, generation=generation)
    return _CorrectionArtifact(entries, generation, raw, f"v2:{generation}")


def _cas_install_locked(
    path: Path, *, before: _CorrectionArtifact, after: _CorrectionArtifact,
    effect_guard=None,
) -> _CorrectionArtifact:
    current = _load_correction_artifact(path, strict=True)
    if _artifact_revision(path, current) != _artifact_revision(path, before):
        raise RuntimeError("correction artifact changed before CAS apply")
    if after.raw is None:  # pragma: no cover - next artifacts always have bytes
        raise RuntimeError("correction artifact after-state has no bytes")
    def guard():
        if effect_guard is not None:
            effect_guard()
        if _artifact_revision(path, _load_correction_artifact(path, strict=True)) != _artifact_revision(path, before):
            raise RuntimeError("correction artifact changed before physical apply")
    if effect_guard is None:
        atomic_write_bytes(path, after.raw, mode=0o600)
    else:
        atomic_write_bytes(path, after.raw, mode=0o600, effect_guard=guard)
    observed = _load_correction_artifact(path, strict=True)
    if _artifact_revision(path, observed) != _artifact_revision(path, after):
        raise RuntimeError("correction artifact readback differs from prepared intent")
    return observed


def _cas_restore_locked(
    path: Path, *, before: _CorrectionArtifact, after: _CorrectionArtifact,
    effect_guard=None,
) -> bool:
    current = _load_correction_artifact(path, strict=True)
    if _artifact_revision(path, current) != _artifact_revision(path, after):
        return False
    def guard():
        if effect_guard is not None:
            effect_guard()
        if _artifact_revision(path, _load_correction_artifact(path, strict=True)) != _artifact_revision(path, after):
            raise RuntimeError("guidance changed before physical restoration")
    if before.raw is None:
        guard()
        path.unlink()
    elif effect_guard is None:
        atomic_write_bytes(path, before.raw, mode=0o600)
    else:
        atomic_write_bytes(path, before.raw, mode=0o600, effect_guard=guard)
    restored = _load_correction_artifact(path, strict=True)
    return _artifact_revision(path, restored) == _artifact_revision(path, before)


def promoted_corrections(*, path: Path | None = None) -> list[ProposerCorrection]:
    """Corrections in the deployed artifact; prompt reads fail soft on damage."""
    path = path if path is not None else corrections_path()
    try:
        with cross_process_lock(path):
            state = _load_correction_artifact(path, strict=False)
    except (OSError, RuntimeError, TypeError, ValueError):
        return []
    corrections: list[ProposerCorrection] = []
    for entry in state.entries.values():
        correction = _entry_correction(entry)
        if correction is not None:
            corrections.append(correction)
    return corrections


def _recover_artifact_locked(controller, path: Path, si) -> _CorrectionArtifact:
    state = _load_correction_artifact(path, strict=True)
    initial_revision = _artifact_revision(path, state)

    def inspect(identity: str):
        observed = _load_correction_artifact(path, strict=True)
        revision = _artifact_revision(path, observed)
        if identity != revision.identity:
            raise si.PromotionLedgerError("unexpected correction artifact identity")
        return revision

    recovered = controller.recover_promotions(
        inspect, artifact_identity=initial_revision.identity)
    if any(getattr(transaction, "in_doubt", False) for transaction in recovered):
        raise si.PromotionLedgerError(
            "unresolved correction promotion blocks new writes")
    return _load_correction_artifact(path, strict=True)


def _factory_candidate(
    correction: ProposerCorrection, evidence: FactoryEvidenceResult,
    *, before_revision, after_revision, si,
):
    receipt_provenance = {
        "source": "factory_learning",
        "correction_key": correction.key(),
        "evidence_sha256": evidence.evidence_sha256,
        "evidence_source_sha256": evidence.source_sha256,
        "evidence": evidence.provenance,
    }
    return si.Candidate(
        rung="prompt",
        summary=(f"factory guidance [{correction.scope}/"
                 f"{correction.signal}]: {correction.detail}"),
        baseline_score=evidence.baseline_score,
        candidate_score=evidence.candidate_score,
        samples=evidence.samples,
        effect_ci_low=evidence.effect_ci_low,
        payload={
            "correction_key": correction.key(),
            "artifact_identity": before_revision.identity,
            "before_sha256": before_revision.sha256,
            "after_sha256": after_revision.sha256,
            "evidence_sha256": evidence.evidence_sha256,
        },
        capability_widens=False,
        rollback={
            "action": "cas_restore_factory_corrections",
            "artifact_identity": before_revision.identity,
            "before_sha256": before_revision.sha256,
            "after_sha256": after_revision.sha256,
        },
        provenance=receipt_provenance,
    )


def _abort_failed_apply_locked(
    controller, preparation, path: Path, *, before: _CorrectionArtifact,
    after: _CorrectionArtifact,
) -> bool:
    """Restore exact-before and durably ABORT, or leave PREPARE for recovery."""
    before_revision = _artifact_revision(path, before)
    after_revision = _artifact_revision(path, after)
    try:
        observed = _load_correction_artifact(path, strict=True)
        observed_revision = _artifact_revision(path, observed)
        if observed_revision == after_revision:
            if not _cas_restore_locked(path, before=before, after=after):
                return False
            observed_revision = _artifact_revision(
                path, _load_correction_artifact(path, strict=True))
        if observed_revision != before_revision:
            return False
        controller.abort_prepared(
            preparation, artifact=before_revision,
            reason="factory correction artifact application failed")
        ledger = getattr(controller, "ledger", None)
        transaction = (
            ledger.transaction(preparation.transaction_id)
            if ledger is not None and preparation.transaction_id is not None else None
        )
        return transaction is not None and transaction.state == "aborted"
    except Exception:
        log.warning(
            "factory_learning: artifact rollback is in doubt; recovery required",
            exc_info=True,
        )
        return False


def _promote_one_locked(
    controller, path: Path, state: _CorrectionArtifact,
    correction: ProposerCorrection, evidence: FactoryEvidenceResult, si,
    *, effect_guard=None, operation=None, provenance=None, strict=False,
) -> tuple[_CorrectionArtifact, str]:
    before = state
    after = _next_artifact(before, correction, evidence)
    before_revision = _artifact_revision(path, before)
    after_revision = _artifact_revision(path, after)
    candidate = _factory_candidate(
        correction, evidence, before_revision=before_revision,
        after_revision=after_revision, si=si)
    if provenance is not None:
        candidate.provenance.update(provenance)
    if operation is not None:
        candidate.id = "factory:" + operation
        candidate.provenance["factory_restore_before"] = _protected_preimage(before)
        si._receipt_provenance(candidate.provenance)
    if effect_guard is not None:
        effect_guard()
    check_learning_halt("factory_learning", "promotion")
    preparation = controller.prepare_promotion(
        candidate, before=before_revision, after=after_revision,
        **({"transaction_id": "factory:" + operation} if operation is not None else {}))
    if not preparation.ok:
        return state, "skipped"
    if preparation.committed:
        observed = _load_correction_artifact(path, strict=True)
        if _artifact_revision(path, observed) != after_revision:
            return state, "stop"
        return observed, "promoted"
    if not preparation.needs_apply:
        return state, "stop"
    try:
        check_learning_halt("factory_learning", "apply")
        if effect_guard is not None:
            effect_guard()
        authorization = controller.authorize_prepared(
            preparation,
            artifact=before_revision,
        )
        if not authorization.ok:
            return state, "skipped"
        observed = _cas_install_locked(path, before=before, after=after, effect_guard=effect_guard)
    except Halted:
        # PREPARE is durable, so a HALT that lands at the final apply boundary
        # must close that transaction while the exact before revision is still
        # provably live.  Never translate the operator interlock into an
        # ordinary skipped candidate: callers need to distinguish HALT.
        recovered = _abort_failed_apply_locked(
            controller, preparation, path, before=before, after=after)
        if not recovered:
            log.warning(
                "factory_learning: HALT left correction transaction in doubt for %s",
                correction.key(),
            )
        raise
    except Exception as exc:
        log.warning(
            "factory_learning: correction artifact apply failed for %s: %s",
            correction.key(), exc,
        )
        recovered = _abort_failed_apply_locked(
            controller, preparation, path, before=before, after=after)
        if strict:
            raise
        return (before, "skipped") if recovered else (state, "stop")
    if effect_guard is not None:
        effect_guard()
    verdict = controller.commit_prepared(
        preparation, artifact=_artifact_revision(path, observed))
    if not verdict.ok:
        # Exact-after stays deployed with its durable PREPARE. A retry recovers
        # COMMIT; reverting could contradict a commit whose ACK alone was lost.
        return observed, "stop"
    return observed, "promoted"


def promote_reviewed_correction(
    correction: ProposerCorrection, evidence: FactoryEvidenceResult, *,
    expected_sha256: str, operation: str, provenance: dict, effect_guard,
) -> dict:
    """One selected correction through the unchanged governed promotion writer.

    The request's callback checks current authority/source at the physical
    artifact replacement. Historical receipt reads never call this function.
    """
    from . import self_improvement as si
    if not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise ValueError("invalid reviewed factory operation")
    if not enabled():
        raise ValueError("factory learning is disabled")
    path = corrections_path()
    with _lock, cross_process_lock(path, strict=True):
        effect_guard()
        controller = si.shared()
        if controller.ledger.transaction("factory:" + operation) is not None:
            raise RuntimeError("read the original reviewed factory transaction")
        state = _recover_artifact_locked(controller, path, si)
        if _artifact_revision(path, state).sha256 != expected_sha256:
            raise RuntimeError("reviewed factory guidance changed")
        if correction.key() in state.entries:
            raise ValueError("this correction is already adopted")
        state, disposition = _promote_one_locked(
            controller, path, state, correction, evidence, si,
            effect_guard=effect_guard, operation=operation, provenance=provenance, strict=True)
        transaction = controller.ledger.transaction("factory:" + operation)
        return {"adopted": disposition == "promoted", "disposition": disposition,
                "transaction": transaction.id if transaction else None,
                "transaction_state": transaction.state if transaction else None}



def _protected_preimage(state):
    from . import crypto_at_rest
    if state.raw is None:
        return {"absent": True}
    # The selected addition is absent before adoption. Removing that one entry
    # reproduces a canonical previous edition without retaining lifetime copies.
    if state.version.startswith("v2:") and state.raw == _serialize_correction_artifact(state.entries, generation=state.generation):
        return {"canonical": True}
    if len(state.raw) > 16000:
        raise ValueError("The complete earlier guidance exceeds protected restoration retention. Nothing was adopted.")
    sealed = crypto_at_rest.seal_to_str(state.raw.decode("utf-8"))
    if not crypto_at_rest.is_sealed_str(sealed):
        raise ValueError("Earlier guidance could not be protected for restoration. Nothing was adopted.")
    return {"sealed": sealed}


def _restore_before(path, transaction, current):
    from . import crypto_at_rest
    value = transaction.record.provenance.get("factory_restore_before")
    if isinstance(value, dict) and set(value) == {"sealed"} and crypto_at_rest.is_sealed_str(value["sealed"]):
        raw = crypto_at_rest.unseal_from_str(value["sealed"]).encode("utf-8")
        if len(raw) > 16000:
            raise ValueError("The complete earlier guidance exceeds its protected retention bound.")
    elif transaction.before.version == "absent:0":
        raw = None
    elif _artifact_revision(path, current) == transaction.before:
        raw = current.raw
    elif transaction.before.version.startswith("v2:"):
        entries = dict(current.entries)
        key = transaction.record.provenance.get("correction_key")
        if key not in entries:
            raise ValueError("The exact earlier guidance is unavailable.")
        entries.pop(key)
        generation = int(transaction.before.version[3:])
        raw = _serialize_correction_artifact(entries, generation=generation)
    else:
        raise ValueError("The exact earlier guidance was not retained for this older adoption. It cannot be safely restored here.")
    entries, generation, version = _parse_correction_artifact(raw, strict=True)
    before = _CorrectionArtifact(entries, generation, raw, version)
    if _artifact_revision(path, before) != transaction.before:
        raise ValueError("The exact earlier guidance could not be verified. Nothing can be restored.")
    return before


def _restoration_plan_locked(controller, path, *, actor, workspace, adoption=None):
    current = _load_correction_artifact(path, strict=True)
    revision = _artifact_revision(path, current)
    if controller.ledger.in_doubt(artifact_identity=revision.identity):
        raise RuntimeError("An earlier guidance adoption is still unconfirmed. Read its original before restoring.")
    owned = [tx for tx in controller.ledger.transactions(artifact_identity=revision.identity, state="committed")
             if not tx.record.rolled_back and
             (tx.record.provenance.get("factory_actor"), tx.record.provenance.get("factory_workspace")) == (actor, workspace)]
    if not owned:
        raise ValueError("No active successful guidance adoption owned by this account is available to restore.")
    tx = owned[-1]
    if adoption is not None and tx.record.provenance.get("factory_operation") != adoption:
        raise RuntimeError("The latest owned guidance adoption changed. Review current guidance again.")
    if revision not in {tx.after, tx.before}:
        raise RuntimeError("Guidance changed after this adoption. Restoring it would overwrite later work, so nothing can be restored.")
    before = _restore_before(path, tx, current)
    return tx, before, current, "restore" if revision == tx.after else "acknowledge"


def restoration_plan(*, actor, workspace, adoption=None):
    """Pure exact-current preview; never repairs, restores or appends a receipt."""
    from . import self_improvement as si
    path = corrections_path()
    with _lock, cross_process_lock(path, strict=True):
        tx, before, current, mode = _restoration_plan_locked(si.shared(), path, actor=actor, workspace=workspace, adoption=adoption)
        return _restoration_summary(path, tx, before, current, mode)


def _restoration_summary(path, tx, before, current, mode):
    return {"adoption": tx.record.provenance["factory_operation"], "transaction": tx.id,
            "artifact": _artifact_revision(path, current).to_dict(), "before": tx.before.to_dict(),
            "mode": mode, "adopted_at": tx.record.promoted_at,
            "current": [_entry_correction(current.entries[key]).guidance for key in sorted(current.entries)],
            "earlier": [_entry_correction(before.entries[key]).guidance for key in sorted(before.entries)]}


def restore_reviewed_correction(*, actor, workspace, adoption, operation, expected_plan, effect_guard):
    """Restore one exact latest owned artifact and durably record its new decision.

    A failure between byte replacement and receipt leaves the original unconfirmed.
    A separately reviewed acknowledgement can append the receipt without rewriting.
    """
    from . import self_improvement as si
    if not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise ValueError("invalid reviewed restoration operation")
    path = corrections_path()
    with _lock, cross_process_lock(path, strict=True):
        effect_guard()
        controller = si.shared()
        tx, before, current, mode = _restoration_plan_locked(controller, path, actor=actor, workspace=workspace, adoption=adoption)
        plan = _restoration_summary(path, tx, before, current, mode)
        if plan != expected_plan:
            raise RuntimeError("The reviewed restoration changed. Nothing new was restored.")
        if mode == "restore" and not _cas_restore_locked(path, before=before, after=current, effect_guard=effect_guard):
            raise RuntimeError("The guidance restoration is unconfirmed. Read its original before another decision.")
        def guard_receipt():
            effect_guard()
            if _artifact_revision(path, _load_correction_artifact(path, strict=True)) != tx.before:
                raise RuntimeError("Restored guidance changed before its receipt. The original remains unconfirmed.")
        metadata = {"factory_restore_operation": operation, "factory_actor": actor,
                    "factory_workspace": workspace, "factory_adoption": adoption, "mode": mode}
        if not controller.ledger.mark_rolled_back(tx.record.id, at=time.time(), effect_guard=guard_receipt, rollback_metadata=metadata):
            raise RuntimeError("The original restoration receipt is unconfirmed. Nothing will be repeated automatically.")
        controller._flush_audit_outbox()
        return {"restored": True, "complete": True, "mode": mode}


def restoration_receipt(*, actor, workspace, operation):
    """Metadata-only pure original read, independent of recent task retention."""
    from . import self_improvement as si
    for record in si.shared().ledger.all():
        value = record.provenance.get("rollback_receipt")
        if isinstance(value, dict) and value.get("factory_restore_operation") == operation:
            if (value.get("factory_actor"), value.get("factory_workspace")) != (actor, workspace):
                raise PermissionError("This original restoration belongs to another account or workspace.")
            return {"restored": record.rolled_back, "complete": record.rolled_back, "mode": value["mode"]}
    return None


def review_and_promote(
    *, min_support: int = 3, controller: Any = None, scorer=None,
    total_packs: int | None = None, promoted_path: Path | None = None,
) -> list[ProposerCorrection]:
    """Govern, transactionally install, and receipt measured corrections.

    Live promotion accepts only strict v2 :class:`MeasuredFactoryEvidence`.
    Under the correction artifact's cross-process lock it first reconciles any
    crash-left PREPARE, then computes exact before/after digests and generations,
    durably PREPAREs through the configured/shared controller, CAS-installs the
    artifact, and COMMITs the hash-chained receipt.  Apply failures restore the
    exact before bytes when that is still provable; ambiguous states remain
    visibly in doubt for deterministic recovery.
    """
    if not enabled():
        return []
    check_learning_halt("factory_learning", "start")
    promoted_path = promoted_path if promoted_path is not None else corrections_path()
    corrections = mine_corrections(min_support=min_support)
    if not corrections:
        return []
    if not isinstance(scorer, MeasuredFactoryEvidence) or not scorer.live_eligible:
        log.warning(
            "factory_learning: refusing live promotion without strict self-digested "
            "version-2 paired evidence",
        )
        return []
    try:
        from . import self_improvement as si
        if controller is None:
            controller = si.shared()
    except Halted:
        raise
    except Exception as e:  # pragma: no cover -- can't build the gate -> fail closed
        log.debug("factory_learning: controller unavailable: %s", e)
        return []

    # Retained for API compatibility. Evidence v2 supplies the real paired
    # sample count; outcome recurrence can propose but never score a candidate.
    _ = total_packs
    promoted: list[ProposerCorrection] = []
    with _lock:
        try:
            with cross_process_lock(promoted_path):
                state = _recover_artifact_locked(controller, promoted_path, si)
                for proposed in corrections:
                    correction = _validated_correction(
                        scope=proposed.scope, signal=proposed.signal,
                        detail=proposed.detail, support=proposed.support,
                    )
                    if correction is None:
                        if proposed.signal == SIGNAL_ENVELOPE_WIDENED:
                            log.warning(
                                "factory_learning: envelope correction %s requires explicit "
                                "authority review; automatic promotion skipped", proposed.key(),
                            )
                        continue
                    if correction.key() in state.entries:
                        continue
                    try:
                        check_learning_halt("factory_learning", "evaluation")
                        evidence = scorer(correction)
                    except (TypeError, ValueError) as exc:
                        log.warning(
                            "factory_learning: evidence unavailable for %s: %s",
                            correction.key(), exc,
                        )
                        continue
                    if evidence.effect_ci_low is None:
                        log.warning(
                            "factory_learning: correction %s has no paired confidence bound",
                            correction.key(),
                        )
                        continue
                    state, disposition = _promote_one_locked(
                        controller, promoted_path, state, correction, evidence, si)
                    if disposition == "promoted":
                        promoted.append(correction)
                    elif disposition == "stop":
                        return promoted
        except Halted:
            raise
        except Exception as exc:
            log.warning("factory_learning: governed promotion failed closed: %s", exc)
            return promoted
    return promoted


def _distinct_pack_count(*, path: Path | None = None) -> int:
    return len({o.pack for o in load_outcomes(path=path)}) or 1


# --------------------------------------------------------------------------
# application: fold promoted guidance into a generator's system prompt
# --------------------------------------------------------------------------
def guidance_block(suite: str | None = None) -> str:
    """The promoted-guidance addendum for ``suite`` (and global), or "".

    Returns "" while disabled, so a caller can unconditionally append it.
    Scope-matched: a finance proposer sees finance + global corrections, never
    another suite's. Capped so a long history can't bloat the system prompt.
    """
    if not enabled():
        return ""
    scope = _safe_suite(suite or "")
    if scope is None:
        return ""
    items = [
        c for c in promoted_corrections()
        if c.scope == _GLOBAL_SCOPE or (scope and c.scope == scope)
    ]
    if not items:
        return ""
    items.sort(key=lambda c: -c.support)
    lines = [f"- {c.guidance}" for c in items[:_MAX_GUIDANCE_ITEMS] if c.guidance]
    if not lines:
        return ""
    return ("\nLearned from packs this factory has already produced (apply when "
            "relevant):\n" + "\n".join(lines))


def augment_system_prompt(base_system: str, *, suite: str | None = None) -> str:
    """Append promoted factory guidance to a proposer system prompt. Identity
    while disabled or when there's nothing promoted (default deployments are
    byte-identical)."""
    block = guidance_block(suite)
    return f"{base_system}\n{block}" if block else base_system


__all__ = [
    "FactoryOutcome", "ProposerCorrection",
    "SIGNAL_TOOL_MISSING", "SIGNAL_SKILL_GAP", "SIGNAL_ENVELOPE_WIDENED",
    "enabled", "outcomes_path", "corrections_path",
    "record_outcome", "load_outcomes", "record_provisioning",
    "mine_corrections", "review_and_promote", "promoted_corrections",
    "load_measured_evidence",
    "guidance_block", "augment_system_prompt",
]
