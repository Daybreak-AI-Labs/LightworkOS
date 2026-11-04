"""Identity and state records for a single evolution experiment.

The runner retains the established imports for compatibility. These records
are deliberately independent of calibration, authorization and execution so a
comparison cannot accidentally hold live agent or archive handles. Case
snapshots contain copied, mutable EvalCase entries and remain internal.
"""
from __future__ import annotations

import json
import re
import secrets
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from hashlib import sha256

from .archive import Candidate
from .eval_harness import EvalCase

_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")


def _confirmation_request_digest(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _normalized_prompt_identity(prompt: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", prompt).split()).casefold()


@dataclass(frozen=True)
class ConfirmationRequest:
    """One nonce-bound request to expose a sealed confirmation family.

    The externally supplied family and evaluator digests bind semantics that
    Python callables cannot be fingerprinted reliably.  Candidate identities,
    the distinct case count, and a fresh nonce prevent a permit from being
    replayed for another comparison.
    """

    seed_candidate_id: str
    champion_candidate_id: str
    case_family_id: str
    case_snapshot_sha256: str
    evaluator_id: str
    case_count: int
    request_id: str = field(default_factory=lambda: secrets.token_hex(16))
    request_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for label, value in (
            ("seed_candidate_id", self.seed_candidate_id),
            ("champion_candidate_id", self.champion_candidate_id),
            ("case_family_id", self.case_family_id),
            ("case_snapshot_sha256", self.case_snapshot_sha256),
            ("evaluator_id", self.evaluator_id),
        ):
            if not isinstance(value, str) or not _HEX_256.fullmatch(value):
                raise ValueError(f"{label} must be a lowercase SHA-256 digest")
        if (not isinstance(self.case_count, int) or isinstance(self.case_count, bool)
                or self.case_count <= 0):
            raise ValueError("case_count must be a positive integer")
        if not isinstance(self.request_id, str) or not _REQUEST_ID.fullmatch(
                self.request_id):
            raise ValueError("request_id must be a 128-bit lowercase hex nonce")
        payload = {
            "version": 1,
            "request_id": self.request_id,
            "seed_candidate_id": self.seed_candidate_id,
            "champion_candidate_id": self.champion_candidate_id,
            "case_family_id": self.case_family_id,
            "case_snapshot_sha256": self.case_snapshot_sha256,
            "evaluator_id": self.evaluator_id,
            "case_count": self.case_count,
        }
        object.__setattr__(
            self, "request_sha256", _confirmation_request_digest(payload))


@dataclass(frozen=True)
class ConfirmationPermit:
    """A short-lived durable-authority receipt for one exact request."""

    request_sha256: str
    critical_z: float
    authorization_id: str
    ledger_tip_sha256: str
    issued_at: float
    expires_at: float


ConfirmationAuthorize = Callable[[ConfirmationRequest], ConfirmationPermit]


@dataclass(frozen=True)
class _ConfirmationPlan:
    """Validated confirmation inputs, kept separate from development search."""

    cases: tuple[EvalCase, ...] | None
    minimum_cases: int
    confidence_z: float


@dataclass(frozen=True)
class _CandidateSnapshot:
    """Exact content-addressed candidate captured before sealed authorization."""

    candidate_id: str
    config_json: str
    score: float

    @classmethod
    def capture(cls, candidate: Candidate) -> _CandidateSnapshot:
        candidate.validate_identity()
        # Candidate enforces the archive's canonical JSON constraints and
        # detaches nested values. Keep immutable bytes across callbacks/awaits.
        detached = Candidate(candidate.config, score=candidate.score, id=candidate.id)
        return cls(detached.id, json.dumps(detached.config, sort_keys=True,
                                          allow_nan=False), detached.score)

    def config_copy(self) -> dict:
        return json.loads(self.config_json)

    def matches_config(self, config: dict) -> bool:
        try:
            return Candidate(config, id=self.candidate_id).id == self.candidate_id
        except (TypeError, ValueError, OverflowError, RecursionError):
            return False

    def matches(self, candidate: Candidate) -> bool:
        try:
            candidate.validate_identity()
            return (candidate.id == self.candidate_id
                    and float(candidate.score) == self.score)
        except (TypeError, ValueError, OverflowError, RecursionError):
            return False

    def original_or_copy(self, candidate: Candidate) -> Candidate:
        if self.matches(candidate):
            return candidate
        return Candidate(self.config_copy(), score=self.score, id=self.candidate_id)


@dataclass(frozen=True)
class _ConfirmationAdmission:
    """One authorized comparison and its effective statistical threshold."""

    comparison_id: str
    confidence_z: float


@dataclass(frozen=True)
class _PairedEvidence:
    """Private evidence for one comparison, never passed to development."""

    seed_scores: tuple[float, ...]
    champion_scores: tuple[float, ...]
    execution_failed: bool


@dataclass(frozen=True)
class _ExperimentRequest:
    """Detached inputs shared by development and one confirmation decision."""

    seed: _CandidateSnapshot
    development_cases: tuple[EvalCase, ...]
    confirmation: _ConfirmationPlan
