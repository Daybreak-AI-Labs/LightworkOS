"""Durable query accounting for a sealed Self-Harness confirmation set.

This module is deliberately independent of :mod:`maverick.self_harness`.  It is
the storage and authorization boundary that a risk-limited evaluator can call
*before* exposing a sealed holdout to either A/B arm.

Properties
----------

* The ledger must be explicitly provisioned. Runtime use opens it read/write but
  never recreates a missing file, so deletion fails closed instead of resetting
  the budget.
* SQLite ``BEGIN IMMEDIATE`` serializes the verify-budget-append transaction
  across threads and processes on supported local filesystems.
* Every immutable policy, query, boundary-attempt, and final-set retirement event
  is SHA-256 linked. A transactionally stored tip and event count expose row
  edits, gaps, reordering, and tail truncation.
* A query is charged before results are observed. There are no refunds; a failed
  arm or crashed evaluator still consumed one access.
* Query, nominal alpha, provider-call, token, dollar, and compute reservations
  are committed in the same SQLite transaction. Finalization replaces the
  reservation with observed cost; an over-reservation result is withheld.
* Every new query must bind an exact final-set digest and preregistered protocol.
  Reservation is atomic with charging, and the same physical set cannot be
  presented again under a revised candidate, purpose, or protocol.
* Finalization records a redacted public-result digest and denied boundary-probe
  surfaces before returning a receipt; probe targets are never persisted.
* The budget is keyed by an operator-provisioned study digest, not by an exact
  view, cycle, signature, candidate, or evaluator epoch. Corpus edits and
  overlapping subsets therefore cannot reset access inside that study.

The alpha budget is a conservative *nominal Bonferroni allocation*, not a claim
that arbitrary adaptive reuse of one holdout is statistically valid. Later
hypotheses can depend on earlier holdout feedback, invalidating ordinary test
assumptions even when nominal alpha sums are bounded. Risk-limited integration
should default to one query, or place this ledger behind an isolated reusable-
holdout broker that reveals only its pre-registered decision.

The local hash chain is tamper-evident, not a cryptographic WORM guarantee. A
privileged attacker able to rewrite or replace the entire database can recompute
an unkeyed chain. Production deployments that include that actor in scope must
anchor ``ledger_id`` and the latest tip in an independently signed/WORM audit
system.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import time
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from statistics import NormalDist
from typing import Any

_SCHEMA_VERSION = "2"
_EVENT_VERSION = 4
_MAX_EVENT_CHARS = 16_384
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_EVENT_COUNT = re.compile(r"^(?:0|[1-9][0-9]*)$")
_QUERY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PURPOSE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")

_EVENTS_TABLE_SQL = (
    "CREATE TABLE events ("
    "seq INTEGER PRIMARY KEY CHECK(typeof(seq)='integer' AND seq >= 1), "
    "payload TEXT NOT NULL CHECK(typeof(payload)='text' AND "
    f"length(payload) BETWEEN 1 AND {_MAX_EVENT_CHARS}), "
    "sha256 TEXT NOT NULL UNIQUE CHECK(typeof(sha256)='text' AND "
    "length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'))"
)
_META_TABLE_SQL = (
    "CREATE TABLE meta ("
    "key TEXT PRIMARY KEY NOT NULL CHECK(key IN "
    "('schema_version','ledger_id','event_count','tip_sha256')), "
    "value TEXT NOT NULL CHECK(typeof(value)='text' AND length(value) <= 128))"
)
_TRIGGER_SQL = {
    "holdout_events_no_update": (
        "CREATE TRIGGER holdout_events_no_update BEFORE UPDATE ON events "
        "BEGIN SELECT RAISE(ABORT, 'holdout events are immutable'); END"
    ),
    "holdout_events_no_delete": (
        "CREATE TRIGGER holdout_events_no_delete BEFORE DELETE ON events "
        "BEGIN SELECT RAISE(ABORT, 'holdout events are immutable'); END"
    ),
    "holdout_meta_no_delete": (
        "CREATE TRIGGER holdout_meta_no_delete BEFORE DELETE ON meta "
        "BEGIN SELECT RAISE(ABORT, 'holdout metadata rows are immutable'); END"
    ),
    "holdout_meta_no_key_update": (
        "CREATE TRIGGER holdout_meta_no_key_update BEFORE UPDATE OF key ON meta "
        "BEGIN SELECT RAISE(ABORT, 'holdout metadata keys are immutable'); END"
    ),
    "holdout_meta_identity_immutable": (
        "CREATE TRIGGER holdout_meta_identity_immutable BEFORE UPDATE OF value ON meta "
        "WHEN OLD.key IN ('schema_version','ledger_id') "
        "BEGIN SELECT RAISE(ABORT, 'holdout metadata identity is immutable'); END"
    ),
    "holdout_meta_no_extra_rows": (
        "CREATE TRIGGER holdout_meta_no_extra_rows BEFORE INSERT ON meta "
        "BEGIN SELECT RAISE(ABORT, 'holdout metadata rows are fixed'); END"
    ),
}
_SCHEMA_SQL = {
    "events": _EVENTS_TABLE_SQL,
    "meta": _META_TABLE_SQL,
    **_TRIGGER_SQL,
}
_POLICY_EVENT_FIELDS = {
    "version", "ledger_id", "sequence", "prev_sha256", "event",
    "holdout_sha256", "policy", "created_at",
}
_QUERY_EVENT_FIELDS = {
    "version", "ledger_id", "sequence", "prev_sha256", "event",
    "holdout_sha256", "view_sha256", "query_id", "cycle_sha256",
    "signature_sha256", "evaluator_epoch_sha256", "purpose", "ordinal",
    "alpha", "issued_at",
}
_QUERY_EVENT_FIELDS_V3 = _QUERY_EVENT_FIELDS | {
    "final_set_sha256", "protocol_sha256",
}
_QUERY_EVENT_FIELDS_V4 = _QUERY_EVENT_FIELDS_V3 | {"declared_cost"}
_ATTEMPT_EVENT_FIELDS = {
    "version", "ledger_id", "sequence", "prev_sha256", "event",
    "holdout_sha256", "query_id", "surface", "attempted_at",
}
_RETIRE_EVENT_FIELDS = {
    "version", "ledger_id", "sequence", "prev_sha256", "event",
    "holdout_sha256", "final_set_sha256", "query_id", "outcome",
    "result_sha256", "retired_at",
}
_RETIRE_EVENT_FIELDS_V4 = _RETIRE_EVENT_FIELDS | {"actual_cost"}
_ATTEMPT_SURFACES = frozenset({
    "artifact_export", "control_path", "credential", "environment", "error_message",
    "evaluator_response", "evaluator_storage", "filesystem", "network",
})
_EVALUATION_OUTCOMES = frozenset({
    "accepted", "access_authorized", "candidate_error", "evaluator_error",
    "rejected",
})

_COST_INTEGER_FIELDS = (
    "provider_calls", "input_tokens", "output_tokens", "compute_millis",
)
_COST_INTEGER_MAX = 10**15
_DOLLAR_MAX = Decimal("1000000000")


class HoldoutLedgerError(RuntimeError):
    """The durable query budget could not be proven or committed."""


class HoldoutBudgetExhausted(HoldoutLedgerError):
    """The sealed set has no authorized queries or nominal alpha remaining."""


class HoldoutLedgerTampered(HoldoutLedgerError):
    """The persisted event chain or transactional tip is inconsistent."""


class FinalSetRetired(HoldoutLedgerError):
    """The requested final set was already exposed or retired."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def fingerprint_manifest(manifest: bytes | str | object) -> str:
    """SHA-256 a complete immutable holdout manifest.

    The manifest must cover cases, labels/grader references, split identity, and
    any other material that changes what the evaluator sees. JSON-compatible
    objects use canonical JSON; strings and bytes are hashed byte-for-byte.
    """
    if isinstance(manifest, bytes):
        payload = manifest
    elif isinstance(manifest, str):
        payload = manifest.encode("utf-8")
    else:
        try:
            payload = _canonical(manifest).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("holdout manifest must be canonically serializable") from exc
    return hashlib.sha256(payload).hexdigest()


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _valid_digest(value: object, *, label: str = "holdout_sha256") -> str:
    if not isinstance(value, str) or not _HEX_256.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _bounded_text(value: object, *, label: str, maximum: int = 4096) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum:
        raise ValueError(f"{label} must contain 1..{maximum} characters")
    return text


def _dollars(value: object, *, label: str) -> str:
    """Return a finite, bounded, non-negative canonical decimal string."""

    if isinstance(value, bool):
        raise ValueError(f"{label} must be a decimal amount")
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a decimal amount") from exc
    if not amount.is_finite() or amount < 0 or amount > _DOLLAR_MAX:
        raise ValueError(f"{label} is outside its bounded range")
    # Six fractional digits is enough for sub-cent provider accounting while
    # keeping event identity stable across float/string callers.
    if amount.as_tuple().exponent < -6:
        raise ValueError(f"{label} supports at most six fractional digits")
    normalized = format(amount, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized or "0"


@dataclass(frozen=True)
class EvaluationCost:
    """Bounded resource reservation or observed cost for one final query.

    Counts and dollars are deliberately provider-neutral. The holdout ledger
    meters them transactionally; detailed provider price evidence remains in
    the provider/Budget accounting subsystem and can be bound by digest in the
    public evaluation result.
    """

    provider_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    compute_millis: int = 0
    dollars: str = "0"

    def __post_init__(self) -> None:
        for field_name in _COST_INTEGER_FIELDS:
            value = getattr(self, field_name)
            if (isinstance(value, bool) or not isinstance(value, int)
                    or not 0 <= value <= _COST_INTEGER_MAX):
                raise ValueError(f"{field_name} is outside its bounded range")
        object.__setattr__(self, "dollars", _dollars(
            self.dollars, label="evaluation dollars"))

    def to_dict(self) -> dict[str, int | str]:
        return {
            field_name: getattr(self, field_name)
            for field_name in _COST_INTEGER_FIELDS
        } | {"dollars": self.dollars}

    @classmethod
    def from_dict(cls, raw: object, *, tampered: bool = False) -> EvaluationCost:
        error = HoldoutLedgerTampered if tampered else ValueError
        expected = {*_COST_INTEGER_FIELDS, "dollars"}
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise error("evaluation cost fields are invalid")
        try:
            return cls(**{field_name: raw[field_name] for field_name in expected})
        except (KeyError, TypeError, ValueError) as exc:
            raise error("evaluation cost is invalid") from exc

    def plus(self, other: EvaluationCost) -> EvaluationCost:
        if not isinstance(other, EvaluationCost):
            raise TypeError("evaluation cost is required")
        values = {
            field_name: getattr(self, field_name) + getattr(other, field_name)
            for field_name in _COST_INTEGER_FIELDS
        }
        return EvaluationCost(
            **values,
            dollars=_dollars(
                Decimal(self.dollars) + Decimal(other.dollars),
                label="evaluation dollars",
            ),
        )

    def minus(self, other: EvaluationCost) -> EvaluationCost:
        if not isinstance(other, EvaluationCost):
            raise TypeError("evaluation cost is required")
        values = {
            field_name: getattr(self, field_name) - getattr(other, field_name)
            for field_name in _COST_INTEGER_FIELDS
        }
        dollars = Decimal(self.dollars) - Decimal(other.dollars)
        if any(value < 0 for value in values.values()) or dollars < 0:
            raise ValueError("evaluation cost subtraction would become negative")
        return EvaluationCost(
            **values, dollars=_dollars(dollars, label="evaluation dollars"))

    def exceeds(self, limit: EvaluationCost) -> str | None:
        if not isinstance(limit, EvaluationCost):
            raise TypeError("evaluation cost limit is required")
        for field_name in _COST_INTEGER_FIELDS:
            if getattr(self, field_name) > getattr(limit, field_name):
                return field_name
        if Decimal(self.dollars) > Decimal(limit.dollars):
            return "dollars"
        return None


def _sum_costs(costs: object) -> EvaluationCost:
    total = EvaluationCost()
    for cost in costs:
        total = total.plus(cost)
    return total


@dataclass(frozen=True)
class AlphaBudget:
    """Fixed nominal allocation for one explicitly provisioned study.

    ``query_alpha * max_queries`` may not exceed ``family_alpha``. The policy is
    written on first access and cannot later be loosened for the same manifest.
    """

    family_alpha: float = 0.05
    query_alpha: float = 0.05
    max_queries: int = 1
    max_provider_calls: int = 1_000_000
    max_input_tokens: int = 1_000_000_000
    max_output_tokens: int = 1_000_000_000
    max_compute_millis: int = 86_400_000
    max_dollars: str = "1000000"

    def __post_init__(self) -> None:
        for label, value in (("family_alpha", self.family_alpha),
                             ("query_alpha", self.query_alpha)):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{label} must be numeric")
            if not math.isfinite(float(value)) or not 1e-12 <= float(value) < 1.0:
                raise ValueError(f"{label} must be finite and in [1e-12, 1)")
        if isinstance(self.max_queries, bool) or not isinstance(self.max_queries, int):
            raise ValueError("max_queries must be an integer")
        if not 1 <= self.max_queries <= 1_000_000:
            raise ValueError("max_queries must be in [1, 1000000]")
        allocated = float(self.query_alpha) * self.max_queries
        if allocated > float(self.family_alpha) + 1e-15:
            raise ValueError("query_alpha * max_queries exceeds family_alpha")
        caps = EvaluationCost(
            provider_calls=self.max_provider_calls,
            input_tokens=self.max_input_tokens,
            output_tokens=self.max_output_tokens,
            compute_millis=self.max_compute_millis,
            dollars=self.max_dollars,
        )
        object.__setattr__(self, "max_dollars", caps.dollars)

    @property
    def cost_limit(self) -> EvaluationCost:
        return EvaluationCost(
            provider_calls=self.max_provider_calls,
            input_tokens=self.max_input_tokens,
            output_tokens=self.max_output_tokens,
            compute_millis=self.max_compute_millis,
            dollars=self.max_dollars,
        )

    def to_dict(self) -> dict[str, float | int | str]:
        return {
            "family_alpha": float(self.family_alpha),
            "query_alpha": float(self.query_alpha),
            "max_queries": self.max_queries,
            "max_provider_calls": self.max_provider_calls,
            "max_input_tokens": self.max_input_tokens,
            "max_output_tokens": self.max_output_tokens,
            "max_compute_millis": self.max_compute_millis,
            "max_dollars": self.max_dollars,
        }

    @classmethod
    def from_dict(cls, raw: object) -> AlphaBudget:
        if not isinstance(raw, Mapping):
            raise HoldoutLedgerTampered("holdout policy is not an object")
        legacy = {"family_alpha", "query_alpha", "max_queries"}
        current = legacy | {
            "max_provider_calls", "max_input_tokens", "max_output_tokens",
            "max_compute_millis", "max_dollars",
        }
        if set(raw) not in (legacy, current):
            raise HoldoutLedgerTampered("holdout policy fields are invalid")
        family = raw["family_alpha"]
        query = raw["query_alpha"]
        maximum = raw["max_queries"]
        if (isinstance(family, bool) or not isinstance(family, (int, float))
                or isinstance(query, bool) or not isinstance(query, (int, float))
                or isinstance(maximum, bool) or not isinstance(maximum, int)):
            raise HoldoutLedgerTampered("holdout policy value types are invalid")
        try:
            kwargs = {
                "family_alpha": family,
                "query_alpha": query,
                "max_queries": maximum,
            }
            if set(raw) == current:
                kwargs.update({field_name: raw[field_name] for field_name in (
                    "max_provider_calls", "max_input_tokens", "max_output_tokens",
                    "max_compute_millis", "max_dollars",
                )})
            return cls(**kwargs)
        except (KeyError, TypeError, ValueError) as exc:
            raise HoldoutLedgerTampered("holdout policy is invalid") from exc


@dataclass(frozen=True)
class HoldoutQuery:
    """One intended exposure of a sealed set to a paired evaluation battery.

    ``holdout_sha256`` is the immutable study digest and budget key.
    ``view_sha256`` identifies the exact pre-registered fold or transformed
    case/label view; changing views must not create a fresh study budget.
    """

    holdout_sha256: str
    query_id: str
    cycle_id: str
    signature: str
    evaluator_epoch: str
    view_sha256: str | None = None
    purpose: str = "confirmation"
    final_set_sha256: str | None = None
    protocol_sha256: str | None = None
    declared_cost: EvaluationCost = field(default_factory=EvaluationCost)

    def event_fields(self) -> dict[str, object]:
        digest = _valid_digest(self.holdout_sha256)
        query_id = str(self.query_id or "").strip()
        purpose = str(self.purpose or "").strip().lower()
        if not _QUERY_ID.fullmatch(query_id):
            raise ValueError("query_id contains unsupported characters or length")
        if not _PURPOSE.fullmatch(purpose):
            raise ValueError("purpose contains unsupported characters or length")
        cycle = _bounded_text(self.cycle_id, label="cycle_id")
        signature = _bounded_text(self.signature, label="signature")
        evaluator = _bounded_text(self.evaluator_epoch, label="evaluator_epoch")
        view_digest = digest if self.view_sha256 is None else _valid_digest(
            self.view_sha256, label="view_sha256")
        if self.final_set_sha256 is None or self.protocol_sha256 is None:
            raise ValueError(
                "final_set_sha256 and protocol_sha256 are required and must be "
                "supplied together")
        final_set_digest = _valid_digest(
            self.final_set_sha256, label="final_set_sha256")
        protocol_digest = _valid_digest(
            self.protocol_sha256, label="protocol_sha256")
        if not isinstance(self.declared_cost, EvaluationCost):
            raise ValueError("declared_cost must be an EvaluationCost")
        return {
            "holdout_sha256": digest,
            "view_sha256": view_digest,
            "query_id": query_id,
            "cycle_sha256": _digest_text(cycle),
            "signature_sha256": _digest_text(signature),
            "evaluator_epoch_sha256": _digest_text(evaluator),
            "purpose": purpose,
            "final_set_sha256": final_set_digest,
            "protocol_sha256": protocol_digest,
            "declared_cost": self.declared_cost.to_dict(),
        }


@dataclass(frozen=True)
class QueryPermit:
    """Durable authorization returned before the evaluator sees the holdout."""

    query_id: str
    holdout_sha256: str
    ordinal: int
    event_sequence: int
    alpha: float
    alpha_remaining: float
    critical_z_two_sided: float
    issued_at: float
    ledger_id: str
    ledger_tip_sha256: str
    final_set_sha256: str = ""
    protocol_sha256: str = ""
    declared_cost: EvaluationCost = field(default_factory=EvaluationCost)


def _valid_permit_digests(permit: QueryPermit) -> tuple[str, str, str]:
    holdout_digest = _valid_digest(
        permit.holdout_sha256, label="holdout_sha256")
    final_set_digest = _valid_digest(
        permit.final_set_sha256, label="final_set_sha256")
    protocol_digest = _valid_digest(
        permit.protocol_sha256, label="protocol_sha256")
    if not isinstance(permit.declared_cost, EvaluationCost):
        raise HoldoutLedgerError("evaluation permit cost is invalid")

    positive_ints = (permit.event_sequence, permit.ordinal)
    numeric = (
        permit.alpha, permit.alpha_remaining,
        permit.critical_z_two_sided, permit.issued_at,
    )
    if (not isinstance(permit.query_id, str)
            or not _QUERY_ID.fullmatch(permit.query_id)
            or not isinstance(permit.ledger_id, str)
            or not _HEX_256.fullmatch(permit.ledger_id)
            or not isinstance(permit.ledger_tip_sha256, str)
            or not _HEX_256.fullmatch(permit.ledger_tip_sha256)
            or any(isinstance(value, bool) or not isinstance(value, int)
                   or value < 1 for value in positive_ints)
            or any(isinstance(value, bool) or not isinstance(value, (int, float))
                   or not math.isfinite(float(value)) for value in numeric)
            or permit.alpha <= 0 or permit.alpha_remaining < 0
            or permit.issued_at < 0):
        raise HoldoutLedgerError("evaluation permit is invalid")
    return holdout_digest, final_set_digest, protocol_digest


@dataclass(frozen=True)
class BoundaryAttempt:
    """One evaluator-boundary probe reported by the candidate sandbox.

    ``target`` is validated for bounded in-process handling and then discarded.
    The ledger stores only the attempt surface, so a path, environment key, URL,
    error string, artifact name, or guessable digest cannot become a disclosure
    channel.
    """

    surface: str
    target: str = ""

    def event_fields(self) -> dict[str, str]:
        if not isinstance(self.surface, str) or not isinstance(self.target, str):
            raise ValueError("boundary attempt fields must be strings")
        surface = self.surface.strip().lower()
        if surface not in _ATTEMPT_SURFACES:
            raise ValueError("boundary attempt surface is unsupported")
        target = self.target
        if len(target) > 4096 or "\x00" in target:
            raise ValueError("boundary attempt target is invalid")
        return {"surface": surface}


def _public_result_digest(public_result: object) -> str:
    try:
        encoded = _canonical(public_result)
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError("public evaluation result must be canonical JSON") from exc
    if not 1 <= len(encoded.encode("utf-8")) <= 65_536:
        raise ValueError("public evaluation result exceeds its size bound")
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _boundary_attempt_fields(
    attempts: tuple[BoundaryAttempt, ...] | list[BoundaryAttempt],
) -> list[dict[str, str]]:
    if not isinstance(attempts, (tuple, list)):
        raise ValueError("denied_attempts must be a bounded sequence")
    if len(attempts) > 256:
        raise ValueError("too many boundary attempts in one evaluation")
    fields: list[dict[str, str]] = []
    for attempt in attempts:
        if not isinstance(attempt, BoundaryAttempt):
            raise ValueError("denied_attempts must contain BoundaryAttempt values")
        fields.append(attempt.event_fields())
    return fields


@dataclass(frozen=True)
class EvaluationReceipt:
    """Durable public receipt for one final-set evaluation.

    The receipt intentionally contains no task, answer-key, evaluator-response,
    credential, or candidate-output bytes. ``result_sha256`` binds the permitted
    public result that the caller received.
    """

    query_id: str
    holdout_sha256: str
    final_set_sha256: str
    protocol_sha256: str
    outcome: str
    result_sha256: str
    denied_attempts: int
    retired_at: float
    ledger_id: str
    event_sequence: int
    ledger_tip_sha256: str
    declared_cost: EvaluationCost = field(default_factory=EvaluationCost)
    actual_cost: EvaluationCost = field(default_factory=EvaluationCost)
    custody: str = "local-controller"


@dataclass(frozen=True)
class HoldoutBudgetStatus:
    holdout_sha256: str
    policy: AlphaBudget | None
    queries: int
    alpha_spent: float
    alpha_remaining: float
    ledger_id: str
    ledger_events: int
    ledger_tip_sha256: str
    reserved_final_sets: int = 0
    retired_final_sets: int = 0
    boundary_attempts: int = 0
    reserved_cost: EvaluationCost = field(default_factory=EvaluationCost)
    actual_cost: EvaluationCost = field(default_factory=EvaluationCost)
    cost_remaining: EvaluationCost = field(default_factory=EvaluationCost)


@dataclass(frozen=True)
class LedgerCustodyStatus:
    """Honest local-storage claim; never substitutes for external custody."""

    local_path_identity_verified: bool
    independent_custody_verified: bool
    platform: str
    limitation: str


@dataclass
class _State:
    policies: dict[str, AlphaBudget] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    query_ids: set[str] = field(default_factory=set)
    queries: dict[str, dict[str, Any]] = field(default_factory=dict)
    reserved_final_sets: dict[str, str] = field(default_factory=dict)
    retirements: dict[str, dict[str, Any]] = field(default_factory=dict)
    boundary_attempts: int = 0
    boundary_attempts_by_holdout: dict[str, int] = field(default_factory=dict)
    reserved_costs: dict[str, EvaluationCost] = field(default_factory=dict)
    actual_costs: dict[str, EvaluationCost] = field(default_factory=dict)
    head: str | None = None
    events: int = 0
    ledger_id: str = ""


@dataclass
class HoldoutQueryLedger:
    """Transactional, hash-chained sealed-holdout access ledger."""

    path: Path
    timeout_seconds: float = 10.0
    max_events: int = 100_000
    now: Callable[[], float] = time.time

    def __post_init__(self) -> None:
        # Freeze a lexical absolute path once without resolving symlinks. A
        # relative path reinterpreted after ``chdir`` could silently select a
        # different valid ledger and reset the holdout budget.
        self.path = Path(os.path.abspath(os.fspath(self.path)))
        if (isinstance(self.timeout_seconds, bool)
                or not isinstance(self.timeout_seconds, (int, float))
                or not math.isfinite(float(self.timeout_seconds))
                or not 0 < float(self.timeout_seconds) <= 86_400):
            raise ValueError("timeout_seconds must be finite and in (0, 86400]")
        if (isinstance(self.max_events, bool) or not isinstance(self.max_events, int)
                or not 1 <= self.max_events <= 10_000_000):
            raise ValueError("max_events must be in [1, 10000000]")

    def custody_status(self) -> LedgerCustodyStatus:
        """Verify the local path and report the boundary it does not prove.

        On Windows, Python's portable stat surface cannot establish an ACL or
        a separate service identity. On POSIX, owner/mode checks exclude common
        accidental sharing but a same-uid process can still rewrite the file.
        Both are development custody only.
        """

        self._assert_regular_file()
        if os.name == "nt":
            limitation = (
                "Windows file identity was verified, but portable runtime checks "
                "do not prove restrictive ACLs or a separate evaluator identity"
            )
        else:
            limitation = (
                "owner and mode were verified, but same-uid processes remain in "
                "the same custody boundary; independent custody needs a separate "
                "evaluator identity"
            )
        return LedgerCustodyStatus(
            local_path_identity_verified=True,
            independent_custody_verified=False,
            platform=os.name,
            limitation=limitation,
        )

    def require_independent_custody(self) -> None:
        status = self.custody_status()
        if not status.independent_custody_verified:
            raise HoldoutLedgerError(
                "independent evaluator custody is not verified: " + status.limitation)

    @classmethod
    def provision(cls, path: str | Path, **kwargs) -> HoldoutQueryLedger:
        """Create a new empty ledger exactly once.

        Existing paths are refused, including empty/corrupt ones. Provisioning is
        an operator/deployment action; evaluation code should only instantiate
        :class:`HoldoutQueryLedger` and must never call this as recovery.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(os.fspath(path), flags, 0o600)
        except OSError as exc:
            raise HoldoutLedgerError("holdout ledger already exists or cannot be created") from exc
        try:
            created_stat = os.fstat(fd)
            if not stat.S_ISREG(created_stat.st_mode):
                raise HoldoutLedgerError("holdout ledger must be a regular file")
            created_identity = (created_stat.st_dev, created_stat.st_ino)
        finally:
            os.close(fd)

        ledger = cls(path=path, **kwargs)
        try:
            with closing(ledger._connect(expected_identity=created_identity)) as conn:
                conn.execute("BEGIN EXCLUSIVE")
                conn.execute(_EVENTS_TABLE_SQL)
                conn.execute(_META_TABLE_SQL)
                conn.executemany(
                    "INSERT INTO meta(key, value) VALUES (?, ?)",
                    (("schema_version", _SCHEMA_VERSION),
                     ("ledger_id", secrets.token_hex(32)),
                     ("event_count", "0"), ("tip_sha256", "")),
                )
                for sql in _TRIGGER_SQL.values():
                    conn.execute(sql)
                conn.commit()
                ledger._assert_regular_file(expected_identity=created_identity)
        except (sqlite3.Error, OSError) as exc:
            # Keep the exclusive path as a fail-closed tombstone. Silently
            # deleting it would permit a second provisioning attempt after an
            # ambiguous partial initialization.
            raise HoldoutLedgerError("could not provision holdout ledger") from exc
        ledger.verify()
        return ledger

    def authorize(self, query: HoldoutQuery, policy: AlphaBudget) -> QueryPermit:
        """Durably spend one query before any holdout result is revealed.

        Duplicate ``query_id`` values are rejected rather than treated as
        idempotent: returning the same permit twice would allow two exposures for
        one charge. A crash before evaluation therefore burns the reservation.
        """
        fields = query.event_fields()
        if not isinstance(policy, AlphaBudget):
            raise ValueError("policy must be an AlphaBudget")
        try:
            timestamp = self.now()
            issued_at = float(timestamp)
        except (TypeError, ValueError, OverflowError) as exc:
            raise HoldoutLedgerError("query timestamp is invalid") from exc
        if (isinstance(timestamp, bool) or not math.isfinite(issued_at)
                or issued_at < 0):
            raise HoldoutLedgerError("query timestamp is invalid")
        z = NormalDist().inv_cdf(1.0 - float(policy.query_alpha) / 2.0)
        if not math.isfinite(z):  # guarded by AlphaBudget's lower alpha floor
            raise HoldoutLedgerError("query alpha produced a non-finite critical value")

        path_identity = self._assert_regular_file()
        conn = self._connect(expected_identity=path_identity)
        committed = False
        try:
            conn.execute("BEGIN IMMEDIATE")
            state = self._read_state(conn)
            digest = fields["holdout_sha256"]
            prior_policy = state.policies.get(digest)
            if prior_policy is not None and prior_policy != policy:
                raise HoldoutLedgerError(
                    "sealed holdout policy is immutable once first queried")
            if fields["query_id"] in state.query_ids:
                raise HoldoutLedgerError("query_id has already been spent")
            used = state.counts.get(digest, 0)
            spent = float(policy.query_alpha) * used
            if used >= policy.max_queries:
                raise HoldoutBudgetExhausted("sealed holdout query limit reached")
            if spent + float(policy.query_alpha) > float(policy.family_alpha) + 1e-15:
                raise HoldoutBudgetExhausted("sealed holdout nominal alpha exhausted")
            final_set_digest = fields["final_set_sha256"]
            if final_set_digest and final_set_digest in state.reserved_final_sets:
                raise FinalSetRetired(
                    "final set was already exposed; provision fresh final challenges")
            declared_cost = EvaluationCost.from_dict(fields["declared_cost"])
            committed_cost = state.actual_costs.get(digest, EvaluationCost()).plus(
                state.reserved_costs.get(digest, EvaluationCost())
            )
            projected_cost = committed_cost.plus(declared_cost)
            exceeded = projected_cost.exceeds(policy.cost_limit)
            if exceeded is not None:
                raise HoldoutBudgetExhausted(
                    f"sealed holdout {exceeded} limit reached")

            if prior_policy is None:
                state = self._append_event(conn, state, {
                    "event": "policy",
                    "holdout_sha256": digest,
                    "policy": policy.to_dict(),
                    "created_at": issued_at,
                })
            ordinal = used + 1
            state = self._append_event(conn, state, {
                "event": "query",
                **fields,
                "ordinal": ordinal,
                "alpha": float(policy.query_alpha),
                "issued_at": issued_at,
            })
            conn.execute("UPDATE meta SET value=? WHERE key='event_count'", (str(state.events),))
            conn.execute("UPDATE meta SET value=? WHERE key='tip_sha256'", (state.head or "",))
            permit_sequence = state.events
            permit_tip = state.head or ""
            permit_ledger_id = state.ledger_id
            conn.commit()
            committed = True

            # A successful sqlite commit is necessary but not sufficient for a
            # security boundary. Re-open through a fresh SQLite handle and prove
            # the exact charged event is durable and the complete chain is still
            # valid. Another process may append between commit/readback; the tip
            # may advance, but our sequence/hash and unique query id must remain.
            self._readback_authorization(
                path_identity=path_identity, sequence=permit_sequence,
                tip=permit_tip, query_id=fields["query_id"],
                ledger_id=permit_ledger_id,
            )
            self._assert_regular_file(expected_identity=path_identity)
        except (HoldoutLedgerError, ValueError):
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise HoldoutLedgerError("could not commit holdout query authorization") from exc
        finally:
            conn.close()

        # Detect a leaf-path swap that occurred after SQLite opened its handle.
        # The spent transaction remains burned, but no permit is returned from an
        # ambiguous/replaced path.
        if committed:
            self._assert_regular_file(expected_identity=path_identity)
        remaining = max(
            0.0, float(policy.family_alpha) - float(policy.query_alpha) * ordinal)
        return QueryPermit(
            query_id=fields["query_id"], holdout_sha256=digest,
            ordinal=ordinal, event_sequence=permit_sequence,
            alpha=float(policy.query_alpha), alpha_remaining=remaining,
            critical_z_two_sided=z, issued_at=issued_at,
            ledger_id=permit_ledger_id, ledger_tip_sha256=permit_tip,
            final_set_sha256=fields["final_set_sha256"],
            protocol_sha256=fields["protocol_sha256"],
            declared_cost=declared_cost,
        )

    def finalize_evaluation(
        self,
        permit: QueryPermit,
        *,
        outcome: str,
        public_result: object,
        denied_attempts: tuple[BoundaryAttempt, ...] | list[BoundaryAttempt] = (),
        actual_cost: EvaluationCost | None = None,
    ) -> EvaluationReceipt:
        """Retire an exposed final set and commit its public result receipt.

        The query reservation already prevents another caller from opening the
        same final set. Finalization adds a permanent retirement/result record and
        the sandbox's denied boundary probes in one transaction. A publication
        error returns no result; the query remains burned and cannot be replayed.
        """
        if not isinstance(permit, QueryPermit):
            raise ValueError("permit must be a QueryPermit")
        if not permit.final_set_sha256 or not permit.protocol_sha256:
            raise HoldoutLedgerError(
                "legacy query permits cannot finalize a governed final set")
        holdout_digest, final_set_digest, protocol_digest = (
            _valid_permit_digests(permit))
        if not isinstance(outcome, str):
            raise ValueError("evaluation outcome must be a string")
        outcome_value = outcome.strip().lower()
        if outcome_value not in _EVALUATION_OUTCOMES:
            raise ValueError("evaluation outcome is unsupported")
        if outcome_value == "access_authorized":
            raise ValueError(
                "access authorization is not an evaluation result; finalize only after scoring")
        result_digest = _public_result_digest(public_result)
        attempt_fields = _boundary_attempt_fields(denied_attempts)
        observed_cost = EvaluationCost() if actual_cost is None else actual_cost
        if not isinstance(observed_cost, EvaluationCost):
            raise ValueError("actual_cost must be an EvaluationCost")
        exceeded = observed_cost.exceeds(permit.declared_cost)
        if exceeded is not None:
            raise HoldoutBudgetExhausted(
                f"observed evaluation {exceeded} exceeded its reservation")
        try:
            timestamp = self.now()
            retired_at = float(timestamp)
        except (TypeError, ValueError, OverflowError) as exc:
            raise HoldoutLedgerError("evaluation timestamp is invalid") from exc
        if (isinstance(timestamp, bool) or not math.isfinite(retired_at)
                or retired_at < 0):
            raise HoldoutLedgerError("evaluation timestamp is invalid")

        path_identity = self._assert_regular_file()
        conn = self._connect(expected_identity=path_identity)
        committed = False
        try:
            conn.execute("BEGIN IMMEDIATE")
            state = self._read_state(conn)
            query = state.queries.get(permit.query_id)
            policy = state.policies.get(holdout_digest)
            if policy is None:
                raise HoldoutLedgerError(
                    "evaluation permit does not match the committed query")
            expected_remaining = max(
                0.0,
                float(policy.family_alpha)
                - float(policy.query_alpha) * int(query.get("ordinal", 0))
                if query is not None else 0.0,
            )
            expected_z = NormalDist().inv_cdf(
                1.0 - float(policy.query_alpha) / 2.0)
            committed_identity = None if query is None else {
                "ledger_id": state.ledger_id,
                "holdout_sha256": query.get("holdout_sha256"),
                "final_set_sha256": query.get("final_set_sha256"),
                "protocol_sha256": query.get("protocol_sha256"),
                "event_sequence": query.get("event_sequence"),
                "ordinal": query.get("ordinal"),
                "issued_at": query.get("issued_at"),
                "alpha": query.get("alpha"),
                "ledger_tip_sha256": query.get("ledger_tip_sha256"),
                "alpha_remaining": expected_remaining,
                "critical_z_two_sided": expected_z,
                "declared_cost": query.get("declared_cost"),
            }
            permit_identity = {
                "ledger_id": permit.ledger_id,
                "holdout_sha256": holdout_digest,
                "final_set_sha256": final_set_digest,
                "protocol_sha256": protocol_digest,
                "event_sequence": permit.event_sequence,
                "ordinal": permit.ordinal,
                "issued_at": permit.issued_at,
                "alpha": permit.alpha,
                "ledger_tip_sha256": permit.ledger_tip_sha256,
                "alpha_remaining": permit.alpha_remaining,
                "critical_z_two_sided": permit.critical_z_two_sided,
                "declared_cost": permit.declared_cost,
            }
            if committed_identity != permit_identity:
                raise HoldoutLedgerError(
                    "evaluation permit does not match the committed query")
            if final_set_digest in state.retirements:
                raise FinalSetRetired("final set result was already finalized")
            if state.reserved_final_sets.get(final_set_digest) != permit.query_id:
                raise HoldoutLedgerTampered(
                    "final set reservation does not match its query")
            for fields in attempt_fields:
                state = self._append_event(conn, state, {
                    "event": "boundary_attempt",
                    "holdout_sha256": holdout_digest,
                    "query_id": permit.query_id,
                    **fields,
                    "attempted_at": retired_at,
                })
            state = self._append_event(conn, state, {
                "event": "retire_final_set",
                "holdout_sha256": holdout_digest,
                "final_set_sha256": final_set_digest,
                "query_id": permit.query_id,
                "outcome": outcome_value,
                "result_sha256": result_digest,
                "retired_at": retired_at,
                "actual_cost": observed_cost.to_dict(),
            })
            conn.execute(
                "UPDATE meta SET value=? WHERE key='event_count'", (str(state.events),))
            conn.execute(
                "UPDATE meta SET value=? WHERE key='tip_sha256'", (state.head or "",))
            sequence = state.events
            tip = state.head or ""
            conn.commit()
            committed = True
            self._readback_finalization(
                path_identity=path_identity, sequence=sequence, tip=tip,
                query_id=permit.query_id, final_set_sha256=final_set_digest,
                ledger_id=permit.ledger_id,
            )
            self._assert_regular_file(expected_identity=path_identity)
        except (HoldoutLedgerError, ValueError):
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise HoldoutLedgerError(
                "could not commit final-set retirement") from exc
        finally:
            conn.close()
        if committed:
            self._assert_regular_file(expected_identity=path_identity)
        return EvaluationReceipt(
            query_id=permit.query_id, holdout_sha256=holdout_digest,
            final_set_sha256=final_set_digest,
            protocol_sha256=protocol_digest, outcome=outcome_value,
            result_sha256=result_digest, denied_attempts=len(attempt_fields),
            retired_at=retired_at, ledger_id=permit.ledger_id,
            event_sequence=sequence, ledger_tip_sha256=tip,
            declared_cost=permit.declared_cost, actual_cost=observed_cost,
        )

    def validate_permit(self, permit: QueryPermit) -> None:
        """Verify a reserved permit before any candidate receives observations.

        Finalization repeats these checks under ``BEGIN IMMEDIATE``. This
        read-only preflight closes the exposure window for callers that carry a
        two-phase permit across scoring and then use the isolated broker.
        """
        if not isinstance(permit, QueryPermit):
            raise ValueError("permit must be a QueryPermit")
        holdout_digest, final_set_digest, protocol_digest = (
            _valid_permit_digests(permit))
        state = self._snapshot_state()
        query = state.queries.get(permit.query_id)
        policy = state.policies.get(holdout_digest)
        if query is None or policy is None:
            raise HoldoutLedgerError(
                "evaluation permit does not match the committed query")
        expected_remaining = max(
            0.0,
            float(policy.family_alpha)
            - float(policy.query_alpha) * int(query.get("ordinal", 0)),
        )
        expected_z = NormalDist().inv_cdf(
            1.0 - float(policy.query_alpha) / 2.0)
        committed_identity = {
            "ledger_id": state.ledger_id,
            "holdout_sha256": query.get("holdout_sha256"),
            "final_set_sha256": query.get("final_set_sha256"),
            "protocol_sha256": query.get("protocol_sha256"),
            "event_sequence": query.get("event_sequence"),
            "ordinal": query.get("ordinal"),
            "issued_at": query.get("issued_at"),
            "alpha": query.get("alpha"),
            "ledger_tip_sha256": query.get("ledger_tip_sha256"),
            "alpha_remaining": expected_remaining,
            "critical_z_two_sided": expected_z,
            "declared_cost": query.get("declared_cost"),
        }
        permit_identity = {
            "ledger_id": permit.ledger_id,
            "holdout_sha256": holdout_digest,
            "final_set_sha256": final_set_digest,
            "protocol_sha256": protocol_digest,
            "event_sequence": permit.event_sequence,
            "ordinal": permit.ordinal,
            "issued_at": permit.issued_at,
            "alpha": permit.alpha,
            "ledger_tip_sha256": permit.ledger_tip_sha256,
            "alpha_remaining": permit.alpha_remaining,
            "critical_z_two_sided": permit.critical_z_two_sided,
            "declared_cost": permit.declared_cost,
        }
        if committed_identity != permit_identity:
            raise HoldoutLedgerError(
                "evaluation permit does not match the committed query")
        if final_set_digest in state.retirements:
            raise FinalSetRetired("final set result was already finalized")
        if state.reserved_final_sets.get(final_set_digest) != permit.query_id:
            raise HoldoutLedgerTampered(
                "final set reservation does not match its query")

    def status(self, holdout_sha256: str) -> HoldoutBudgetStatus:
        digest = _valid_digest(holdout_sha256)
        state = self._snapshot_state()
        policy = state.policies.get(digest)
        queries = state.counts.get(digest, 0)
        spent = float(policy.query_alpha) * queries if policy else 0.0
        remaining = max(0.0, float(policy.family_alpha) - spent) if policy else 0.0
        reserved = sum(
            1 for query_id in state.reserved_final_sets.values()
            if state.queries[query_id]["holdout_sha256"] == digest
        )
        retired = sum(
            1 for retirement in state.retirements.values()
            if state.queries[retirement["query_id"]]["holdout_sha256"] == digest
        )
        reserved_cost = state.reserved_costs.get(digest, EvaluationCost())
        actual_cost = state.actual_costs.get(digest, EvaluationCost())
        cost_remaining = (
            policy.cost_limit.minus(reserved_cost.plus(actual_cost))
            if policy else EvaluationCost()
        )
        return HoldoutBudgetStatus(
            holdout_sha256=digest, policy=policy, queries=queries,
            alpha_spent=spent, alpha_remaining=remaining,
            ledger_id=state.ledger_id, ledger_events=state.events,
            ledger_tip_sha256=state.head or "",
            reserved_final_sets=reserved, retired_final_sets=retired,
            boundary_attempts=state.boundary_attempts_by_holdout.get(digest, 0),
            reserved_cost=reserved_cost, actual_cost=actual_cost,
            cost_remaining=cost_remaining,
        )

    def verify(self) -> HoldoutBudgetStatus:
        """Verify the complete event chain and transactional tip."""
        state = self._snapshot_state()
        return HoldoutBudgetStatus(
            holdout_sha256="", policy=None, queries=sum(state.counts.values()),
            alpha_spent=0.0, alpha_remaining=0.0,
            ledger_id=state.ledger_id, ledger_events=state.events,
            ledger_tip_sha256=state.head or "",
            reserved_final_sets=len(state.reserved_final_sets),
            retired_final_sets=len(state.retirements),
            boundary_attempts=state.boundary_attempts,
            reserved_cost=_sum_costs(state.reserved_costs.values()),
            actual_cost=_sum_costs(state.actual_costs.values()),
        )

    def _snapshot_state(self) -> _State:
        """Read one verified snapshot and normalize SQLite corruption errors."""
        path_identity = self._assert_regular_file()
        conn = self._connect(expected_identity=path_identity)
        try:
            conn.execute("BEGIN")
            state = self._read_state(conn)
            conn.commit()
            self._assert_regular_file(expected_identity=path_identity)
        except HoldoutLedgerError:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise HoldoutLedgerTampered(
                "cannot read a consistent holdout ledger snapshot") from exc
        finally:
            conn.close()
        self._assert_regular_file(expected_identity=path_identity)
        return state

    def _readback_authorization(
        self, *, path_identity: tuple[int, int], sequence: int, tip: str,
        query_id: str, ledger_id: str,
    ) -> None:
        conn = self._connect(expected_identity=path_identity)
        try:
            conn.execute("BEGIN")
            state = self._read_state(conn)
            persisted = conn.execute(
                "SELECT sha256 FROM events WHERE seq=?", (sequence,),
            ).fetchone()
            if (persisted != (tip,) or query_id not in state.query_ids
                    or state.events < sequence or state.ledger_id != ledger_id):
                raise HoldoutLedgerError(
                    "committed holdout query authorization failed readback")
            conn.commit()
            self._assert_regular_file(expected_identity=path_identity)
        except HoldoutLedgerError:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise HoldoutLedgerError(
                "committed holdout query authorization failed readback") from exc
        finally:
            conn.close()
        self._assert_regular_file(expected_identity=path_identity)

    def _readback_finalization(
        self, *, path_identity: tuple[int, int], sequence: int, tip: str,
        query_id: str, final_set_sha256: str, ledger_id: str,
    ) -> None:
        conn = self._connect(expected_identity=path_identity)
        try:
            conn.execute("BEGIN")
            state = self._read_state(conn)
            persisted = conn.execute(
                "SELECT sha256 FROM events WHERE seq=?", (sequence,),
            ).fetchone()
            retirement = state.retirements.get(final_set_sha256)
            if (persisted != (tip,) or retirement is None
                    or retirement.get("query_id") != query_id
                    or state.events < sequence or state.ledger_id != ledger_id):
                raise HoldoutLedgerError(
                    "committed final-set retirement failed readback")
            conn.commit()
            self._assert_regular_file(expected_identity=path_identity)
        except HoldoutLedgerError:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise HoldoutLedgerError(
                "committed final-set retirement failed readback") from exc
        finally:
            conn.close()
        self._assert_regular_file(expected_identity=path_identity)

    def _connect(
        self, *, expected_identity: tuple[int, int] | None = None,
    ) -> sqlite3.Connection:
        identity = self._assert_regular_file(expected_identity=expected_identity)
        conn = None
        try:
            # mode=rw is load-bearing: sqlite3.connect(path) silently creates a
            # missing file, which would reset the cross-cycle budget. ``as_uri``
            # percent-encodes ``?``/``#`` in legal POSIX filenames, so a path can
            # never inject SQLite URI parameters. Avoid ``resolve()`` here: it
            # would follow a leaf symlink introduced after the lstat check.
            uri = self.path.absolute().as_uri() + "?mode=rw&cache=private"
            conn = sqlite3.connect(
                uri, uri=True, timeout=float(self.timeout_seconds),
                isolation_level=None,
            )
            self._assert_regular_file(expected_identity=identity)
            conn.execute(f"PRAGMA busy_timeout={int(self.timeout_seconds * 1000)}")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA foreign_keys=ON")
            journal = conn.execute("PRAGMA journal_mode").fetchone()
            # Provisioning uses SQLite's rollback-journal DELETE mode. Refuse a
            # persistent mode change (notably WAL) rather than silently adding
            # unaudited ``-wal``/``-shm`` state to this security boundary.
            if not journal or str(journal[0]).lower() != "delete":
                raise HoldoutLedgerError(
                    "holdout ledger SQLite journal mode changed unexpectedly")
            if conn.execute("PRAGMA synchronous").fetchone() != (2,):
                raise HoldoutLedgerError("holdout ledger could not enable FULL sync")
            self._assert_regular_file(expected_identity=identity)
            return conn
        except HoldoutLedgerError:
            if conn is not None:
                conn.close()
            raise
        except (sqlite3.Error, OSError, ValueError) as exc:
            if conn is not None:
                conn.close()
            raise HoldoutLedgerError("cannot open provisioned holdout ledger") from exc

    def _assert_regular_file(
        self, *, expected_identity: tuple[int, int] | None = None,
    ) -> tuple[int, int]:
        try:
            parent = self.path.parent.lstat()
            current = self.path.lstat()
        except (OSError, ValueError) as exc:
            raise HoldoutLedgerError(
                "holdout ledger is missing; runtime refuses to recreate it") from exc
        if not stat.S_ISDIR(parent.st_mode):
            raise HoldoutLedgerError("holdout ledger parent must be a real directory")
        if not stat.S_ISREG(current.st_mode):
            raise HoldoutLedgerError("holdout ledger must be a regular file")
        if current.st_nlink != 1:
            raise HoldoutLedgerError("holdout ledger must not have hard links")
        if os.name == "posix":
            if current.st_uid != os.geteuid():
                raise HoldoutLedgerError("holdout ledger must be owned by the runtime user")
            if current.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise HoldoutLedgerError("holdout ledger permissions permit external writes")
            writable_parent = parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            if writable_parent and not parent.st_mode & stat.S_ISVTX:
                raise HoldoutLedgerError(
                    "holdout ledger parent permissions permit path replacement")
        identity = (current.st_dev, current.st_ino)
        if expected_identity is not None and identity != expected_identity:
            raise HoldoutLedgerError("holdout ledger path was replaced during access")
        return identity

    @staticmethod
    def _normalize_schema_sql(value: object) -> str:
        # Collapse formatting only. Do NOT case-fold the full SQL: case changes
        # inside string literals can change trigger semantics (for example the
        # protected metadata keys) while keywords themselves are insensitive.
        return " ".join(str(value or "").split())

    def _verify_schema(self, conn: sqlite3.Connection) -> None:
        """Require the provisioned tables and immutability triggers verbatim."""
        try:
            rows = list(conn.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"))
        except sqlite3.Error as exc:
            raise HoldoutLedgerTampered("cannot read holdout ledger schema") from exc
        actual = {str(name): (str(kind), sql) for kind, name, sql in rows}
        if set(actual) != set(_SCHEMA_SQL):
            raise HoldoutLedgerTampered("holdout ledger schema objects are invalid")
        for name, expected_sql in _SCHEMA_SQL.items():
            kind, actual_sql = actual[name]
            expected_kind = "table" if name in {"events", "meta"} else "trigger"
            if (kind != expected_kind
                    or self._normalize_schema_sql(actual_sql)
                    != self._normalize_schema_sql(expected_sql)):
                raise HoldoutLedgerTampered(
                    f"holdout ledger schema object {name} is invalid")

    def _meta(self, conn: sqlite3.Connection) -> dict[str, str]:
        try:
            self._verify_schema(conn)
            raw = list(conn.execute("SELECT key, value FROM meta"))
        except HoldoutLedgerTampered:
            raise
        except sqlite3.Error as exc:
            raise HoldoutLedgerTampered("cannot read holdout ledger metadata") from exc
        meta = {str(key): str(value) for key, value in raw}
        required = {"schema_version", "ledger_id", "event_count", "tip_sha256"}
        if (len(raw) != len(required) or set(meta) != required
                or meta.get("schema_version") != _SCHEMA_VERSION):
            raise HoldoutLedgerTampered("holdout ledger metadata is invalid")
        if not _HEX_256.fullmatch(meta.get("ledger_id", "")):
            raise HoldoutLedgerTampered("holdout ledger id is invalid")
        return meta

    def _read_state(self, conn: sqlite3.Connection) -> _State:  # noqa: C901
        try:
            integrity = conn.execute("PRAGMA integrity_check(1)").fetchone()
        except sqlite3.Error as exc:
            raise HoldoutLedgerTampered("holdout ledger integrity check failed") from exc
        if integrity != ("ok",):
            raise HoldoutLedgerTampered("holdout ledger storage is corrupt")
        meta = self._meta(conn)
        if not _EVENT_COUNT.fullmatch(meta["event_count"]):
            raise HoldoutLedgerTampered("holdout ledger event count is invalid")
        event_count = int(meta["event_count"])
        if not 0 <= event_count <= self.max_events:
            raise HoldoutLedgerTampered("holdout ledger event count exceeds its bound")
        try:
            rows = conn.execute("SELECT seq, payload, sha256 FROM events ORDER BY seq")
        except sqlite3.Error as exc:
            raise HoldoutLedgerTampered("cannot read holdout ledger events") from exc

        state = _State(ledger_id=meta["ledger_id"])
        expected_seq = 0
        while True:
            try:
                row = rows.fetchone()
            except sqlite3.Error as exc:
                raise HoldoutLedgerTampered(
                    "cannot read holdout ledger events") from exc
            if row is None:
                break
            expected_seq += 1
            if expected_seq > event_count:
                raise HoldoutLedgerTampered(
                    "holdout ledger event count does not match its tip")
            seq, encoded, claimed = row
            if (seq != expected_seq or isinstance(seq, bool)
                    or not isinstance(encoded, str)
                    or not 1 <= len(encoded) <= _MAX_EVENT_CHARS):
                raise HoldoutLedgerTampered("holdout ledger event sequence has a gap")
            try:
                event = json.loads(encoded)
            except (RecursionError, TypeError, ValueError) as exc:
                raise HoldoutLedgerTampered("holdout ledger event is invalid JSON") from exc
            try:
                canonical = _canonical(event) if isinstance(event, dict) else None
            except (RecursionError, TypeError, ValueError) as exc:
                raise HoldoutLedgerTampered(
                    "holdout ledger event is not canonical") from exc
            if canonical != encoded:
                raise HoldoutLedgerTampered("holdout ledger event is not canonical")
            expected_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            if claimed != expected_hash or event.get("prev_sha256") != state.head:
                raise HoldoutLedgerTampered("holdout ledger hash chain is broken")
            version = event.get("version")
            if (isinstance(version, bool) or not isinstance(version, int)
                    or version not in (2, 3, _EVENT_VERSION)):
                raise HoldoutLedgerTampered("holdout ledger event version is invalid")
            self._apply_event(state, event)
            state.head = expected_hash
            state.events = expected_seq

        if state.events != event_count:
            raise HoldoutLedgerTampered("holdout ledger event count does not match its tip")

        tip = meta["tip_sha256"]
        if tip != (state.head or ""):
            raise HoldoutLedgerTampered("holdout ledger transactional tip does not match")
        if tip and not _HEX_256.fullmatch(tip):
            raise HoldoutLedgerTampered("holdout ledger tip is invalid")
        return state

    def _apply_event(  # noqa: C901 -- one replay validator owns every transition
        self, state: _State, event: dict[str, Any],
    ) -> None:
        kind = event.get("event")
        version = event.get("version")
        if kind == "policy":
            expected_fields = _POLICY_EVENT_FIELDS
        elif kind == "query":
            expected_fields = ({
                2: _QUERY_EVENT_FIELDS,
                3: _QUERY_EVENT_FIELDS_V3,
                _EVENT_VERSION: _QUERY_EVENT_FIELDS_V4,
            }.get(version))
        elif kind == "boundary_attempt" and version in (3, _EVENT_VERSION):
            expected_fields = _ATTEMPT_EVENT_FIELDS
        elif kind == "retire_final_set" and version in (3, _EVENT_VERSION):
            expected_fields = (
                _RETIRE_EVENT_FIELDS_V4
                if version == _EVENT_VERSION else _RETIRE_EVENT_FIELDS
            )
        else:
            raise HoldoutLedgerTampered("holdout ledger event transition is invalid")
        if expected_fields is None:
            raise HoldoutLedgerTampered("holdout ledger event transition is invalid")
        if set(event) != expected_fields:
            raise HoldoutLedgerTampered("holdout ledger event fields are invalid")
        sequence = event.get("sequence")
        if (event.get("ledger_id") != state.ledger_id
                or isinstance(sequence, bool) or not isinstance(sequence, int)
                or sequence != state.events + 1):
            raise HoldoutLedgerTampered(
                "holdout ledger event identity or sequence is invalid")
        try:
            digest = _valid_digest(event.get("holdout_sha256"))
        except ValueError as exc:
            raise HoldoutLedgerTampered("holdout ledger event has an invalid digest") from exc
        if kind == "policy":
            if digest in state.policies:
                raise HoldoutLedgerTampered("holdout ledger repeats a policy")
            policy = AlphaBudget.from_dict(event.get("policy"))
            created_at = event.get("created_at")
            if (isinstance(created_at, bool) or not isinstance(created_at, (int, float))
                    or not math.isfinite(float(created_at)) or float(created_at) < 0):
                raise HoldoutLedgerTampered("holdout policy timestamp is invalid")
            state.policies[digest] = policy
            state.counts[digest] = 0
            state.reserved_costs[digest] = EvaluationCost()
            state.actual_costs[digest] = EvaluationCost()
            return
        if kind == "boundary_attempt":
            query_id = event.get("query_id")
            surface = event.get("surface")
            attempted_at = event.get("attempted_at")
            if not isinstance(query_id, str) or query_id not in state.queries:
                raise HoldoutLedgerTampered(
                    "boundary attempt does not reference a committed query")
            query = state.queries[query_id]
            if query.get("holdout_sha256") != digest:
                raise HoldoutLedgerTampered(
                    "boundary attempt holdout does not match its query")
            final_set_sha256 = query.get("final_set_sha256", "")
            if final_set_sha256 and final_set_sha256 in state.retirements:
                raise HoldoutLedgerTampered(
                    "boundary attempt was recorded after final-set retirement")
            if not isinstance(surface, str) or surface not in _ATTEMPT_SURFACES:
                raise HoldoutLedgerTampered("boundary attempt surface is invalid")
            if (isinstance(attempted_at, bool)
                    or not isinstance(attempted_at, (int, float))
                    or not math.isfinite(float(attempted_at))
                    or float(attempted_at) < 0):
                raise HoldoutLedgerTampered("boundary attempt timestamp is invalid")
            state.boundary_attempts += 1
            state.boundary_attempts_by_holdout[digest] = (
                state.boundary_attempts_by_holdout.get(digest, 0) + 1)
            return
        if kind == "retire_final_set":
            query_id = event.get("query_id")
            final_set_sha256 = event.get("final_set_sha256")
            result_sha256 = event.get("result_sha256")
            outcome = event.get("outcome")
            retired_at = event.get("retired_at")
            if not isinstance(query_id, str):
                raise HoldoutLedgerTampered(
                    "final-set retirement query id is invalid")
            query = state.queries.get(query_id)
            if (query is None or query.get("holdout_sha256") != digest):
                raise HoldoutLedgerTampered(
                    "final-set retirement does not reference its query")
            if (not isinstance(final_set_sha256, str)
                    or not _HEX_256.fullmatch(final_set_sha256)
                    or query.get("final_set_sha256") != final_set_sha256
                    or state.reserved_final_sets.get(final_set_sha256) != query_id
                    or final_set_sha256 in state.retirements):
                raise HoldoutLedgerTampered("final-set retirement is invalid")
            if (not isinstance(result_sha256, str)
                    or not _HEX_256.fullmatch(result_sha256)):
                raise HoldoutLedgerTampered(
                    "final-set result digest is invalid")
            if not isinstance(outcome, str) or outcome not in _EVALUATION_OUTCOMES:
                raise HoldoutLedgerTampered("final-set outcome is invalid")
            if (isinstance(retired_at, bool)
                    or not isinstance(retired_at, (int, float))
                    or not math.isfinite(float(retired_at)) or float(retired_at) < 0):
                raise HoldoutLedgerTampered("final-set retirement timestamp is invalid")
            declared_cost = query.get("declared_cost")
            if not isinstance(declared_cost, EvaluationCost):
                raise HoldoutLedgerTampered("query cost reservation is invalid")
            actual_cost = (
                EvaluationCost.from_dict(event.get("actual_cost"), tampered=True)
                if version == _EVENT_VERSION else EvaluationCost()
            )
            exceeded = actual_cost.exceeds(declared_cost)
            if exceeded is not None:
                raise HoldoutLedgerTampered(
                    f"evaluation {exceeded} exceeds its committed reservation")
            try:
                state.reserved_costs[digest] = state.reserved_costs.get(
                    digest, EvaluationCost()).minus(declared_cost)
                state.actual_costs[digest] = state.actual_costs.get(
                    digest, EvaluationCost()).plus(actual_cost)
            except ValueError as exc:
                raise HoldoutLedgerTampered(
                    "evaluation cost accounting is inconsistent") from exc
            if state.reserved_costs[digest].plus(
                    state.actual_costs[digest]).exceeds(
                        state.policies[digest].cost_limit) is not None:
                raise HoldoutLedgerTampered("evaluation cost cap was exceeded")
            state.retirements[final_set_sha256] = {
                "query_id": query_id, "outcome": outcome,
                "result_sha256": result_sha256,
                "actual_cost": actual_cost,
            }
            return
        if kind != "query" or digest not in state.policies:
            raise HoldoutLedgerTampered("holdout ledger event transition is invalid")
        query_id = event.get("query_id")
        purpose = event.get("purpose")
        if (not isinstance(query_id, str) or not _QUERY_ID.fullmatch(query_id)
                or query_id in state.query_ids):
            raise HoldoutLedgerTampered("holdout query id is invalid or duplicated")
        if not isinstance(purpose, str) or not _PURPOSE.fullmatch(purpose):
            raise HoldoutLedgerTampered("holdout query purpose is invalid")
        for key in (
            "view_sha256", "cycle_sha256", "signature_sha256",
            "evaluator_epoch_sha256",
        ):
            value = event.get(key)
            if not isinstance(value, str) or not _HEX_256.fullmatch(value):
                raise HoldoutLedgerTampered(f"holdout query {key} is invalid")
        policy = state.policies[digest]
        expected_ordinal = state.counts[digest] + 1
        ordinal = event.get("ordinal")
        alpha = event.get("alpha")
        issued_at = event.get("issued_at")
        if (isinstance(ordinal, bool) or not isinstance(ordinal, int)
                or ordinal != expected_ordinal
                or isinstance(alpha, bool) or not isinstance(alpha, (int, float))
                or not math.isfinite(float(alpha))
                or float(alpha) != float(policy.query_alpha)):
            raise HoldoutLedgerTampered("holdout query charge is invalid")
        if (isinstance(issued_at, bool) or not isinstance(issued_at, (int, float))
                or not math.isfinite(float(issued_at)) or float(issued_at) < 0):
            raise HoldoutLedgerTampered("holdout query timestamp is invalid")
        if expected_ordinal > policy.max_queries:
            raise HoldoutLedgerTampered("holdout ledger records an over-budget query")
        if float(policy.query_alpha) * expected_ordinal > float(policy.family_alpha) + 1e-15:
            raise HoldoutLedgerTampered("holdout ledger records alpha overspend")
        state.query_ids.add(query_id)
        final_set_sha256 = event.get("final_set_sha256", "")
        protocol_sha256 = event.get("protocol_sha256", "")
        if version in (3, _EVENT_VERSION):
            for label, value in (
                ("final_set_sha256", final_set_sha256),
                ("protocol_sha256", protocol_sha256),
            ):
                if (not isinstance(value, str)
                        or not _HEX_256.fullmatch(value)):
                    raise HoldoutLedgerTampered(f"holdout query {label} is invalid")
            if final_set_sha256 in state.reserved_final_sets:
                raise HoldoutLedgerTampered(
                    "holdout ledger repeats an exposed final set")
        declared_cost = (
            EvaluationCost.from_dict(event.get("declared_cost"), tampered=True)
            if version == _EVENT_VERSION else EvaluationCost()
        )
        committed_cost = state.reserved_costs.get(digest, EvaluationCost()).plus(
            state.actual_costs.get(digest, EvaluationCost())
        )
        exceeded = committed_cost.plus(declared_cost).exceeds(policy.cost_limit)
        if exceeded is not None:
            raise HoldoutLedgerTampered(
                f"holdout ledger records {exceeded} overspend")
        state.queries[query_id] = {
            "holdout_sha256": digest,
            "final_set_sha256": str(final_set_sha256),
            "protocol_sha256": str(protocol_sha256),
            "event_sequence": sequence,
            "ordinal": ordinal,
            "alpha": float(alpha),
            "issued_at": float(issued_at),
            "ledger_tip_sha256": hashlib.sha256(
                _canonical(event).encode("utf-8"),
            ).hexdigest(),
            "declared_cost": declared_cost,
        }
        if final_set_sha256:
            state.reserved_final_sets[final_set_sha256] = query_id
        state.counts[digest] = expected_ordinal
        state.reserved_costs[digest] = state.reserved_costs.get(
            digest, EvaluationCost()).plus(declared_cost)

    def _append_event(
        self, conn: sqlite3.Connection, state: _State, payload: dict[str, Any],
    ) -> _State:
        if state.events >= self.max_events:
            raise HoldoutLedgerError("holdout ledger retention bound reached")
        event = {
            "version": _EVENT_VERSION,
            "ledger_id": state.ledger_id,
            "sequence": state.events + 1,
            "prev_sha256": state.head,
            **payload,
        }
        try:
            encoded = _canonical(event)
        except (TypeError, ValueError) as exc:
            raise HoldoutLedgerError("holdout event is not serializable") from exc
        if not 1 <= len(encoded) <= _MAX_EVENT_CHARS:
            raise HoldoutLedgerError("holdout event exceeds its size bound")
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        try:
            conn.execute(
                "INSERT INTO events(seq, payload, sha256) VALUES (?, ?, ?)",
                (state.events + 1, encoded, digest),
            )
        except sqlite3.Error as exc:
            raise HoldoutLedgerError("cannot append holdout ledger event") from exc
        # Apply the exact persisted representation so writer and verifier share
        # one transition validator.
        self._apply_event(state, event)
        state.head = digest
        state.events += 1
        return state


__all__ = [
    "AlphaBudget", "BoundaryAttempt", "EvaluationCost", "EvaluationReceipt",
    "FinalSetRetired", "LedgerCustodyStatus",
    "HoldoutBudgetExhausted", "HoldoutBudgetStatus", "HoldoutLedgerError",
    "HoldoutLedgerTampered", "HoldoutQuery", "HoldoutQueryLedger",
    "QueryPermit", "fingerprint_manifest",
]
