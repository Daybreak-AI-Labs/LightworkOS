"""Read-only, privacy-safe projection of the governed learning lifecycle.

The learning subsystems deliberately have different authorities:

* dreaming keeps private, mutable insight records;
* hindsight persists aggregate replay measurements;
* :mod:`learning_proof` returns an in-memory statistical result; and
* :class:`self_improvement.PromotionLedger` is the durable authority for a
  promotion or rollback.

This module does not merge those stores or write a new ledger.  It projects
the caller-supplied source records into a small digest-only view which a future
API or dashboard can render without exposing prompts, goal titles, summaries,
artifact locators, transaction ids, or approval signatures.

The projection is intentionally conservative.  A digest is a stable reference,
not an independent attestation of the source it was calculated from.  In
particular, dream insights are mutable, a ``LiftResult`` is not persisted with
its task suite, and a workspace snapshot id is *not* a content digest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Iterable, Mapping
from copy import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .constant_time import text_equals

EVOLUTION_LEDGER_SCHEMA = "lightwork.evolution-ledger-projection.v1"
PROMOTION_RECEIPT_SCHEMA = "lightwork.evolution-promotion-receipt.v1"

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[0-9a-f]{16,64}$")
_MAX_ITEMS = 1_000
_MAX_TEXT = 4_096
_MAX_SIGNATURE = 4_096
_ENTRY_ORDER = {
    "dreaming": 0,
    "hindsight": 1,
    "proof": 2,
    "promotion": 3,
    "rollback": 4,
}
_SNAPSHOT_DIGEST_KEYS = frozenset(
    {
        "snapshot_sha256",
        "workspace_snapshot_sha256",
        "workspace_snapshot_digest",
        "snapshot_digest",
    }
)
_LINEAGE_DIGEST_KEYS = frozenset(
    {
        "parent_sha256",
        "parent_entry_sha256",
        "lineage_sha256",
        "source_sha256",
        "proof_sha256",
        "learning_proof_sha256",
        "dream_sha256",
        "dreaming_sha256",
        "hindsight_sha256",
    }
)


class EvolutionLedgerError(ValueError):
    """A source cannot be represented without weakening the projection claim."""


def _canonical_json(value: Any) -> bytes:
    """The sole byte representation used for public evolution digests."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvolutionLedgerError("source cannot be canonically digested") from exc


def _digest(label: str, value: Any) -> str:
    """Domain-separate every digest so equal bytes cannot be cross-claimed."""
    if not isinstance(label, str) or not label:
        raise EvolutionLedgerError("digest label is invalid")
    blob = value if isinstance(value, bytes) else _canonical_json(value)
    hasher = hashlib.sha256()
    hasher.update(b"lightwork.evolution-ledger.v1\0")
    hasher.update(label.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(blob)
    return hasher.hexdigest()


def _valid_digest(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.lower()
    return normalized if _DIGEST_RE.fullmatch(normalized) else None


def _bounded_text(
    value: Any,
    label: str,
    *,
    allow_empty: bool = False,
    allow_controls: bool = False,
) -> str:
    if not isinstance(value, str):
        raise EvolutionLedgerError(f"{label} must be a string")
    if len(value) > _MAX_TEXT or (not allow_controls and any(ord(char) < 32 for char in value)):
        raise EvolutionLedgerError(f"{label} is not safely bounded")
    if not value and not allow_empty:
        raise EvolutionLedgerError(f"{label} must not be empty")
    return value


def _optional_time(value: Any, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise EvolutionLedgerError(f"{label} must be a finite timestamp")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise EvolutionLedgerError(f"{label} must be a finite timestamp") from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise EvolutionLedgerError(f"{label} must be a finite timestamp")
    return parsed


def _optional_float(value: Any, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed):
        return None
    return parsed


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise EvolutionLedgerError(f"{label} must be a non-negative integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise EvolutionLedgerError(f"{label} must be a non-negative integer") from exc
    if parsed < 0 or parsed != value and not (isinstance(value, float) and value.is_integer()):
        raise EvolutionLedgerError(f"{label} must be a non-negative integer")
    return parsed


def _field(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _source_mapping(source: Any) -> Mapping[str, Any]:
    return source if isinstance(source, Mapping) else {}


def _limited(sources: Iterable[Any] | None, label: str, max_items: int) -> list[Any]:
    if sources is None:
        return []
    if (
        isinstance(max_items, bool)
        or not isinstance(max_items, int)
        or not 1 <= max_items <= _MAX_ITEMS
    ):
        raise EvolutionLedgerError(f"{label} max_items must be between 1 and {_MAX_ITEMS}")
    try:
        iterator = iter(sources)
    except TypeError as exc:
        raise EvolutionLedgerError(f"{label} must be iterable") from exc
    out: list[Any] = []
    for item in iterator:
        if len(out) >= max_items:
            raise EvolutionLedgerError(f"{label} exceeds the configured projection limit")
        out.append(item)
    return out


def _collect_named_digests(
    source: Any,
    names: frozenset[str],
    *,
    suffixes: bool = False,
) -> tuple[str, ...]:
    """Collect only already-formed digest values from bounded nested mappings."""
    found: set[str] = set()
    stack: list[tuple[Any, int]] = [(source, 0)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        visited += 1
        if visited > 256:
            break
        if isinstance(current, Mapping):
            for key, value in current.items():
                key_text = key.lower() if isinstance(key, str) else ""
                is_named = key_text in names or (suffixes and key_text.endswith("_sha256"))
                if is_named:
                    candidates = value if isinstance(value, (list, tuple, set)) else (value,)
                    for candidate in candidates:
                        digest = _valid_digest(candidate)
                        if digest is not None:
                            found.add(digest)
                if depth < 4 and isinstance(value, (Mapping, list, tuple)):
                    stack.append((value, depth + 1))
        elif depth < 4 and isinstance(current, (list, tuple)):
            for value in current:
                if isinstance(value, (Mapping, list, tuple)):
                    stack.append((value, depth + 1))
    return tuple(sorted(found))


def _snapshot_digest(*sources: Any, explicit: Any = None) -> tuple[str | None, tuple[str, ...]]:
    """Return one recorded snapshot digest, never a snapshot id or pathname."""
    if explicit is not None:
        digest = _valid_digest(explicit)
        if digest is None:
            raise EvolutionLedgerError("explicit snapshot digest is invalid")
        return digest, ()
    found: set[str] = set()
    for source in sources:
        found.update(_collect_named_digests(source, _SNAPSHOT_DIGEST_KEYS))
    if len(found) == 1:
        return next(iter(found)), ()
    if len(found) > 1:
        return None, ("snapshot_digest_ambiguous",)
    return None, ("workspace_snapshot_digest_not_recorded",)


def _safe_key_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.lower()
    return normalized if _KEY_ID_RE.fullmatch(normalized) else None


def _signature_digest(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > _MAX_SIGNATURE:
        return None
    return _digest("approval-signature", value)


def _approval_request_digest(request: Any) -> str:
    try:
        message = request.message()
    except Exception as exc:
        raise EvolutionLedgerError("approval request cannot be canonicalized") from exc
    if not isinstance(message, bytes) or not message:
        raise EvolutionLedgerError("approval request message is invalid")
    return _digest("approval-request", message)


@dataclass(frozen=True)
class EvolutionLedgerEntry:
    """A redacted lifecycle event suitable for a read-only product surface."""

    kind: str
    occurred_at: float | None
    source_sha256: str
    subject_sha256: str
    entry_sha256: str
    lineage_sha256: tuple[str, ...] = ()
    evidence_sha256: tuple[str, ...] = ()
    integrity: str = "runtime_supplied"
    approval_signer_key_id: str | None = None
    approval_status: str = "not_applicable"
    snapshot_sha256: str | None = None
    artifact_sha256: str | None = None
    promotion_receipt_sha256: str | None = None
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """A JSON-safe object containing no raw learning source fields."""
        return {
            "schema": EVOLUTION_LEDGER_SCHEMA,
            "kind": self.kind,
            "occurred_at": self.occurred_at,
            "source_sha256": self.source_sha256,
            "subject_sha256": self.subject_sha256,
            "entry_sha256": self.entry_sha256,
            "lineage_sha256": list(self.lineage_sha256),
            "evidence_sha256": list(self.evidence_sha256),
            "integrity": self.integrity,
            "approval_signer_key_id": self.approval_signer_key_id,
            "approval_status": self.approval_status,
            "snapshot_sha256": self.snapshot_sha256,
            "artifact_sha256": self.artifact_sha256,
            "promotion_receipt_sha256": self.promotion_receipt_sha256,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class EvolutionLedgerProjection:
    """The complete redacted projection plus its explicit evidence limits."""

    entries: tuple[EvolutionLedgerEntry, ...]
    limitations: tuple[str, ...] = ()
    schema: str = EVOLUTION_LEDGER_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "entries": [entry.to_dict() for entry in self.entries],
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class PromotionReceiptVerification:
    """Receipt integrity and optional approval verification are reported apart."""

    receipt_valid: bool
    receipt_sha256: str | None
    approval_status: str
    approval_signer_key_id: str | None = None
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_valid": self.receipt_valid,
            "receipt_sha256": self.receipt_sha256,
            "approval_status": self.approval_status,
            "approval_signer_key_id": self.approval_signer_key_id,
            "limitations": list(self.limitations),
        }


def _make_entry(
    *,
    kind: str,
    occurred_at: float | None,
    source_sha256: str,
    subject_sha256: str,
    lineage_sha256: Iterable[str] = (),
    evidence_sha256: Iterable[str] = (),
    integrity: str,
    approval_signer_key_id: str | None = None,
    approval_status: str = "not_applicable",
    snapshot_sha256: str | None = None,
    artifact_sha256: str | None = None,
    promotion_receipt_sha256: str | None = None,
    limitations: Iterable[str] = (),
) -> EvolutionLedgerEntry:
    if kind not in _ENTRY_ORDER:
        raise EvolutionLedgerError("evolution entry kind is invalid")
    source_sha256 = _valid_digest(source_sha256) or ""
    subject_sha256 = _valid_digest(subject_sha256) or ""
    if not source_sha256 or not subject_sha256:
        raise EvolutionLedgerError("evolution entry source digest is invalid")
    lineage = tuple(sorted({_valid_digest(value) for value in lineage_sha256} - {None}))
    evidence = tuple(sorted({_valid_digest(value) for value in evidence_sha256} - {None}))
    snapshot_sha256 = _valid_digest(snapshot_sha256)
    artifact_sha256 = _valid_digest(artifact_sha256)
    promotion_receipt_sha256 = _valid_digest(promotion_receipt_sha256)
    safe_key = _safe_key_id(approval_signer_key_id)
    safe_limits = tuple(sorted({str(value) for value in limitations if value}))
    body = {
        "schema": EVOLUTION_LEDGER_SCHEMA,
        "kind": kind,
        "occurred_at": occurred_at,
        "source_sha256": source_sha256,
        "subject_sha256": subject_sha256,
        "lineage_sha256": list(lineage),
        "evidence_sha256": list(evidence),
        "integrity": integrity,
        "approval_signer_key_id": safe_key,
        "approval_status": approval_status,
        "snapshot_sha256": snapshot_sha256,
        "artifact_sha256": artifact_sha256,
        "promotion_receipt_sha256": promotion_receipt_sha256,
        "limitations": list(safe_limits),
    }
    return EvolutionLedgerEntry(
        entry_sha256=_digest("entry", body),
        kind=kind,
        occurred_at=occurred_at,
        source_sha256=source_sha256,
        subject_sha256=subject_sha256,
        lineage_sha256=lineage,
        evidence_sha256=evidence,
        integrity=integrity,
        approval_signer_key_id=safe_key,
        approval_status=approval_status,
        snapshot_sha256=snapshot_sha256,
        artifact_sha256=artifact_sha256,
        promotion_receipt_sha256=promotion_receipt_sha256,
        limitations=safe_limits,
    )


def _source_time(source: Any) -> float | None:
    value = _field(source, "ts", None)
    if value is None:
        value = _field(source, "occurred_at", None)
    return _optional_time(value, "source occurrence time")


def _source_lineage(source: Any) -> tuple[str, ...]:
    return _collect_named_digests(_source_mapping(source), _LINEAGE_DIGEST_KEYS)


def _source_evidence(source: Any) -> tuple[str, ...]:
    return _collect_named_digests(_source_mapping(source), frozenset(), suffixes=True)


def project_dreaming_insights(
    insights: Iterable[Any] | None,
    *,
    max_items: int = _MAX_ITEMS,
) -> tuple[EvolutionLedgerEntry, ...]:
    """Project ``DreamInsight``-like values without exposing text or scope ids.

    The output is a fingerprint of the current private insight, not a durable
    history: dreaming atomically rewrites and retires its insight store.
    """
    entries: list[EvolutionLedgerEntry] = []
    for insight in _limited(insights, "dreaming insights", max_items):
        text = _bounded_text(
            _field(insight, "text"),
            "dream insight text",
            allow_controls=True,
        )
        kind = _bounded_text(_field(insight, "kind", "failure_pattern"), "dream insight kind")
        domain = _field(insight, "domain", None)
        if domain is not None:
            domain = _bounded_text(domain, "dream insight domain", allow_empty=True)
        evidence = _nonnegative_int(_field(insight, "evidence", 1), "dream insight evidence")
        timestamp = _source_time(insight)
        scoped = (
            _field(insight, "channel", None) is not None
            or _field(insight, "user_id", None) is not None
        )
        source_sha256 = _digest(
            "dreaming-insight",
            {
                "text_sha256": _digest("dreaming-insight-text", text),
                "kind_sha256": _digest("dreaming-insight-kind", kind),
                "domain_sha256": _digest("dreaming-insight-domain", domain)
                if domain is not None
                else None,
                "evidence": evidence,
                "scoped": scoped,
                "occurred_at": timestamp,
            },
        )
        snapshot, snapshot_limits = _snapshot_digest(_source_mapping(insight))
        entries.append(
            _make_entry(
                kind="dreaming",
                occurred_at=timestamp,
                source_sha256=source_sha256,
                subject_sha256=source_sha256,
                lineage_sha256=_source_lineage(insight),
                evidence_sha256=_source_evidence(insight),
                integrity="mutable_private_dream_store",
                snapshot_sha256=snapshot,
                limitations=(
                    "dreaming_source_is_mutable_not_history_complete",
                    "unkeyed_digest_can_be_guessable_for_low_entropy_text",
                    *snapshot_limits,
                ),
            )
        )
    return tuple(entries)


def _count_or_length(value: Any, label: str) -> int:
    if isinstance(value, (list, tuple, set)):
        return len(value)
    return _nonnegative_int(value, label)


def project_hindsight_reports(
    reports: Iterable[Any] | None,
    *,
    max_items: int = _MAX_ITEMS,
) -> tuple[EvolutionLedgerEntry, ...]:
    """Project aggregate hindsight reports while omitting goal titles/labels."""
    entries: list[EvolutionLedgerEntry] = []
    for report in _limited(reports, "hindsight reports", max_items):
        n_goals = _nonnegative_int(_field(report, "n_goals"), "hindsight n_goals")
        covered_now = _nonnegative_int(_field(report, "covered_now"), "hindsight covered_now")
        covered_before = _nonnegative_int(
            _field(report, "covered_before"), "hindsight covered_before"
        )
        gained = _count_or_length(_field(report, "gained"), "hindsight gained")
        regressed = _count_or_length(_field(report, "regressed"), "hindsight regressed")
        timestamp = _source_time(report)
        source_sha256 = _digest(
            "hindsight-report",
            {
                "occurred_at": timestamp,
                "n_goals": n_goals,
                "covered_now": covered_now,
                "covered_before": covered_before,
                "gained": gained,
                "regressed": regressed,
            },
        )
        snapshot, snapshot_limits = _snapshot_digest(_source_mapping(report))
        integrity = (
            "aggregate_hindsight_ledger_unverified"
            if isinstance(report, Mapping) and timestamp is not None
            else "runtime_hindsight_report_unbound"
        )
        entries.append(
            _make_entry(
                kind="hindsight",
                occurred_at=timestamp,
                source_sha256=source_sha256,
                subject_sha256=source_sha256,
                lineage_sha256=_source_lineage(report),
                evidence_sha256=_source_evidence(report),
                integrity=integrity,
                snapshot_sha256=snapshot,
                limitations=(
                    "goal_titles_and_before_labels_omitted_for_privacy",
                    "hindsight_aggregate_not_independently_audit_verified",
                    *snapshot_limits,
                ),
            )
        )
    return tuple(entries)


def project_learning_proofs(
    results: Iterable[Any] | None,
    *,
    max_items: int = _MAX_ITEMS,
) -> tuple[EvolutionLedgerEntry, ...]:
    """Project ``LiftResult``-like measurements without task inputs or outputs."""
    entries: list[EvolutionLedgerEntry] = []
    for result in _limited(results, "learning proofs", max_items):
        timestamp = _source_time(result)
        material = {
            "occurred_at": timestamp,
            "n": _nonnegative_int(_field(result, "n"), "proof n"),
            "baseline_mean": _optional_float(_field(result, "baseline_mean"), "proof baseline"),
            "treatment_mean": _optional_float(_field(result, "treatment_mean"), "proof treatment"),
            "delta": _optional_float(_field(result, "delta"), "proof delta"),
            "ci_low": _optional_float(_field(result, "ci_low"), "proof ci_low"),
            "ci_high": _optional_float(_field(result, "ci_high"), "proof ci_high"),
            "wins": _nonnegative_int(_field(result, "wins"), "proof wins"),
            "losses": _nonnegative_int(_field(result, "losses"), "proof losses"),
            "ties": _nonnegative_int(_field(result, "ties"), "proof ties"),
            "significant": bool(_field(result, "significant")),
            "improved": bool(_field(result, "improved")),
        }
        if any(
            material[name] is None
            for name in ("baseline_mean", "treatment_mean", "delta", "ci_low", "ci_high")
        ):
            raise EvolutionLedgerError("learning proof contains a non-finite score")
        source_sha256 = _digest("learning-proof", material)
        snapshot, snapshot_limits = _snapshot_digest(_source_mapping(result))
        entries.append(
            _make_entry(
                kind="proof",
                occurred_at=timestamp,
                source_sha256=source_sha256,
                subject_sha256=source_sha256,
                lineage_sha256=_source_lineage(result),
                evidence_sha256=_source_evidence(result),
                integrity="runtime_lift_result_unbound",
                snapshot_sha256=snapshot,
                limitations=(
                    "lift_result_is_not_bound_to_a_durable_task_suite_or_runner",
                    "statistical_measurement_not_independently_reexecuted",
                    *snapshot_limits,
                ),
            )
        )
    return tuple(entries)


def _record_snapshot_and_refs(
    record: Any,
    *,
    explicit: Any = None,
) -> tuple[str | None, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    provenance = _field(record, "provenance", {})
    audit_payload = _field(record, "audit_payload", {})
    if not isinstance(provenance, Mapping) or not isinstance(audit_payload, Mapping):
        raise EvolutionLedgerError("promotion provenance is not an object")
    snapshot, snapshot_limits = _snapshot_digest(
        provenance,
        audit_payload,
        explicit=explicit,
    )
    references = set(_collect_named_digests(provenance, _LINEAGE_DIGEST_KEYS))
    references.update(_collect_named_digests(audit_payload, _LINEAGE_DIGEST_KEYS))
    evidence = set(_collect_named_digests(provenance, frozenset(), suffixes=True))
    evidence.update(_collect_named_digests(audit_payload, frozenset(), suffixes=True))
    return (
        snapshot,
        tuple(sorted(references)),
        tuple(sorted(evidence | references | set(filter(None, [snapshot])))),
        snapshot_limits,
    )


def _transaction_receipt(
    transaction: Any, record: Any
) -> tuple[dict[str, Any] | None, str | None, tuple[str, ...], str | None]:
    if transaction is None:
        return None, None, (), None
    tx_record = _field(transaction, "record")
    if _field(tx_record, "id") != _field(record, "id"):
        raise EvolutionLedgerError("promotion transaction does not belong to the record")
    state = _field(transaction, "state")
    if state not in {"prepared", "committed", "aborted"}:
        raise EvolutionLedgerError("promotion transaction state is invalid")
    transaction_id = _bounded_text(_field(transaction, "id"), "promotion transaction id")

    def artifact(value: Any, label: str) -> dict[str, str] | None:
        if value is None:
            return None
        artifact_sha256 = _valid_digest(_field(value, "sha256"))
        if artifact_sha256 is None:
            raise EvolutionLedgerError(f"promotion {label} artifact digest is invalid")
        return {
            "identity_sha256": _digest(
                f"{label}-artifact-identity",
                _bounded_text(_field(value, "identity"), f"{label} artifact identity"),
            ),
            "sha256": artifact_sha256,
            "version_sha256": _digest(
                f"{label}-artifact-version",
                _bounded_text(_field(value, "version"), f"{label} artifact version"),
            ),
        }

    before = artifact(_field(transaction, "before"), "before")
    after = artifact(_field(transaction, "after"), "after")
    last_observed = artifact(_field(transaction, "last_observed"), "observed")
    body = {
        "id_sha256": _digest("promotion-transaction-id", transaction_id),
        "state": state,
        "prepared_at": _optional_time(
            _field(transaction, "prepared_at"), "transaction prepared_at"
        ),
        "resolved_at": _optional_time(
            _field(transaction, "resolved_at"), "transaction resolved_at"
        ),
        "before": before,
        "after": after,
        "last_observed": last_observed,
        "recovery_attempts": _nonnegative_int(
            _field(transaction, "recovery_attempts", 0), "transaction recovery_attempts"
        ),
    }
    evidence = tuple(
        sorted({value["sha256"] for value in (before, after, last_observed) if value is not None})
    )
    return body, body["id_sha256"], evidence, after["sha256"] if after else None


def _promotion_receipt_body(
    record: Any,
    *,
    transaction: Any = None,
    snapshot_sha256: Any = None,
    event: str = "promotion",
) -> dict[str, Any]:
    if event not in {"promotion", "rollback"}:
        raise EvolutionLedgerError("promotion receipt event is invalid")
    record_id = _bounded_text(_field(record, "id"), "promotion record id")
    rung = _bounded_text(_field(record, "rung"), "promotion rung")
    promoted_at = _optional_time(_field(record, "promoted_at"), "promotion promoted_at")
    if promoted_at is None:
        raise EvolutionLedgerError("promotion promoted_at is required")
    rolled_back = bool(_field(record, "rolled_back", False))
    rolled_back_at = _optional_time(
        _field(record, "rolled_back_at", None), "promotion rolled_back_at"
    )
    if event == "rollback" and not rolled_back:
        raise EvolutionLedgerError("cannot construct a rollback receipt for an active promotion")

    payload_sha256 = _valid_digest(_field(record, "payload_sha256", None))
    model_risk_sha256 = _valid_digest(_field(record, "model_risk_payload_sha256", None))
    signer_key_id = _safe_key_id(_field(record, "approver_id", None))
    signature_sha256 = _signature_digest(_field(record, "approval_signature", None))
    approval_request_sha256 = None
    if payload_sha256 is not None and signature_sha256 is not None:
        try:
            from .approval_signing import ApprovalRequest

            approval_request_sha256 = _approval_request_digest(
                ApprovalRequest(record_id, rung, payload_sha256)
            )
        except Exception as exc:
            raise EvolutionLedgerError("promotion approval request is unavailable") from exc

    approval_status = "not_recorded"
    if any(value is not None for value in (payload_sha256, signature_sha256, signer_key_id)):
        approval_status = (
            "recorded_unverified"
            if all(
                value is not None
                for value in (
                    payload_sha256,
                    signature_sha256,
                    signer_key_id,
                    approval_request_sha256,
                )
            )
            else "incomplete_record"
        )

    snapshot, references, evidence_and_snapshot, snapshot_limits = _record_snapshot_and_refs(
        record,
        explicit=snapshot_sha256,
    )
    transaction_body, transaction_sha256, transaction_evidence, artifact_sha256 = (
        _transaction_receipt(
            transaction,
            record,
        )
    )
    limitations = ["summary_omitted_for_privacy"]
    limitations.extend(snapshot_limits)
    if snapshot is None:
        limitations.append("workspace_snapshot_digest_not_recorded")
    if transaction_body is None:
        limitations.append("runtime_artifact_binding_not_recorded")
    if approval_status == "recorded_unverified":
        limitations.append("approval_signature_requires_private_binding_verification")
    else:
        limitations.append("human_approval_signature_not_verifiable_from_receipt")
    if _field(record, "approver_id", None) is not None and signer_key_id is None:
        limitations.append("approval_signer_key_id_not_safe_to_expose")
    if _field(record, "payload_sha256", None) is not None and payload_sha256 is None:
        limitations.append("approval_payload_digest_invalid")
    if _field(record, "model_risk_payload_sha256", None) is not None and model_risk_sha256 is None:
        limitations.append("model_risk_payload_digest_invalid")

    scores = {
        "baseline": _optional_float(_field(record, "baseline_score"), "promotion baseline_score"),
        "candidate": _optional_float(
            _field(record, "candidate_score"), "promotion candidate_score"
        ),
        "samples": _optional_float(_field(record, "samples", None), "promotion samples"),
        "effect_ci_low": _optional_float(
            _field(record, "effect_ci_low", None), "promotion effect_ci_low"
        ),
    }
    if scores["baseline"] is None or scores["candidate"] is None:
        limitations.append("promotion_score_not_finite")
    record_material = {
        "record_id_sha256": _digest("promotion-record-id", record_id),
        "rung_sha256": _digest("promotion-rung", rung),
        "promoted_at": promoted_at,
        "scores": scores,
        "payload_sha256": payload_sha256,
        "model_risk_payload_sha256": model_risk_sha256,
        "approval_signer_key_id": signer_key_id,
        "approval_signature_sha256": signature_sha256,
        "approval_request_sha256": approval_request_sha256,
        "referenced_sha256": list(references),
    }
    if event == "rollback":
        record_material["rolled_back_at"] = rolled_back_at
    record_sha256 = _digest(f"{event}-record", record_material)
    return {
        "schema": PROMOTION_RECEIPT_SCHEMA,
        "event": event,
        "record_sha256": record_sha256,
        "record_id_sha256": record_material["record_id_sha256"],
        "rung_sha256": record_material["rung_sha256"],
        "occurred_at": rolled_back_at if event == "rollback" else promoted_at,
        "scores": scores,
        "payload_sha256": payload_sha256,
        "model_risk_payload_sha256": model_risk_sha256,
        "approval": {
            "signer_key_id": signer_key_id,
            "status": approval_status,
            "request_sha256": approval_request_sha256,
            "signature_sha256": signature_sha256,
        },
        "snapshot_sha256": snapshot,
        "transaction": transaction_body,
        "transaction_sha256": transaction_sha256,
        "artifact_sha256": artifact_sha256,
        "referenced_sha256": list(references),
        "evidence_sha256": list(sorted(set(evidence_and_snapshot) | set(transaction_evidence))),
        "limitations": sorted(set(limitations)),
    }


def build_promotion_receipt(
    record: Any,
    *,
    transaction: Any = None,
    snapshot_sha256: str | None = None,
    event: str = "promotion",
) -> dict[str, Any]:
    """Build a deterministic, digest-only receipt without persisting anything.

    ``event`` is normally ``"promotion"``.  ``"rollback"`` is available to
    project a record which has a durable rollback marker.  Neither form
    includes the candidate id, summary, raw provenance, artifact locator,
    approval signature, or snapshot path.
    """
    body = _promotion_receipt_body(
        record,
        transaction=transaction,
        snapshot_sha256=snapshot_sha256,
        event=event,
    )
    return {**body, "receipt_sha256": _digest("promotion-receipt", body)}


_RECEIPT_BODY_KEYS = frozenset(
    {
        "schema",
        "event",
        "record_sha256",
        "record_id_sha256",
        "rung_sha256",
        "occurred_at",
        "scores",
        "payload_sha256",
        "model_risk_payload_sha256",
        "approval",
        "snapshot_sha256",
        "transaction",
        "transaction_sha256",
        "artifact_sha256",
        "referenced_sha256",
        "evidence_sha256",
        "limitations",
    }
)


def _verified_receipt_body(receipt: Any) -> tuple[dict[str, Any], str]:
    if not isinstance(receipt, Mapping):
        raise EvolutionLedgerError("receipt must be an object")
    if set(receipt) != _RECEIPT_BODY_KEYS | {"receipt_sha256"}:
        raise EvolutionLedgerError("receipt schema fields are invalid")
    body = {key: receipt[key] for key in _RECEIPT_BODY_KEYS}
    if body["schema"] != PROMOTION_RECEIPT_SCHEMA:
        raise EvolutionLedgerError("receipt schema is unsupported")
    if body["event"] not in {"promotion", "rollback"}:
        raise EvolutionLedgerError("receipt event is invalid")
    supplied = _valid_digest(receipt.get("receipt_sha256"))
    if supplied is None or not hmac.compare_digest(supplied, _digest("promotion-receipt", body)):
        raise EvolutionLedgerError("receipt digest does not verify")
    for key in (
        "record_sha256",
        "record_id_sha256",
        "rung_sha256",
    ):
        if _valid_digest(body.get(key)) is None:
            raise EvolutionLedgerError("receipt contains an invalid required digest")
    return body, supplied


def verify_promotion_receipt(
    receipt: Any,
    *,
    approval_request: Any = None,
    approval_signature: str | None = None,
    trusted_pubkeys: list[str] | None = None,
) -> PromotionReceiptVerification:
    """Verify receipt bytes and, when privately supplied, its approval binding.

    A privacy-safe receipt carries only a hash of the request and signature.
    Therefore signature verification needs the original ``ApprovalRequest``
    and signature out of band.  Passing neither still verifies receipt bytes,
    but deliberately cannot establish a human approval claim.
    """
    try:
        body, receipt_sha256 = _verified_receipt_body(receipt)
    except EvolutionLedgerError:
        return PromotionReceiptVerification(
            receipt_valid=False,
            receipt_sha256=None,
            approval_status="receipt_invalid",
            limitations=("receipt_integrity_failed",),
        )

    approval = body["approval"]
    if not isinstance(approval, Mapping):
        return PromotionReceiptVerification(
            receipt_valid=True,
            receipt_sha256=receipt_sha256,
            approval_status="receipt_invalid",
            limitations=("approval_receipt_shape_invalid",),
        )
    claimed_key_id = _safe_key_id(approval.get("signer_key_id"))
    recorded = approval.get("status")
    request_digest = _valid_digest(approval.get("request_sha256"))
    signature_digest = _valid_digest(approval.get("signature_sha256"))
    if recorded == "not_recorded" and request_digest is None and signature_digest is None:
        return PromotionReceiptVerification(
            receipt_valid=True,
            receipt_sha256=receipt_sha256,
            approval_status="not_recorded",
            approval_signer_key_id=claimed_key_id,
            limitations=("receipt_has_no_human_approval_material",),
        )
    if approval_request is None or not approval_signature:
        return PromotionReceiptVerification(
            receipt_valid=True,
            receipt_sha256=receipt_sha256,
            approval_status="not_verifiable_without_private_binding",
            approval_signer_key_id=claimed_key_id,
            limitations=("original_approval_request_and_signature_required",),
        )
    try:
        request_sha256 = _approval_request_digest(approval_request)
        supplied_signature_sha256 = _signature_digest(approval_signature)
        payload_sha256 = _valid_digest(_field(approval_request, "payload_sha256"))
        rung = _bounded_text(_field(approval_request, "rung"), "approval rung")
    except EvolutionLedgerError:
        return PromotionReceiptVerification(
            receipt_valid=True,
            receipt_sha256=receipt_sha256,
            approval_status="private_binding_invalid",
            approval_signer_key_id=claimed_key_id,
            limitations=("original_approval_request_is_invalid",),
        )
    if (
        request_digest is None
        or signature_digest is None
        or supplied_signature_sha256 is None
        or not hmac.compare_digest(request_digest, request_sha256)
        or not hmac.compare_digest(signature_digest, supplied_signature_sha256)
        or not hmac.compare_digest(body["rung_sha256"], _digest("promotion-rung", rung))
        or payload_sha256 is None
        or not text_equals(str(body.get("payload_sha256") or ""), payload_sha256)
    ):
        return PromotionReceiptVerification(
            receipt_valid=True,
            receipt_sha256=receipt_sha256,
            approval_status="private_binding_mismatch",
            approval_signer_key_id=claimed_key_id,
            limitations=("private_approval_material_does_not_match_receipt",),
        )
    try:
        from .approval_signing import verify

        verified_key_id = verify(
            approval_request,
            approval_signature,
            trusted_pubkeys=trusted_pubkeys,
        )
    except Exception:
        verified_key_id = None
    if verified_key_id is None:
        return PromotionReceiptVerification(
            receipt_valid=True,
            receipt_sha256=receipt_sha256,
            approval_status="signature_untrusted_or_invalid",
            approval_signer_key_id=claimed_key_id,
            limitations=("approval_signature_did_not_verify_against_supplied_trust_roots",),
        )
    verified_key_id = _safe_key_id(verified_key_id)
    if (
        verified_key_id is None
        or claimed_key_id is None
        or not hmac.compare_digest(claimed_key_id, verified_key_id)
    ):
        return PromotionReceiptVerification(
            receipt_valid=True,
            receipt_sha256=receipt_sha256,
            approval_status="approval_signer_key_id_mismatch",
            approval_signer_key_id=claimed_key_id,
            limitations=("receipt_signer_key_id_does_not_match_verified_key",),
        )
    return PromotionReceiptVerification(
        receipt_valid=True,
        receipt_sha256=receipt_sha256,
        approval_status="verified",
        approval_signer_key_id=verified_key_id,
    )


def _readonly_promotion_state(
    ledger: Any,
) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """Read a ledger without calling its repairing/locking public query API.

    ``PromotionLedger.all()`` intentionally repairs a stale compatibility JSON
    projection and acquires a lock file.  Those are correct operational
    behaviours, but a view endpoint must not create a lock or repair source
    evidence merely because an auditor opened it.  Its journal parser is
    already the authority verifier; run it on a shallow copy so even its
    in-memory audit-outbox refresh is not observable by the caller.  A racing
    append yields an incomplete/hash-invalid stream and fails closed.
    """
    path = getattr(ledger, "path", None)
    if path is None:
        records = getattr(ledger, "_records", None)
        transactions = getattr(ledger, "_transactions", None)
        if not isinstance(records, dict) or not isinstance(transactions, dict):
            raise EvolutionLedgerError("in-memory promotion ledger state is unavailable")
        return dict(records), dict(transactions), False

    try:
        reader = copy(ledger)
        projection_path = Path(path)
        journal_path = Path(f"{projection_path}.journal")
        if journal_path.exists():
            records, transactions, _head = reader._read_journal_state_locked()
            return records, transactions, True
        if projection_path.exists():
            return reader._read_projection_locked(), {}, False
        return {}, {}, False
    except Exception as exc:
        raise EvolutionLedgerError("promotion ledger cannot be read fail-closed") from exc


def _promotion_entries(ledger: Any) -> tuple[tuple[EvolutionLedgerEntry, ...], tuple[str, ...]]:
    if ledger is None:
        return (), ()
    records_by_id, transactions_by_id, hash_chained = _readonly_promotion_state(ledger)
    records = list(records_by_id.values())
    transactions = list(transactions_by_id.values())
    transactions_by_record: dict[str, Any] = {}
    for transaction in transactions:
        if _field(transaction, "state") != "committed":
            continue
        record_id = _field(_field(transaction, "record"), "id")
        if not isinstance(record_id, str) or record_id in transactions_by_record:
            raise EvolutionLedgerError("promotion ledger has ambiguous committed transactions")
        transactions_by_record[record_id] = transaction
    persistent = getattr(ledger, "path", None) is not None
    if hash_chained:
        integrity = "hash_chained_local_promotion_ledger"
        global_limits = ("promotion_ledger_is_local_not_externally_anchored",)
    elif persistent:
        integrity = "legacy_projection_promotion_ledger"
        global_limits = ("promotion_ledger_has_no_hash_chained_journal",)
    else:
        integrity = "in_memory_promotion_ledger"
        global_limits = ("promotion_ledger_is_not_durable",)
    entries: list[EvolutionLedgerEntry] = []
    for record in records:
        record_id = _bounded_text(_field(record, "id"), "promotion record id")
        transaction = transactions_by_record.get(record_id)
        promotion_receipt = build_promotion_receipt(record, transaction=transaction)
        promotion_subject = promotion_receipt["record_id_sha256"]
        promotion_entry = _make_entry(
            kind="promotion",
            occurred_at=_optional_time(promotion_receipt["occurred_at"], "promotion occurred_at"),
            source_sha256=promotion_receipt["record_sha256"],
            subject_sha256=promotion_subject,
            lineage_sha256=promotion_receipt["referenced_sha256"],
            evidence_sha256=promotion_receipt["evidence_sha256"],
            integrity=integrity,
            approval_signer_key_id=promotion_receipt["approval"]["signer_key_id"],
            approval_status=promotion_receipt["approval"]["status"],
            snapshot_sha256=promotion_receipt["snapshot_sha256"],
            artifact_sha256=promotion_receipt["artifact_sha256"],
            promotion_receipt_sha256=promotion_receipt["receipt_sha256"],
            limitations=(*promotion_receipt["limitations"], *global_limits),
        )
        entries.append(promotion_entry)
        if not bool(_field(record, "rolled_back", False)):
            continue
        rollback_receipt = build_promotion_receipt(
            record,
            transaction=transaction,
            event="rollback",
        )
        rollback_entry = _make_entry(
            kind="rollback",
            occurred_at=_optional_time(rollback_receipt["occurred_at"], "rollback occurred_at"),
            source_sha256=rollback_receipt["record_sha256"],
            subject_sha256=promotion_subject,
            lineage_sha256=(promotion_entry.entry_sha256, *rollback_receipt["referenced_sha256"]),
            evidence_sha256=rollback_receipt["evidence_sha256"],
            integrity=integrity,
            approval_signer_key_id=rollback_receipt["approval"]["signer_key_id"],
            approval_status=rollback_receipt["approval"]["status"],
            snapshot_sha256=rollback_receipt["snapshot_sha256"],
            artifact_sha256=rollback_receipt["artifact_sha256"],
            promotion_receipt_sha256=rollback_receipt["receipt_sha256"],
            limitations=(*rollback_receipt["limitations"], *global_limits),
        )
        entries.append(rollback_entry)
    return tuple(entries), global_limits


def promotion_receipt_for_entry(ledger: Any, entry_sha256: str) -> dict[str, Any] | None:
    """Read a digest-only receipt for an exact currently recorded history row.

    This performs no repair or approval verification. If a concurrent change
    replaces the selected row, the caller must refresh instead of receiving a
    receipt for a different record.
    """
    selected = _valid_digest(entry_sha256)
    if selected is None:
        raise EvolutionLedgerError("history row fingerprint is invalid")
    entries, _limits = _promotion_entries(ledger)
    target = next((entry for entry in entries if entry.entry_sha256 == selected), None)
    if target is None:
        return None
    records, transactions, _chained = _readonly_promotion_state(ledger)
    by_record = {_field(_field(tx, "record"), "id"): tx for tx in transactions.values()
                 if _field(tx, "state") == "committed"}
    for record in records.values():
        if _digest("promotion-record-id", _field(record, "id")) != target.subject_sha256:
            continue
        if target.kind == "rollback" and not _field(record, "rolled_back", False):
            return None
        receipt = build_promotion_receipt(record, transaction=by_record.get(_field(record, "id")),
                                          event=target.kind)
        if hmac.compare_digest(receipt["receipt_sha256"], target.promotion_receipt_sha256 or ""):
            return receipt
    return None


def project_evolution_ledger(
    promotion_ledger: Any = None,
    *,
    dreams: Iterable[Any] | None = None,
    hindsight: Iterable[Any] | None = None,
    proofs: Iterable[Any] | None = None,
    max_items: int = _MAX_ITEMS,
) -> EvolutionLedgerProjection:
    """Create a deterministic, read-only projection over existing authorities.

    The function never constructs a :class:`PromotionLedger`, writes a source
    file, invokes a learning cycle, or verifies a signature.  Pass already-read
    ``DreamInsight``/``HindsightReport``/``LiftResult`` values and an existing
    ledger instance.  Signature verification remains an explicit private
    operation through :func:`verify_promotion_receipt`.
    """
    entries = [
        *project_dreaming_insights(dreams, max_items=max_items),
        *project_hindsight_reports(hindsight, max_items=max_items),
        *project_learning_proofs(proofs, max_items=max_items),
    ]
    promotions, promotion_limits = _promotion_entries(promotion_ledger)
    entries.extend(promotions)
    entries.sort(
        key=lambda entry: (
            entry.occurred_at is None,
            entry.occurred_at if entry.occurred_at is not None else 0.0,
            _ENTRY_ORDER[entry.kind],
            entry.entry_sha256,
        )
    )
    limitations = set(promotion_limits)
    if dreams:
        limitations.add("dreaming_history_is_not_complete_or_immutable")
    if hindsight:
        limitations.add("hindsight_rows_are_aggregate_and_not_independently_verified")
    if proofs:
        limitations.add("learning_proofs_are_runtime_results_without_persisted_suite_binding")
    return EvolutionLedgerProjection(
        entries=tuple(entries),
        limitations=tuple(sorted(limitations)),
    )


__all__ = [
    "EVOLUTION_LEDGER_SCHEMA",
    "PROMOTION_RECEIPT_SCHEMA",
    "EvolutionLedgerEntry",
    "EvolutionLedgerError",
    "EvolutionLedgerProjection",
    "PromotionReceiptVerification",
    "build_promotion_receipt",
    "project_dreaming_insights",
    "project_evolution_ledger",
    "promotion_receipt_for_entry",
    "project_hindsight_reports",
    "project_learning_proofs",
    "verify_promotion_receipt",
]
