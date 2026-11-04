"""Fail-closed execution admission for work claimed by an outcome pilot.

Outcome pilots live in the dashboard package, but goals and vendor workflows
can also be started through core entry points.  This module reads only the
tenant-scoped governed records shared by those surfaces.  Work with no exact
pilot claim is unchanged; a claimed item can start only after the complete
pilot manifest and every manifest-bound accounting admission are readable.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from .governed_records import GovernedRecordStore
from .outcome_accounting import SCHEMA as ACCOUNTING_SCHEMA
from .outcome_accounting import STORE as ACCOUNTING_STORE

_PILOTS = GovernedRecordStore("outcome_pilots", "OPL", "outcome_pilots")
_ADMISSION_INDEX = GovernedRecordStore(
    "outcome_pilot_admission_index", "OPI", "outcome_pilot_admission_index",
)
_INDEX_ID = "OPI-active-work-items"
_INDEX_SCHEMA = "lightwork.outcome-pilot-admission-index.v1"
_MANIFEST_SCHEMA = "lightwork.outcome-pilot-admission-manifest.v1"
_MAX_CASES = 100
_MAX_CLAIMS = 100_000


class OutcomePilotAdmissionRequired(RuntimeError):
    """The exact work item has a pilot claim that is not safe to execute."""

    code = "outcome_pilot_admission_incomplete"


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _work_item_key(kind: str, reference: str) -> str:
    if kind not in {"goal", "vendor"}:
        raise ValueError("unsupported outcome-pilot work-item kind")
    if not isinstance(reference, str) or not reference or len(reference) > 200:
        raise ValueError("invalid outcome-pilot work-item reference")
    return _digest({"kind": kind, "reference": reference})


def _expected_entries(pilot: dict[str, Any]) -> list[dict[str, Any]]:
    cases = pilot.get("cases")
    plan_version = pilot.get("plan_version")
    pilot_id = pilot.get("id")
    if (
        not isinstance(cases, list)
        or not 1 <= len(cases) <= _MAX_CASES
        or not _sha256(plan_version)
        or not isinstance(pilot_id, str)
        or not pilot_id.startswith("OPL-")
    ):
        raise ValueError("invalid pilot plan")
    contract = f"outcome-pilot:{pilot_id}:{plan_version}"
    entries: list[dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("invalid pilot case")
        case_id = case.get("id")
        kind = case.get("kind")
        reference = case.get("reference")
        input_version = case.get("input_version")
        if (
            not isinstance(case_id, str)
            or not case_id
            or len(case_id) > 200
            or kind not in {"goal", "vendor"}
            or not isinstance(reference, str)
            or not reference
            or len(reference) > 200
            or not isinstance(input_version, str)
            or not input_version
            or len(input_version) > 512
        ):
            raise ValueError("invalid pilot case binding")
        entries.append({
            "case_id": case_id,
            "admission_id": f"{pilot_id}:{case_id}",
            "work_item_id": f"{kind}:{reference}",
            "acceptance_contract_ref": contract,
            "input_version": input_version,
            "accounting_record_id": None,
            "admitted_at": None,
        })
    if len({entry["case_id"] for entry in entries}) != len(entries):
        raise ValueError("duplicate pilot case identity")
    return entries


def _complete_manifest(pilot: dict[str, Any]) -> list[dict[str, Any]]:
    manifest = pilot.get("admission_manifest")
    keys = {
        "schema", "status", "pilot_id", "plan_version", "expected_count",
        "admitted_count", "manifest_sha256", "completion_sha256", "entries",
    }
    if not isinstance(manifest, dict) or set(manifest) != keys:
        raise ValueError("missing pilot admission manifest")
    expected = _expected_entries(pilot)
    immutable = (
        "case_id", "admission_id", "work_item_id",
        "acceptance_contract_ref", "input_version",
    )
    expected_digest = _digest([
        {key: entry[key] for key in immutable} for entry in expected
    ])
    if any((
        manifest.get("schema") != _MANIFEST_SCHEMA,
        manifest.get("status") != "complete",
        manifest.get("pilot_id") != pilot.get("id"),
        manifest.get("plan_version") != pilot.get("plan_version"),
        manifest.get("expected_count") != len(expected),
        manifest.get("admitted_count") != len(expected),
        manifest.get("manifest_sha256") != expected_digest,
    )):
        raise ValueError("incomplete pilot admission manifest")
    entries = manifest.get("entries")
    entry_keys = {*immutable, "accounting_record_id", "admitted_at"}
    if not isinstance(entries, list) or len(entries) != len(expected):
        raise ValueError("incomplete pilot admission entries")
    completion: list[dict[str, Any]] = []
    for entry, expected_entry in zip(entries, expected, strict=True):
        if (
            not isinstance(entry, dict)
            or set(entry) != entry_keys
            or any(entry.get(key) != expected_entry[key] for key in immutable)
        ):
            raise ValueError("pilot admission entry changed")
        record_id = entry.get("accounting_record_id")
        admitted_at = entry.get("admitted_at")
        if (
            not isinstance(record_id, str)
            or not record_id
            or len(record_id) > 200
            or isinstance(admitted_at, bool)
            or not isinstance(admitted_at, (int, float))
            or not math.isfinite(admitted_at)
            or admitted_at < 0
        ):
            raise ValueError("invalid pilot admission entry")
        completion.append({
            "case_id": entry["case_id"],
            "accounting_record_id": record_id,
            "admitted_at": admitted_at,
        })
    if (
        len({row["accounting_record_id"] for row in completion}) != len(completion)
        or not _sha256(manifest.get("completion_sha256"))
        or manifest["completion_sha256"]
        != _digest([manifest["manifest_sha256"], completion])
    ):
        raise ValueError("pilot admission completion failed integrity validation")
    return entries


def _verify_accounting(pilot: dict[str, Any], entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        record = ACCOUNTING_STORE.get(entry["accounting_record_id"])
        expected = {
            "id": entry["accounting_record_id"],
            "schema": ACCOUNTING_SCHEMA,
            "admission_id": entry["admission_id"],
            "work_item_id": entry["work_item_id"],
            "acceptance_contract_ref": entry["acceptance_contract_ref"],
            "owner_id": pilot.get("actor"),
            "admitted_at": entry["admitted_at"],
        }
        if not isinstance(record, dict) or any(
            record.get(key) != value for key, value in expected.items()
        ):
            raise ValueError("pilot accounting admission is unavailable")


def _require(kind: str, reference: str) -> dict[str, Any] | None:
    index = _ADMISSION_INDEX.get(_INDEX_ID)
    if index is None:
        return None
    claims = index.get("claims")
    if (
        index.get("schema") != _INDEX_SCHEMA
        or not isinstance(claims, dict)
        or len(claims) > _MAX_CLAIMS
    ):
        raise ValueError("pilot admission index is unavailable")
    claim = claims.get(_work_item_key(kind, reference))
    if claim is None:
        return None
    if (
        not isinstance(claim, dict)
        or set(claim) != {"pilot_id", "creation_request"}
        or not isinstance(claim.get("pilot_id"), str)
        or not claim["pilot_id"].startswith("OPL-")
        or not _sha256(claim.get("creation_request"))
    ):
        raise ValueError("pilot work-item claim is unavailable")
    pilot = _PILOTS.get(claim["pilot_id"])
    if (
        not isinstance(pilot, dict)
        or pilot.get("id") != claim["pilot_id"]
        or pilot.get("creation_request") != claim["creation_request"]
        or pilot.get("state", "frozen") != "frozen"
    ):
        raise ValueError("claimed pilot plan is unavailable")
    matching = [
        case for case in pilot.get("cases", [])
        if isinstance(case, dict)
        and case.get("kind") == kind
        and case.get("reference") == reference
    ]
    if len(matching) != 1:
        raise ValueError("pilot work-item binding changed")
    entries = _complete_manifest(pilot)
    _verify_accounting(pilot, entries)
    return {
        "pilot_id": pilot["id"],
        "plan_version": pilot["plan_version"],
        "completion_sha256": pilot["admission_manifest"]["completion_sha256"],
    }


def require_work_item_admission(kind: str, reference: str) -> dict[str, Any] | None:
    """Allow unclaimed work, or prove the exact claimed pilot fully admitted.

    The public failure deliberately contains no pilot, tenant, owner, or
    accounting identifiers.  Callers may expose it to an authorized operator.
    """
    try:
        return _require(kind, reference)
    except OutcomePilotAdmissionRequired:
        raise
    except Exception as exc:
        # The PUBLIC message stays identifier-free, but operators need the real
        # cause: a read/parse/crypto error on the shared admission index would
        # otherwise silently block EVERY work item (unclaimed goals included,
        # which must take the no-op path) with no server-side signal.
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "outcome-pilot admission gate refused %s:%s -- underlying cause: %s: %s",
            kind, reference, type(exc).__name__, exc,
        )
        raise OutcomePilotAdmissionRequired(
            "This work item belongs to an outcome pilot whose complete "
            "accounting admission is not verified. Open the pilot in the app "
            "and retry its admission recovery before starting work."
        ) from exc


__all__ = [
    "OutcomePilotAdmissionRequired",
    "require_work_item_admission",
]
