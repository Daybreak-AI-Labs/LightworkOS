"""Vendored deterministic engine for the Model Risk Officer standalone.

This module imports nothing from ``maverick``.  It analyzes bounded, declared
metadata and writes only to an unsigned local store.  Framework mappings are
versioned advisory aids: they are not legal conclusions, conformity
assessments, or certifications.  DGM analysis produces a report and cannot
promote, deploy, roll back, or contact any external system.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from local_store_lock import cross_process_lock as _shared_cross_process_lock
from request_limits import reject_sensitive_fields

MAX_LOCAL_STORE_BYTES = 8 * 1024 * 1024
MAX_LOCAL_RECORDS = 5_000
MAX_ASSETS = 2_000
MAX_EVIDENCE_ROWS = 8_000
MAX_RELATIONSHIPS = 256
DEFAULT_FRESHNESS_DAYS = 90

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,159}\Z")
_ASSET_TYPES = frozenset({"model", "agent", "tool", "dataset", "provider"})
_CRITICALITIES = frozenset({"low", "moderate", "high", "critical"})
_LIFECYCLES = frozenset({"proposed", "development", "testing", "production", "retired"})
_DATA_CLASSES = frozenset({"public", "internal", "confidential", "restricted"})
_EU_USE_CASES = frozenset(
    {
        "general",
        "human_interaction",
        "generative_ai",
        "biometric",
        "critical_infrastructure",
        "education",
        "employment",
        "essential_services",
        "law_enforcement",
        "migration",
        "justice",
        "safety_component",
        "prohibited_practice_review",
    }
)
_LEGAL_STATUSES = frozenset(
    {
        "undetermined",
        "in_scope",
        "out_of_scope",
        "transparency_review",
        "potential_high_risk_review",
        "prohibited_practice_review",
    }
)
_EVALUATION_TYPES = frozenset(
    {
        "performance",
        "safety",
        "security",
        "red_team",
        "fairness",
        "privacy",
        "robustness",
        "human_factors",
    }
)
_EVALUATION_OUTCOMES = frozenset({"pass", "fail", "inconclusive"})
_CHANGE_TYPES = frozenset(
    {"model", "agent", "tool", "dataset", "provider", "configuration", "policy"}
)
_DRIFT_STATUSES = frozenset({"within_threshold", "breach", "unknown"})
_INCIDENT_SEVERITIES = frozenset({"low", "moderate", "high", "critical"})
_INCIDENT_STATUSES = frozenset({"open", "contained", "resolved"})
_THIRD_PARTY_STATUSES = frozenset({"satisfactory", "conditional", "unsatisfactory", "incomplete"})
_REVIEW_DECISIONS = frozenset({"approved", "needs_changes", "rejected"})
_ACCEPTANCE_DECISIONS = frozenset({"accepted", "declined"})

FRAMEWORK_CATALOG = (
    {
        "id": "nist-ai-rmf-1.0",
        "name": "NIST AI Risk Management Framework",
        "version": "1.0 (January 2023)",
        "status_note": "NIST AI RMF 1.0 is under revision; verify the current official publication before relying on this mapping.",
        "url": "https://www.nist.gov/itl/ai-risk-management-framework",
        "mapping_type": "advisory-control-theme",
    },
    {
        "id": "iso-iec-42001-2023",
        "name": "ISO/IEC 42001 Artificial intelligence management system",
        "version": "ISO/IEC 42001:2023",
        "status_note": "Management-system theme mapping only; this tool does not perform a conformity assessment or certification.",
        "url": "https://www.iso.org/standard/81230.html",
        "mapping_type": "advisory-management-system-theme",
    },
    {
        "id": "eu-ai-act-2024-1689",
        "name": "EU Artificial Intelligence Act",
        "version": "Regulation (EU) 2024/1689",
        "status_note": "Applicability, roles, implementation timing, and obligations require a current human legal assessment; this tool hardcodes no compliance deadline.",
        "url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
        "mapping_type": "advisory-legal-review-prompt",
    },
)

FRAMEWORK_REFS = {
    "govern": {
        "framework": "nist-ai-rmf-1.0",
        "reference": "GOVERN",
        "advisory": True,
    },
    "map": {
        "framework": "nist-ai-rmf-1.0",
        "reference": "MAP",
        "advisory": True,
    },
    "measure": {
        "framework": "nist-ai-rmf-1.0",
        "reference": "MEASURE",
        "advisory": True,
    },
    "manage": {
        "framework": "nist-ai-rmf-1.0",
        "reference": "MANAGE",
        "advisory": True,
    },
    "aims-context": {
        "framework": "iso-iec-42001-2023",
        "reference": "AIMS context and planning theme",
        "advisory": True,
    },
    "aims-operation": {
        "framework": "iso-iec-42001-2023",
        "reference": "AIMS operation and performance-evaluation theme",
        "advisory": True,
    },
    "aims-improvement": {
        "framework": "iso-iec-42001-2023",
        "reference": "AIMS improvement theme",
        "advisory": True,
    },
    "eu-human-applicability": {
        "framework": "eu-ai-act-2024-1689",
        "reference": "Human role, scope, and risk-applicability review",
        "advisory": True,
    },
}


class RevisionConflict(ValueError):
    """The caller's compare-and-swap revision is stale."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _required(value: object, label: str, limit: int = 300) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if not text or len(text) > limit:
        raise ValueError(f"{label} must contain 1 to {limit} characters")
    if _CONTROL_RE.search(text):
        raise ValueError(f"{label} contains control characters")
    return text


def _optional(value: object, label: str, limit: int = 2_000) -> str:
    if value in (None, ""):
        return ""
    return _required(value, label, limit)


def _token(value: object, label: str) -> str:
    text = _required(value, label, 160)
    if not _TOKEN_RE.fullmatch(text):
        raise ValueError(f"{label} must be a stable identifier token")
    return text


def _choice(value: object, label: str, choices: frozenset[str]) -> str:
    text = _required(value, label, 80).lower()
    if text not in choices:
        raise ValueError(f"{label} must be one of {sorted(choices)}")
    return text


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _timestamp(value: object, label: str) -> datetime:
    text = _required(value, label, 80)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _now_iso() -> str:
    return _iso(datetime.now(timezone.utc))


def _only(row: dict, allowed: set[str], label: str) -> None:
    if not isinstance(row, dict):
        raise ValueError(f"{label} must be an object")
    unexpected = set(row).difference(allowed)
    if unexpected:
        raise ValueError(f"unsupported {label} fields: {sorted(unexpected)}")


def _items(value: object, label: str, limit: int) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    if len(value) > limit:
        raise ValueError(f"{label} exceeds {limit} items")
    if not all(isinstance(row, dict) for row in value):
        raise ValueError(f"{label} entries must be objects")
    return value


def _tokens(value: object, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_RELATIONSHIPS:
        raise ValueError(f"{label} must be a list of at most {MAX_RELATIONSHIPS} items")
    return sorted({_token(item, label) for item in value})


def _checked_revision(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("expected_revision must be a non-negative integer")
    return value


def _cross_process_lock(path: Path):
    return _shared_cross_process_lock(path, private=True)


class LocalStore:
    """Atomic private local JSON store with a global revision CAS."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(
            path
            or os.environ.get(
                "MODEL_RISK_OFFICER_STORE",
                ".model-risk-ai-assurance-officer/records.json",
            )
        )
        self._lock = threading.RLock()

    def _read(self) -> dict:
        if not self.path.exists():
            return {"revision": 0, "records": []}
        if self.path.is_symlink():
            raise ValueError("local store must not be a symbolic link")
        if self.path.stat().st_size > MAX_LOCAL_STORE_BYTES:
            raise ValueError("local store exceeds the supported size")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("local store cannot be read as valid JSON") from exc
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("revision"), int)
            or isinstance(value.get("revision"), bool)
            or not isinstance(value.get("records"), list)
            or len(value["records"]) > MAX_LOCAL_RECORDS
        ):
            raise ValueError("local store is malformed")
        return value

    def _write(self, state: dict) -> None:
        payload = json.dumps(
            state,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        if len(payload) > MAX_LOCAL_STORE_BYTES:
            raise ValueError("local store write would exceed the supported 8 MiB size")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        with tempfile.NamedTemporaryFile("wb", dir=self.path.parent, delete=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def current_revision(self) -> int:
        return self._read()["revision"]

    def list_records(self, kind: str | None = None) -> list[dict]:
        rows = self._read()["records"]
        return [dict(row) for row in rows if kind is None or row.get("type") == kind]

    def get_record(self, record_id: str) -> dict | None:
        return next(
            (dict(row) for row in reversed(self._read()["records"]) if row.get("id") == record_id),
            None,
        )

    def save(self, record: dict, expected_revision: int) -> dict:
        expected = _checked_revision(expected_revision)
        with self._lock, _cross_process_lock(self.path):
            state = self._read()
            if state["revision"] != expected:
                raise RevisionConflict(
                    f"revision changed: expected {expected}, found {state['revision']}"
                )
            if len(state["records"]) >= MAX_LOCAL_RECORDS:
                raise ValueError("local store record limit reached")
            row = dict(record)
            row.setdefault("id", uuid.uuid4().hex)
            row.setdefault("created_at", _now_iso())
            state["revision"] += 1
            row["revision"] = state["revision"]
            state["records"].append(row)
            self._write(state)
            return row

    def replace(self, record_id: str, record: dict, expected_revision: int) -> dict:
        expected = _checked_revision(expected_revision)
        with self._lock, _cross_process_lock(self.path):
            state = self._read()
            if state["revision"] != expected:
                raise RevisionConflict(
                    f"revision changed: expected {expected}, found {state['revision']}"
                )
            index = next(
                (
                    index
                    for index in range(len(state["records"]) - 1, -1, -1)
                    if state["records"][index].get("id") == record_id
                ),
                None,
            )
            if index is None:
                raise ValueError("stored record not found")
            previous = state["records"][index]
            row = dict(record)
            row["id"] = record_id
            row.setdefault("created_at", previous.get("created_at", _now_iso()))
            state["revision"] += 1
            row["revision"] = state["revision"]
            state["records"][index] = row
            self._write(state)
            return row


def _legal_assertion(value: object) -> dict:
    if value in (None, {}):
        return {
            "status": "undetermined",
            "asserted_by": "",
            "asserted_at": "",
            "rationale": "",
            "basis_version": "",
            "human_asserted": False,
        }
    if not isinstance(value, dict):
        raise ValueError("legal_applicability must be an object")
    _only(
        value,
        {"status", "asserted_by", "asserted_at", "rationale", "basis_version"},
        "legal applicability",
    )
    status = _choice(value.get("status"), "legal_applicability.status", _LEGAL_STATUSES)
    if status == "undetermined":
        if any(
            value.get(key) not in (None, "") for key in ("asserted_by", "asserted_at", "rationale")
        ):
            raise ValueError("undetermined legal applicability must not name an assertion")
        return {
            "status": status,
            "asserted_by": "",
            "asserted_at": "",
            "rationale": "",
            "basis_version": _optional(value.get("basis_version"), "basis_version", 160),
            "human_asserted": False,
        }
    return {
        "status": status,
        "asserted_by": _required(value.get("asserted_by"), "asserted_by", 200),
        "asserted_at": _iso(_timestamp(value.get("asserted_at"), "asserted_at")),
        "rationale": _required(value.get("rationale"), "rationale", 2_000),
        "basis_version": _required(value.get("basis_version"), "basis_version", 160),
        "human_asserted": True,
    }


def _asset(row: dict) -> dict:
    _only(
        row,
        {
            "id",
            "asset_type",
            "name",
            "owner",
            "criticality",
            "lifecycle",
            "version",
            "intended_use",
            "data_classification",
            "eu_use_case",
            "third_party",
            "provider_ref",
            "lineage_refs",
            "model_refs",
            "tool_refs",
            "dataset_refs",
            "legal_applicability",
        },
        "asset",
    )
    external_id = _token(row.get("id"), "asset.id")
    asset_type = _choice(row.get("asset_type"), "asset_type", _ASSET_TYPES)
    provider_ref = _optional(row.get("provider_ref"), "provider_ref", 160)
    if provider_ref:
        provider_ref = _token(provider_ref, "provider_ref")
    third_party = _boolean(row.get("third_party", False), "third_party")
    return {
        "id": f"MRA-{_digest({'id': external_id})[:24]}",
        "external_id": external_id,
        "asset_type": asset_type,
        "name": _required(row.get("name"), "name", 300),
        "owner": _optional(row.get("owner"), "owner", 200),
        "criticality": _choice(row.get("criticality", "moderate"), "criticality", _CRITICALITIES),
        "lifecycle": _choice(row.get("lifecycle", "development"), "lifecycle", _LIFECYCLES),
        "version": _optional(row.get("version"), "version", 160),
        "intended_use": _optional(row.get("intended_use"), "intended_use", 1_500),
        "data_classification": _choice(
            row.get("data_classification", "internal"),
            "data_classification",
            _DATA_CLASSES,
        ),
        "eu_use_case": _choice(row.get("eu_use_case", "general"), "eu_use_case", _EU_USE_CASES),
        "third_party": third_party,
        "provider_ref": provider_ref,
        "lineage_refs": _tokens(row.get("lineage_refs"), "lineage_refs"),
        "model_refs": _tokens(row.get("model_refs"), "model_refs"),
        "tool_refs": _tokens(row.get("tool_refs"), "tool_refs"),
        "dataset_refs": _tokens(row.get("dataset_refs"), "dataset_refs"),
        "legal_applicability": _legal_assertion(row.get("legal_applicability")),
    }


def _evidence_base(row: dict, allowed: set[str], label: str) -> tuple[str, str]:
    _only(row, allowed, label)
    source_id = _token(row.get("id"), f"{label}.id")
    asset_ref = _token(row.get("asset_ref"), f"{label}.asset_ref")
    return source_id, asset_ref


def _evaluation(row: dict, now: datetime, freshness_days: int) -> dict:
    source_id, asset_ref = _evidence_base(
        row,
        {
            "id",
            "asset_ref",
            "evaluation_type",
            "conducted_at",
            "outcome",
            "evaluator",
            "evidence_ref",
            "scope_version",
        },
        "evaluation",
    )
    conducted = _timestamp(row.get("conducted_at"), "conducted_at")
    if conducted > now:
        raise ValueError("conducted_at cannot be in the future")
    return {
        "id": f"MRE-{_digest({'kind': 'evaluation', 'id': source_id})[:24]}",
        "external_id": source_id,
        "asset_ref": asset_ref,
        "evaluation_type": _choice(
            row.get("evaluation_type"), "evaluation_type", _EVALUATION_TYPES
        ),
        "conducted_at": _iso(conducted),
        "outcome": _choice(row.get("outcome"), "outcome", _EVALUATION_OUTCOMES),
        "evaluator": _required(row.get("evaluator"), "evaluator", 200),
        "evidence_ref": _required(row.get("evidence_ref"), "evidence_ref", 500),
        "scope_version": _optional(row.get("scope_version"), "scope_version", 160),
        "freshness": ("fresh" if now - conducted <= timedelta(days=freshness_days) else "stale"),
    }


def _change(row: dict, now: datetime) -> dict:
    source_id, asset_ref = _evidence_base(
        row,
        {
            "id",
            "asset_ref",
            "changed_at",
            "change_type",
            "approved",
            "approver",
            "version_after",
            "evidence_ref",
        },
        "change",
    )
    changed = _timestamp(row.get("changed_at"), "changed_at")
    if changed > now:
        raise ValueError("changed_at cannot be in the future")
    approved = _boolean(row.get("approved"), "approved")
    approver = _optional(row.get("approver"), "approver", 200)
    if approved and not approver:
        raise ValueError("approved changes require an approver")
    return {
        "id": f"MRC-{_digest({'kind': 'change', 'id': source_id})[:24]}",
        "external_id": source_id,
        "asset_ref": asset_ref,
        "changed_at": _iso(changed),
        "change_type": _choice(row.get("change_type"), "change_type", _CHANGE_TYPES),
        "approved": approved,
        "approver": approver,
        "version_after": _required(row.get("version_after"), "version_after", 160),
        "evidence_ref": _required(row.get("evidence_ref"), "evidence_ref", 500),
    }


def _drift(row: dict, now: datetime) -> dict:
    source_id, asset_ref = _evidence_base(
        row,
        {"id", "asset_ref", "observed_at", "status", "metric", "evidence_ref"},
        "drift signal",
    )
    observed = _timestamp(row.get("observed_at"), "observed_at")
    if observed > now:
        raise ValueError("drift observed_at cannot be in the future")
    return {
        "id": f"MRD-{_digest({'kind': 'drift', 'id': source_id})[:24]}",
        "external_id": source_id,
        "asset_ref": asset_ref,
        "observed_at": _iso(observed),
        "status": _choice(row.get("status"), "drift status", _DRIFT_STATUSES),
        "metric": _required(row.get("metric"), "metric", 300),
        "evidence_ref": _required(row.get("evidence_ref"), "evidence_ref", 500),
    }


def _incident(row: dict, now: datetime) -> dict:
    source_id, asset_ref = _evidence_base(
        row,
        {"id", "asset_ref", "occurred_at", "severity", "status", "title", "evidence_ref"},
        "incident",
    )
    occurred = _timestamp(row.get("occurred_at"), "occurred_at")
    if occurred > now:
        raise ValueError("incident occurred_at cannot be in the future")
    return {
        "id": f"MRI-{_digest({'kind': 'incident', 'id': source_id})[:24]}",
        "external_id": source_id,
        "asset_ref": asset_ref,
        "occurred_at": _iso(occurred),
        "severity": _choice(row.get("severity"), "incident severity", _INCIDENT_SEVERITIES),
        "status": _choice(row.get("status"), "incident status", _INCIDENT_STATUSES),
        "title": _required(row.get("title"), "title", 500),
        "evidence_ref": _required(row.get("evidence_ref"), "evidence_ref", 500),
    }


def _third_party_assessment(row: dict, now: datetime, freshness_days: int) -> dict:
    source_id, asset_ref = _evidence_base(
        row,
        {
            "id",
            "asset_ref",
            "assessed_at",
            "status",
            "assessor",
            "contract_controls",
            "exit_plan",
            "evidence_ref",
        },
        "third-party assessment",
    )
    assessed = _timestamp(row.get("assessed_at"), "assessed_at")
    if assessed > now:
        raise ValueError("third-party assessed_at cannot be in the future")
    return {
        "id": f"MRT-{_digest({'kind': 'third-party', 'id': source_id})[:24]}",
        "external_id": source_id,
        "asset_ref": asset_ref,
        "assessed_at": _iso(assessed),
        "status": _choice(row.get("status"), "third-party status", _THIRD_PARTY_STATUSES),
        "assessor": _required(row.get("assessor"), "assessor", 200),
        "contract_controls": _boolean(row.get("contract_controls"), "contract_controls"),
        "exit_plan": _boolean(row.get("exit_plan"), "exit_plan"),
        "evidence_ref": _required(row.get("evidence_ref"), "evidence_ref", 500),
        "freshness": ("fresh" if now - assessed <= timedelta(days=freshness_days) else "stale"),
    }


def _unique(rows: list[dict], label: str) -> list[dict]:
    seen: dict[str, dict] = {}
    for row in rows:
        external_id = row["external_id"]
        if external_id in seen:
            raise ValueError(f"duplicate {label} id: {external_id}")
        seen[external_id] = row
    return [seen[key] for key in sorted(seen)]


def _operational_classification(asset: dict) -> dict:
    score = {"low": 5, "moderate": 20, "high": 35, "critical": 50}[asset["criticality"]]
    drivers = [f"declared criticality: {asset['criticality']}"]
    if asset["lifecycle"] == "production":
        score += 10
        drivers.append("production lifecycle")
    data_weight = {"public": 0, "internal": 3, "confidential": 8, "restricted": 15}[
        asset["data_classification"]
    ]
    score += data_weight
    if data_weight:
        drivers.append(f"{asset['data_classification']} data")
    if asset["third_party"]:
        score += 10
        drivers.append("third-party dependency")
    if asset["asset_type"] in {"model", "agent"}:
        score += 5
        drivers.append(f"{asset['asset_type']} execution surface")
    if asset["eu_use_case"] in {
        "biometric",
        "critical_infrastructure",
        "education",
        "employment",
        "essential_services",
        "law_enforcement",
        "migration",
        "justice",
        "safety_component",
    }:
        score += 10
        drivers.append("declared safety- or rights-sensitive use-case metadata")
    if asset["eu_use_case"] == "prohibited_practice_review":
        score += 20
        drivers.append("declared prohibited-practice review flag")
    score = min(score, 100)
    level = (
        "critical"
        if score >= 70
        else "high"
        if score >= 50
        else "moderate"
        if score >= 25
        else "low"
    )
    return {
        "asset_id": asset["id"],
        "asset_ref": asset["external_id"],
        "level": level,
        "score": score,
        "drivers": drivers,
        "classification_type": "operational-triage-not-legal",
        "legal_applicability": dict(asset["legal_applicability"]),
        "automatic_legal_verdict": False,
    }


def _finding(
    kind: str,
    severity: str,
    asset: dict,
    summary: str,
    refs: list[str],
    evidence_ids: list[str] | None = None,
) -> dict:
    cited_evidence = sorted(set(evidence_ids or [asset["id"]]))
    return {
        "id": f"MRF-{_digest({'kind': kind, 'asset': asset['id'], 'evidence': cited_evidence})[:24]}",
        "finding_type": kind,
        "severity": severity,
        "asset_id": asset["id"],
        "asset_ref": asset["external_id"],
        "asset_name": asset["name"],
        "summary": summary,
        "framework_refs": [dict(FRAMEWORK_REFS[ref]) for ref in refs],
        "evidence_ids": cited_evidence,
        "advisory_only": True,
        "certification_effect": False,
    }


def _by_ref(rows: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        grouped.setdefault(row["asset_ref"], []).append(row)
    return grouped


def _normalized_snapshot_rows(
    snapshot: dict, assessed: datetime, freshness_days: int
) -> dict[str, list[dict]]:
    assets = _unique(
        [_asset(row) for row in _items(snapshot.get("assets"), "assets", MAX_ASSETS)],
        "asset",
    )
    if not assets:
        raise ValueError("assets must contain at least one item")
    return {
        "assets": assets,
        "evaluations": _unique(
            [
                _evaluation(row, assessed, freshness_days)
                for row in _items(
                    snapshot.get("evaluations"),
                    "evaluations",
                    MAX_EVIDENCE_ROWS,
                )
            ],
            "evaluation",
        ),
        "changes": _unique(
            [
                _change(row, assessed)
                for row in _items(snapshot.get("changes"), "changes", MAX_EVIDENCE_ROWS)
            ],
            "change",
        ),
        "drift": _unique(
            [
                _drift(row, assessed)
                for row in _items(
                    snapshot.get("drift_signals"),
                    "drift_signals",
                    MAX_EVIDENCE_ROWS,
                )
            ],
            "drift signal",
        ),
        "incidents": _unique(
            [
                _incident(row, assessed)
                for row in _items(snapshot.get("incidents"), "incidents", MAX_EVIDENCE_ROWS)
            ],
            "incident",
        ),
        "third_party": _unique(
            [
                _third_party_assessment(row, assessed, freshness_days)
                for row in _items(
                    snapshot.get("third_party_assessments"),
                    "third_party_assessments",
                    MAX_EVIDENCE_ROWS,
                )
            ],
            "third-party assessment",
        ),
    }


def _validate_snapshot_references(rows: dict[str, list[dict]]) -> None:
    assets = rows["assets"]
    asset_index = {row["external_id"]: row for row in assets}
    for label, values in (
        ("evaluation", rows["evaluations"]),
        ("change", rows["changes"]),
        ("drift signal", rows["drift"]),
        ("incident", rows["incidents"]),
        ("third-party assessment", rows["third_party"]),
    ):
        unknown = [row["asset_ref"] for row in values if row["asset_ref"] not in asset_index]
        if unknown:
            raise ValueError(f"{label} references unknown asset: {sorted(unknown)[0]}")
    for asset in assets:
        for field in ("lineage_refs", "model_refs", "tool_refs", "dataset_refs"):
            unknown = set(asset[field]).difference(asset_index)
            if unknown:
                raise ValueError(f"{field} references unknown assets: {sorted(unknown)}")
            if asset["external_id"] in asset[field]:
                raise ValueError(f"{field} must not self-reference the asset")
        for field, expected_type in (
            ("model_refs", "model"),
            ("tool_refs", "tool"),
            ("dataset_refs", "dataset"),
        ):
            if any(asset_index[ref]["asset_type"] != expected_type for ref in asset[field]):
                raise ValueError(f"{field} must reference only {expected_type} assets")
        if asset["provider_ref"]:
            provider = asset_index.get(asset["provider_ref"])
            if provider is None or provider["asset_type"] != "provider":
                raise ValueError("provider_ref must reference an inventoried provider")
    if any(
        asset_index[row["asset_ref"]]["asset_type"] != "provider" for row in rows["third_party"]
    ):
        raise ValueError("third-party assessments must reference provider assets")


def _governance_findings(asset: dict) -> list[dict]:
    findings = []
    if not asset["owner"]:
        findings.append(
            _finding(
                "unowned-asset",
                "high",
                asset,
                "No accountable owner is declared.",
                ["govern", "aims-context"],
            )
        )
    if not asset["intended_use"]:
        findings.append(
            _finding(
                "missing-intended-use",
                "moderate",
                asset,
                "The intended use and boundaries are not declared.",
                ["map", "aims-context"],
            )
        )
    if (
        asset["lifecycle"] == "production"
        and asset["legal_applicability"]["status"] == "undetermined"
    ):
        findings.append(
            _finding(
                "legal-applicability-undetermined",
                "high",
                asset,
                "A qualified human has not asserted current legal role and applicability metadata.",
                ["eu-human-applicability", "govern"],
            )
        )
    if asset["asset_type"] in {"model", "dataset"} and not asset["lineage_refs"]:
        findings.append(
            _finding(
                "missing-lineage",
                "high",
                asset,
                "No upstream lineage references are declared.",
                ["map", "aims-operation"],
            )
        )
    if asset["asset_type"] == "agent" and not (asset["model_refs"] and asset["tool_refs"]):
        findings.append(
            _finding(
                "incomplete-agent-composition",
                "high",
                asset,
                "The agent does not declare both model and tool composition.",
                ["map", "aims-operation"],
            )
        )
    return findings


def _evaluation_findings(
    asset: dict,
    evaluations: list[dict],
    changes: list[dict],
    classification: dict,
) -> list[dict]:
    findings = []
    needs_evaluation = asset["asset_type"] in {"model", "agent"} and asset["lifecycle"] in {
        "testing",
        "production",
    }
    if needs_evaluation and not evaluations:
        severity = "critical" if classification["level"] == "critical" else "high"
        return [
            _finding(
                "missing-evaluation",
                severity,
                asset,
                "No evaluation evidence is declared for this active AI asset.",
                ["measure", "aims-operation"],
            )
        ]
    latest_change = max(
        (_timestamp(row["changed_at"], "changed_at") for row in changes),
        default=None,
    )
    valid_evaluations = []
    for evaluation in evaluations:
        conducted = _timestamp(evaluation["conducted_at"], "conducted_at")
        invalidated = latest_change is not None and latest_change > conducted
        evaluation["invalidated_by_later_change"] = invalidated
        if evaluation["freshness"] == "fresh" and not invalidated:
            valid_evaluations.append(evaluation)
        if evaluation["outcome"] == "fail":
            findings.append(
                _finding(
                    "failed-evaluation",
                    "critical",
                    asset,
                    f"The {evaluation['evaluation_type']} evaluation is recorded as failed.",
                    ["measure", "manage", "aims-improvement"],
                    [evaluation["id"]],
                )
            )
    if needs_evaluation and not valid_evaluations:
        findings.append(
            _finding(
                "stale-or-invalidated-evidence",
                "high",
                asset,
                "All declared evaluation evidence is stale or predates a recorded change.",
                ["measure", "aims-operation"],
                [row["id"] for row in evaluations],
            )
        )
    has_red_team = any(
        row["evaluation_type"] == "red_team" and row["outcome"] == "pass"
        for row in valid_evaluations
    )
    if classification["level"] in {"high", "critical"} and not has_red_team:
        findings.append(
            _finding(
                "missing-current-red-team",
                "high",
                asset,
                "No current passing red-team evaluation covers this elevated operational risk.",
                ["measure", "manage", "aims-operation"],
                [row["id"] for row in evaluations],
            )
        )
    return findings


def _operational_findings(
    asset: dict,
    changes: list[dict],
    drift: list[dict],
    incidents: list[dict],
) -> list[dict]:
    findings = []
    for change in changes:
        if not change["approved"]:
            findings.append(
                _finding(
                    "unapproved-change",
                    "critical",
                    asset,
                    "A recorded change lacks human approval.",
                    ["govern", "manage", "aims-operation"],
                    [change["id"]],
                )
            )
    latest_drift = max(drift, key=lambda row: (row["observed_at"], row["id"]), default=None)
    needs_drift = asset["asset_type"] in {"model", "agent"} and asset["lifecycle"] == "production"
    if needs_drift and latest_drift is None:
        findings.append(
            _finding(
                "missing-drift-evidence",
                "high",
                asset,
                "No drift signal is declared for the production AI asset.",
                ["measure", "manage", "aims-operation"],
            )
        )
    if latest_drift and latest_drift["status"] in {"breach", "unknown"}:
        breach = latest_drift["status"] == "breach"
        findings.append(
            _finding(
                "drift-breach" if breach else "drift-unknown",
                "critical" if breach else "high",
                asset,
                f"The latest drift status is {latest_drift['status']}.",
                ["measure", "manage", "aims-improvement"],
                [latest_drift["id"]],
            )
        )
    for incident in incidents:
        if incident["status"] != "resolved":
            severe = incident["severity"] in {"high", "critical"}
            findings.append(
                _finding(
                    "open-incident",
                    "critical" if severe else "high",
                    asset,
                    f"An {incident['severity']} incident remains {incident['status']}.",
                    ["manage", "aims-improvement"],
                    [incident["id"]],
                )
            )
    return findings


def _provider_findings(asset: dict, assessments: list[dict]) -> list[dict]:
    findings = []
    if asset["third_party"] and not asset["provider_ref"] and asset["asset_type"] != "provider":
        findings.append(
            _finding(
                "missing-provider-link",
                "high",
                asset,
                "The third-party asset is not linked to an inventoried provider.",
                ["govern", "map", "aims-context"],
            )
        )
    if asset["asset_type"] != "provider":
        return findings
    if not assessments:
        findings.append(
            _finding(
                "missing-third-party-assessment",
                "high",
                asset,
                "No third-party assurance assessment is declared.",
                ["govern", "map", "aims-context"],
            )
        )
        return findings
    latest = max(assessments, key=lambda row: (row["assessed_at"], row["id"]))
    if latest["freshness"] == "stale" or latest["status"] in {
        "unsatisfactory",
        "incomplete",
    }:
        findings.append(
            _finding(
                "third-party-assurance-gap",
                "high",
                asset,
                "The latest provider assessment is stale, incomplete, or unsatisfactory.",
                ["govern", "manage", "aims-operation"],
                [latest["id"]],
            )
        )
    if not latest["contract_controls"] or not latest["exit_plan"]:
        findings.append(
            _finding(
                "third-party-resilience-gap",
                "high",
                asset,
                "Contract controls or an exit plan are not evidenced.",
                ["govern", "manage", "aims-context"],
                [latest["id"]],
            )
        )
    return findings


def analyze_snapshot(
    snapshot: dict,
    *,
    now: str | None = None,
    freshness_days: int = DEFAULT_FRESHNESS_DAYS,
) -> dict:
    """Normalize one declared snapshot and return a deterministic assessment."""
    reject_sensitive_fields(snapshot)
    if not isinstance(snapshot, dict):
        raise ValueError("snapshot must be an object")
    _only(
        snapshot,
        {
            "assets",
            "evaluations",
            "changes",
            "drift_signals",
            "incidents",
            "third_party_assessments",
        },
        "snapshot",
    )
    if (
        not isinstance(freshness_days, int)
        or isinstance(freshness_days, bool)
        or not 1 <= freshness_days <= 730
    ):
        raise ValueError("freshness_days must be an integer from 1 to 730")
    assessed = _timestamp(now, "now") if now is not None else datetime.now(timezone.utc)
    rows = _normalized_snapshot_rows(snapshot, assessed, freshness_days)
    _validate_snapshot_references(rows)
    assets = rows["assets"]
    for asset in assets:
        assertion = asset["legal_applicability"]
        if (
            assertion["human_asserted"]
            and _timestamp(assertion["asserted_at"], "asserted_at") > assessed
        ):
            raise ValueError("legal applicability asserted_at cannot be in the future")
    evaluations = rows["evaluations"]
    changes = rows["changes"]
    drift = rows["drift"]
    incidents = rows["incidents"]
    third_party = rows["third_party"]

    evaluation_map = _by_ref(evaluations)
    change_map = _by_ref(changes)
    drift_map = _by_ref(drift)
    incident_map = _by_ref(incidents)
    third_party_map = _by_ref(third_party)
    classifications = [_operational_classification(asset) for asset in assets]
    classification_map = {row["asset_ref"]: row for row in classifications}
    findings: list[dict] = []

    for asset in assets:
        asset_ref = asset["external_id"]
        asset_evaluations = evaluation_map.get(asset_ref, [])
        asset_changes = change_map.get(asset_ref, [])
        asset_drift = drift_map.get(asset_ref, [])
        asset_incidents = incident_map.get(asset_ref, [])
        classification = classification_map[asset_ref]
        findings.extend(_governance_findings(asset))
        findings.extend(
            _evaluation_findings(asset, asset_evaluations, asset_changes, classification)
        )
        findings.extend(_operational_findings(asset, asset_changes, asset_drift, asset_incidents))
        findings.extend(_provider_findings(asset, third_party_map.get(asset_ref, [])))

    findings.sort(key=lambda row: (row["asset_ref"], row["finding_type"], row["id"]))
    summary = {
        "asset_count": len(assets),
        "asset_types": {
            kind: sum(row["asset_type"] == kind for row in assets) for kind in sorted(_ASSET_TYPES)
        },
        "finding_count": len(findings),
        "findings_by_severity": {
            severity: sum(row["severity"] == severity for row in findings)
            for severity in ("critical", "high", "moderate", "low")
        },
        "operational_risk_levels": {
            level: sum(row["level"] == level for row in classifications)
            for level in ("critical", "high", "moderate", "low")
        },
    }
    result = {
        "type": "assurance_assessment",
        "assessed_at": _iso(assessed),
        "freshness_days": freshness_days,
        "inventory": assets,
        "classifications": classifications,
        "evaluations": evaluations,
        "changes": changes,
        "drift_signals": drift,
        "incidents": incidents,
        "third_party_assessments": third_party,
        "findings": findings,
        "summary": summary,
        "framework_catalog": [dict(row) for row in FRAMEWORK_CATALOG],
        "review": {"status": "pending_human_review"},
        "legal_applicability_automation": False,
        "legal_applicability_default": "undetermined",
        "certification": False,
        "advisory_only": True,
    }
    result["id"] = f"MRAA-{_digest(result)[:24]}"
    return result


def review_assessment(
    assessment: dict,
    decision: object,
    reviewer: object,
    rationale: object,
    decided_at: object,
) -> dict:
    if assessment.get("type") != "assurance_assessment":
        raise ValueError("record is not an assurance assessment")
    row = dict(assessment)
    row["review"] = {
        "status": _choice(decision, "decision", _REVIEW_DECISIONS),
        "reviewer": _required(reviewer, "reviewer", 200),
        "rationale": _required(rationale, "rationale", 2_000),
        "decided_at": _iso(_timestamp(decided_at, "decided_at")),
        "certification": False,
        "legal_verdict": False,
    }
    return row


def create_risk_acceptance(
    assessment: dict,
    finding_id: object,
    decision: object,
    reviewer: object,
    rationale: object,
    expires_at: object,
    decided_at: object,
) -> dict:
    if assessment.get("type") != "assurance_assessment":
        raise ValueError("record is not an assurance assessment")
    finding_token = _token(finding_id, "finding_id")
    finding = next((row for row in assessment["findings"] if row["id"] == finding_token), None)
    if finding is None:
        raise ValueError("finding is not part of this assessment")
    decided = _timestamp(decided_at, "decided_at")
    expiry = _timestamp(expires_at, "expires_at")
    if expiry <= decided:
        raise ValueError("expires_at must be after decided_at")
    choice = _choice(decision, "decision", _ACCEPTANCE_DECISIONS)
    result = {
        "type": "risk_acceptance",
        "assessment_id": assessment["id"],
        "finding_id": finding["id"],
        "asset_id": finding["asset_id"],
        "decision": choice,
        "reviewer": _required(reviewer, "reviewer", 200),
        "rationale": _required(rationale, "rationale", 2_000),
        "decided_at": _iso(decided),
        "expires_at": _iso(expiry),
        "local_human_attestation": True,
        "closes_finding": False,
        "certification": False,
    }
    result["id"] = f"MRAC-{_digest(result)[:24]}"
    return result


def build_dgm_readiness_report(
    assessment: dict,
    acceptances: list[dict],
    target_asset_ref: object,
    candidate_id: object,
    candidate_version: object,
    requested_by: object,
    now: object,
) -> dict:
    """Build a local readiness report; never perform a DGM effect."""
    if assessment.get("type") != "assurance_assessment":
        raise ValueError("record is not an assurance assessment")
    target_ref = _token(target_asset_ref, "target_asset_ref")
    target = next(
        (row for row in assessment["inventory"] if row["external_id"] == target_ref), None
    )
    if target is None or target["asset_type"] not in {"model", "agent"}:
        raise ValueError("target_asset_ref must identify an inventoried model or agent")
    checked_at = _timestamp(now, "now")
    active_acceptance_rows = [
        row
        for row in acceptances
        if row.get("type") == "risk_acceptance"
        and row.get("assessment_id") == assessment["id"]
        and row.get("decision") == "accepted"
        and _timestamp(row.get("expires_at"), "expires_at") > checked_at
    ]
    active_acceptances = {row.get("finding_id") for row in active_acceptance_rows}
    non_overridable = {
        "failed-evaluation",
        "unapproved-change",
        "drift-breach",
        "open-incident",
        "legal-applicability-undetermined",
    }
    target_findings = [row for row in assessment["findings"] if row["asset_id"] == target["id"]]
    blockers: list[dict] = []
    if assessment.get("review", {}).get("status") != "approved":
        blockers.append(
            {
                "code": "assessment-not-approved",
                "detail": "The assurance assessment lacks an approved human review.",
            }
        )
    for finding in target_findings:
        if finding["severity"] not in {"critical", "high"}:
            continue
        accepted = finding["id"] in active_acceptances
        if not accepted or finding["finding_type"] in non_overridable:
            blockers.append(
                {
                    "code": "active-finding",
                    "finding_id": finding["id"],
                    "finding_type": finding["finding_type"],
                    "risk_acceptance_considered": accepted,
                    "acceptance_can_override": finding["finding_type"] not in non_overridable,
                }
            )
    evaluations = [row for row in assessment["evaluations"] if row["asset_ref"] == target_ref]
    required_types = {"performance", "safety", "security"}
    classification = next(
        row for row in assessment["classifications"] if row["asset_ref"] == target_ref
    )
    if classification["level"] in {"high", "critical"}:
        required_types.add("red_team")
    current_pass_types = {
        row["evaluation_type"]
        for row in evaluations
        if row["outcome"] == "pass"
        and row["freshness"] == "fresh"
        and not row.get("invalidated_by_later_change", False)
    }
    for missing in sorted(required_types.difference(current_pass_types)):
        blockers.append({"code": "missing-current-passing-evaluation", "evaluation_type": missing})
    blockers.sort(
        key=lambda row: (
            row["code"],
            str(row.get("finding_id", "")),
            str(row.get("evaluation_type", "")),
        )
    )
    report = {
        "type": "dgm_readiness_report",
        "assessment_id": assessment["id"],
        "target_asset_id": target["id"],
        "target_asset_ref": target_ref,
        "candidate_id": _token(candidate_id, "candidate_id"),
        "candidate_version": _required(candidate_version, "candidate_version", 160),
        "requested_by": _required(requested_by, "requested_by", 200),
        "checked_at": _iso(checked_at),
        "ready_for_human_promotion_decision": not blockers,
        "blockers": blockers,
        "active_risk_acceptance_ids": sorted(str(row["id"]) for row in active_acceptance_rows),
        "accepted_finding_ids": sorted(active_acceptances),
        "promotion_executed": False,
        "deployment_executed": False,
        "rollback_executed": False,
        "external_effects": False,
        "advisory_only": True,
        "certification": False,
    }
    report["id"] = f"MRDG-{_digest(report)[:24]}"
    return report


__all__ = [
    "DEFAULT_FRESHNESS_DAYS",
    "FRAMEWORK_CATALOG",
    "LocalStore",
    "RevisionConflict",
    "analyze_snapshot",
    "build_dgm_readiness_report",
    "create_risk_acceptance",
    "review_assessment",
]
