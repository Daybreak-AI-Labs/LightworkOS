"""Vendor-neutral, deterministic training/evaluation environment contracts.

The contract deliberately lives below any one RL vendor.  A Lightwork
environment is a versioned set of provenance-bearing cases plus a deterministic
JSON rubric.  The same pack can be evaluated locally or exported as
backend-neutral rows for an external training backend without changing its
decision boundary.

Built-in packs contain public/synthetic seed cases only.  They are useful for
integration tests and base-model bakeoffs; :func:`promotion_readiness` refuses
to describe them as promotion-grade until the configured minimum number of
independent train and holdout families exists.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CASE_SCHEMA = "lightwork.training-environment-case.v1"
PACK_SCHEMA = "lightwork.training-environment-pack.v1"
EVALUATION_SCHEMA = "lightwork.training-environment-evaluation.v1"
CONSENT_SCHEMA = "lightwork.training-consent.v1"
REDACTION_EVIDENCE_SCHEMA = "lightwork.training-redaction-evidence.v1"
PACK_LOCK_SCHEMA = "lightwork.training-environment-lock.v1"
ADMITTED_CONTENT_SCHEMA = "lightwork.training-admitted-content.v1"
TRUSTED_EVIDENCE_REGISTRY_SCHEMA = "lightwork.training-evidence-registry.v1"
BOUNDARY_DECISION_SCHEMA = "lightwork.training-boundary-decision.v1"
TRUSTED_EVIDENCE_REGISTRY_BASENAME = "trusted_evidence_registry.json"

MAX_CASES = 5_000
MAX_PACK_BYTES = 16 * 1024 * 1024
MAX_PROMPT_BYTES = 64 * 1024
MAX_EXPECTED_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 128 * 1024
MAX_TRUSTED_EVIDENCE_REGISTRY_BYTES = 4 * 1024 * 1024

SPLITS = frozenset({"train", "validation", "holdout"})
PROVENANCE = frozenset({"public", "synthetic", "human_example", "human_correction",
                        "tenant_trace"})
CLASSIFICATIONS = frozenset({"public", "internal", "confidential", "restricted"})
CONSENT_SCOPES = frozenset({"tenant_training", "hosted_training"})
ANSWER_VISIBILITY = frozenset({"published", "sealed"})
REDACTION_STATUSES = frozenset({"not_applicable", "reviewed_no_detector_matches"})
_ID_RE = re.compile(r"[a-z][a-z0-9_.-]{2,127}\Z")
_CASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class EnvironmentError(ValueError):
    """A pack or model output violated the deterministic contract."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bounded_text(value: object, label: str, maximum: int, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise EnvironmentError(f"{label} must be a string")
    text = value.strip()
    if required and not text:
        raise EnvironmentError(f"{label} is required")
    if len(text.encode("utf-8")) > maximum:
        raise EnvironmentError(f"{label} exceeds {maximum} bytes")
    if "\x00" in text:
        raise EnvironmentError(f"{label} contains a NUL byte")
    return text


def _identifier(value: object, label: str, pattern: re.Pattern[str]) -> str:
    text = _bounded_text(value, label, 128)
    if not pattern.fullmatch(text):
        raise EnvironmentError(f"{label} is not a bounded identifier")
    return text


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise EnvironmentError(f"{label} must be an object")
    if not _strict_json_value(value):
        raise EnvironmentError(f"{label} contains a non-standard JSON value")
    copied = json.loads(_canonical(dict(value)))
    if len(_canonical(copied)) > MAX_EXPECTED_BYTES:
        raise EnvironmentError(f"{label} exceeds {MAX_EXPECTED_BYTES} bytes")
    return copied


def _exact_fields(
    raw: Mapping[str, Any],
    label: str,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    """Reject both misspelled authority fields and silent schema extensions."""
    keys = set(raw)
    non_string = [key for key in keys if not isinstance(key, str)]
    if non_string:
        raise EnvironmentError(f"{label} field names must be strings")
    missing = sorted(required - keys)
    if missing:
        raise EnvironmentError(f"{label} is missing required fields: {missing}")
    unknown = sorted(keys - required - optional)
    if unknown:
        raise EnvironmentError(f"{label} contains unknown fields: {unknown}")


def _strict_json_loads(value: str) -> object:
    def reject_constant(token: str) -> object:
        raise EnvironmentError(f"non-standard JSON constant {token!r}")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, item in pairs:
            if key in out:
                raise EnvironmentError(f"duplicate JSON field {key!r}")
            out[key] = item
        return out

    try:
        return json.loads(
            value,
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except json.JSONDecodeError as exc:
        raise EnvironmentError("invalid JSON") from exc


def _strict_json_value(value: object, *, depth: int = 0) -> bool:
    if depth > 32:
        return False
    if value is None or isinstance(value, (str, bool, int)):
        return not isinstance(value, int) or isinstance(value, bool) or abs(value) <= 10**100
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return len(value) <= 10_000 and all(
            _strict_json_value(item, depth=depth + 1) for item in value
        )
    if isinstance(value, Mapping):
        return (
            len(value) <= 10_000
            and all(isinstance(key, str) for key in value)
            and all(_strict_json_value(item, depth=depth + 1) for item in value.values())
        )
    return False


def _sha256_text(value: object, label: str) -> str:
    digest = _bounded_text(value, label, 64).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise EnvironmentError(f"{label} must be a SHA-256 hex digest")
    return digest


@dataclass(frozen=True)
class ConsentEvidence:
    """Exact tenant authority for one narrowly scoped training purpose."""

    record_id: str
    tenant_id: str
    case_id: str
    environment_id: str
    admitted_content_sha256: str
    allowed_purpose: str
    valid_until: float
    retention_days: int
    approved_by: str
    revoked: bool
    schema: str = CONSENT_SCHEMA

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> ConsentEvidence:
        _exact_fields(
            raw,
            "training consent",
            required=frozenset({
                "schema",
                "record_id",
                "tenant_id",
                "case_id",
                "environment_id",
                "admitted_content_sha256",
                "allowed_purpose",
                "valid_until",
                "retention_days",
                "approved_by",
                "revoked",
            }),
        )
        if raw.get("schema") != CONSENT_SCHEMA:
            raise EnvironmentError("unsupported training-consent schema")
        purpose = _bounded_text(raw.get("allowed_purpose"), "allowed_purpose", 32)
        if purpose not in CONSENT_SCOPES:
            raise EnvironmentError(
                f"allowed_purpose must be one of {sorted(CONSENT_SCOPES)}",
            )
        valid_until_raw = raw.get("valid_until")
        if (
            not isinstance(valid_until_raw, (int, float))
            or isinstance(valid_until_raw, bool)
            or not math.isfinite(float(valid_until_raw))
            or float(valid_until_raw) <= 0.0
        ):
            raise EnvironmentError("consent valid_until must be a positive timestamp")
        retention_raw = raw.get("retention_days")
        if (
            not isinstance(retention_raw, int)
            or isinstance(retention_raw, bool)
            or not 1 <= retention_raw <= 3_650
        ):
            raise EnvironmentError("consent retention_days must be in 1..3650")
        revoked = raw.get("revoked")
        if not isinstance(revoked, bool):
            raise EnvironmentError("consent revoked must be a boolean")
        return cls(
            record_id=_identifier(raw.get("record_id"), "consent record_id", _CASE_ID_RE),
            tenant_id=_bounded_text(raw.get("tenant_id"), "consent tenant_id", 256),
            case_id=_identifier(raw.get("case_id"), "consent case_id", _CASE_ID_RE),
            environment_id=_identifier(
                raw.get("environment_id"), "consent environment_id", _ID_RE,
            ),
            admitted_content_sha256=_sha256_text(
                raw.get("admitted_content_sha256"),
                "consent admitted_content_sha256",
            ),
            allowed_purpose=purpose,
            valid_until=float(valid_until_raw),
            retention_days=retention_raw,
            approved_by=_bounded_text(raw.get("approved_by"), "consent approved_by", 256),
            revoked=revoked,
        )

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "record_id": self.record_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "environment_id": self.environment_id,
            "admitted_content_sha256": self.admitted_content_sha256,
            "allowed_purpose": self.allowed_purpose,
            "valid_until": self.valid_until,
            "retention_days": self.retention_days,
            "approved_by": self.approved_by,
            "revoked": self.revoked,
        }

    @property
    def digest(self) -> str:
        return _sha256(self.public_dict())


@dataclass(frozen=True)
class RedactionEvidence:
    """Bound detector evidence; never a claim that all possible PII is absent."""

    status: str
    evidence_id: str = ""
    case_id: str = ""
    environment_id: str = ""
    detector: str = ""
    detector_version: str = ""
    detector_code_sha256: str = ""
    input_sha256: str = ""
    output_sha256: str = ""
    pass_count: int = 0
    residual_labels: tuple[str, ...] = ()
    human_reviewed: bool = False
    revoked: bool = False
    schema: str = REDACTION_EVIDENCE_SCHEMA

    @classmethod
    def from_mapping(
        cls,
        raw: Mapping[str, Any],
        *,
        required: bool,
    ) -> RedactionEvidence:
        status = _bounded_text(raw.get("status"), "redaction status", 64)
        if status == "not_applicable":
            _exact_fields(
                raw,
                "not-applicable redaction evidence",
                required=frozenset({"status"}),
                optional=frozenset({
                    "schema",
                    "detector",
                    "detector_version",
                    "detector_code_sha256",
                    "input_sha256",
                    "output_sha256",
                    "pass_count",
                    "residual_labels",
                    "human_reviewed",
                }),
            )
        else:
            _exact_fields(
                raw,
                "training redaction evidence",
                required=frozenset({
                    "schema",
                    "evidence_id",
                    "case_id",
                    "environment_id",
                    "status",
                    "detector",
                    "detector_version",
                    "detector_code_sha256",
                    "input_sha256",
                    "output_sha256",
                    "pass_count",
                    "residual_labels",
                    "human_reviewed",
                    "revoked",
                }),
            )
        if raw.get("schema", REDACTION_EVIDENCE_SCHEMA) != REDACTION_EVIDENCE_SCHEMA:
            raise EnvironmentError("unsupported training-redaction-evidence schema")
        if status not in REDACTION_STATUSES:
            raise EnvironmentError(
                f"redaction status must be one of {sorted(REDACTION_STATUSES)}",
            )
        if status == "not_applicable":
            if required:
                raise EnvironmentError(
                    "human or non-public training cases require bound redaction evidence",
                )
            canonical_defaults = {
                "detector": "",
                "detector_version": "",
                "detector_code_sha256": "",
                "input_sha256": "",
                "output_sha256": "",
                "pass_count": 0,
                "residual_labels": [],
                "human_reviewed": False,
            }
            for field, expected in canonical_defaults.items():
                if field in raw and raw[field] != expected:
                    raise EnvironmentError(
                        f"not-applicable redaction evidence cannot set {field}",
                    )
            return cls(status=status)
        detector = _bounded_text(raw.get("detector"), "redaction detector", 128)
        detector_version = _bounded_text(
            raw.get("detector_version"), "redaction detector_version", 128,
        )
        pass_count = raw.get("pass_count")
        if (
            not isinstance(pass_count, int)
            or isinstance(pass_count, bool)
            or not 1 <= pass_count <= 64
        ):
            raise EnvironmentError("redaction pass_count must be in 1..64")
        residual_raw = raw.get("residual_labels")
        if (
            not isinstance(residual_raw, list)
            or len(residual_raw) > 64
            or not all(isinstance(item, str) and item.strip() for item in residual_raw)
        ):
            raise EnvironmentError("residual_labels must be a bounded string list")
        residual = tuple(sorted(set(
            _bounded_text(item, "residual label", 128) for item in residual_raw
        )))
        reviewed = raw.get("human_reviewed")
        if reviewed is not True:
            raise EnvironmentError("redaction evidence requires human_reviewed=true")
        if residual:
            raise EnvironmentError("redaction evidence contains residual detector labels")
        revoked = raw.get("revoked")
        if not isinstance(revoked, bool):
            raise EnvironmentError("redaction revoked must be a boolean")
        return cls(
            status=status,
            evidence_id=_identifier(
                raw.get("evidence_id"), "redaction evidence_id", _CASE_ID_RE,
            ),
            case_id=_identifier(raw.get("case_id"), "redaction case_id", _CASE_ID_RE),
            environment_id=_identifier(
                raw.get("environment_id"), "redaction environment_id", _ID_RE,
            ),
            detector=detector,
            detector_version=detector_version,
            detector_code_sha256=_sha256_text(
                raw.get("detector_code_sha256"), "detector_code_sha256",
            ),
            input_sha256=_sha256_text(raw.get("input_sha256"), "input_sha256"),
            output_sha256=_sha256_text(raw.get("output_sha256"), "output_sha256"),
            pass_count=pass_count,
            residual_labels=residual,
            human_reviewed=True,
            revoked=revoked,
        )

    def public_dict(self) -> dict[str, Any]:
        public = {
            "schema": self.schema,
            "status": self.status,
            "detector": self.detector,
            "detector_version": self.detector_version,
            "detector_code_sha256": self.detector_code_sha256,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "pass_count": self.pass_count,
            "residual_labels": list(self.residual_labels),
            "human_reviewed": self.human_reviewed,
        }
        if self.status != "not_applicable":
            public.update({
                "evidence_id": self.evidence_id,
                "case_id": self.case_id,
                "environment_id": self.environment_id,
                "revoked": self.revoked,
            })
        return public

    @property
    def digest(self) -> str:
        return _sha256(self.public_dict())


@dataclass(frozen=True)
class TrustedEvidenceRegistry:
    """A server-resolved, content-addressed authority snapshot.

    A case cannot create this trust by naming an approver or detector.  The
    active tenant's protected registry is the only source accepted by
    :func:`check_boundary`; request callers cannot supply or replace it.
    """

    registry_id: str
    revision: str
    consent_records: tuple[tuple[str, str], ...]
    redaction_records: tuple[tuple[str, str], ...]
    schema: str = TRUSTED_EVIDENCE_REGISTRY_SCHEMA

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> TrustedEvidenceRegistry:
        _exact_fields(
            raw,
            "trusted evidence registry",
            required=frozenset({
                "schema",
                "registry_id",
                "revision",
                "consent_records",
                "redaction_records",
            }),
        )
        if raw.get("schema") != TRUSTED_EVIDENCE_REGISTRY_SCHEMA:
            raise EnvironmentError("unsupported trusted-evidence-registry schema")

        def records(field: str) -> tuple[tuple[str, str], ...]:
            value = raw.get(field)
            if not isinstance(value, Mapping) or len(value) > MAX_CASES:
                raise EnvironmentError(f"{field} must be a bounded object")
            parsed = [
                (
                    _identifier(record_id, f"{field} record_id", _CASE_ID_RE),
                    _sha256_text(digest, f"{field} digest"),
                )
                for record_id, digest in value.items()
            ]
            return tuple(sorted(parsed))

        return cls(
            registry_id=_identifier(raw.get("registry_id"), "registry_id", _CASE_ID_RE),
            revision=_bounded_text(raw.get("revision"), "registry revision", 256),
            consent_records=records("consent_records"),
            redaction_records=records("redaction_records"),
        )

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "registry_id": self.registry_id,
            "revision": self.revision,
            "consent_records": dict(self.consent_records),
            "redaction_records": dict(self.redaction_records),
        }

    @property
    def digest(self) -> str:
        return _sha256(self.public_dict())

    def expected_digest(self, kind: str, record_id: str) -> str | None:
        if kind == "consent":
            records = self.consent_records
        elif kind == "redaction":
            records = self.redaction_records
        else:
            raise EnvironmentError(f"unsupported evidence kind {kind!r}")
        return dict(records).get(record_id)


def _parse_reason_codes(
    raw: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> tuple[str, ...]:
    values = raw.get("required_reason_codes")
    if values is None:
        values = []
        for field in ("missing", "unclear"):
            field_values = expected.get(field, [])
            if isinstance(field_values, list) and all(
                isinstance(item, str) and item for item in field_values
            ):
                values.extend(f"{field}:{item}" for item in field_values)
    if (
        not isinstance(values, list)
        or len(values) > 64
        or not all(isinstance(item, str) and item.strip() for item in values)
    ):
        raise EnvironmentError("required_reason_codes must be a bounded string list")
    return tuple(sorted(set(
        _bounded_text(item, "required reason code", 128) for item in values
    )))


def _parse_consent(
    raw: Mapping[str, Any],
    *,
    required: bool,
    case_id: str,
    environment_id: str,
    admitted_content_sha256: str,
) -> ConsentEvidence | None:
    legacy_fields = {
        "tenant_id", "consent_scope", "consent_record_id",
        "consent_valid_until", "consent_revoked",
    } & set(raw)
    if legacy_fields:
        raise EnvironmentError("training authority must use the structured consent object")
    value = raw.get("consent")
    if value is None:
        if required:
            raise EnvironmentError(
                "human or non-public training cases require structured consent",
            )
        return None
    if not isinstance(value, Mapping):
        raise EnvironmentError("consent must be an object")
    consent = ConsentEvidence.from_mapping(value)
    if consent.case_id != case_id:
        raise EnvironmentError("consent is not bound to this case_id")
    if consent.environment_id != environment_id:
        raise EnvironmentError("consent is not bound to this environment_id")
    if consent.admitted_content_sha256 != admitted_content_sha256:
        raise EnvironmentError("consent is not bound to canonical admitted content")
    return consent


def _parse_evidence_region(
    raw: Mapping[str, Any],
    *,
    prompt: str,
    case_id: str,
    required_citations: tuple[str, ...],
) -> tuple[str, str]:
    evidence_raw = raw.get("evidence_text")
    if evidence_raw is None:
        markers = [
            marker for marker in ("Answers:", "Message:", "Text:")
            if marker in prompt
        ]
        if len(markers) != 1:
            raise EnvironmentError(
                "evidence_text is required when the prompt has no unique source marker",
            )
        evidence_text = _bounded_text(
            prompt.split(markers[0], 1)[1],
            "derived evidence_text",
            MAX_PROMPT_BYTES,
        )
    else:
        evidence_text = _bounded_text(
            evidence_raw, "evidence_text", MAX_PROMPT_BYTES,
        )
        if evidence_text not in prompt:
            raise EnvironmentError("evidence_text must be an exact prompt span")
    source_id = _identifier(
        raw.get("source_id", f"{case_id}:input"), "source_id", _CASE_ID_RE,
    )
    missing = [quote for quote in required_citations if quote not in evidence_text]
    if missing:
        raise EnvironmentError(
            "required citations must be exact spans in evidence_text: "
            + ", ".join(missing[:8]),
        )
    return source_id, evidence_text


def _parse_redaction(
    raw: Mapping[str, Any],
    *,
    required: bool,
    case_id: str,
    environment_id: str,
    admitted_content_sha256: str,
) -> RedactionEvidence:
    value = raw.get("redaction_evidence")
    if not isinstance(value, Mapping):
        raise EnvironmentError("redaction_evidence must be an object")
    evidence = RedactionEvidence.from_mapping(value, required=required)
    if evidence.status == "not_applicable":
        return evidence
    if evidence.case_id != case_id:
        raise EnvironmentError("redaction evidence is not bound to this case_id")
    if evidence.environment_id != environment_id:
        raise EnvironmentError(
            "redaction evidence is not bound to this environment_id",
        )
    if evidence.output_sha256 != admitted_content_sha256:
        raise EnvironmentError(
            "redaction output is not canonical admitted content",
        )
    return evidence


_CASE_REQUIRED_FIELDS = frozenset({
    "schema",
    "case_id",
    "environment_id",
    "split",
    "family_id",
    "prompt",
    "expected",
    "required_citations",
    "provenance",
    "source_uri",
    "license",
    "data_classification",
})
_CASE_OPTIONAL_FIELDS = frozenset({
    "required_reason_codes",
    "source_id",
    "evidence_text",
    "consent",
    "redaction_evidence",
    "answer_visibility",
    "unordered_fields",
})


def _reject_empty_rubric_objects(value: object, path: str = "expected") -> None:
    if isinstance(value, Mapping):
        if not value:
            raise EnvironmentError(f"{path} contains an empty scored object")
        for key, item in value.items():
            _reject_empty_rubric_objects(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_empty_rubric_objects(item, f"{path}[{index}]")


def _admitted_content_payload(parsed: Mapping[str, Any]) -> dict[str, Any]:
    """Return exactly the case content that authority evidence must cover."""
    return {
        "schema": ADMITTED_CONTENT_SCHEMA,
        "case_schema": CASE_SCHEMA,
        "case_id": parsed["case_id"],
        "environment_id": parsed["environment_id"],
        "split": parsed["split"],
        "family_id": parsed["family_id"],
        "prompt": parsed["prompt"],
        "expected": parsed["expected"],
        "required_citations": list(parsed["required_citations"]),
        "required_reason_codes": list(parsed["required_reason_codes"]),
        "source_id": parsed["source_id"],
        "evidence_text": parsed["evidence_text"],
        "provenance": parsed["provenance"],
        "source_uri": parsed["source_uri"],
        "license": parsed["license"],
        "data_classification": parsed["data_classification"],
        "answer_visibility": parsed["answer_visibility"],
        "unordered_fields": list(parsed["unordered_fields"]),
    }


def _parse_case_content(raw: Mapping[str, Any]) -> dict[str, Any]:
    _exact_fields(
        raw,
        "environment case",
        required=_CASE_REQUIRED_FIELDS,
        optional=_CASE_OPTIONAL_FIELDS,
    )
    if raw.get("schema") != CASE_SCHEMA:
        raise EnvironmentError("unsupported environment-case schema")
    case_id = _identifier(raw.get("case_id"), "case_id", _CASE_ID_RE)
    environment_id = _identifier(
        raw.get("environment_id"), "environment_id", _ID_RE,
    )
    family_id = _identifier(raw.get("family_id"), "family_id", _CASE_ID_RE)
    split = _bounded_text(raw.get("split"), "split", 32)
    if split not in SPLITS:
        raise EnvironmentError(f"split must be one of {sorted(SPLITS)}")
    provenance = _bounded_text(raw.get("provenance"), "provenance", 32)
    if provenance not in PROVENANCE:
        raise EnvironmentError(f"unsupported provenance {provenance!r}")
    classification = _bounded_text(
        raw.get("data_classification"), "data_classification", 32,
    )
    if classification not in CLASSIFICATIONS:
        raise EnvironmentError(
            f"data_classification must be one of {sorted(CLASSIFICATIONS)}",
        )
    prompt = _bounded_text(raw.get("prompt"), "prompt", MAX_PROMPT_BYTES)
    expected = _mapping(raw.get("expected"), "expected")
    if not expected:
        raise EnvironmentError("expected must contain at least one scored field")
    _reject_empty_rubric_objects(expected)
    reserved = {"citations", "reason_codes"} & set(expected)
    if reserved:
        raise EnvironmentError(
            f"expected uses reserved evidence fields: {sorted(reserved)}",
        )
    citations = raw.get("required_citations")
    if not isinstance(citations, list) or len(citations) > 64:
        raise EnvironmentError("required_citations must be a bounded list")
    required_citations = tuple(
        _bounded_text(item, "required citation", 512) for item in citations
    )
    if len(set(required_citations)) != len(required_citations):
        raise EnvironmentError("required_citations must not contain duplicates")
    required_reason_codes = _parse_reason_codes(raw, expected)
    source_id, evidence_text = _parse_evidence_region(
        raw,
        prompt=prompt,
        case_id=case_id,
        required_citations=required_citations,
    )
    source_uri = _bounded_text(raw.get("source_uri"), "source_uri", 2048)
    if not source_uri.startswith("https://"):
        raise EnvironmentError("source_uri must use https")
    license_name = _bounded_text(raw.get("license"), "license", 512)
    authority_required = (
        provenance not in {"public", "synthetic"}
        or classification != "public"
    )
    answer_visibility = _bounded_text(
        raw.get(
            "answer_visibility",
            "sealed" if authority_required else "published",
        ),
        "answer_visibility",
        32,
    )
    if answer_visibility not in ANSWER_VISIBILITY:
        raise EnvironmentError(
            f"answer_visibility must be one of {sorted(ANSWER_VISIBILITY)}",
        )
    unordered = raw.get(
        "unordered_fields",
        ["findings", "present", "missing", "unclear", "citations"],
    )
    if (
        not isinstance(unordered, list)
        or len(unordered) > 32
        or not all(
            isinstance(item, str)
            and re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", item)
            for item in unordered
        )
    ):
        raise EnvironmentError("unordered_fields must be a bounded field-name list")
    parsed = {
        "case_id": case_id,
        "environment_id": environment_id,
        "split": split,
        "family_id": family_id,
        "prompt": prompt,
        "expected": expected,
        "required_citations": required_citations,
        "required_reason_codes": required_reason_codes,
        "source_id": source_id,
        "evidence_text": evidence_text,
        "provenance": provenance,
        "source_uri": source_uri,
        "license": license_name,
        "data_classification": classification,
        "answer_visibility": answer_visibility,
        "unordered_fields": tuple(sorted(set(unordered))),
        "authority_required": authority_required,
    }
    parsed["admitted_content_sha256"] = _sha256(_admitted_content_payload(parsed))
    return parsed


def admitted_content_sha256(raw: Mapping[str, Any]) -> str:
    """Hash normalized trainable content before consent/redaction is attached."""
    if not isinstance(raw, Mapping):
        raise EnvironmentError("environment case must be an object")
    return str(_parse_case_content(raw)["admitted_content_sha256"])


@dataclass(frozen=True)
class EnvironmentCase:
    """One independently identifiable task and its hidden deterministic answer."""

    case_id: str
    environment_id: str
    split: str
    family_id: str
    prompt: str
    expected: dict[str, Any]
    required_citations: tuple[str, ...] = ()
    required_reason_codes: tuple[str, ...] = ()
    source_id: str = ""
    evidence_text: str = ""
    provenance: str = "synthetic"
    source_uri: str = ""
    license: str = "Lightwork synthetic benchmark"
    data_classification: str = "public"
    consent: ConsentEvidence | None = None
    redaction_evidence: RedactionEvidence = RedactionEvidence(status="not_applicable")
    answer_visibility: str = "published"
    unordered_fields: tuple[str, ...] = (
        "findings", "present", "missing", "unclear", "citations",
    )
    schema: str = CASE_SCHEMA

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> EnvironmentCase:
        if not isinstance(raw, Mapping):
            raise EnvironmentError("environment case must be an object")
        parsed = _parse_case_content(raw)
        admitted_digest = str(parsed["admitted_content_sha256"])
        authority_required = bool(parsed["authority_required"])
        consent = _parse_consent(
            raw,
            required=authority_required,
            case_id=str(parsed["case_id"]),
            environment_id=str(parsed["environment_id"]),
            admitted_content_sha256=admitted_digest,
        )
        redaction_evidence = _parse_redaction(
            raw,
            required=authority_required,
            case_id=str(parsed["case_id"]),
            environment_id=str(parsed["environment_id"]),
            admitted_content_sha256=admitted_digest,
        )
        return cls(
            case_id=str(parsed["case_id"]),
            environment_id=str(parsed["environment_id"]),
            split=str(parsed["split"]),
            family_id=str(parsed["family_id"]),
            prompt=str(parsed["prompt"]),
            expected=dict(parsed["expected"]),
            required_citations=tuple(parsed["required_citations"]),
            required_reason_codes=tuple(parsed["required_reason_codes"]),
            source_id=str(parsed["source_id"]),
            evidence_text=str(parsed["evidence_text"]),
            provenance=str(parsed["provenance"]),
            source_uri=str(parsed["source_uri"]),
            license=str(parsed["license"]),
            data_classification=str(parsed["data_classification"]),
            consent=consent,
            redaction_evidence=redaction_evidence,
            answer_visibility=str(parsed["answer_visibility"]),
            unordered_fields=tuple(parsed["unordered_fields"]),
        )

    @property
    def tenant_id(self) -> str:
        return self.consent.tenant_id if self.consent else ""

    @property
    def consent_scope(self) -> str:
        return self.consent.allowed_purpose if self.consent else ""

    @property
    def consent_record_id(self) -> str:
        return self.consent.record_id if self.consent else ""

    @property
    def consent_valid_until(self) -> float:
        return self.consent.valid_until if self.consent else 0.0

    @property
    def consent_revoked(self) -> bool:
        return self.consent.revoked if self.consent else False

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "case_id": self.case_id,
            "environment_id": self.environment_id,
            "split": self.split,
            "family_id": self.family_id,
            "prompt": self.prompt,
            "expected": self.expected,
            "required_citations": list(self.required_citations),
            "required_reason_codes": list(self.required_reason_codes),
            "source_id": self.source_id,
            "evidence_text": self.evidence_text,
            "provenance": self.provenance,
            "source_uri": self.source_uri,
            "license": self.license,
            "data_classification": self.data_classification,
            "consent": self.consent.public_dict() if self.consent else None,
            "redaction_evidence": self.redaction_evidence.public_dict(),
            "answer_visibility": self.answer_visibility,
            "unordered_fields": list(self.unordered_fields),
        }

    @property
    def digest(self) -> str:
        return _sha256(self.public_dict())

    @property
    def prompt_digest(self) -> str:
        return hashlib.sha256(self.prompt.encode("utf-8")).hexdigest()

    @property
    def admitted_content_sha256(self) -> str:
        """Digest of all trainable content, excluding authority assertions."""
        return _sha256(_admitted_content_payload({
            "case_id": self.case_id,
            "environment_id": self.environment_id,
            "split": self.split,
            "family_id": self.family_id,
            "prompt": self.prompt,
            "expected": self.expected,
            "required_citations": self.required_citations,
            "required_reason_codes": self.required_reason_codes,
            "source_id": self.source_id,
            "evidence_text": self.evidence_text,
            "provenance": self.provenance,
            "source_uri": self.source_uri,
            "license": self.license,
            "data_classification": self.data_classification,
            "answer_visibility": self.answer_visibility,
            "unordered_fields": self.unordered_fields,
        }))


@dataclass(frozen=True)
class EnvironmentPack:
    """A content-addressed taskset whose train/holdout families cannot overlap."""

    environment_id: str
    version: str
    description: str
    cases: tuple[EnvironmentCase, ...]
    schema: str = PACK_SCHEMA

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "environment_id": self.environment_id,
            "version": self.version,
            "description": self.description,
            "cases": [
                case.public_dict() for case in sorted(self.cases, key=lambda item: item.case_id)
            ],
        }

    @property
    def digest(self) -> str:
        return _sha256(self.public_dict())

    def split(self, name: str) -> tuple[EnvironmentCase, ...]:
        if name not in SPLITS:
            raise EnvironmentError(f"unknown split {name!r}")
        return tuple(sorted(
            (case for case in self.cases if case.split == name),
            key=lambda case: case.case_id,
        ))


@dataclass(frozen=True)
class BoundaryDecision:
    allowed: bool
    target: str
    reasons: tuple[str, ...]
    pack_digest: str = ""
    registry_digest: str = ""
    admitted_content_digests: tuple[tuple[str, str], ...] = ()
    evaluated_at: float = 0.0
    schema: str = BOUNDARY_DECISION_SCHEMA

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "allowed": self.allowed,
            "target": self.target,
            "reasons": list(self.reasons),
            "pack_digest": self.pack_digest,
            "registry_digest": self.registry_digest,
            "admitted_content_digests": dict(self.admitted_content_digests),
            "evaluated_at": self.evaluated_at,
        }

    @property
    def digest(self) -> str:
        # ``evaluated_at`` is audit metadata, not policy input.  Omitting it
        # makes repeated pre-expiry checks stable while ``allowed``/``reasons``
        # still change the commitment at expiry or revocation.
        return _sha256({
            key: value
            for key, value in self.public_dict().items()
            if key != "evaluated_at"
        })


@dataclass(frozen=True)
class RewardResult:
    case_id: str
    parsed: bool
    passed: bool
    correctness: float
    citation_score: float
    reason_code_score: float
    reward: float
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class EnvironmentEvaluation:
    environment_id: str
    environment_digest: str
    split: str
    results: tuple[RewardResult, ...]
    missing_case_ids: tuple[str, ...] = ()
    extra_case_ids: tuple[str, ...] = ()
    schema: str = EVALUATION_SCHEMA

    @property
    def score(self) -> float:
        denominator = len(self.results) + len(self.extra_case_ids)
        if not denominator:
            return 0.0
        return sum(result.reward for result in self.results) / denominator

    @property
    def pass_rate(self) -> float:
        denominator = len(self.results) + len(self.extra_case_ids)
        if not denominator:
            return 0.0
        return sum(1 for result in self.results if result.passed) / denominator

    @property
    def digest(self) -> str:
        return _sha256({
            "schema": self.schema,
            "environment_id": self.environment_id,
            "environment_digest": self.environment_digest,
            "split": self.split,
            "score": self.score,
            "pass_rate": self.pass_rate,
            "missing_case_ids": list(self.missing_case_ids),
            "extra_case_ids": list(self.extra_case_ids),
            "results": [
                {
                    "case_id": result.case_id,
                    "parsed": result.parsed,
                    "passed": result.passed,
                    "correctness": result.correctness,
                    "citation_score": result.citation_score,
                    "reason_code_score": result.reason_code_score,
                    "reward": result.reward,
                    "reasons": list(result.reasons),
                }
                for result in self.results
            ],
        })


def _validate_pack(pack: EnvironmentPack) -> None:
    if not pack.cases:
        raise EnvironmentError("environment pack is empty")
    if len(pack.cases) > MAX_CASES:
        raise EnvironmentError(f"environment pack exceeds {MAX_CASES} cases")
    case_ids: set[str] = set()
    prompt_splits: dict[str, str] = {}
    family_splits: dict[str, str] = {}
    for case in pack.cases:
        if case.environment_id != pack.environment_id:
            raise EnvironmentError("case environment_id does not match its pack")
        if case.case_id in case_ids:
            raise EnvironmentError(f"duplicate case_id {case.case_id!r}")
        case_ids.add(case.case_id)
        prior_prompt_split = prompt_splits.setdefault(case.prompt_digest, case.split)
        if prior_prompt_split != case.split:
            raise EnvironmentError(
                f"identical prompt appears in {prior_prompt_split} and {case.split}",
            )
        prior_family_split = family_splits.setdefault(case.family_id, case.split)
        if prior_family_split != case.split:
            raise EnvironmentError(
                f"family {case.family_id!r} crosses {prior_family_split}/{case.split}",
            )
    if not pack.split("holdout"):
        raise EnvironmentError("environment pack must contain a holdout split")


def validate_environment_case(case: EnvironmentCase) -> EnvironmentCase:
    """Validate a case even when it was constructed outside ``from_mapping``."""
    if not isinstance(case, EnvironmentCase):
        raise EnvironmentError("environment case must be EnvironmentCase")
    try:
        normalized = EnvironmentCase.from_mapping(case.public_dict())
    except EnvironmentError:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise EnvironmentError("environment case is malformed") from exc
    if normalized != case:
        raise EnvironmentError("environment case is not canonically normalized")
    return case


def validate_environment_pack(pack: EnvironmentPack) -> EnvironmentPack:
    """Validate an arbitrary in-memory pack before a trusted operation."""
    if not isinstance(pack, EnvironmentPack):
        raise EnvironmentError("environment pack must be EnvironmentPack")
    if pack.schema != PACK_SCHEMA:
        raise EnvironmentError("unsupported environment-pack schema")
    if _identifier(pack.environment_id, "environment_id", _ID_RE) != pack.environment_id:
        raise EnvironmentError("environment_id is not canonically normalized")
    if _bounded_text(pack.version, "version", 64) != pack.version:
        raise EnvironmentError("version is not canonically normalized")
    if _bounded_text(pack.description, "description", 2048) != pack.description:
        raise EnvironmentError("description is not canonically normalized")
    if not isinstance(pack.cases, tuple):
        raise EnvironmentError("environment pack cases must be an immutable tuple")
    for case in pack.cases:
        validate_environment_case(case)
    _validate_pack(pack)
    return pack


def environment_pack_dir() -> Path:
    return Path(__file__).with_name("environment_packs")


def _load_pack_lock() -> dict[str, dict[str, str]]:
    path = environment_pack_dir() / "environment_packs.lock.json"
    try:
        blob = path.read_bytes()
    except OSError as exc:
        raise EnvironmentError("environment-pack lock is unavailable") from exc
    if len(blob) > 256 * 1024:
        raise EnvironmentError("environment-pack lock exceeds its size bound")
    try:
        raw = _strict_json_loads(blob.decode("utf-8"))
    except (EnvironmentError, UnicodeDecodeError) as exc:
        raise EnvironmentError("environment-pack lock is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise EnvironmentError("environment-pack lock must be an object")
    _exact_fields(
        raw,
        "environment-pack lock",
        required=frozenset({"schema", "packs"}),
    )
    if raw.get("schema") != PACK_LOCK_SCHEMA:
        raise EnvironmentError("unsupported environment-pack lock schema")
    entries = raw.get("packs")
    if not isinstance(entries, dict) or not entries:
        raise EnvironmentError("environment-pack lock must contain pack entries")
    parsed: dict[str, dict[str, str]] = {}
    for environment_id, entry in entries.items():
        identifier = _identifier(environment_id, "locked environment_id", _ID_RE)
        if not isinstance(entry, Mapping) or set(entry) != {
            "file_sha256", "semantic_sha256",
        }:
            raise EnvironmentError(f"{identifier}: invalid lock entry")
        parsed[identifier] = {
            "file_sha256": _sha256_text(
                entry.get("file_sha256"), f"{identifier} file_sha256",
            ),
            "semantic_sha256": _sha256_text(
                entry.get("semantic_sha256"), f"{identifier} semantic_sha256",
            ),
        }
    files = {
        path.stem for path in environment_pack_dir().glob("*.ndjson")
    }
    if files != set(parsed):
        raise EnvironmentError("environment-pack files and lock entries differ")
    return parsed


def list_environment_ids() -> tuple[str, ...]:
    return tuple(sorted(_load_pack_lock()))


def load_environment(environment_id: str) -> EnvironmentPack:
    identifier = _identifier(environment_id, "environment_id", _ID_RE)
    path = environment_pack_dir() / f"{identifier}.ndjson"
    lock = _load_pack_lock()
    if identifier not in lock:
        raise EnvironmentError(f"unknown environment {identifier!r}")
    try:
        blob = path.read_bytes()
    except OSError as exc:
        raise EnvironmentError(f"unknown environment {identifier!r}") from exc
    if len(blob) > MAX_PACK_BYTES:
        raise EnvironmentError(f"environment pack exceeds {MAX_PACK_BYTES} bytes")
    if hashlib.sha256(blob).hexdigest() != lock[identifier]["file_sha256"]:
        raise EnvironmentError(f"{identifier}: file digest differs from its lock")
    cases: list[EnvironmentCase] = []
    description = ""
    version = ""
    try:
        lines = blob.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise EnvironmentError(f"{path.name} is not UTF-8") from exc
    for line_number, raw_line in enumerate(lines, 1):
        if not raw_line.strip():
            continue
        if len(cases) >= MAX_CASES:
            raise EnvironmentError(f"{path.name} exceeds {MAX_CASES} cases")
        try:
            raw = _strict_json_loads(raw_line)
        except EnvironmentError as exc:
            raise EnvironmentError(
                f"{path.name}:{line_number} is not strict JSON",
            ) from exc
        if not isinstance(raw, dict):
            raise EnvironmentError(f"{path.name}:{line_number} must be an object")
        if "pack_version" not in raw or "pack_description" not in raw:
            raise EnvironmentError(
                f"{path.name}:{line_number} requires explicit pack metadata",
            )
        row_version = _bounded_text(raw.pop("pack_version"), "pack_version", 64)
        row_description = _bounded_text(
            raw.pop("pack_description"), "pack_description", 2048,
        )
        if version and version != row_version:
            raise EnvironmentError("pack_version changed within one environment")
        if description and description != row_description:
            raise EnvironmentError("pack_description changed within one environment")
        version, description = row_version, row_description
        cases.append(EnvironmentCase.from_mapping(raw))
    pack = EnvironmentPack(
        environment_id=identifier,
        version=version or "1.0.0",
        description=description or identifier,
        cases=tuple(cases),
    )
    validate_environment_pack(pack)
    if pack.digest != lock[identifier]["semantic_sha256"]:
        raise EnvironmentError(f"{identifier}: semantic digest differs from its lock")
    return pack


def _independent_family_fingerprints(
    cases: tuple[EnvironmentCase, ...],
) -> dict[str, str]:
    """Commit family task content without trusting caller-selected labels."""

    grouped: dict[str, list[str]] = {}
    for case in cases:
        unordered_fields = frozenset(case.unordered_fields)
        task_fingerprint = _sha256({
            "prompt": case.prompt,
            "evidence_text": case.evidence_text,
            "expected_leaves": _leaf_pairs(
                case.expected,
                unordered_fields=unordered_fields,
            ),
        })
        grouped.setdefault(case.family_id, []).append(task_fingerprint)
    return {
        family_id: _sha256(sorted(task_fingerprints))
        for family_id, task_fingerprints in grouped.items()
    }


def promotion_readiness(
    pack: EnvironmentPack,
    *,
    minimum_train_families: int = 20,
    minimum_holdout_families: int = 20,
) -> dict[str, Any]:
    """Describe evidence volume without pretending seed packs are deployable."""
    validate_environment_pack(pack)
    for label, value in (
        ("minimum_train_families", minimum_train_families),
        ("minimum_holdout_families", minimum_holdout_families),
    ):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 20 <= value <= MAX_CASES
        ):
            raise EnvironmentError(f"{label} must be an integer in 20..{MAX_CASES}")
    train_families = _independent_family_fingerprints(pack.split("train"))
    holdout_families = _independent_family_fingerprints(pack.split("holdout"))
    independent_train = set(train_families.values())
    independent_holdout = set(holdout_families.values())
    reasons: list[str] = []
    if len(independent_train) < len(train_families):
        reasons.append(
            "train family labels repeat identical task content; relabeling does "
            "not create independent evidence",
        )
    if len(independent_holdout) < len(holdout_families):
        reasons.append(
            "holdout family labels repeat identical task content; relabeling "
            "does not create independent evidence",
        )
    if independent_train & independent_holdout:
        reasons.append(
            "identical family task content appears in both train and holdout",
        )
    if len(independent_train) < minimum_train_families:
        reasons.append(
            f"need {minimum_train_families} independent train families; "
            f"have {len(independent_train)}",
        )
    if len(independent_holdout) < minimum_holdout_families:
        reasons.append(
            f"need {minimum_holdout_families} independent holdout families; "
            f"have {len(independent_holdout)}",
        )
    disclosed = [
        case.case_id for case in pack.split("holdout")
        if case.answer_visibility != "sealed"
    ]
    if disclosed:
        reasons.append(
            "holdout answers are published seed data, not sealed promotion evidence: "
            + ", ".join(disclosed[:8]),
        )
    return {
        "ready": not reasons,
        "environment_id": pack.environment_id,
        "environment_digest": pack.digest,
        "train_families": len(independent_train),
        "holdout_families": len(independent_holdout),
        "reasons": reasons,
    }


def _validate_trusted_evidence_registry(
    registry: TrustedEvidenceRegistry,
) -> TrustedEvidenceRegistry:
    if not isinstance(registry, TrustedEvidenceRegistry):
        raise EnvironmentError(
            "trusted evidence registry must be a canonical server snapshot",
        )
    try:
        normalized = TrustedEvidenceRegistry.from_mapping(registry.public_dict())
    except EnvironmentError:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise EnvironmentError("trusted evidence registry is malformed") from exc
    if normalized != registry:
        raise EnvironmentError("trusted evidence registry is not canonically normalized")
    return registry


def trusted_evidence_registry_path() -> Path:
    """Return the protected active-tenant registry provisioned by the server."""
    from ..paths import current_tenant_id_strict, data_dir

    tenant_id = current_tenant_id_strict()
    if not tenant_id:
        raise EnvironmentError(
            "training authority requires an explicit tenant scope",
        )
    return data_dir(
        "model_improvement",
        TRUSTED_EVIDENCE_REGISTRY_BASENAME,
        tenant=tenant_id,
    )


def _server_trusted_evidence_registry() -> TrustedEvidenceRegistry:
    """Resolve consent/redaction authority from protected server state only."""
    from ..file_lock import (
        atomic_read_bytes,
        ensure_private_directory,
        ensure_private_file,
    )

    path = trusted_evidence_registry_path()
    try:
        ensure_private_directory(path.parent)
        ensure_private_file(path)
        blob = atomic_read_bytes(path)
    except (OSError, PermissionError) as exc:
        raise EnvironmentError(
            "server training-evidence registry is unavailable",
        ) from exc
    if not blob or len(blob) > MAX_TRUSTED_EVIDENCE_REGISTRY_BYTES:
        raise EnvironmentError(
            "server training-evidence registry exceeds its storage boundary",
        )
    try:
        raw = _strict_json_loads(blob.decode("utf-8"))
    except (EnvironmentError, UnicodeDecodeError) as exc:
        raise EnvironmentError(
            "server training-evidence registry is malformed",
        ) from exc
    if not isinstance(raw, Mapping):
        raise EnvironmentError(
            "server training-evidence registry must be an object",
        )
    return _validate_trusted_evidence_registry(
        TrustedEvidenceRegistry.from_mapping(raw),
    )


def _authority_trust_reasons(
    case: EnvironmentCase,
    registry: TrustedEvidenceRegistry | None,
) -> list[str]:
    reasons: list[str] = []
    consent = case.consent
    if consent is not None:
        if consent.revoked:
            reasons.append(f"{case.case_id}: training consent is revoked")
        expected = (
            registry.expected_digest("consent", consent.record_id)
            if registry is not None
            else None
        )
        if expected is None:
            reasons.append(
                f"{case.case_id}: consent is absent from the server trust registry",
            )
        elif expected != consent.digest:
            reasons.append(
                f"{case.case_id}: consent differs from the server trust registry",
            )
    evidence = case.redaction_evidence
    if evidence.status == "reviewed_no_detector_matches":
        if evidence.revoked:
            reasons.append(f"{case.case_id}: redaction evidence is revoked")
        expected = (
            registry.expected_digest("redaction", evidence.evidence_id)
            if registry is not None
            else None
        )
        if expected is None:
            reasons.append(
                f"{case.case_id}: redaction evidence is absent from the server "
                "trust registry",
            )
        elif expected != evidence.digest:
            reasons.append(
                f"{case.case_id}: redaction evidence differs from the server "
                "trust registry",
            )
    return reasons


def check_boundary(
    pack: EnvironmentPack,
    target: str,
) -> BoundaryDecision:
    """Fail closed for hosted or cross-tenant movement.

    ``tenant_local`` permits public/synthetic data and one tenant's explicitly
    consented records. ``hosted`` permits public data only; tenant-derived public
    data additionally needs exact hosted-training consent and bound redaction
    evidence.
    Cross-tenant training remains structurally unsupported until Lightwork has a
    separately reviewed secure-aggregation and privacy-accounting subsystem.
    """
    validate_environment_pack(pack)
    authority_present = any(
        case.consent is not None
        or case.redaction_evidence.status == "reviewed_no_detector_matches"
        for case in pack.cases
    )
    if authority_present:
        from ..paths import current_tenant_id_strict

        authority_tenants = {case.tenant_id for case in pack.cases if case.tenant_id}
        active_tenant = current_tenant_id_strict()
        if (
            len(authority_tenants) != 1
            or active_tenant not in authority_tenants
        ):
            raise EnvironmentError(
                "training authority must resolve from the matching active tenant",
            )
        registry = _server_trusted_evidence_registry()
    else:
        registry = None
    destination = _bounded_text(target, "target", 32)
    current = float(time.time())
    if not math.isfinite(current) or current < 0:
        raise EnvironmentError("trusted training clock returned an invalid timestamp")
    reasons: list[str] = []
    ordered_cases = tuple(sorted(pack.cases, key=lambda case: case.case_id))
    for case in ordered_cases:
        reasons.extend(_authority_trust_reasons(case, registry))
    if destination == "cross_tenant":
        reasons.append(
            "cross-tenant model training is unsupported; weight updates are not "
            "a privacy boundary",
        )
    elif destination == "hosted":
        for case in ordered_cases:
            if case.data_classification != "public":
                reasons.append(f"{case.case_id}: non-public data cannot use hosted training")
            if case.tenant_id:
                if case.consent_scope != "hosted_training":
                    reasons.append(
                        f"{case.case_id}: consent does not authorize hosted training",
                    )
                if case.consent_valid_until <= current:
                    reasons.append(f"{case.case_id}: hosted-training consent is expired")
                if case.redaction_evidence.status != "reviewed_no_detector_matches":
                    reasons.append(
                        f"{case.case_id}: bound redaction evidence is required",
                    )
            elif case.provenance not in {"public", "synthetic"}:
                reasons.append(
                    f"{case.case_id}: non-tenant human provenance lacks authority",
                )
    elif destination == "tenant_local":
        tenant_ids = {case.tenant_id for case in ordered_cases if case.tenant_id}
        if len(tenant_ids) > 1:
            reasons.append("tenant-local pack contains more than one tenant")
        for case in ordered_cases:
            if case.tenant_id:
                if case.consent_scope != "tenant_training":
                    reasons.append(
                        f"{case.case_id}: consent_scope does not authorize tenant training",
                    )
                if case.consent_valid_until <= current:
                    reasons.append(f"{case.case_id}: training consent is expired")
    else:
        reasons.append(f"unsupported training target {destination!r}")
    return BoundaryDecision(
        allowed=not reasons,
        target=destination,
        reasons=tuple(reasons),
        pack_digest=pack.digest,
        registry_digest=registry.digest if registry is not None else "",
        admitted_content_digests=tuple(
            (case.case_id, case.admitted_content_sha256) for case in ordered_cases
        ),
        evaluated_at=current,
    )


def _leaf_pairs(
    value: object,
    prefix: str = "",
    *,
    unordered_fields: frozenset[str] = frozenset(),
) -> dict[str, object]:
    if isinstance(value, Mapping):
        out: dict[str, object] = {}
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            label = f"{prefix}.{key}" if prefix else str(key)
            out.update(_leaf_pairs(
                item,
                label,
                unordered_fields=unordered_fields,
            ))
        return out
    if isinstance(value, list):
        if prefix in unordered_fields:
            return {
                prefix: sorted(
                    value,
                    key=lambda item: _canonical(item),
                ),
            }
        return {prefix: value}
    return {prefix: value}


def _score_citations(
    case: EnvironmentCase,
    citations: object,
) -> tuple[float, bool, list[str]]:
    if not isinstance(citations, list) or len(citations) > 64:
        return 0.0, False, ["citations must be a bounded list"]
    grounded = True
    supplied_quotes: set[str] = set()
    seen_citations: set[bytes] = set()
    for citation in citations:
        if not isinstance(citation, Mapping) or set(citation) != {
            "source_id", "quote", "start", "end",
        }:
            grounded = False
            continue
        encoded = _canonical(dict(citation))
        if encoded in seen_citations:
            grounded = False
            continue
        seen_citations.add(encoded)
        source_id = citation.get("source_id")
        quote = citation.get("quote")
        start = citation.get("start")
        end = citation.get("end")
        if (
            source_id != case.source_id
            or not isinstance(quote, str)
            or not quote
            or not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 0
            or end < start
            or end > len(case.evidence_text)
            or case.evidence_text[start:end] != quote
        ):
            grounded = False
            continue
        supplied_quotes.add(quote)
    score = (
        sum(1 for quote in case.required_citations if quote in supplied_quotes)
        / len(case.required_citations)
        if case.required_citations
        else 1.0
    )
    reasons = []
    if score < 1.0:
        reasons.append("required evidence citations are missing")
    if not grounded:
        reasons.append(
            "citation must bind the exact source_id and span in evidence_text",
        )
    return score, grounded, reasons


def _score_reason_codes(
    case: EnvironmentCase,
    reason_codes: object,
) -> tuple[float, bool, list[str]]:
    if (
        not isinstance(reason_codes, list)
        or len(reason_codes) > 64
        or not all(isinstance(item, str) and item for item in reason_codes)
    ):
        return 0.0, False, ["reason_codes must be a bounded string list"]
    supplied = set(reason_codes)
    required = set(case.required_reason_codes)
    if not required:
        score = 1.0 if not supplied else 0.0
    else:
        score = len(supplied & required) / len(required)
        if supplied - required:
            score = min(score, 0.5)
    exact = score == 1.0 and len(reason_codes) == len(supplied)
    reasons = (
        []
        if exact
        else ["reason_codes do not exactly match the deterministic rubric"]
    )
    return score, exact, reasons


def score_output(case: EnvironmentCase, output: str | Mapping[str, Any]) -> RewardResult:
    """Score one strict JSON answer; no LLM judge participates."""
    validate_environment_case(case)
    reasons: list[str] = []
    if isinstance(output, str):
        if len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
            return RewardResult(
                case_id=case.case_id, parsed=False, passed=False,
                correctness=0.0, citation_score=0.0, reason_code_score=0.0,
                reward=0.0,
                reasons=(f"output exceeds {MAX_OUTPUT_BYTES} bytes",),
            )
        try:
            candidate = _strict_json_loads(output)
        except EnvironmentError:
            return RewardResult(
                case_id=case.case_id, parsed=False, passed=False,
                correctness=0.0, citation_score=0.0, reason_code_score=0.0,
                reward=0.0,
                reasons=("output is not one strict JSON object",),
            )
    elif isinstance(output, Mapping):
        candidate = dict(output)
    else:
        candidate = None
    if not isinstance(candidate, dict):
        return RewardResult(
            case_id=case.case_id, parsed=False, passed=False,
            correctness=0.0, citation_score=0.0, reason_code_score=0.0,
            reward=0.0,
            reasons=("output is not one strict JSON object",),
        )
    if not _strict_json_value(candidate):
        return RewardResult(
            case_id=case.case_id,
            parsed=False,
            passed=False,
            correctness=0.0,
            citation_score=0.0,
            reason_code_score=0.0,
            reward=0.0,
            reasons=("output contains a non-standard or unbounded JSON value",),
        )
    try:
        serialized_size = len(_canonical(candidate))
    except (TypeError, ValueError):
        serialized_size = MAX_OUTPUT_BYTES + 1
    if serialized_size > MAX_OUTPUT_BYTES:
        return RewardResult(
            case_id=case.case_id,
            parsed=False,
            passed=False,
            correctness=0.0,
            citation_score=0.0,
            reason_code_score=0.0,
            reward=0.0,
            reasons=(f"output exceeds {MAX_OUTPUT_BYTES} bytes",),
        )

    allowed = set(case.expected) | {"citations", "reason_codes"}
    extra = sorted(set(candidate) - allowed)
    if extra:
        reasons.append(f"unexpected output fields: {extra}")
    unordered = frozenset(case.unordered_fields)
    expected_leaves = _leaf_pairs(case.expected, unordered_fields=unordered)
    candidate_leaves = _leaf_pairs({
        key: value
        for key, value in candidate.items()
        if key not in {"citations", "reason_codes"}
    }, unordered_fields=unordered)
    matches = sum(
        1 for path, value in expected_leaves.items()
        if path in candidate_leaves and candidate_leaves[path] == value
    )
    correctness = matches / len(expected_leaves) if expected_leaves else 1.0
    extra_leaf_paths = sorted(set(candidate_leaves) - set(expected_leaves))
    leaf_shape_ok = not extra_leaf_paths
    if correctness < 1.0:
        reasons.append(f"matched {matches}/{len(expected_leaves)} expected fields")
    if extra_leaf_paths:
        reasons.append(f"unexpected nested output fields: {extra_leaf_paths[:8]}")

    citation_score, grounded, citation_reasons = _score_citations(
        case, candidate.get("citations", []),
    )
    reasons.extend(citation_reasons)
    reason_code_score, reason_codes_exact, reason_reasons = _score_reason_codes(
        case, candidate.get("reason_codes", []),
    )
    reasons.extend(reason_reasons)

    reward = (
        0.80 * correctness
        + 0.15 * citation_score
        + 0.05 * reason_code_score
    )
    passed = (
        correctness == 1.0
        and citation_score == 1.0
        and reason_code_score == 1.0
        and reason_codes_exact
        and grounded
        and not extra
        and leaf_shape_ok
    )
    return RewardResult(
        case_id=case.case_id,
        parsed=True,
        passed=passed,
        correctness=correctness,
        citation_score=citation_score,
        reason_code_score=reason_code_score,
        reward=reward if not extra and leaf_shape_ok else min(reward, 0.5),
        reasons=tuple(reasons),
    )


def evaluate_outputs(
    pack: EnvironmentPack,
    outputs: Mapping[str, str | Mapping[str, Any]],
    *,
    split: str = "holdout",
) -> EnvironmentEvaluation:
    validate_environment_pack(pack)
    if not isinstance(outputs, Mapping):
        raise EnvironmentError("outputs must be a mapping keyed by case_id")
    selected = pack.split(split)
    if not selected:
        raise EnvironmentError(f"environment split {split!r} is empty")
    selected_ids = {case.case_id for case in selected}
    results: list[RewardResult] = []
    missing: list[str] = []
    for case in selected:
        if case.case_id not in outputs:
            missing.append(case.case_id)
            results.append(RewardResult(
                case_id=case.case_id,
                parsed=False,
                passed=False,
                correctness=0.0,
                citation_score=0.0,
                reason_code_score=0.0,
                reward=0.0,
                reasons=("model produced no output",),
            ))
            continue
        results.append(score_output(case, outputs[case.case_id]))
    extra = sorted(str(case_id) for case_id in outputs if str(case_id) not in selected_ids)
    return EnvironmentEvaluation(
        environment_id=pack.environment_id,
        environment_digest=pack.digest,
        split=split,
        results=tuple(results),
        missing_case_ids=tuple(sorted(missing)),
        extra_case_ids=tuple(extra),
    )


def expected_output(case: EnvironmentCase) -> dict[str, Any]:
    """Build the exact structured gold answer without exposing it in prompts."""
    validate_environment_case(case)
    citations = []
    for quote in case.required_citations:
        start = case.evidence_text.index(quote)
        citations.append({
            "source_id": case.source_id,
            "quote": quote,
            "start": start,
            "end": start + len(quote),
        })
    return {
        **case.expected,
        "citations": citations,
        "reason_codes": list(case.required_reason_codes),
    }


def export_rows(
    pack: EnvironmentPack,
    *,
    split: str,
    include_answers: bool = True,
) -> list[dict[str, Any]]:
    """Return backend-neutral rows, refusing sealed-answer disclosure."""
    validate_environment_pack(pack)
    if not isinstance(include_answers, bool):
        raise EnvironmentError("include_answers must be a boolean")
    selected = pack.split(split)
    if not selected:
        raise EnvironmentError(f"environment split {split!r} is empty")
    if include_answers and any(
        case.answer_visibility == "sealed" for case in selected
    ):
        raise EnvironmentError(
            "sealed answers cannot be exported into a backend task bundle",
        )
    rows = []
    for case in selected:
        row = {
            "case_id": case.case_id,
            "family_id": case.family_id,
            "prompt": [{"role": "user", "content": case.prompt}],
            "split": case.split,
            "max_turns": 1,
            "case_digest": case.digest,
            "environment_digest": pack.digest,
        }
        if include_answers:
            row["answer"] = json.dumps(
                expected_output(case), sort_keys=True, separators=(",", ":"),
            )
        rows.append(row)
    return rows


__all__ = [
    "ADMITTED_CONTENT_SCHEMA",
    "BOUNDARY_DECISION_SCHEMA",
    "BoundaryDecision",
    "CASE_SCHEMA",
    "CLASSIFICATIONS",
    "CONSENT_SCHEMA",
    "ConsentEvidence",
    "EVALUATION_SCHEMA",
    "EnvironmentCase",
    "EnvironmentError",
    "EnvironmentEvaluation",
    "EnvironmentPack",
    "PACK_SCHEMA",
    "PACK_LOCK_SCHEMA",
    "PROVENANCE",
    "REDACTION_EVIDENCE_SCHEMA",
    "RedactionEvidence",
    "RewardResult",
    "SPLITS",
    "TRUSTED_EVIDENCE_REGISTRY_SCHEMA",
    "TRUSTED_EVIDENCE_REGISTRY_BASENAME",
    "TrustedEvidenceRegistry",
    "admitted_content_sha256",
    "check_boundary",
    "environment_pack_dir",
    "evaluate_outputs",
    "expected_output",
    "export_rows",
    "list_environment_ids",
    "load_environment",
    "promotion_readiness",
    "score_output",
    "trusted_evidence_registry_path",
    "validate_environment_case",
    "validate_environment_pack",
]
