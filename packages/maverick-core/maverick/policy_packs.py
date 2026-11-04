"""Signed, versioned policy-pack decision support.

Policy packs are bounded data, never executable policy and never a compliance
certificate.  The deployment-global catalog is immutable: an external update
must verify against an operator-pinned Ed25519 key before it can be staged, and
staging never activates it.  A global administrator performs a separate CAS
activation.  Tenant subscriptions and evidence attestations use the shared
governed-record authority, so their revisions and audit outbox follow the same
local/Postgres contract as the rest of Lightwork's governance records.

The module intentionally does not decide legal applicability.  Framework
mappings are informative, and every pack carries a non-certification notice.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

PACK_SCHEMA = "lightwork.policy-pack.v1"
UPDATE_SCHEMA = "lightwork.policy-pack-update.v1"
CATALOG_SCHEMA = "lightwork.policy-pack-catalog-entry.v1"
CHANNEL_SCHEMA = "lightwork.policy-pack-active-channel.v1"
SUBSCRIPTION_SCHEMA = "lightwork.policy-pack-subscription.v1"
ATTESTATION_SCHEMA = "lightwork.policy-pack-attestation.v1"
RUNTIME_OVERLAY_SCHEMA = "lightwork.policy-pack-runtime-overlay.v1"

MAX_PACK_BYTES = 512_000
MAX_UPDATE_BYTES = 768_000
MAX_CONTROLS = 256
MAX_REQUIREMENTS_PER_CONTROL = 64
MAX_EVIDENCE_BINDINGS = 512
MAX_CATALOG_ENTRIES = 4_096
MAX_RETIRED_REQUIREMENTS = 1_024
MAX_REDIRECTS = 3
MAX_READ_LIMIT = 500

NON_CERTIFICATION_NOTICE = (
    "Decision support only. This pack does not certify compliance, determine "
    "legal applicability, or provide legal advice. A qualified human reviewer "
    "must validate scope, mappings, evidence, and conclusions."
)
MAPPING_NOTICE = (
    "Informative cross-reference only; not a certification or legal conclusion."
)

_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX_128 = re.compile(r"[0-9a-f]{128}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PACK_ID = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}\Z")
_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z"
)
_UPDATE_DOMAIN = b"LIGHTWORK-POLICY-PACK-UPDATE-V1\x00"


class PolicyPackError(RuntimeError):
    """Base policy-pack failure."""


class PolicyPackValidationError(PolicyPackError, ValueError):
    """A pack or governed record is malformed or internally inconsistent."""


class PolicyPackUpdateRefused(PolicyPackError, ValueError):
    """An external update failed transport, trust, or anti-rollback checks."""


class PolicyPackStateError(PolicyPackError):
    """Stored active state cannot be trusted or is not ready for use."""


class PolicyPackTenantRequired(PolicyPackStateError):
    """A tenant-local subscription operation lacks explicit tenant authority."""


class PackVersionCollision(PolicyPackUpdateRefused):
    """The same pack id/version was presented with different content."""


def enabled() -> bool:
    """Return the fail-closed deployment-global ``[policy_packs]`` gate."""

    try:
        from .config import config_source_errors, load_global_config

        cfg = load_global_config()
        if config_source_errors(include_tenant=False) or not isinstance(cfg, dict):
            return False
        section = cfg.get("policy_packs")
        return isinstance(section, dict) and section.get("enable") is True
    except Exception:
        return False


def _require_tenant_scope() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise PolicyPackTenantRequired(
            "policy-pack subscriptions require an explicit tenant scope",
        )
    return tenant


def _canonical_bytes(value: Any, *, limit: int | None = None) -> bytes:
    try:
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PolicyPackValidationError("value is not canonical bounded JSON") from exc
    if limit is not None and len(raw) > limit:
        raise PolicyPackValidationError(f"canonical JSON exceeds {limit} bytes")
    return raw


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _copy_json(value: Any) -> Any:
    return json.loads(_canonical_bytes(value).decode("utf-8"))


def _object(value: Any, label: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyPackValidationError(f"{label} must be an object")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise PolicyPackValidationError(
            f"{label} contains unsupported fields: {', '.join(unknown)}"
        )
    return value


def _text(value: Any, label: str, limit: int, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise PolicyPackValidationError(f"{label} must be a string")
    clean = value.strip()
    if not clean and not empty:
        raise PolicyPackValidationError(f"{label} is required")
    if len(clean) > limit or any(ord(char) < 32 for char in clean):
        raise PolicyPackValidationError(f"{label} exceeds its safe text bound")
    return clean


def _token(value: Any, label: str, limit: int = 128) -> str:
    clean = _text(value, label, limit)
    if not _TOKEN.fullmatch(clean):
        raise PolicyPackValidationError(f"{label} is not a safe token")
    return clean


def _pack_id(value: Any) -> str:
    clean = _text(value, "pack_id", 64)
    if not _PACK_ID.fullmatch(clean):
        raise PolicyPackValidationError("pack_id is not a safe lower-case identifier")
    return clean


@dataclass(frozen=True)
class _ParsedSemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...]


def parse_semver(value: Any) -> _ParsedSemVer:
    """Parse strict SemVer 2.0, including prerelease/build syntax."""

    clean = _text(value, "version", 64)
    match = _SEMVER.fullmatch(clean)
    if match is None:
        raise PolicyPackValidationError("version must be valid SemVer 2.0")
    prerelease = tuple((match.group(4) or "").split(".")) if match.group(4) else ()
    for identifier in prerelease:
        if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
            raise PolicyPackValidationError(
                "numeric SemVer prerelease identifiers cannot have leading zeroes"
            )
    return _ParsedSemVer(
        major=int(match.group(1)),
        minor=int(match.group(2)),
        patch=int(match.group(3)),
        prerelease=prerelease,
    )


def compare_semver(left: str, right: str) -> int:
    """Return -1/0/1 according to SemVer precedence (build metadata ignored)."""

    a, b = parse_semver(left), parse_semver(right)
    core_a = (a.major, a.minor, a.patch)
    core_b = (b.major, b.minor, b.patch)
    if core_a != core_b:
        return -1 if core_a < core_b else 1
    if not a.prerelease and not b.prerelease:
        return 0
    if not a.prerelease:
        return 1
    if not b.prerelease:
        return -1
    for item_a, item_b in zip(a.prerelease, b.prerelease, strict=False):
        if item_a == item_b:
            continue
        numeric_a, numeric_b = item_a.isdigit(), item_b.isdigit()
        if numeric_a and numeric_b:
            return -1 if int(item_a) < int(item_b) else 1
        if numeric_a != numeric_b:
            return -1 if numeric_a else 1
        return -1 if item_a < item_b else 1
    if len(a.prerelease) == len(b.prerelease):
        return 0
    return -1 if len(a.prerelease) < len(b.prerelease) else 1


def _iso_date(value: Any, label: str) -> str:
    clean = _text(value, label, 10)
    try:
        parsed = date.fromisoformat(clean)
    except ValueError as exc:
        raise PolicyPackValidationError(f"{label} must be an ISO date") from exc
    if parsed.isoformat() != clean:
        raise PolicyPackValidationError(f"{label} must be an ISO date")
    return clean


def _https_url(value: Any, label: str, *, limit: int = 2_048) -> str:
    clean = _text(value, label, limit)
    parsed = urlsplit(clean)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise PolicyPackValidationError(
            f"{label} must be an HTTPS URL without credentials or a fragment"
        )
    try:
        _ = parsed.port
    except ValueError as exc:
        raise PolicyPackValidationError(f"{label} has an invalid port") from exc
    return clean


def _positive_int(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise PolicyPackValidationError(f"{label} must be between 1 and {maximum}")
    return value


def _normalize_requirement(value: Any, control_id: str) -> dict[str, Any]:
    row = _object(
        value,
        f"control {control_id} evidence requirement",
        {
            "requirement_id",
            "evidence_kind",
            "description",
            "minimum_count",
            "accepted_schemas",
            "validity_days",
            "semantic_sha256",
        },
    )
    requirement_id = _token(row.get("requirement_id"), "requirement_id", 64)
    schemas = row.get("accepted_schemas")
    if not isinstance(schemas, list) or len(schemas) > 32:
        raise PolicyPackValidationError("accepted_schemas must be a list of at most 32")
    accepted = sorted({_token(item, "accepted schema", 128) for item in schemas})
    validity = row.get("validity_days")
    if validity is not None:
        validity = _positive_int(validity, "validity_days", 36_500)
    logical = {
        "requirement_id": requirement_id,
        "evidence_kind": _token(row.get("evidence_kind"), "evidence_kind", 64),
        "description": _text(row.get("description"), "requirement description", 2_000),
        "minimum_count": _positive_int(
            row.get("minimum_count"), "minimum_count", 100
        ),
        "accepted_schemas": accepted,
        "validity_days": validity,
    }
    semantic = _digest(logical)
    supplied = row.get("semantic_sha256")
    if supplied is not None and supplied != semantic:
        raise PolicyPackValidationError(
            f"requirement {requirement_id} semantic_sha256 does not match its content"
        )
    return {**logical, "semantic_sha256": semantic}


def _normalize_mapping(value: Any, control_id: str) -> dict[str, Any]:
    row = _object(
        value,
        f"control {control_id} mapping",
        {
            "framework",
            "control_id",
            "relationship",
            "non_certifying",
            "non_legal_advice",
            "notice",
        },
    )
    if row.get("non_certifying") is not True or row.get("non_legal_advice") is not True:
        raise PolicyPackValidationError(
            "every mapping must explicitly be non-certifying and non-legal"
        )
    notice = _text(row.get("notice"), "mapping notice", 512)
    if notice != MAPPING_NOTICE:
        raise PolicyPackValidationError("mapping notice must use the canonical disclaimer")
    return {
        "framework": _text(row.get("framework"), "mapping framework", 128),
        "control_id": _text(row.get("control_id"), "mapped control_id", 128),
        "relationship": _token(row.get("relationship"), "mapping relationship", 32),
        "non_certifying": True,
        "non_legal_advice": True,
        "notice": notice,
    }


def _normalize_citation(value: Any, control_id: str) -> dict[str, Any]:
    row = _object(
        value,
        f"control {control_id} citation",
        {"title", "url", "locator"},
    )
    return {
        "title": _text(row.get("title"), "citation title", 256),
        "url": _https_url(row.get("url"), "citation URL"),
        "locator": _text(row.get("locator"), "citation locator", 256),
    }


def _normalize_control(value: Any) -> dict[str, Any]:
    row = _object(
        value,
        "control",
        {
            "control_id",
            "title",
            "objective",
            "evidence_requirements",
            "mappings",
            "citations",
            "requirements_sha256",
        },
    )
    control_id = _token(row.get("control_id"), "control_id", 64)
    raw_requirements = row.get("evidence_requirements")
    if (
        not isinstance(raw_requirements, list)
        or not raw_requirements
        or len(raw_requirements) > MAX_REQUIREMENTS_PER_CONTROL
    ):
        raise PolicyPackValidationError(
            f"control {control_id} must have 1-{MAX_REQUIREMENTS_PER_CONTROL} requirements"
        )
    requirements = [_normalize_requirement(item, control_id) for item in raw_requirements]
    requirements.sort(key=lambda item: item["requirement_id"])
    requirement_ids = [item["requirement_id"] for item in requirements]
    if len(requirement_ids) != len(set(requirement_ids)):
        raise PolicyPackValidationError(f"control {control_id} has duplicate requirement ids")

    raw_mappings = row.get("mappings")
    raw_citations = row.get("citations")
    if not isinstance(raw_mappings, list) or len(raw_mappings) > 32:
        raise PolicyPackValidationError("mappings must be a list of at most 32")
    if not isinstance(raw_citations, list) or not raw_citations or len(raw_citations) > 32:
        raise PolicyPackValidationError("citations must contain 1-32 primary references")
    mappings = [_normalize_mapping(item, control_id) for item in raw_mappings]
    mappings.sort(
        key=lambda item: (
            item["framework"],
            item["control_id"],
            item["relationship"],
        )
    )
    citations = [_normalize_citation(item, control_id) for item in raw_citations]
    citations.sort(key=lambda item: (item["url"], item["locator"], item["title"]))
    requirement_digest = _digest(
        [
            {
                "requirement_id": item["requirement_id"],
                "semantic_sha256": item["semantic_sha256"],
            }
            for item in requirements
        ]
    )
    supplied = row.get("requirements_sha256")
    if supplied is not None and supplied != requirement_digest:
        raise PolicyPackValidationError(
            f"control {control_id} requirements_sha256 does not match"
        )
    return {
        "control_id": control_id,
        "title": _text(row.get("title"), "control title", 256),
        "objective": _text(row.get("objective"), "control objective", 2_000),
        "evidence_requirements": requirements,
        "mappings": mappings,
        "citations": citations,
        "requirements_sha256": requirement_digest,
    }


def _normalize_runtime_overlay(value: Any, control_ids: set[str]) -> dict[str, Any]:
    row = _object(value, "runtime_overlay", {"schema", "checks"})
    if row.get("schema") != RUNTIME_OVERLAY_SCHEMA:
        raise PolicyPackValidationError("runtime_overlay has an unsupported schema")
    raw_checks = row.get("checks")
    if not isinstance(raw_checks, list) or len(raw_checks) > 64:
        raise PolicyPackValidationError("runtime overlay checks must be a list of at most 64")
    checks: list[dict[str, Any]] = []
    for raw in raw_checks:
        check = _object(
            raw,
            "runtime overlay check",
            {"check_id", "control_id", "signal", "expected"},
        )
        control_id = _token(check.get("control_id"), "runtime control_id", 64)
        if control_id not in control_ids:
            raise PolicyPackValidationError("runtime overlay references an unknown control")
        expected = check.get("expected")
        if isinstance(expected, float) or not isinstance(expected, (str, int, bool)):
            raise PolicyPackValidationError("runtime expected value must be string/int/bool")
        if isinstance(expected, str):
            expected = _text(expected, "runtime expected value", 256, empty=True)
        checks.append(
            {
                "check_id": _token(check.get("check_id"), "runtime check_id", 64),
                "control_id": control_id,
                "signal": _token(check.get("signal"), "runtime signal", 128),
                "expected": expected,
            }
        )
    checks.sort(key=lambda item: item["check_id"])
    ids = [item["check_id"] for item in checks]
    if len(ids) != len(set(ids)):
        raise PolicyPackValidationError("runtime overlay has duplicate check ids")
    return {"schema": RUNTIME_OVERLAY_SCHEMA, "checks": checks}


def _normalize_notice(value: Any) -> dict[str, Any]:
    row = _object(
        value,
        "notice",
        {"certification", "legal_advice", "human_review_required", "text"},
    )
    if (
        row.get("certification") is not False
        or row.get("legal_advice") is not False
        or row.get("human_review_required") is not True
    ):
        raise PolicyPackValidationError(
            "notice must disclaim certification/legal advice and require human review"
        )
    return {
        "certification": False,
        "legal_advice": False,
        "human_review_required": True,
        "text": _text(row.get("text"), "notice text", 1_000),
    }


def finalize_pack(value: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a pack, calculate semantic/content digests, and enforce bounds.

    Supplied digest fields are checked, not trusted.  Lists with stable ids are
    sorted so publisher formatting and list order do not change the digest.
    """

    row = _object(
        value,
        "policy pack",
        {
            "schema",
            "pack_id",
            "version",
            "framework",
            "scope",
            "controls",
            "runtime_overlay",
            "notice",
            "content_sha256",
        },
    )
    if row.get("schema") != PACK_SCHEMA:
        raise PolicyPackValidationError("unsupported policy-pack schema")
    pack_id = _pack_id(row.get("pack_id"))
    version = _text(row.get("version"), "version", 64)
    parse_semver(version)
    framework = _object(
        row.get("framework"), "framework", {"name", "version", "as_of"}
    )
    scope = _object(row.get("scope"), "scope", {"coverage", "description"})
    raw_controls = row.get("controls")
    if not isinstance(raw_controls, list) or not raw_controls or len(raw_controls) > MAX_CONTROLS:
        raise PolicyPackValidationError(f"controls must contain 1-{MAX_CONTROLS} entries")
    controls = [_normalize_control(item) for item in raw_controls]
    controls.sort(key=lambda item: item["control_id"])
    control_ids = [item["control_id"] for item in controls]
    if len(control_ids) != len(set(control_ids)):
        raise PolicyPackValidationError("control_id values must be unique and stable")
    normalized: dict[str, Any] = {
        "schema": PACK_SCHEMA,
        "pack_id": pack_id,
        "version": version,
        "framework": {
            "name": _text(framework.get("name"), "framework name", 128),
            "version": _text(framework.get("version"), "framework version", 64),
            "as_of": _iso_date(framework.get("as_of"), "framework as_of"),
        },
        "scope": {
            "coverage": _token(scope.get("coverage"), "scope coverage", 64),
            "description": _text(scope.get("description"), "scope description", 2_000),
        },
        "controls": controls,
        "notice": _normalize_notice(row.get("notice")),
    }
    if row.get("runtime_overlay") is not None:
        normalized["runtime_overlay"] = _normalize_runtime_overlay(
            row["runtime_overlay"], set(control_ids)
        )
    content_digest = _digest(normalized)
    supplied = row.get("content_sha256")
    if supplied is not None and supplied != content_digest:
        raise PolicyPackValidationError("content_sha256 does not match canonical pack")
    normalized["content_sha256"] = content_digest
    _canonical_bytes(normalized, limit=MAX_PACK_BYTES)
    return normalized


def validate_pack(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a wire/stored pack and require every digest to be present."""

    if not isinstance(value, dict) or not isinstance(value.get("content_sha256"), str):
        raise PolicyPackValidationError("policy pack is missing content_sha256")
    controls = value.get("controls")
    if not isinstance(controls, list):
        raise PolicyPackValidationError("policy pack controls are missing")
    for control in controls:
        if not isinstance(control, dict) or not isinstance(
            control.get("requirements_sha256"), str
        ):
            raise PolicyPackValidationError("control is missing requirements_sha256")
        requirements = control.get("evidence_requirements")
        if not isinstance(requirements, list):
            raise PolicyPackValidationError("control requirements are missing")
        if any(
            not isinstance(item, dict)
            or not isinstance(item.get("semantic_sha256"), str)
            for item in requirements
        ):
            raise PolicyPackValidationError("evidence requirement is missing semantic_sha256")
    return finalize_pack(value)


def canonical_pack_bytes(value: Mapping[str, Any]) -> bytes:
    """Canonical bytes of a validated pack, including its checked digest."""

    return _canonical_bytes(validate_pack(value), limit=MAX_PACK_BYTES)


def semantic_diff(old: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic control/requirement diff for one pack id."""

    before, after = validate_pack(old), validate_pack(new)
    if before["pack_id"] != after["pack_id"]:
        raise PolicyPackValidationError("semantic diff requires the same pack_id")
    old_controls = {item["control_id"]: item for item in before["controls"]}
    new_controls = {item["control_id"]: item for item in after["controls"]}
    common = set(old_controls).intersection(new_controls)
    requirement_changed = sorted(
        control_id
        for control_id in common
        if old_controls[control_id]["requirements_sha256"]
        != new_controls[control_id]["requirements_sha256"]
    )
    unchanged = sorted(
        control_id
        for control_id in common
        if old_controls[control_id]["requirements_sha256"]
        == new_controls[control_id]["requirements_sha256"]
    )
    metadata_changed = sorted(
        control_id
        for control_id in unchanged
        if old_controls[control_id] != new_controls[control_id]
    )
    return {
        "pack_id": before["pack_id"],
        "from_version": before["version"],
        "to_version": after["version"],
        "from_content_sha256": before["content_sha256"],
        "to_content_sha256": after["content_sha256"],
        "controls_added": sorted(set(new_controls) - set(old_controls)),
        "controls_removed": sorted(set(old_controls) - set(new_controls)),
        "requirements_changed": requirement_changed,
        "requirements_unchanged": unchanged,
        "metadata_changed": metadata_changed,
    }


def _update_signed_bytes(pack: Mapping[str, Any]) -> bytes:
    normalized = validate_pack(pack)
    body = {
        "schema": UPDATE_SCHEMA,
        "content_sha256": normalized["content_sha256"],
        "pack": normalized,
    }
    return _UPDATE_DOMAIN + _canonical_bytes(body, limit=MAX_UPDATE_BYTES)


def sign_update(pack: Mapping[str, Any], *, private_key_hex: str, key_id: str) -> dict[str, Any]:
    """Publisher/test helper that signs a finalized pack with Ed25519."""

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    normalized = validate_pack(pack)
    signer = _token(key_id, "publisher key_id", 64)
    try:
        private = bytes.fromhex(private_key_hex)
        if len(private) != 32:
            raise ValueError
        signature = Ed25519PrivateKey.from_private_bytes(private).sign(
            _update_signed_bytes(normalized)
        )
    except (TypeError, ValueError) as exc:
        raise PolicyPackValidationError("private key must be 32-byte hex") from exc
    return {
        "schema": UPDATE_SCHEMA,
        "pack": normalized,
        "content_sha256": normalized["content_sha256"],
        "publisher_key_id": signer,
        "signature": signature.hex(),
    }


def verify_update(
    envelope: Mapping[str, Any], *, trusted_public_keys: Mapping[str, str]
) -> tuple[dict[str, Any], str]:
    """Fail-closed shape/digest/trust verification for a signed update."""

    row = _object(
        envelope,
        "policy-pack update",
        {"schema", "pack", "content_sha256", "publisher_key_id", "signature"},
    )
    if row.get("schema") != UPDATE_SCHEMA:
        raise PolicyPackUpdateRefused("unsupported policy-pack update schema")
    if not isinstance(trusted_public_keys, Mapping) or not trusted_public_keys:
        raise PolicyPackUpdateRefused("no trusted policy-pack publisher keys configured")
    signer = _token(row.get("publisher_key_id"), "publisher key_id", 64)
    public_hex = trusted_public_keys.get(signer)
    if not isinstance(public_hex, str) or not re.fullmatch(r"[0-9A-Fa-f]{64}", public_hex):
        raise PolicyPackUpdateRefused("policy-pack update signer is not trusted")
    signature = row.get("signature")
    if not isinstance(signature, str) or not _HEX_128.fullmatch(signature.lower()):
        raise PolicyPackUpdateRefused("policy-pack update signature is malformed or absent")
    try:
        pack = validate_pack(row.get("pack"))
    except PolicyPackValidationError as exc:
        raise PolicyPackUpdateRefused(str(exc)) from exc
    if row.get("content_sha256") != pack["content_sha256"]:
        raise PolicyPackUpdateRefused("update digest does not match the embedded pack")
    from .audit.signing import verify_ed25519

    if not verify_ed25519(public_hex.lower(), signature.lower(), _update_signed_bytes(pack)):
        raise PolicyPackUpdateRefused("policy-pack update signature is not trusted")
    return pack, signer


def _mapping(framework: str, control_id: str) -> dict[str, Any]:
    return {
        "framework": framework,
        "control_id": control_id,
        "relationship": "informative",
        "non_certifying": True,
        "non_legal_advice": True,
        "notice": MAPPING_NOTICE,
    }


def _citation(title: str, url: str, locator: str) -> dict[str, str]:
    return {"title": title, "url": url, "locator": locator}


def _requirement(
    requirement_id: str,
    evidence_kind: str,
    description: str,
    *schemas: str,
    minimum_count: int = 1,
    validity_days: int | None = None,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "evidence_kind": evidence_kind,
        "description": description,
        "minimum_count": minimum_count,
        "accepted_schemas": list(schemas),
        "validity_days": validity_days,
    }


def _notice() -> dict[str, Any]:
    return {
        "certification": False,
        "legal_advice": False,
        "human_review_required": True,
        "text": NON_CERTIFICATION_NOTICE,
    }


_NIST_SOURCE = "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"
_NIST_FRAMEWORK = "NIST AI Risk Management Framework"
_NIST_CITATION = "NIST AI 100-1, AI RMF Core"
_EU_SOURCE = "https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng"
_EU_FRAMEWORK = "Regulation (EU) 2024/1689 (Artificial Intelligence Act)"


def _starter_control(
    control_id: str,
    title: str,
    objective: str,
    requirement: dict[str, Any],
    mapping_framework: str,
    mapping_id: str,
    citation_title: str,
    citation_url: str,
    locator: str,
) -> dict[str, Any]:
    return {
        "control_id": control_id,
        "title": title,
        "objective": objective,
        "evidence_requirements": [requirement],
        "mappings": [_mapping(mapping_framework, mapping_id)],
        "citations": [_citation(citation_title, citation_url, locator)],
    }


_NIST_AI_RMF_STARTER = finalize_pack(
    {
        "schema": PACK_SCHEMA,
        "pack_id": "nist-ai-rmf-1.0-starter",
        "version": "1.0.0",
        "framework": {
            "name": "NIST Artificial Intelligence Risk Management Framework",
            "version": "1.0",
            "as_of": "2023-01-26",
        },
        "scope": {
            "coverage": "starter_subset",
            "description": (
                "A conservative evidence-oriented starter subset of AI RMF 1.0. "
                "It is not a complete profile or checklist."
            ),
        },
        "controls": [
            _starter_control(
                "NIST-AIRMF-GOVERN-1",
                "Governance policies and accountable roles",
                "Maintain reviewed AI-risk policy, ownership, and decision authority.",
                _requirement(
                    "governance-policy",
                    "policy",
                    "Approved policy identifying AI-risk roles, escalation, and review cadence.",
                    "lightwork.policy-evidence.v1",
                ),
                _NIST_FRAMEWORK,
                "GOVERN 1",
                "NIST AI RMF 1.0",
                _NIST_SOURCE,
                _NIST_CITATION,
            ),
            _starter_control(
                "NIST-AIRMF-MAP-1",
                "Context and intended purpose",
                "Document intended purpose, users, impacts, assumptions, and deployment context.",
                _requirement(
                    "context-record",
                    "model_card",
                    "Reviewed system-context record covering intended use and foreseeable misuse.",
                    "lightwork.model-card-evidence.v1",
                ),
                _NIST_FRAMEWORK,
                "MAP 1",
                "NIST AI RMF 1.0",
                _NIST_SOURCE,
                _NIST_CITATION,
            ),
            _starter_control(
                "NIST-AIRMF-MEASURE-2",
                "Independent measurement evidence",
                "Retain scoped evaluation evidence for relevant trustworthiness characteristics.",
                _requirement(
                    "evaluation-record",
                    "evaluation",
                    "Reviewed evaluation with dataset/scope, method, results, and artifact digest.",
                    "lightwork.evaluation-evidence.v1",
                    validity_days=365,
                ),
                _NIST_FRAMEWORK,
                "MEASURE 2",
                "NIST AI RMF 1.0",
                _NIST_SOURCE,
                _NIST_CITATION,
            ),
            _starter_control(
                "NIST-AIRMF-MANAGE-2",
                "Risk treatment and monitoring",
                "Track approved risk treatment, monitoring, escalation, and residual-risk decisions.",
                _requirement(
                    "risk-treatment-record",
                    "risk_decision",
                    "Human-approved risk treatment and monitoring decision with accountable owner.",
                    "lightwork.risk-decision-evidence.v1",
                ),
                _NIST_FRAMEWORK,
                "MANAGE 2",
                "NIST AI RMF 1.0",
                _NIST_SOURCE,
                _NIST_CITATION,
            ),
        ],
        "notice": _notice(),
    }
)


def _eu_control(
    suffix: str,
    article: str,
    title: str,
    objective: str,
    requirement: dict[str, Any],
) -> dict[str, Any]:
    return _starter_control(
        f"EU-AIA-{suffix}",
        title,
        objective,
        requirement,
        _EU_FRAMEWORK,
        article,
        "Consolidated Artificial Intelligence Act",
        _EU_SOURCE,
        article,
    )


_EU_AI_ACT_STARTER = finalize_pack(
    {
        "schema": PACK_SCHEMA,
        "pack_id": "eu-ai-act-2026-decision-support",
        "version": "1.0.0",
        "framework": {
            "name": "EU Artificial Intelligence Act",
            "version": "2026-07-27-consolidated",
            "as_of": "2026-07-27",
        },
        "scope": {
            "coverage": "decision_support_subset",
            "description": (
                "Evidence prompts for selected provider obligations. Applicability, actor role, "
                "high-risk classification, transition dates, and national procedure require "
                "qualified human legal review."
            ),
        },
        "controls": [
            _eu_control(
                "ART9",
                "Article 9",
                "Risk-management system",
                "Maintain lifecycle risk identification, evaluation, treatment, and testing evidence.",
                _requirement(
                    "risk-management-record",
                    "risk_assessment",
                    "Reviewed lifecycle AI-risk assessment and treatment record.",
                    "lightwork.ai-risk-assessment-evidence.v1",
                ),
            ),
            _eu_control(
                "ART10",
                "Article 10",
                "Data and data-governance evidence",
                "Document relevant data-governance practices and dataset limitations.",
                _requirement(
                    "data-governance-record",
                    "data_governance",
                    "Reviewed data provenance, quality, representativeness, and limitation record.",
                    "lightwork.data-governance-evidence.v1",
                ),
            ),
            _eu_control(
                "ART11",
                "Article 11 and Annex IV",
                "Technical documentation",
                "Retain version-bound technical documentation and supporting artifact digests.",
                _requirement(
                    "technical-documentation",
                    "technical_documentation",
                    "Reviewed technical documentation bound to the assessed AI-system version.",
                    "lightwork.ai-technical-documentation-evidence.v1",
                ),
            ),
            _eu_control(
                "ART12",
                "Article 12",
                "Record-keeping capability",
                "Document logging design, retention, integrity, and access controls.",
                _requirement(
                    "logging-control-record",
                    "logging_control",
                    "Reviewed record of automatic logging capability and governed retention.",
                    "lightwork.logging-control-evidence.v1",
                ),
            ),
            _eu_control(
                "ART13",
                "Article 13",
                "Transparency and instructions",
                "Retain reviewed instructions and information supplied to deployers.",
                _requirement(
                    "instructions-for-use",
                    "instructions",
                    "Approved instructions for use with scope, limitations, and oversight needs.",
                    "lightwork.instructions-evidence.v1",
                ),
            ),
            _eu_control(
                "ART14",
                "Article 14",
                "Human oversight",
                "Document effective human-oversight design, authority, and operational testing.",
                _requirement(
                    "human-oversight-record",
                    "human_oversight",
                    "Reviewed oversight procedure and evidence that intervention paths were tested.",
                    "lightwork.human-oversight-evidence.v1",
                ),
            ),
            _eu_control(
                "ART15",
                "Article 15",
                "Accuracy, robustness, and cybersecurity",
                "Retain scoped evaluation and adversarial-test evidence for declared performance.",
                _requirement(
                    "performance-evaluation",
                    "evaluation",
                    "Reviewed accuracy, robustness, and cybersecurity evaluation with exact artifacts.",
                    "lightwork.evaluation-evidence.v1",
                    validity_days=365,
                ),
            ),
            _eu_control(
                "ART17",
                "Article 17",
                "Quality-management system",
                "Maintain reviewed procedures, responsibilities, records, and corrective-action evidence.",
                _requirement(
                    "quality-management-record",
                    "policy",
                    "Approved AI quality-management policy and procedure set.",
                    "lightwork.policy-evidence.v1",
                ),
            ),
            _eu_control(
                "ART72",
                "Article 72",
                "Post-market monitoring",
                "Document systematic post-market monitoring and resulting corrective actions.",
                _requirement(
                    "post-market-monitoring",
                    "monitoring",
                    "Reviewed monitoring plan and evidence of periodic operation.",
                    "lightwork.monitoring-evidence.v1",
                    validity_days=365,
                ),
            ),
            _eu_control(
                "ART73",
                "Article 73",
                "Serious-incident decision support",
                "Retain human-reviewed awareness, threshold, clock, routing, and reporting decisions.",
                _requirement(
                    "serious-incident-record",
                    "incident_analysis",
                    "Reviewed serious-incident assessment with citations and authority-routing basis.",
                    "lightwork.ai-incident-assessment-evidence.v1",
                ),
            ),
        ],
        "notice": _notice(),
    }
)


_BUNDLED_MANIFESTS = {
    _NIST_AI_RMF_STARTER["pack_id"]: _NIST_AI_RMF_STARTER,
    _EU_AI_ACT_STARTER["pack_id"]: _EU_AI_ACT_STARTER,
}


def bundled_manifests() -> dict[str, dict[str, Any]]:
    """Return isolated copies of the conservative built-in starter packs."""

    return copy.deepcopy(_BUNDLED_MANIFESTS)


def bundled_summaries() -> dict[str, dict[str, Any]]:
    """Return public built-in metadata without projecting raw manifests."""

    return {
        pack_id: {
            "pack_id": pack["pack_id"],
            "version": pack["version"],
            "content_sha256": pack["content_sha256"],
            "framework": copy.deepcopy(pack["framework"]),
            "coverage": pack["scope"]["coverage"],
            "control_count": len(pack["controls"]),
            "runtime_check_count": len(
                (pack.get("runtime_overlay") or {}).get("checks") or [],
            ),
            "legal_certification": False,
        }
        for pack_id, pack in sorted(_BUNDLED_MANIFESTS.items())
    }


@dataclass(frozen=True)
class FetchResponse:
    """Injected update-transport response; redirects are handled by this module."""

    url: str
    status_code: int
    headers: Mapping[str, str]
    body: bytes


UpdateTransport = Callable[[str, int], FetchResponse]


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(_https_url(url, "update URL"))
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    return scheme, host, parsed.port or 443


def _default_transport(url: str, maximum: int) -> FetchResponse:
    from urllib.request import Request

    from .tools.http_fetch import guarded_urlopen

    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Lightwork-Policy-Pack-Updater/1.0",
        },
        method="GET",
    )
    chunks = bytearray()
    with guarded_urlopen(request, timeout=30.0) as response:
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > maximum:
                    raise PolicyPackUpdateRefused("policy-pack update is oversized")
            except ValueError:
                raise PolicyPackUpdateRefused("update Content-Length is invalid") from None
        while True:
            chunk = response.read(min(65_536, maximum + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > maximum:
                raise PolicyPackUpdateRefused("policy-pack update is oversized")
        return FetchResponse(
            url=str(response.geturl()),
            status_code=int(response.status),
            headers=dict(response.headers),
            body=bytes(chunks),
        )


def fetch_update(  # noqa: C901 - explicit redirect/size/content trust boundary
    url: str,
    *,
    transport: UpdateTransport | None = None,
) -> dict[str, Any]:
    """Fetch one bounded JSON update over same-origin HTTPS redirects."""

    try:
        requested = _https_url(url, "update URL")
    except PolicyPackValidationError as exc:
        raise PolicyPackUpdateRefused(str(exc)) from exc
    expected_origin = _origin(requested)
    current = requested
    fetch = transport or _default_transport
    response: FetchResponse | None = None
    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = fetch(current, MAX_UPDATE_BYTES)
        except PolicyPackUpdateRefused:
            raise
        except Exception as exc:
            raise PolicyPackUpdateRefused(
                f"policy-pack update fetch failed: {type(exc).__name__}: {exc}"
            ) from exc
        if not isinstance(response, FetchResponse):
            raise PolicyPackUpdateRefused("update transport returned an invalid response")
        if _origin(response.url) != expected_origin:
            raise PolicyPackUpdateRefused("off-host policy-pack update response refused")
        headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > MAX_UPDATE_BYTES:
                    raise PolicyPackUpdateRefused("policy-pack update is oversized")
            except ValueError:
                raise PolicyPackUpdateRefused("update Content-Length is invalid") from None
        if not isinstance(response.body, bytes) or len(response.body) > MAX_UPDATE_BYTES:
            raise PolicyPackUpdateRefused("policy-pack update is oversized or not bytes")
        if response.status_code in {301, 302, 303, 307, 308}:
            location = headers.get("location")
            if not location:
                raise PolicyPackUpdateRefused("update redirect has no Location")
            redirected = urljoin(current, location)
            if _origin(redirected) != expected_origin:
                raise PolicyPackUpdateRefused("off-host policy-pack redirect refused")
            current = _https_url(redirected, "redirect URL")
            continue
        if response.status_code != 200:
            raise PolicyPackUpdateRefused(
                f"policy-pack update channel returned HTTP {response.status_code}"
            )
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type and content_type != "application/json" and not content_type.endswith(
            "+json"
        ):
            raise PolicyPackUpdateRefused("policy-pack update is not JSON content")
        try:
            text = response.body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyPackUpdateRefused("policy-pack update is not valid UTF-8") from exc

        def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise PolicyPackUpdateRefused(
                        f"policy-pack update contains duplicate key {key!r}"
                    )
                result[key] = value
            return result

        try:
            decoded = json.loads(text, object_pairs_hook=no_duplicates)
        except PolicyPackUpdateRefused:
            raise
        except json.JSONDecodeError as exc:
            raise PolicyPackUpdateRefused("policy-pack update is not valid JSON") from exc
        if not isinstance(decoded, dict):
            raise PolicyPackUpdateRefused("policy-pack update must be a JSON object")
        return decoded
    raise PolicyPackUpdateRefused("too many policy-pack update redirects")


def _record_id(prefix: str, identity: str) -> str:
    return f"{prefix}-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:56]}"


def _actor(value: Any) -> str:
    return _text(value, "actor", 256)


def _expected_revision(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PolicyPackValidationError("expected_revision must be a non-negative integer")
    return value


def _read_limit(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_READ_LIMIT
    ):
        raise PolicyPackValidationError(
            f"read limit must be between 1 and {MAX_READ_LIMIT}"
        )
    return value


def _read_page(items: list[dict[str, Any]], *, limit: int) -> dict[str, Any]:
    truncated = len(items) > limit
    selected = items[:limit]
    return {
        "items": selected,
        "count": len(selected),
        "truncated": truncated,
        "limit": limit,
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _iso_instant(value: Any, label: str) -> float:
    clean = _text(value, label, 64)
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyPackValidationError(f"{label} must be an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise PolicyPackValidationError(f"{label} must include a timezone")
    return parsed.timestamp()


def _catalog_entry_id(pack_id: str, version: str) -> str:
    return _record_id("ppk", f"{pack_id}\x00{version}")


def _channel_id(pack_id: str) -> str:
    return _record_id("ppc", pack_id)


def subscription_id(pack_id: str) -> str:
    """Stable tenant-local subscription id for one pack family."""

    return _record_id("pps", _pack_id(pack_id))


def _catalog_store() -> GovernedRecordStore:
    return GovernedRecordStore(
        "policy_pack_catalog",
        "ppk",
        "policy_pack_catalog_entry",
        authority_scope="deployment_global",
    )


def _channel_store() -> GovernedRecordStore:
    return GovernedRecordStore(
        "policy_pack_channels",
        "ppc",
        "policy_pack_active_channel",
        authority_scope="deployment_global",
    )


def _subscription_store() -> GovernedRecordStore:
    return GovernedRecordStore(
        "policy_pack_subscriptions",
        "pps",
        "policy_pack_subscription",
    )


def _attestation_store() -> GovernedRecordStore:
    return GovernedRecordStore(
        "policy_pack_attestations",
        "ppa",
        "policy_pack_attestation",
    )


def _validate_catalog_entry(record: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(record, dict) or record.get("schema") != CATALOG_SCHEMA:
        raise PolicyPackStateError("policy-pack catalog entry is malformed")
    try:
        pack = validate_pack(record.get("pack"))
    except PolicyPackValidationError as exc:
        raise PolicyPackStateError(f"stored policy pack is invalid: {exc}") from exc
    expected_id = _catalog_entry_id(pack["pack_id"], pack["version"])
    if (
        record.get("id") != expected_id
        or record.get("pack_id") != pack["pack_id"]
        or record.get("pack_version") != pack["version"]
        or record.get("content_sha256") != pack["content_sha256"]
    ):
        raise PolicyPackStateError("catalog entry identity does not match its pack")
    provenance = record.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("kind") not in {
        "bundled",
        "signed_update",
    }:
        raise PolicyPackStateError("catalog entry provenance is invalid")
    if provenance["kind"] == "signed_update":
        signature = provenance.get("signature")
        if (
            not isinstance(signature, str)
            or not _HEX_128.fullmatch(signature.lower())
            or not isinstance(provenance.get("publisher_key_id"), str)
        ):
            raise PolicyPackStateError("catalog signature provenance is malformed")
    return record, pack


def _validate_channel(
    record: Any,
    *,
    catalog: GovernedRecordStore,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not isinstance(record, dict) or record.get("schema") != CHANNEL_SCHEMA:
        raise PolicyPackStateError("active policy-pack channel is malformed")
    pack_id = record.get("pack_id")
    if not isinstance(pack_id, str) or record.get("id") != _channel_id(pack_id):
        raise PolicyPackStateError("active policy-pack channel identity is invalid")
    entry_id = record.get("catalog_entry_id")
    if not isinstance(entry_id, str):
        raise PolicyPackStateError("active policy-pack channel has no catalog entry")
    entry = catalog.get(entry_id)
    if entry is None:
        raise PolicyPackStateError("active policy-pack catalog entry is missing")
    entry, pack = _validate_catalog_entry(entry)
    if (
        pack["pack_id"] != pack_id
        or record.get("pack_version") != pack["version"]
        or record.get("content_sha256") != pack["content_sha256"]
    ):
        raise PolicyPackStateError("active channel does not match its immutable catalog entry")
    return record, entry, pack


def _requirement_states(pack: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        control["control_id"]: {
            "requirements_sha256": control["requirements_sha256"],
            "status": "missing",
            "attestation_id": None,
            "previous_requirements_sha256": None,
            "stale_reason": None,
        }
        for control in pack["controls"]
    }


def _validate_requirement_state(control_id: str, value: Any) -> dict[str, Any]:
    row = _object(
        value,
        f"subscription requirement {control_id}",
        {
            "requirements_sha256",
            "status",
            "attestation_id",
            "previous_requirements_sha256",
            "stale_reason",
        },
    )
    digest = row.get("requirements_sha256")
    if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
        raise PolicyPackStateError("subscription requirement digest is invalid")
    status = row.get("status")
    if status not in {"missing", "current", "stale"}:
        raise PolicyPackStateError("subscription requirement status is invalid")
    attestation_id = row.get("attestation_id")
    if attestation_id is not None and (
        not isinstance(attestation_id, str) or not attestation_id.startswith("ppa-")
    ):
        raise PolicyPackStateError("subscription attestation link is invalid")
    if status == "current" and attestation_id is None:
        raise PolicyPackStateError("current requirement has no attestation")
    if status == "missing" and attestation_id is not None:
        raise PolicyPackStateError("missing requirement cannot link an attestation")
    previous = row.get("previous_requirements_sha256")
    if previous is not None and (
        not isinstance(previous, str) or not _HEX_64.fullmatch(previous)
    ):
        raise PolicyPackStateError("previous requirement digest is invalid")
    reason = row.get("stale_reason")
    if reason is not None and (not isinstance(reason, str) or len(reason) > 512):
        raise PolicyPackStateError("stale reason is invalid")
    return row


_DIFF_LIST_FIELDS = (
    "controls_added",
    "controls_removed",
    "requirements_changed",
    "requirements_unchanged",
    "metadata_changed",
)


def _safe_diff_projection(
    value: Any,
    *,
    pack_id: str,
    pack_version: str,
    pack_sha256: str,
) -> dict[str, Any] | None:
    """Validate and project the last stored semantic diff without evidence links."""

    if value is None:
        return None
    try:
        row = _object(
            value,
            "subscription semantic diff",
            {
                "pack_id",
                "from_version",
                "to_version",
                "from_content_sha256",
                "to_content_sha256",
                *_DIFF_LIST_FIELDS,
            },
        )
    except PolicyPackValidationError as exc:
        # This value came from the durable subscription row, not from the
        # caller.  Treat a malformed or forward-incompatible projection as a
        # state-integrity failure so API callers cannot mistake corruption for
        # a correctable request error and continue on a weaker path.
        raise PolicyPackStateError(
            "subscription semantic diff is malformed"
        ) from exc
    if row.get("pack_id") != pack_id or row.get("to_version") != pack_version:
        raise PolicyPackStateError("subscription semantic diff identity is invalid")
    try:
        parse_semver(_text(row.get("from_version"), "diff from_version", 64))
        parse_semver(_text(row.get("to_version"), "diff to_version", 64))
    except PolicyPackValidationError as exc:
        raise PolicyPackStateError("subscription semantic diff version is invalid") from exc
    for field in ("from_content_sha256", "to_content_sha256"):
        digest = row.get(field)
        if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
            raise PolicyPackStateError("subscription semantic diff digest is invalid")
    if row["to_content_sha256"] != pack_sha256:
        raise PolicyPackStateError("subscription semantic diff target is invalid")
    projected = {
        "pack_id": pack_id,
        "from_version": row["from_version"],
        "to_version": row["to_version"],
        "from_content_sha256": row["from_content_sha256"],
        "to_content_sha256": row["to_content_sha256"],
    }
    for field in _DIFF_LIST_FIELDS:
        raw = row.get(field)
        if not isinstance(raw, list) or len(raw) > MAX_CONTROLS:
            raise PolicyPackStateError("subscription semantic diff controls are invalid")
        try:
            controls = [_token(item, f"diff {field} control_id", 64) for item in raw]
        except PolicyPackValidationError as exc:
            raise PolicyPackStateError(
                "subscription semantic diff control identity is invalid"
            ) from exc
        if controls != sorted(set(controls)):
            raise PolicyPackStateError("subscription semantic diff controls are not canonical")
        projected[field] = controls
    return projected


def _normalize_bindings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > MAX_EVIDENCE_BINDINGS:
        raise PolicyPackValidationError(
            f"evidence_bindings must contain 1-{MAX_EVIDENCE_BINDINGS} entries"
        )
    bindings: list[dict[str, Any]] = []
    for raw in value:
        row = _object(
            raw,
            "evidence binding",
            {
                "requirement_id",
                "evidence_id",
                "evidence_revision",
                "evidence_sha256",
            },
        )
        digest = row.get("evidence_sha256")
        if not isinstance(digest, str) or not _HEX_64.fullmatch(digest.lower()):
            raise PolicyPackValidationError("evidence_sha256 must be 64 lower-case hex")
        bindings.append(
            {
                "requirement_id": _token(
                    row.get("requirement_id"), "binding requirement_id", 64
                ),
                "evidence_id": _token(row.get("evidence_id"), "evidence_id", 128),
                "evidence_revision": _positive_int(
                    row.get("evidence_revision"), "evidence_revision", 2_147_483_647
                ),
                "evidence_sha256": digest.lower(),
            }
        )
    bindings.sort(
        key=lambda item: (
            item["requirement_id"],
            item["evidence_id"],
            item["evidence_revision"],
            item["evidence_sha256"],
        )
    )
    identities = [
        (
            item["requirement_id"],
            item["evidence_id"],
            item["evidence_revision"],
        )
        for item in bindings
    ]
    if len(identities) != len(set(identities)):
        raise PolicyPackValidationError("duplicate evidence binding")
    return bindings


def _attestation_logical(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": ATTESTATION_SCHEMA,
        "subscription_id": record.get("subscription_id"),
        "pack_id": record.get("pack_id"),
        "issued_pack_version": record.get("issued_pack_version"),
        "issued_pack_sha256": record.get("issued_pack_sha256"),
        "control_id": record.get("control_id"),
        "requirements_sha256": record.get("requirements_sha256"),
        "evidence_bindings": record.get("evidence_bindings"),
        "reviewer": record.get("reviewer"),
        "idempotency_key": record.get("idempotency_key"),
    }


def _validate_attestation(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or record.get("schema") != ATTESTATION_SCHEMA:
        raise PolicyPackStateError("policy-pack attestation is malformed")
    try:
        subscription = _token(record.get("subscription_id"), "subscription_id", 64)
        pack_id = _pack_id(record.get("pack_id"))
        version = _text(record.get("issued_pack_version"), "issued pack version", 64)
        parse_semver(version)
        control_id = _token(record.get("control_id"), "control_id", 64)
        bindings = _normalize_bindings(record.get("evidence_bindings"))
        reviewer = _actor(record.get("reviewer"))
        idempotency = _token(record.get("idempotency_key"), "idempotency_key", 128)
        _iso_instant(record.get("attested_at"), "attested_at")
    except PolicyPackValidationError as exc:
        raise PolicyPackStateError(f"policy-pack attestation is invalid: {exc}") from exc
    for field in ("issued_pack_sha256", "requirements_sha256", "attestation_sha256"):
        digest = record.get(field)
        if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
            raise PolicyPackStateError(f"attestation {field} is invalid")
    logical = {
        "schema": ATTESTATION_SCHEMA,
        "subscription_id": subscription,
        "pack_id": pack_id,
        "issued_pack_version": version,
        "issued_pack_sha256": record["issued_pack_sha256"],
        "control_id": control_id,
        "requirements_sha256": record["requirements_sha256"],
        "evidence_bindings": bindings,
        "reviewer": reviewer,
        "idempotency_key": idempotency,
    }
    digest = _digest(logical)
    if (
        record.get("attestation_sha256") != digest
        or record.get("id") != _record_id("ppa", digest)
    ):
        raise PolicyPackStateError("attestation digest or identity does not match")
    return record


class PolicyPackService:
    """Governed catalog, activation, subscription, and attestation authority."""

    def __init__(
        self,
        *,
        catalog: GovernedRecordStore | None = None,
        channels: GovernedRecordStore | None = None,
        subscriptions: GovernedRecordStore | None = None,
        attestations: GovernedRecordStore | None = None,
    ) -> None:
        self.catalog = catalog or _catalog_store()
        self.channels = channels or _channel_store()
        self.subscriptions = subscriptions or _subscription_store()
        self.attestations = attestations or _attestation_store()

    def _stage(
        self,
        pack: Mapping[str, Any],
        *,
        actor: str,
        provenance: Mapping[str, Any],
    ) -> dict[str, Any]:
        normalized = validate_pack(pack)
        identity = _catalog_entry_id(normalized["pack_id"], normalized["version"])
        existing = self.catalog.get(identity)
        if existing is not None:
            existing, old_pack = _validate_catalog_entry(existing)
            if old_pack["content_sha256"] != normalized["content_sha256"]:
                raise PackVersionCollision(
                    "same pack_id/version has a different canonical content digest"
                )
            return existing
        record = {
            "schema": CATALOG_SCHEMA,
            "id": identity,
            "pack_id": normalized["pack_id"],
            "pack_version": normalized["version"],
            "content_sha256": normalized["content_sha256"],
            "pack": normalized,
            "provenance": _copy_json(provenance),
            "staged_by": _actor(actor),
            "staged_at": _now_iso(),
        }
        try:
            return self.catalog.create(
                record,
                action="stage",
                actor=_actor(actor),
                max_records=MAX_CATALOG_ENTRIES,
            )
        except RecordConflict:
            concurrent = self.catalog.get(identity)
            if concurrent is None:
                raise
            concurrent, old_pack = _validate_catalog_entry(concurrent)
            if old_pack["content_sha256"] != normalized["content_sha256"]:
                raise PackVersionCollision(
                    "same pack_id/version was staged concurrently with different content"
                ) from None
            return concurrent

    def stage_signed_update(
        self,
        envelope: Mapping[str, Any],
        *,
        trusted_public_keys: Mapping[str, str],
        actor: str,
    ) -> dict[str, Any]:
        pack, signer = verify_update(
            envelope, trusted_public_keys=trusted_public_keys
        )
        return self._stage(
            pack,
            actor=actor,
            provenance={
                "kind": "signed_update",
                "publisher_key_id": signer,
                "signature": envelope["signature"],
            },
        )

    def fetch_and_stage(
        self,
        url: str,
        *,
        trusted_public_keys: Mapping[str, str],
        actor: str,
        transport: UpdateTransport | None = None,
    ) -> dict[str, Any]:
        envelope = fetch_update(url, transport=transport)
        return self.stage_signed_update(
            envelope,
            trusted_public_keys=trusted_public_keys,
            actor=actor,
        )

    def stage_bundled(self, pack_id: str, *, actor: str) -> dict[str, Any]:
        identity = _pack_id(pack_id)
        pack = _BUNDLED_MANIFESTS.get(identity)
        if pack is None:
            raise KeyError(identity)
        return self._stage(
            pack,
            actor=actor,
            provenance={"kind": "bundled", "bundle": identity},
        )

    def get_catalog_entry(self, entry_id: str) -> dict[str, Any] | None:
        record = self.catalog.get(_token(entry_id, "catalog entry id", 64))
        if record is None:
            return None
        return _validate_catalog_entry(record)[0]

    def get_catalog_summary(self, entry_id: str) -> dict[str, Any] | None:
        record = self.catalog.get(_token(entry_id, "catalog entry id", 64))
        if record is None:
            return None
        entry, pack = _validate_catalog_entry(record)
        overlay = pack.get("runtime_overlay")
        checks = overlay.get("checks", []) if isinstance(overlay, dict) else []
        return {
            "id": entry["id"],
            "pack_id": pack["pack_id"],
            "pack_version": pack["version"],
            "content_sha256": pack["content_sha256"],
            "framework": copy.deepcopy(pack["framework"]),
            "coverage": pack["scope"]["coverage"],
            "control_count": len(pack["controls"]),
            "runtime_check_count": len(checks),
            "provenance_kind": entry["provenance"]["kind"],
            "staged_by": entry.get("staged_by"),
            "staged_at": entry.get("staged_at"),
            "revision": entry.get("revision"),
        }

    def list_catalog(self, *, limit: int = 100) -> dict[str, Any]:
        """Bounded deployment-global catalog metadata, with no signature bytes.

        The extra sentinel row is validated before it is omitted.  One corrupt
        global entry therefore fails the whole page closed instead of being
        silently skipped and presented as a trustworthy catalog.
        """

        bounded = _read_limit(limit)
        views: list[dict[str, Any]] = []
        for record in self.catalog.list(limit=bounded + 1):
            entry, pack = _validate_catalog_entry(record)
            overlay = pack.get("runtime_overlay")
            checks = overlay.get("checks", []) if isinstance(overlay, dict) else []
            views.append(
                {
                    "id": entry["id"],
                    "pack_id": pack["pack_id"],
                    "pack_version": pack["version"],
                    "content_sha256": pack["content_sha256"],
                    "framework": copy.deepcopy(pack["framework"]),
                    "coverage": pack["scope"]["coverage"],
                    "control_count": len(pack["controls"]),
                    "runtime_check_count": len(checks),
                    "provenance_kind": entry["provenance"]["kind"],
                    "staged_by": entry.get("staged_by"),
                    "staged_at": entry.get("staged_at"),
                    "revision": entry.get("revision"),
                }
            )
        views.sort(key=lambda item: (item["pack_id"], item["pack_version"], item["id"]))
        return _read_page(views, limit=bounded)

    def activate(
        self,
        catalog_entry_id: str,
        *,
        actor: str,
        expected_revision: int,
        admin: bool,
    ) -> dict[str, Any]:
        """CAS-activate a staged entry. Verification/staging never calls this."""

        if admin is not True:
            raise PermissionError("policy-pack activation requires global admin authority")
        expected = _expected_revision(expected_revision)
        entry = self.catalog.get(_token(catalog_entry_id, "catalog entry id", 64))
        if entry is None:
            raise KeyError(catalog_entry_id)
        entry, pack = _validate_catalog_entry(entry)
        channel_id = _channel_id(pack["pack_id"])
        current = self.channels.get(channel_id)
        activation = {
            "catalog_entry_id": entry["id"],
            "pack_version": pack["version"],
            "content_sha256": pack["content_sha256"],
        }
        if current is None:
            if expected != 0:
                raise RecordConflict("policy-pack activation revision conflict")
            record = {
                "schema": CHANNEL_SCHEMA,
                "id": channel_id,
                "pack_id": pack["pack_id"],
                **activation,
                "previous_catalog_entry_id": None,
                "activated_by": _actor(actor),
                "activated_at": _now_iso(),
            }
            try:
                return self.channels.create(record, action="activate", actor=_actor(actor))
            except RecordConflict:
                raise RecordConflict("policy-pack activation revision conflict") from None

        current, _, current_pack = _validate_channel(current, catalog=self.catalog)
        if current.get("revision") != expected:
            raise RecordConflict("policy-pack activation revision conflict")
        if current["catalog_entry_id"] == entry["id"]:
            return current
        precedence = compare_semver(pack["version"], current_pack["version"])
        if precedence < 0:
            raise PolicyPackUpdateRefused("policy-pack activation downgrade refused")
        if precedence == 0:
            raise PackVersionCollision(
                "same active pack version has a different catalog entry"
            )

        def mutate(row: dict[str, Any]) -> None:
            if row.get("catalog_entry_id") != current["catalog_entry_id"]:
                raise RecordConflict("policy-pack activation authority changed")
            row["previous_catalog_entry_id"] = row["catalog_entry_id"]
            row.update(activation)
            row["activated_by"] = _actor(actor)
            row["activated_at"] = _now_iso()

        updated = self.channels.update(
            channel_id,
            mutate,
            expected_revision=expected,
            action="activate",
            actor=_actor(actor),
        )
        if updated is None:
            raise PolicyPackStateError("active policy-pack channel disappeared")
        return updated

    def active_pack(self, pack_id: str) -> dict[str, Any] | None:
        channel = self.channels.get(_channel_id(_pack_id(pack_id)))
        if channel is None:
            return None
        return _validate_channel(channel, catalog=self.catalog)[2]

    def get_channel_summary(self, pack_id: str) -> dict[str, Any] | None:
        channel = self.channels.get(_channel_id(_pack_id(pack_id)))
        if channel is None:
            return None
        channel, entry, pack = _validate_channel(channel, catalog=self.catalog)
        return {
            "id": channel["id"],
            "pack_id": pack["pack_id"],
            "pack_version": pack["version"],
            "content_sha256": pack["content_sha256"],
            "catalog_entry_id": entry["id"],
            "previous_catalog_entry_id": channel.get("previous_catalog_entry_id"),
            "framework": copy.deepcopy(pack["framework"]),
            "coverage": pack["scope"]["coverage"],
            "control_count": len(pack["controls"]),
            "activated_by": channel.get("activated_by"),
            "activated_at": channel.get("activated_at"),
            "revision": channel.get("revision"),
        }

    def list_channels(self, *, limit: int = 100) -> dict[str, Any]:
        """Bounded validated deployment-global active-channel projections."""

        bounded = _read_limit(limit)
        views: list[dict[str, Any]] = []
        for record in self.channels.list(limit=bounded + 1):
            channel, entry, pack = _validate_channel(record, catalog=self.catalog)
            views.append(
                {
                    "id": channel["id"],
                    "pack_id": pack["pack_id"],
                    "pack_version": pack["version"],
                    "content_sha256": pack["content_sha256"],
                    "catalog_entry_id": entry["id"],
                    "previous_catalog_entry_id": channel.get(
                        "previous_catalog_entry_id"
                    ),
                    "framework": copy.deepcopy(pack["framework"]),
                    "coverage": pack["scope"]["coverage"],
                    "control_count": len(pack["controls"]),
                    "activated_by": channel.get("activated_by"),
                    "activated_at": channel.get("activated_at"),
                    "revision": channel.get("revision"),
                }
            )
        views.sort(key=lambda item: (item["pack_id"], item["id"]))
        return _read_page(views, limit=bounded)

    def _active_triplet(
        self, pack_id: str
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        channel = self.channels.get(_channel_id(_pack_id(pack_id)))
        if channel is None:
            raise PolicyPackStateError("policy pack has no active version")
        return _validate_channel(channel, catalog=self.catalog)

    def subscribe(self, pack_id: str, *, actor: str) -> dict[str, Any]:
        _require_tenant_scope()
        _, entry, pack = self._active_triplet(pack_id)
        record = {
            "schema": SUBSCRIPTION_SCHEMA,
            "id": subscription_id(pack["pack_id"]),
            "status": "active",
            "pack_id": pack["pack_id"],
            "pack_version": pack["version"],
            "pack_sha256": pack["content_sha256"],
            "catalog_entry_id": entry["id"],
            "requirements": _requirement_states(pack),
            "retired_requirements": [],
            "last_diff": None,
            "subscribed_by": _actor(actor),
            "subscribed_at": _now_iso(),
        }
        return self.subscriptions.create(record, action="subscribe", actor=_actor(actor))

    def _validate_subscription(
        self,
        record: Any,
        *,
        require_active_channel: bool,
        validate_attestation_links: bool,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if not isinstance(record, dict) or record.get("schema") != SUBSCRIPTION_SCHEMA:
            raise PolicyPackStateError("active policy-pack subscription is malformed")
        try:
            pack_id = _pack_id(record.get("pack_id"))
            version = _text(record.get("pack_version"), "subscription pack version", 64)
            parse_semver(version)
        except PolicyPackValidationError as exc:
            raise PolicyPackStateError(f"subscription identity is invalid: {exc}") from exc
        if (
            record.get("id") != subscription_id(pack_id)
            or record.get("status") != "active"
            or not isinstance(record.get("pack_sha256"), str)
            or not _HEX_64.fullmatch(record["pack_sha256"])
        ):
            raise PolicyPackStateError("active subscription identity/status is invalid")
        entry = self.catalog.get(str(record.get("catalog_entry_id") or ""))
        if entry is None:
            raise PolicyPackStateError("subscription catalog entry is missing")
        entry, pack = _validate_catalog_entry(entry)
        if (
            pack["pack_id"] != pack_id
            or pack["version"] != version
            or pack["content_sha256"] != record["pack_sha256"]
        ):
            raise PolicyPackStateError("subscription does not match its catalog entry")
        if require_active_channel:
            _, active_entry, active = self._active_triplet(pack_id)
            if (
                active_entry["id"] != entry["id"]
                or active["content_sha256"] != pack["content_sha256"]
            ):
                raise PolicyPackStateError(
                    "subscription is stale; refresh it to the active pack before use"
                )
        requirements = record.get("requirements")
        if not isinstance(requirements, dict):
            raise PolicyPackStateError("subscription requirements are malformed")
        controls = {item["control_id"]: item for item in pack["controls"]}
        if set(requirements) != set(controls):
            raise PolicyPackStateError("subscription requirement set does not match its pack")
        for control_id, state_value in requirements.items():
            state = _validate_requirement_state(control_id, state_value)
            if state["requirements_sha256"] != controls[control_id]["requirements_sha256"]:
                raise PolicyPackStateError("subscription requirement digest does not match pack")
            if validate_attestation_links and state["status"] == "current":
                attestation = self.attestations.get(state["attestation_id"])
                if attestation is None:
                    raise PolicyPackStateError("current subscription attestation is missing")
                attestation = _validate_attestation(attestation)
                if (
                    attestation["subscription_id"] != record["id"]
                    or attestation["pack_id"] != pack_id
                    or attestation["control_id"] != control_id
                    or attestation["requirements_sha256"]
                    != state["requirements_sha256"]
                ):
                    raise PolicyPackStateError(
                        "current attestation is not bound to this requirement"
                    )
        retired = record.get("retired_requirements")
        if not isinstance(retired, list) or len(retired) > MAX_RETIRED_REQUIREMENTS:
            raise PolicyPackStateError("retired subscription requirements are malformed")
        return record, pack

    def get_subscription(self, pack_id: str) -> dict[str, Any] | None:
        _require_tenant_scope()
        record = self.subscriptions.get(subscription_id(pack_id))
        if record is None:
            return None
        return self._validate_subscription(
            record,
            require_active_channel=False,
            validate_attestation_links=True,
        )[0]

    def get_subscription_summary(self, pack_id: str) -> dict[str, Any] | None:
        _require_tenant_scope()
        record = self.subscriptions.get(subscription_id(pack_id))
        if record is None:
            return None
        record, pack = self._validate_subscription(
            record,
            require_active_channel=False,
            validate_attestation_links=True,
        )
        _, _, active_pack = self._active_triplet(pack["pack_id"])
        counts = {"current": 0, "stale": 0, "missing": 0}
        for control_id, state_value in record["requirements"].items():
            state = _validate_requirement_state(control_id, state_value)
            counts[state["status"]] += 1
        return {
            "id": record["id"],
            "pack_id": pack["pack_id"],
            "pack_version": pack["version"],
            "pack_sha256": pack["content_sha256"],
            "active_pack_version": active_pack["version"],
            "active_pack_sha256": active_pack["content_sha256"],
            "needs_refresh": pack["content_sha256"] != active_pack["content_sha256"],
            "control_count": len(pack["controls"]),
            "current_count": counts["current"],
            "stale_count": counts["stale"],
            "missing_count": counts["missing"],
            "retired_count": len(record["retired_requirements"]),
            "subscribed_by": record.get("subscribed_by"),
            "subscribed_at": record.get("subscribed_at"),
            "refreshed_by": record.get("refreshed_by"),
            "refreshed_at": record.get("refreshed_at"),
            "revision": record.get("revision"),
        }

    def get_subscription_change_detail(
        self,
        pack_id: str,
    ) -> dict[str, Any] | None:
        """Return exact change and re-attestation state without evidence identifiers."""

        _require_tenant_scope()
        record = self.subscriptions.get(subscription_id(_pack_id(pack_id)))
        if record is None:
            return None
        record, pack = self._validate_subscription(
            record,
            require_active_channel=False,
            validate_attestation_links=True,
        )

        def attestation_present(control_id: str, state: Mapping[str, Any]) -> bool:
            attestation_id = state.get("attestation_id")
            if attestation_id is None:
                return False
            attestation = self.attestations.get(str(attestation_id))
            if attestation is None:
                raise PolicyPackStateError("subscription attestation is missing")
            attestation = _validate_attestation(attestation)
            expected_requirements = (
                state.get("previous_requirements_sha256")
                if state.get("status") == "stale"
                else state.get("requirements_sha256")
            )
            if (
                attestation["subscription_id"] != record["id"]
                or attestation["pack_id"] != pack["pack_id"]
                or attestation["control_id"] != control_id
                or attestation["requirements_sha256"]
                != expected_requirements
            ):
                raise PolicyPackStateError(
                    "subscription attestation is not bound to its requirement"
                )
            return True

        controls: list[dict[str, Any]] = []
        for control_id in sorted(record["requirements"]):
            state = _validate_requirement_state(
                control_id,
                record["requirements"][control_id],
            )
            controls.append(
                {
                    "control_id": control_id,
                    "status": state["status"],
                    "requirements_sha256": state["requirements_sha256"],
                    "previous_requirements_sha256": state.get(
                        "previous_requirements_sha256"
                    ),
                    "stale_reason": state.get("stale_reason"),
                    "attestation_present": attestation_present(control_id, state),
                }
            )

        retired: list[dict[str, Any]] = []
        for value in record["retired_requirements"]:
            state = _object(
                value,
                "retired subscription requirement",
                {
                    "control_id",
                    "requirements_sha256",
                    "attestation_id",
                    "retired_by_pack_sha256",
                },
            )
            try:
                control_id = _token(
                    state.get("control_id"),
                    "retired control_id",
                    64,
                )
            except PolicyPackValidationError as exc:
                raise PolicyPackStateError(
                    "retired subscription requirement identity is invalid"
                ) from exc
            for field in ("requirements_sha256", "retired_by_pack_sha256"):
                digest = state.get(field)
                if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
                    raise PolicyPackStateError(
                        "retired subscription requirement digest is invalid"
                    )
            attestation_id = state.get("attestation_id")
            if attestation_id is not None and (
                not isinstance(attestation_id, str)
                or not attestation_id.startswith("ppa-")
            ):
                raise PolicyPackStateError(
                    "retired subscription attestation link is invalid"
                )
            retired.append(
                {
                    "control_id": control_id,
                    "requirements_sha256": state["requirements_sha256"],
                    "retired_by_pack_sha256": state["retired_by_pack_sha256"],
                    "attestation_present": attestation_present(control_id, state),
                }
            )
        retired.sort(
            key=lambda item: (
                item["control_id"],
                item["retired_by_pack_sha256"],
            )
        )
        return {
            "id": record["id"],
            "pack_id": pack["pack_id"],
            "pack_version": pack["version"],
            "pack_sha256": pack["content_sha256"],
            "revision": record["revision"],
            "last_diff": _safe_diff_projection(
                record.get("last_diff"),
                pack_id=pack["pack_id"],
                pack_version=pack["version"],
                pack_sha256=pack["content_sha256"],
            ),
            "controls": controls,
            "retired_controls": retired,
            "certification": False,
            "legal_advice": False,
        }

    def active_subscription(self, pack_id: str) -> dict[str, Any] | None:
        _require_tenant_scope()
        record = self.subscriptions.get(subscription_id(pack_id))
        if record is None:
            return None
        return self._validate_subscription(
            record,
            require_active_channel=True,
            validate_attestation_links=True,
        )[0]

    def list_subscriptions(self, *, limit: int = 100) -> dict[str, Any]:
        """Bounded tenant-local subscription status without evidence details.

        Linked current attestations are validated, but their ids, evidence ids,
        revisions, and digests are deliberately not projected into this
        dashboard-oriented list.
        """

        _require_tenant_scope()
        bounded = _read_limit(limit)
        views: list[dict[str, Any]] = []
        active_cache: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = {}
        for stored in self.subscriptions.list(limit=bounded + 1):
            record, pack = self._validate_subscription(
                stored,
                require_active_channel=False,
                validate_attestation_links=True,
            )
            active = active_cache.get(pack["pack_id"])
            if active is None:
                active = self._active_triplet(pack["pack_id"])
                active_cache[pack["pack_id"]] = active
            _, _, active_pack = active
            counts = {"current": 0, "stale": 0, "missing": 0}
            for control_id, state_value in record["requirements"].items():
                state = _validate_requirement_state(control_id, state_value)
                counts[state["status"]] += 1
            views.append(
                {
                    "id": record["id"],
                    "pack_id": pack["pack_id"],
                    "pack_version": pack["version"],
                    "pack_sha256": pack["content_sha256"],
                    "active_pack_version": active_pack["version"],
                    "active_pack_sha256": active_pack["content_sha256"],
                    "needs_refresh": (
                        pack["content_sha256"] != active_pack["content_sha256"]
                    ),
                    "control_count": len(pack["controls"]),
                    "current_count": counts["current"],
                    "stale_count": counts["stale"],
                    "missing_count": counts["missing"],
                    "retired_count": len(record["retired_requirements"]),
                    "subscribed_by": record.get("subscribed_by"),
                    "subscribed_at": record.get("subscribed_at"),
                    "refreshed_by": record.get("refreshed_by"),
                    "refreshed_at": record.get("refreshed_at"),
                    "revision": record.get("revision"),
                }
            )
        views.sort(key=lambda item: (item["pack_id"], item["id"]))
        return _read_page(views, limit=bounded)

    def subscription_changes(self, pack_id: str) -> dict[str, Any] | None:
        """The exact safe change view: what moved, and what it makes stale.

        Read-only. ``pending_diff`` is the control/requirement delta between
        the subscription's bound pack version and the currently active channel
        version; ``applied_diff`` is the delta the last refresh actually
        applied. Neither carries pack prose or evidence content — control ids,
        versions, and digests only.
        """

        _require_tenant_scope()
        record = self.subscriptions.get(subscription_id(pack_id))
        if record is None:
            return None
        record, pack = self._validate_subscription(
            record,
            require_active_channel=False,
            validate_attestation_links=True,
        )
        _, _, active_pack = self._active_triplet(pack["pack_id"])
        needs_refresh = pack["content_sha256"] != active_pack["content_sha256"]
        pending = semantic_diff(pack, active_pack) if needs_refresh else None
        requirements = {
            control_id: _validate_requirement_state(control_id, value)
            for control_id, value in record["requirements"].items()
        }
        return {
            "id": record["id"],
            "pack_id": pack["pack_id"],
            "pack_version": pack["version"],
            "pack_sha256": pack["content_sha256"],
            "active_pack_version": active_pack["version"],
            "active_pack_sha256": active_pack["content_sha256"],
            "needs_refresh": needs_refresh,
            "refresh_is_forward": compare_semver(
                active_pack["version"], pack["version"]
            ) > 0,
            "pending_diff": pending,
            "applied_diff": copy.deepcopy(record.get("last_diff")),
            "requirements": requirements,
            "retired_requirements": copy.deepcopy(
                record.get("retired_requirements") or []
            ),
            "refreshed_by": record.get("refreshed_by"),
            "refreshed_at": record.get("refreshed_at"),
            "revision": record.get("revision"),
        }

    def refresh_subscription(
        self,
        subscription_identity: str,
        *,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        _require_tenant_scope()
        expected = _expected_revision(expected_revision)
        current = self.subscriptions.get(
            _token(subscription_identity, "subscription_id", 64)
        )
        if current is None:
            raise KeyError(subscription_identity)
        current, old_pack = self._validate_subscription(
            current,
            require_active_channel=False,
            validate_attestation_links=True,
        )
        if current.get("revision") != expected:
            raise RecordConflict("policy-pack subscription revision conflict")
        _, active_entry, active_pack = self._active_triplet(current["pack_id"])
        if active_pack["content_sha256"] == old_pack["content_sha256"]:
            return current
        if compare_semver(active_pack["version"], old_pack["version"]) <= 0:
            raise PolicyPackStateError("active pack is not a forward subscription update")
        diff = semantic_diff(old_pack, active_pack)
        old_states = current["requirements"]
        new_controls = {item["control_id"]: item for item in active_pack["controls"]}
        new_states: dict[str, dict[str, Any]] = {}
        for control_id, control in new_controls.items():
            prior = old_states.get(control_id)
            if prior is None:
                new_states[control_id] = {
                    "requirements_sha256": control["requirements_sha256"],
                    "status": "missing",
                    "attestation_id": None,
                    "previous_requirements_sha256": None,
                    "stale_reason": None,
                }
                continue
            prior = _validate_requirement_state(control_id, prior)
            if prior["requirements_sha256"] == control["requirements_sha256"]:
                new_states[control_id] = copy.deepcopy(prior)
                continue
            new_states[control_id] = {
                "requirements_sha256": control["requirements_sha256"],
                "status": "stale" if prior["attestation_id"] else "missing",
                "attestation_id": prior["attestation_id"],
                "previous_requirements_sha256": prior["requirements_sha256"],
                "stale_reason": (
                    "evidence requirements changed in "
                    f"policy pack {active_pack['version']}"
                ),
            }
        retired = copy.deepcopy(current.get("retired_requirements") or [])
        for control_id in sorted(set(old_states) - set(new_controls)):
            prior = _validate_requirement_state(control_id, old_states[control_id])
            retired.append(
                {
                    "control_id": control_id,
                    "requirements_sha256": prior["requirements_sha256"],
                    "attestation_id": prior["attestation_id"],
                    "retired_by_pack_sha256": active_pack["content_sha256"],
                }
            )
        if len(retired) > MAX_RETIRED_REQUIREMENTS:
            raise PolicyPackStateError("subscription retirement history capacity reached")

        def mutate(row: dict[str, Any]) -> None:
            if row.get("pack_sha256") != current["pack_sha256"]:
                raise RecordConflict("policy-pack subscription authority changed")
            row["pack_version"] = active_pack["version"]
            row["pack_sha256"] = active_pack["content_sha256"]
            row["catalog_entry_id"] = active_entry["id"]
            row["requirements"] = new_states
            row["retired_requirements"] = retired
            row["last_diff"] = diff
            row["refreshed_by"] = _actor(actor)
            row["refreshed_at"] = _now_iso()

        updated = self.subscriptions.update(
            current["id"],
            mutate,
            expected_revision=expected,
            action="refresh",
            actor=_actor(actor),
        )
        if updated is None:
            raise PolicyPackStateError("policy-pack subscription disappeared")
        return self._validate_subscription(
            updated,
            require_active_channel=True,
            validate_attestation_links=True,
        )[0]

    @staticmethod
    def _verify_evidence(
        control: Mapping[str, Any],
        bindings: list[dict[str, Any]],
        resolver: Callable[[str], Mapping[str, Any] | None],
        *,
        now: float,
    ) -> None:
        requirements = {
            item["requirement_id"]: item for item in control["evidence_requirements"]
        }
        unknown = sorted({item["requirement_id"] for item in bindings} - set(requirements))
        if unknown:
            raise PolicyPackValidationError(
                f"evidence bindings reference unknown requirements: {', '.join(unknown)}"
            )
        by_requirement: dict[str, set[str]] = {key: set() for key in requirements}
        for binding in bindings:
            requirement = requirements[binding["requirement_id"]]
            record = resolver(binding["evidence_id"])
            if not isinstance(record, Mapping):
                raise PolicyPackValidationError(
                    f"governed evidence {binding['evidence_id']} was not found"
                )
            revision = record.get("revision")
            digest = record.get("content_sha256")
            if (
                record.get("id") != binding["evidence_id"]
                or revision != binding["evidence_revision"]
                or not isinstance(digest, str)
                or not hmac.compare_digest(digest, binding["evidence_sha256"])
            ):
                raise PolicyPackValidationError(
                    f"governed evidence {binding['evidence_id']} revision/digest mismatch"
                )
            if record.get("evidence_kind") != requirement["evidence_kind"]:
                raise PolicyPackValidationError("governed evidence kind does not satisfy requirement")
            accepted = requirement["accepted_schemas"]
            if accepted and record.get("schema") not in accepted:
                raise PolicyPackValidationError(
                    "governed evidence schema does not satisfy requirement"
                )
            validity_days = requirement["validity_days"]
            if validity_days is not None:
                observed = _iso_instant(record.get("observed_at"), "evidence observed_at")
                if observed > now + 300 or now - observed > validity_days * 86_400:
                    raise PolicyPackValidationError("governed evidence is future-dated or expired")
            by_requirement[binding["requirement_id"]].add(binding["evidence_id"])
        for requirement_id, requirement in requirements.items():
            if len(by_requirement[requirement_id]) < requirement["minimum_count"]:
                raise PolicyPackValidationError(
                    f"requirement {requirement_id} has insufficient exact evidence"
                )

    def attest_control(
        self,
        subscription_identity: str,
        control_id: str,
        *,
        evidence_bindings: list[dict[str, Any]],
        evidence_resolver: Callable[[str], Mapping[str, Any] | None],
        expected_revision: int,
        actor: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Human re-attestation bound to exact governed evidence revisions/digests."""

        _require_tenant_scope()
        if not callable(evidence_resolver):
            raise PolicyPackValidationError("evidence_resolver is required")
        expected = _expected_revision(expected_revision)
        identity = _token(subscription_identity, "subscription_id", 64)
        record = self.subscriptions.get(identity)
        if record is None:
            raise KeyError(identity)
        record, pack = self._validate_subscription(
            record,
            require_active_channel=True,
            validate_attestation_links=True,
        )
        if record.get("revision") != expected:
            raise RecordConflict("policy-pack subscription revision conflict")
        target = _token(control_id, "control_id", 64)
        control = next(
            (item for item in pack["controls"] if item["control_id"] == target),
            None,
        )
        if control is None:
            raise KeyError(target)
        bindings = _normalize_bindings(evidence_bindings)
        self._verify_evidence(
            control,
            bindings,
            evidence_resolver,
            now=float(now if now is not None else datetime.now(timezone.utc).timestamp()),
        )
        reviewer = _actor(actor)
        idempotency = _token(idempotency_key, "idempotency_key", 128)
        logical = {
            "schema": ATTESTATION_SCHEMA,
            "subscription_id": record["id"],
            "pack_id": pack["pack_id"],
            "issued_pack_version": pack["version"],
            "issued_pack_sha256": pack["content_sha256"],
            "control_id": target,
            "requirements_sha256": control["requirements_sha256"],
            "evidence_bindings": bindings,
            "reviewer": reviewer,
            "idempotency_key": idempotency,
        }
        digest = _digest(logical)
        attestation_id = _record_id("ppa", digest)
        attestation = self.attestations.get(attestation_id)
        if attestation is None:
            new_attestation = {
                **logical,
                "id": attestation_id,
                "attestation_sha256": digest,
                "attested_at": _now_iso(),
            }
            try:
                attestation = self.attestations.create(
                    new_attestation,
                    action="attest",
                    actor=reviewer,
                )
            except RecordConflict:
                attestation = self.attestations.get(attestation_id)
                if attestation is None:
                    raise
        attestation = _validate_attestation(attestation)
        if _attestation_logical(attestation) != logical:
            raise PolicyPackStateError("attestation identity collision")
        current_state = _validate_requirement_state(target, record["requirements"][target])
        if current_state["status"] == "current" and current_state["attestation_id"] == attestation_id:
            return {"attestation": attestation, "subscription": record, "idempotent": True}

        def mutate(row: dict[str, Any]) -> None:
            if row.get("pack_sha256") != record["pack_sha256"]:
                raise RecordConflict("policy-pack subscription authority changed")
            state = _validate_requirement_state(target, row["requirements"][target])
            if state["requirements_sha256"] != control["requirements_sha256"]:
                raise RecordConflict("policy-pack requirement authority changed")
            row["requirements"][target] = {
                "requirements_sha256": control["requirements_sha256"],
                "status": "current",
                "attestation_id": attestation_id,
                "previous_requirements_sha256": state.get(
                    "previous_requirements_sha256"
                ),
                "stale_reason": None,
            }

        updated = self.subscriptions.update(
            record["id"],
            mutate,
            expected_revision=expected,
            action="attest",
            actor=reviewer,
        )
        if updated is None:
            raise PolicyPackStateError("policy-pack subscription disappeared")
        updated = self._validate_subscription(
            updated,
            require_active_channel=True,
            validate_attestation_links=True,
        )[0]
        return {"attestation": attestation, "subscription": updated, "idempotent": False}


_DEFAULT = PolicyPackService()


def stage_signed_update(
    envelope: Mapping[str, Any],
    *,
    trusted_public_keys: Mapping[str, str],
    actor: str,
) -> dict[str, Any]:
    return _DEFAULT.stage_signed_update(
        envelope, trusted_public_keys=trusted_public_keys, actor=actor
    )


def stage_bundled(pack_id: str, *, actor: str) -> dict[str, Any]:
    return _DEFAULT.stage_bundled(pack_id, actor=actor)


def fetch_and_stage(
    url: str,
    *,
    trusted_public_keys: Mapping[str, str],
    actor: str,
    transport: UpdateTransport | None = None,
) -> dict[str, Any]:
    return _DEFAULT.fetch_and_stage(
        url,
        trusted_public_keys=trusted_public_keys,
        actor=actor,
        transport=transport,
    )


def activate_pack(
    catalog_entry_id: str,
    *,
    actor: str,
    expected_revision: int,
    admin: bool,
) -> dict[str, Any]:
    return _DEFAULT.activate(
        catalog_entry_id,
        actor=actor,
        expected_revision=expected_revision,
        admin=admin,
    )


def active_pack(pack_id: str) -> dict[str, Any] | None:
    return _DEFAULT.active_pack(pack_id)


def get_catalog_summary(entry_id: str) -> dict[str, Any] | None:
    return _DEFAULT.get_catalog_summary(entry_id)


def get_channel_summary(pack_id: str) -> dict[str, Any] | None:
    return _DEFAULT.get_channel_summary(pack_id)


def list_catalog(*, limit: int = 100) -> dict[str, Any]:
    return _DEFAULT.list_catalog(limit=limit)


def list_channels(*, limit: int = 100) -> dict[str, Any]:
    return _DEFAULT.list_channels(limit=limit)


def subscribe(pack_id: str, *, actor: str) -> dict[str, Any]:
    return _DEFAULT.subscribe(pack_id, actor=actor)


def get_subscription(pack_id: str) -> dict[str, Any] | None:
    return _DEFAULT.get_subscription(pack_id)


def get_subscription_summary(pack_id: str) -> dict[str, Any] | None:
    return _DEFAULT.get_subscription_summary(pack_id)


def get_subscription_change_detail(pack_id: str) -> dict[str, Any] | None:
    return _DEFAULT.get_subscription_change_detail(pack_id)


def active_subscription(pack_id: str) -> dict[str, Any] | None:
    return _DEFAULT.active_subscription(pack_id)


def list_subscriptions(*, limit: int = 100) -> dict[str, Any]:
    return _DEFAULT.list_subscriptions(limit=limit)


def subscription_changes(pack_id: str) -> dict[str, Any] | None:
    return _DEFAULT.subscription_changes(pack_id)


def refresh_subscription(
    subscription_identity: str,
    *,
    expected_revision: int,
    actor: str,
) -> dict[str, Any]:
    return _DEFAULT.refresh_subscription(
        subscription_identity,
        expected_revision=expected_revision,
        actor=actor,
    )


def attest_control(
    subscription_identity: str,
    control_id: str,
    *,
    evidence_bindings: list[dict[str, Any]],
    evidence_resolver: Callable[[str], Mapping[str, Any] | None],
    expected_revision: int,
    actor: str,
    idempotency_key: str,
    now: float | None = None,
) -> dict[str, Any]:
    return _DEFAULT.attest_control(
        subscription_identity,
        control_id,
        evidence_bindings=evidence_bindings,
        evidence_resolver=evidence_resolver,
        expected_revision=expected_revision,
        actor=actor,
        idempotency_key=idempotency_key,
        now=now,
    )


__all__ = [
    "ATTESTATION_SCHEMA",
    "CATALOG_SCHEMA",
    "CHANNEL_SCHEMA",
    "FetchResponse",
    "MAPPING_NOTICE",
    "MAX_READ_LIMIT",
    "NON_CERTIFICATION_NOTICE",
    "PACK_SCHEMA",
    "PackVersionCollision",
    "PolicyPackError",
    "PolicyPackService",
    "PolicyPackStateError",
    "PolicyPackTenantRequired",
    "PolicyPackUpdateRefused",
    "PolicyPackValidationError",
    "SUBSCRIPTION_SCHEMA",
    "UPDATE_SCHEMA",
    "activate_pack",
    "active_pack",
    "active_subscription",
    "attest_control",
    "bundled_manifests",
    "bundled_summaries",
    "canonical_pack_bytes",
    "compare_semver",
    "enabled",
    "fetch_and_stage",
    "fetch_update",
    "finalize_pack",
    "get_subscription",
    "get_subscription_change_detail",
    "get_catalog_summary",
    "get_channel_summary",
    "get_subscription_summary",
    "list_catalog",
    "list_channels",
    "list_subscriptions",
    "parse_semver",
    "refresh_subscription",
    "semantic_diff",
    "sign_update",
    "stage_bundled",
    "stage_signed_update",
    "subscribe",
    "subscription_changes",
    "subscription_id",
    "validate_pack",
    "verify_update",
]
