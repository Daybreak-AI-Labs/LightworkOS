"""Evidence-labelled specialist-model candidates and deployment estimates.

The catalog is a bakeoff input, never a runtime router. Production selection
continues to use :func:`maverick.config.get_role_model`. Catalog priority is an
engineering-planning judgment, not a benchmark result.

Upstream repositories and artifact repositories are pinned to immutable
revisions. A pinned repository is still not a qualified inference artifact:
production promotion additionally needs a content-addressed artifact manifest
captured by the training/deployment receipt.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

CATALOG_SCHEMA = "lightwork.specialist-model-catalog.v1"
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_MODELS = 256
MAX_LIST_ITEMS = 64

_ID_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{1,127}\Z")
_MODEL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@+\-]{1,255}\Z")
_REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_STATUSES = frozenset({
    "primary_bakeoff",
    "secondary_bakeoff",
    "upper_bound",
    "watchlist",
})

# These are exact serialization/quantization formats, not interchangeable
# aliases. A runtime qualified for GGUF Q4_0 is not thereby qualified for GPTQ,
# MXFP4, NVFP4, AWQ, or any other nominally four-bit format.
_FORMAT_BITS = {
    "safetensors-bf16": 16,
    "safetensors-fp16": 16,
    "safetensors-fp8": 8,
    "safetensors-gptq-int4": 4,
    "safetensors-mxfp4": 4,
    "safetensors-nvfp4": 4,
    "gguf-q4_0": 4,
    "onnx-int4": 4,
}


class SpecialistModelError(ValueError):
    """Catalog or planning input is invalid."""


def _strict_json_loads(blob: bytes) -> object:
    def reject_constant(token: str) -> object:
        raise SpecialistModelError(f"catalog contains non-standard JSON {token!r}")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise SpecialistModelError(f"catalog duplicates field {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(
            blob,
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicates,
        )
    except json.JSONDecodeError as exc:
        raise SpecialistModelError("specialist-model catalog is not valid JSON") from exc


def _required_text(value: object, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise SpecialistModelError(f"{label} must be a string")
    text = value.strip()
    if not text or len(text.encode("utf-8")) > maximum or "\x00" in text:
        raise SpecialistModelError(f"{label} must be non-empty and at most {maximum} bytes")
    return text


def _optional_digest(value: object, label: str) -> str:
    if value in (None, ""):
        return ""
    digest = _required_text(value, label, 64).lower()
    if not _SHA256_RE.fullmatch(digest):
        raise SpecialistModelError(f"{label} must be a SHA-256 hex digest")
    return digest


def _revision(value: object, label: str) -> str:
    revision = _required_text(value, label, 40).lower()
    if not _REVISION_RE.fullmatch(revision):
        raise SpecialistModelError(f"{label} must be an immutable 40-character commit")
    return revision


def _positive_number(value: object, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise SpecialistModelError(f"{label} must be a positive finite number")
    return float(value)


def _positive_int(value: object, label: str) -> int:
    number = _positive_number(value, label)
    if not number.is_integer():
        raise SpecialistModelError(f"{label} must be an integer")
    return int(number)


def _bounded_text_list(
    value: object,
    label: str,
    *,
    required: bool,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        raise SpecialistModelError(f"{label} must be a bounded list")
    if required and not value:
        raise SpecialistModelError(f"{label} must not be empty")
    return tuple(
        _required_text(item, f"{label} item", 512)
        for item in value
    )


@dataclass(frozen=True)
class ArtifactSize:
    """One exact repository format and its published aggregate size."""

    format: str
    size_gib: float
    repository_id: str
    revision: str
    source_url: str
    artifact_manifest_sha256: str = ""
    evidence: str = "official_artifact"

    @property
    def reproducibly_identified(self) -> bool:
        """Whether exact files, not only their repository, are content-bound."""
        return bool(self.artifact_manifest_sha256)


def _parse_artifacts(value: object) -> tuple[ArtifactSize, ...]:
    if not isinstance(value, list) or not value:
        raise SpecialistModelError("artifacts must be a non-empty list")
    if len(value) > MAX_LIST_ITEMS:
        raise SpecialistModelError("artifacts exceeds its size bound")
    artifacts: list[ArtifactSize] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {
            "format",
            "size_gib",
            "repository_id",
            "revision",
            "source_url",
            "artifact_manifest_sha256",
            "evidence",
        }:
            raise SpecialistModelError("artifact entry must be an exact object")
        artifact_format = _required_text(item.get("format"), "artifact format", 64)
        if artifact_format not in _FORMAT_BITS:
            raise SpecialistModelError(f"unknown artifact format {artifact_format!r}")
        repository_id = _required_text(
            item.get("repository_id"), "artifact repository_id", 256,
        )
        if not _MODEL_ID_RE.fullmatch(repository_id):
            raise SpecialistModelError("artifact repository_id is invalid")
        artifact_revision = _revision(item.get("revision"), "artifact revision")
        source_url = _required_text(item.get("source_url"), "artifact source_url", 2048)
        if not source_url.startswith("https://") or artifact_revision not in source_url:
            raise SpecialistModelError(
                "artifact source_url must use https and contain its pinned revision",
            )
        artifacts.append(ArtifactSize(
            format=artifact_format,
            size_gib=_positive_number(item.get("size_gib"), "artifact size_gib"),
            repository_id=repository_id,
            revision=artifact_revision,
            source_url=source_url,
            artifact_manifest_sha256=_optional_digest(
                item.get("artifact_manifest_sha256"),
                "artifact_manifest_sha256",
            ),
            evidence=_required_text(
                item.get("evidence", "official_artifact"),
                "artifact evidence",
                64,
            ),
        ))
    artifact_formats = [artifact.format for artifact in artifacts]
    if len(artifact_formats) != len(set(artifact_formats)):
        raise SpecialistModelError("artifact formats must be unique per candidate")
    return tuple(artifacts)


@dataclass(frozen=True)
class SpecialistModel:
    catalog_id: str
    model_id: str
    upstream_revision: str
    family: str
    architecture: str
    license_id: str
    license: str
    license_url: str
    model_card_url: str
    total_parameters_b: float
    active_parameters_b: float
    context_tokens: int
    preferred_format: str
    artifacts: tuple[ArtifactSize, ...]
    roles: tuple[str, ...]
    tool_calling: str
    structured_output: str
    fine_tuning: str
    caveats: tuple[str, ...]
    planning_priority: int
    planning_basis: str
    status: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> SpecialistModel:
        expected_fields = {
            "catalog_id",
            "model_id",
            "upstream_revision",
            "family",
            "architecture",
            "license_id",
            "license",
            "license_url",
            "model_card_url",
            "total_parameters_b",
            "active_parameters_b",
            "context_tokens",
            "preferred_format",
            "artifacts",
            "roles",
            "tool_calling",
            "structured_output",
            "fine_tuning",
            "caveats",
            "planning_priority",
            "planning_basis",
            "status",
        }
        if set(raw) != expected_fields:
            raise SpecialistModelError(
                "catalog candidate has missing or unexpected fields",
            )
        catalog_id = _required_text(raw.get("catalog_id"), "catalog_id", 128)
        if not _ID_RE.fullmatch(catalog_id):
            raise SpecialistModelError("catalog_id is not a bounded identifier")
        model_id = _required_text(raw.get("model_id"), "model_id", 256)
        if not _MODEL_ID_RE.fullmatch(model_id):
            raise SpecialistModelError("model_id is not a bounded model identifier")
        upstream_revision = _revision(raw.get("upstream_revision"), "upstream_revision")
        urls = {
            label: _required_text(raw.get(label), label, 2048)
            for label in ("license_url", "model_card_url")
        }
        if any(not value.startswith("https://") for value in urls.values()):
            raise SpecialistModelError("catalog evidence URLs must use https")
        for label, value in urls.items():
            if "/blob/main/" in value or "/tree/main" in value:
                raise SpecialistModelError(
                    f"{label} must not reference a mutable main branch",
                )
            if (
                value.startswith("https://huggingface.co/")
                and upstream_revision not in value
            ):
                raise SpecialistModelError(
                    f"{label} must contain the candidate's pinned revision",
                )

        artifacts = _parse_artifacts(raw.get("artifacts"))

        preferred = _required_text(raw.get("preferred_format"), "preferred_format", 64)
        if preferred not in _FORMAT_BITS:
            raise SpecialistModelError("preferred_format is unsupported")
        if preferred not in {artifact.format for artifact in artifacts}:
            raise SpecialistModelError("preferred_format needs an exact catalog artifact")
        priority = _positive_int(raw.get("planning_priority"), "planning_priority")
        if priority > 4:
            raise SpecialistModelError("planning_priority must be in 1..4")
        planning_basis = _required_text(raw.get("planning_basis"), "planning_basis", 128)
        if planning_basis != "engineering_judgment_not_benchmark":
            raise SpecialistModelError("planning_basis must disclose non-benchmark judgment")
        status = _required_text(raw.get("status"), "status", 64)
        if status not in _STATUSES:
            raise SpecialistModelError(f"status must be one of {sorted(_STATUSES)}")
        total = _positive_number(raw.get("total_parameters_b"), "total_parameters_b")
        active = _positive_number(raw.get("active_parameters_b"), "active_parameters_b")
        if active > total:
            raise SpecialistModelError("active parameters cannot exceed total parameters")
        role_values = _bounded_text_list(raw.get("roles"), "roles", required=True)
        if len(role_values) != len(set(role_values)):
            raise SpecialistModelError("roles must not contain duplicates")
        roles = tuple(sorted(role_values))
        caveats = _bounded_text_list(raw.get("caveats"), "caveats", required=False)
        if len(caveats) != len(set(caveats)):
            raise SpecialistModelError("caveats must not contain duplicates")
        license_id = _required_text(raw.get("license_id"), "license_id", 128)
        if not _MODEL_ID_RE.fullmatch(license_id):
            raise SpecialistModelError("license_id is not a bounded identifier")
        return cls(
            catalog_id=catalog_id,
            model_id=model_id,
            upstream_revision=upstream_revision,
            family=_required_text(raw.get("family"), "family", 128),
            architecture=_required_text(raw.get("architecture"), "architecture", 128),
            license_id=license_id,
            license=_required_text(raw.get("license"), "license", 256),
            license_url=urls["license_url"],
            model_card_url=urls["model_card_url"],
            total_parameters_b=total,
            active_parameters_b=active,
            context_tokens=_positive_int(raw.get("context_tokens"), "context_tokens"),
            preferred_format=preferred,
            artifacts=artifacts,
            roles=roles,
            tool_calling=_required_text(raw.get("tool_calling"), "tool_calling", 1000),
            structured_output=_required_text(
                raw.get("structured_output"), "structured_output", 1000,
            ),
            fine_tuning=_required_text(raw.get("fine_tuning"), "fine_tuning", 1000),
            caveats=caveats,
            planning_priority=priority,
            planning_basis=planning_basis,
            status=status,
        )


@dataclass(frozen=True)
class SpecialistCatalog:
    as_of: str
    models: tuple[SpecialistModel, ...]
    source_sha256: str
    schema: str = CATALOG_SCHEMA

    @property
    def digest(self) -> str:
        """Digest of the exact bytes parsed by :func:`load_catalog`."""
        return self.source_sha256

    def get(self, catalog_id: str) -> SpecialistModel:
        for model in self.models:
            if model.catalog_id == catalog_id:
                return model
        raise SpecialistModelError(f"unknown specialist-model candidate {catalog_id!r}")


@dataclass(frozen=True)
class DeploymentEstimate:
    catalog_id: str
    artifact_format: str
    artifact_revision: str
    artifact_manifest_sha256: str
    context_tokens: int
    concurrency: int
    weights_gib: float
    runtime_reserve_gib: float
    context_reserve_gib: float
    minimum_memory_gib: float
    available_memory_gib: float
    fits: bool
    artifact_reproducible: bool
    size_evidence: str
    warnings: tuple[str, ...]


def catalog_path() -> Path:
    return Path(__file__).with_name("specialist_models.v1.json")


def load_catalog(path: Path | None = None) -> SpecialistCatalog:
    resolved_path = path or catalog_path()
    try:
        blob = resolved_path.read_bytes()
    except OSError as exc:
        raise SpecialistModelError("specialist-model catalog is unavailable") from exc
    if len(blob) > MAX_CATALOG_BYTES:
        raise SpecialistModelError(f"catalog exceeds {MAX_CATALOG_BYTES} bytes")
    raw = _strict_json_loads(blob)
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema", "as_of", "models"}
        or raw.get("schema") != CATALOG_SCHEMA
    ):
        raise SpecialistModelError("unsupported specialist-model catalog schema")
    try:
        date.fromisoformat(_required_text(raw.get("as_of"), "as_of", 10))
    except ValueError as exc:
        raise SpecialistModelError("as_of must be an ISO calendar date") from exc
    rows = raw.get("models")
    if not isinstance(rows, list) or not rows or len(rows) > MAX_MODELS:
        raise SpecialistModelError("catalog models must be a bounded non-empty list")
    models = tuple(SpecialistModel.from_mapping(row) for row in rows)
    ids = [model.catalog_id for model in models]
    model_ids = [model.model_id for model in models]
    if len(ids) != len(set(ids)) or len(model_ids) != len(set(model_ids)):
        raise SpecialistModelError("catalog candidate/model identifiers must be unique")
    return SpecialistCatalog(
        as_of=str(raw["as_of"]),
        models=models,
        source_sha256=hashlib.sha256(blob).hexdigest(),
    )


def _artifact_for(model: SpecialistModel, artifact_format: str) -> ArtifactSize | None:
    for artifact in model.artifacts:
        if artifact.format == artifact_format:
            return artifact
    return None


def matches_catalog_artifact(
    model: SpecialistModel,
    *,
    repository_id: str,
    revision: str,
    artifact_format: str,
) -> bool:
    """Whether an exact immutable artifact tuple belongs to this candidate."""
    if not isinstance(model, SpecialistModel):
        raise SpecialistModelError("model must be a SpecialistModel")
    return any(
        artifact.format == artifact_format
        and (
            (
                repository_id == artifact.repository_id
                and revision == artifact.revision
            )
            or (
                artifact.repository_id == model.model_id
                and repository_id == model.model_id
                and revision == model.upstream_revision
            )
        )
        for artifact in model.artifacts
    )


def estimate_deployment(
    model: SpecialistModel,
    *,
    available_memory_gib: float,
    artifact_format: str | None = None,
    context_tokens: int = 16_384,
    concurrency: int = 1,
) -> DeploymentEstimate:
    """Return a conservative planning estimate, explicitly not a benchmark."""
    available = _positive_number(available_memory_gib, "available_memory_gib")
    selected_format = artifact_format or model.preferred_format
    if selected_format not in _FORMAT_BITS:
        raise SpecialistModelError(f"unsupported artifact format {selected_format!r}")
    context = _positive_int(context_tokens, "context_tokens")
    parallel = _positive_int(concurrency, "concurrency")
    if context > model.context_tokens:
        raise SpecialistModelError(
            f"{model.catalog_id} declares at most {model.context_tokens} context tokens",
        )
    artifact = _artifact_for(model, selected_format)
    if artifact is not None:
        weights = artifact.size_gib
        evidence = artifact.evidence
        artifact_revision = artifact.revision
        artifact_manifest_sha256 = artifact.artifact_manifest_sha256
    else:
        # Total parameters, not active MoE parameters, determine resident weight
        # memory unless a separately qualified offload scheme is in use.
        bits = _FORMAT_BITS[selected_format]
        weights = model.total_parameters_b * 1_000_000_000 * bits / 8 / 1024**3
        weights *= 1.12  # scales/metadata/allocator planning reserve
        evidence = "parameter_arithmetic_estimate"
        artifact_revision = ""
        artifact_manifest_sha256 = ""
    runtime_reserve = max(1.5, weights * 0.18)
    # Architecture-specific KV sizes vary. This deliberately coarse reserve
    # prevents a weight file that barely fits from being called a viable fit.
    context_reserve = max(1.0, (context / 8192) * 0.35 * parallel)
    minimum = weights + runtime_reserve + context_reserve
    warnings = [
        "planning estimate only; benchmark exact runtime, format, context, and load",
    ]
    if artifact is None:
        warnings.append("no catalog artifact exists for this exact format")
    elif not artifact.reproducibly_identified:
        warnings.append(
            "repository is revision-pinned but exact files need a signed manifest digest",
        )
    architecture = model.architecture.lower()
    if "mixture-of-experts" in architecture:
        warnings.append(
            "active MoE parameters reduce compute, not resident expert-weight memory",
        )
    elif model.active_parameters_b < model.total_parameters_b:
        warnings.append(
            "active-parameter claim is architecture-specific and does not reduce "
            "the resident-weight estimate",
        )
    if context > 32_768:
        warnings.append("long context can dominate KV-cache memory and latency")
    return DeploymentEstimate(
        catalog_id=model.catalog_id,
        artifact_format=selected_format,
        artifact_revision=artifact_revision,
        artifact_manifest_sha256=artifact_manifest_sha256,
        context_tokens=context,
        concurrency=parallel,
        weights_gib=round(weights, 3),
        runtime_reserve_gib=round(runtime_reserve, 3),
        context_reserve_gib=round(context_reserve, 3),
        minimum_memory_gib=round(minimum, 3),
        available_memory_gib=available,
        fits=minimum <= available,
        artifact_reproducible=bool(artifact_manifest_sha256),
        size_evidence=evidence,
        warnings=tuple(warnings),
    )


def candidate_matrix(
    role: str,
    *,
    available_memory_gib: float,
    context_tokens: int = 16_384,
    concurrency: int = 1,
    catalog: SpecialistCatalog | None = None,
) -> list[tuple[SpecialistModel, DeploymentEstimate]]:
    """List planning candidates; callers still qualify, choose, and configure."""
    label = _required_text(role, "role", 64)
    resolved = catalog or load_catalog()
    matrix = []
    for model in resolved.models:
        if label not in model.roles:
            continue
        try:
            estimate = estimate_deployment(
                model,
                available_memory_gib=available_memory_gib,
                context_tokens=context_tokens,
                concurrency=concurrency,
            )
        except SpecialistModelError:
            continue
        matrix.append((model, estimate))
    return sorted(
        matrix,
        key=lambda pair: (
            not pair[1].fits,
            pair[1].minimum_memory_gib,
            -pair[0].planning_priority,
            pair[0].catalog_id,
        ),
    )


__all__ = [
    "ArtifactSize",
    "CATALOG_SCHEMA",
    "DeploymentEstimate",
    "SpecialistCatalog",
    "SpecialistModel",
    "SpecialistModelError",
    "candidate_matrix",
    "catalog_path",
    "estimate_deployment",
    "load_catalog",
    "matches_catalog_artifact",
]
