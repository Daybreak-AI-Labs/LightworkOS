"""Stock, fail-closed composition for multimodal AI Evidence Analysis.

The evidence-analysis core deliberately requires deployment-owned authority
resolvers.  This module supplies a usable local/reference composition without
weakening that boundary:

* tenant configuration is parsed as an exact, bounded snapshot;
* artifact, criteria, reviewer, and adapter authorities are enrolled in an
  append-only digest-chained registry with a closed history budget;
* retention maintenance replaces expired authority chains with minimized,
  time-bounded tombstones and a constant-size rolling integrity anchor;
* raw artifacts and extracted text are never accepted by or persisted in the
  registry;
* the bounded local extraction adapter and deterministic criteria adapter are
  pinned to their exact implementation/configuration authorities; and
* the dashboard receives lazy enable/store/lifetime/readiness and maintenance
  seams.  Installation performs no store I/O.

The local adapter enrollment is a self-pinned reference authority, not an
external attestation, OCR-quality claim, legal conclusion, or provider/customer
acceptance result.  Deployments can replace these seams with independently
operated authorities while retaining the same core contract.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import math
import re
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from maverick import ai_evidence_analysis as evidence
from maverick.ai_evidence_local_parsers import (
    GovernedLocalExtractionAdapter,
    LegacyXLSConfig,
    LocalParserSandboxConfig,
    TesseractOCRConfig,
)
from maverick.file_lock import (
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

_SECTION_KEYS = frozenset(
    {
        "enable",
        "enabled_media_types",
        "max_artifact_bytes",
        "max_artifacts_per_case",
        "max_authority_records",
        "max_extracted_text_bytes",
        "retention_seconds",
        "parser_sandbox",
        "ocr",
        "legacy_xls",
    }
)
_MEDIA_BY_NAME = {
    "jpeg": evidence.MEDIA_JPEG,
    "pdf": evidence.MEDIA_PDF,
    "png": evidence.MEDIA_PNG,
    "text": evidence.MEDIA_TEXT,
    "xls": evidence.MEDIA_XLS,
    "xlsx": evidence.MEDIA_XLSX,
}
_NAME_BY_MEDIA = {value: key for key, value in _MEDIA_BY_NAME.items()}
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_REGISTRY_KINDS = frozenset({"adapter", "artifact", "criteria", "reviewer"})
_REVIEW_CAPABILITIES = frozenset({"approve", "reject", "revoke"})
_CONCLUSION_TERMS = frozenset(
    {"certified", "compliant", "conformant", "lawful", "noncompliant", "unlawful"}
)
_REGISTRY_SCHEMA_VERSION = 2
_ZERO_DIGEST = "0" * 64
_MAX_VALID_SECONDS = 366 * 24 * 60 * 60
_MAX_RETENTION_SECONDS = 10 * 366 * 24 * 60 * 60
_LOCAL_MAX_EXTRACTED_CHARACTERS = 1_000_000


class AIEvidenceAnalysisCompositionError(evidence.EvidenceAnalysisConfigError):
    """A tenant composition or enrolled authority is unavailable or invalid."""


class AIEvidenceAnalysisAuthorityConflict(AIEvidenceAnalysisCompositionError):
    """An authority enrollment CAS, identity, or immutable binding changed."""


@dataclass(frozen=True, slots=True)
class AIEvidenceAnalysisSettings:
    """Exact tenant settings admitted by the stock composition."""

    enabled_media_types: tuple[str, ...]
    max_artifact_bytes: int
    max_artifacts_per_case: int
    max_authority_records: int
    max_extracted_text_bytes: int
    retention_seconds: int
    parser_sandbox: LocalParserSandboxConfig | None
    ocr: TesseractOCRConfig | None
    legacy_xls: LegacyXLSConfig | None

    def artifact_limit(self, media_type: str) -> int:
        if media_type not in self.enabled_media_types:
            raise evidence.EvidenceAnalysisConfigError(
                "evidence media type is disabled by tenant configuration"
            )
        return min(self.max_artifact_bytes, evidence.artifact_byte_limit(media_type))


@dataclass(frozen=True, slots=True)
class AuthorityRegistryIntegrity:
    schema: str
    records: int
    live_authorities: int
    retained_expired_authorities: int
    active_artifacts: int
    tombstones: int
    compacted_records: int
    compacted_authorities: int
    purged_tombstones: int
    capacity_limit: int
    compaction_anchor_sha256: str
    terminal_sha256: str
    verification_sha256: str


@dataclass(frozen=True, slots=True)
class AuthorityCompactionResult:
    schema: str
    records_before: int
    records_after: int
    compacted_authorities: int
    compacted_records: int
    purged_tombstones: int
    tombstones_after: int
    compaction_anchor_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceMaintenanceResult:
    schema: str
    tenant_id: str
    registry_records: int
    registry_records_before: int
    live_authorities: int
    retained_expired_authorities: int
    authority_tombstones: int
    compacted_authorities: int
    compacted_authority_records: int
    purged_authority_tombstones: int
    authority_compaction_anchor_sha256: str
    analyses_before: int
    purged_analysis_ids: tuple[str, ...]
    purged_analyses: int
    purged_history_records: int
    purged_operations: int
    analyses_after: int
    integrity_verified: bool


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise AIEvidenceAnalysisCompositionError(
            "evidence authority registry material is not canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= 2 * 1024 * 1024:
        raise AIEvidenceAnalysisCompositionError(
            "evidence authority registry material exceeds its byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
        raise AIEvidenceAnalysisCompositionError(
            f"{label} must be a bounded opaque identifier"
        )
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise AIEvidenceAnalysisCompositionError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise AIEvidenceAnalysisCompositionError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise AIEvidenceAnalysisCompositionError(f"{label} is not a finite timestamp")
    return float(value)


def _table(config: Mapping[str, Any], key: str) -> Mapping[str, Any] | None:
    value = config.get(key)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise AIEvidenceAnalysisCompositionError(f"{key} must be a table")
    return value


def _nested_table(
    section: Mapping[str, Any],
    key: str,
    *,
    allowed: frozenset[str],
) -> Mapping[str, Any] | None:
    value = section.get(key)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise AIEvidenceAnalysisCompositionError(
            f"ai_evidence_analysis.{key} must be a table"
        )
    if set(value) - allowed:
        raise AIEvidenceAnalysisCompositionError(
            f"ai_evidence_analysis.{key} key is unsupported"
        )
    enabled = value.get("enable", False)
    if type(enabled) is not bool:
        raise AIEvidenceAnalysisCompositionError(
            f"ai_evidence_analysis.{key}.enable must be boolean"
        )
    return value if enabled else None


def _string(value: object, label: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not 1 <= len(value) <= maximum
        or "\x00" in value
    ):
        raise AIEvidenceAnalysisCompositionError(f"{label} is invalid")
    return value


def _parser_sandbox_settings(
    section: Mapping[str, Any],
) -> LocalParserSandboxConfig | None:
    table = _nested_table(
        section,
        "parser_sandbox",
        allowed=frozenset(
            {"enable", "mode", "launcher", "launcher_sha256", "launcher_version"}
        ),
    )
    if table is None:
        return None
    return LocalParserSandboxConfig(
        mode=_string(
            table.get("mode"),
            "ai_evidence_analysis.parser_sandbox.mode",
            maximum=32,
        ),
        launcher=_string(
            table.get("launcher"),
            "ai_evidence_analysis.parser_sandbox.launcher",
            maximum=1_024,
        ),
        launcher_sha256=_string(
            table.get("launcher_sha256"),
            "ai_evidence_analysis.parser_sandbox.launcher_sha256",
            maximum=64,
        ),
        launcher_version=_string(
            table.get("launcher_version"),
            "ai_evidence_analysis.parser_sandbox.launcher_version",
            maximum=64,
        ),
    )


def _ocr_settings(section: Mapping[str, Any]) -> TesseractOCRConfig | None:
    table = _nested_table(
        section,
        "ocr",
        allowed=frozenset(
            {
                "enable",
                "executable",
                "executable_sha256",
                "tesseract_version",
                "traineddata_path",
                "traineddata_sha256",
                "runtime_library_paths",
                "runtime_libraries_sha256",
                "pillow_version",
                "pillow_manifest_sha256",
                "timeout_seconds",
                "max_pixels",
                "max_output_bytes",
                "max_memory_bytes",
            }
        ),
    )
    if table is None:
        return None
    raw_runtime_paths = table.get("runtime_library_paths")
    if (
        isinstance(raw_runtime_paths, (str, bytes))
        or not isinstance(raw_runtime_paths, Sequence)
        or not 1 <= len(raw_runtime_paths) <= 512
        or any(
            not isinstance(path, str)
            or path != path.strip()
            or not 1 <= len(path) <= 1_024
            or "\x00" in path
            for path in raw_runtime_paths
        )
    ):
        raise AIEvidenceAnalysisCompositionError(
            "ai_evidence_analysis.ocr.runtime_library_paths is invalid"
        )
    return TesseractOCRConfig(
        executable=_string(
            table.get("executable"), "ai_evidence_analysis.ocr.executable", maximum=1_024
        ),
        executable_sha256=_string(
            table.get("executable_sha256"),
            "ai_evidence_analysis.ocr.executable_sha256",
            maximum=64,
        ),
        tesseract_version=_string(
            table.get("tesseract_version"),
            "ai_evidence_analysis.ocr.tesseract_version",
            maximum=64,
        ),
        traineddata_path=_string(
            table.get("traineddata_path"),
            "ai_evidence_analysis.ocr.traineddata_path",
            maximum=1_024,
        ),
        traineddata_sha256=_string(
            table.get("traineddata_sha256"),
            "ai_evidence_analysis.ocr.traineddata_sha256",
            maximum=64,
        ),
        runtime_library_paths=tuple(raw_runtime_paths),
        runtime_libraries_sha256=_string(
            table.get("runtime_libraries_sha256"),
            "ai_evidence_analysis.ocr.runtime_libraries_sha256",
            maximum=64,
        ),
        pillow_version=_string(
            table.get("pillow_version"),
            "ai_evidence_analysis.ocr.pillow_version",
            maximum=64,
        ),
        pillow_manifest_sha256=_string(
            table.get("pillow_manifest_sha256"),
            "ai_evidence_analysis.ocr.pillow_manifest_sha256",
            maximum=64,
        ),
        timeout_seconds=_integer(
            table.get("timeout_seconds", 30),
            "ai_evidence_analysis.ocr.timeout_seconds",
            1,
            120,
        ),
        max_pixels=_integer(
            table.get("max_pixels", 40_000_000),
            "ai_evidence_analysis.ocr.max_pixels",
            1,
            100_000_000,
        ),
        max_output_bytes=_integer(
            table.get("max_output_bytes", 1_048_576),
            "ai_evidence_analysis.ocr.max_output_bytes",
            1_024,
            10_485_760,
        ),
        max_memory_bytes=_integer(
            table.get("max_memory_bytes", 536_870_912),
            "ai_evidence_analysis.ocr.max_memory_bytes",
            67_108_864,
            2_147_483_648,
        ),
    )


def _legacy_xls_settings(section: Mapping[str, Any]) -> LegacyXLSConfig | None:
    table = _nested_table(
        section,
        "legacy_xls",
        allowed=frozenset(
            {
                "enable",
                "xlrd_version",
                "xlrd_manifest_sha256",
                "olefile_version",
                "olefile_manifest_sha256",
                "timeout_seconds",
                "max_workbook_stream_bytes",
                "max_record_bytes",
                "max_records",
                "max_sheets",
                "max_rows_per_sheet",
                "max_columns_per_sheet",
                "max_cells",
                "max_output_bytes",
                "max_memory_bytes",
            }
        ),
    )
    if table is None:
        return None
    return LegacyXLSConfig(
        xlrd_version=_string(
            table.get("xlrd_version"),
            "ai_evidence_analysis.legacy_xls.xlrd_version",
            maximum=64,
        ),
        xlrd_manifest_sha256=_string(
            table.get("xlrd_manifest_sha256"),
            "ai_evidence_analysis.legacy_xls.xlrd_manifest_sha256",
            maximum=64,
        ),
        olefile_version=_string(
            table.get("olefile_version"),
            "ai_evidence_analysis.legacy_xls.olefile_version",
            maximum=64,
        ),
        olefile_manifest_sha256=_string(
            table.get("olefile_manifest_sha256"),
            "ai_evidence_analysis.legacy_xls.olefile_manifest_sha256",
            maximum=64,
        ),
        timeout_seconds=_integer(
            table.get("timeout_seconds", 15),
            "ai_evidence_analysis.legacy_xls.timeout_seconds",
            1,
            120,
        ),
        max_workbook_stream_bytes=_integer(
            table.get("max_workbook_stream_bytes", 33_554_432),
            "ai_evidence_analysis.legacy_xls.max_workbook_stream_bytes",
            1_024,
            67_108_864,
        ),
        max_record_bytes=_integer(
            table.get("max_record_bytes", 8_388_608),
            "ai_evidence_analysis.legacy_xls.max_record_bytes",
            1_024,
            16_777_215,
        ),
        max_records=_integer(
            table.get("max_records", 500_000),
            "ai_evidence_analysis.legacy_xls.max_records",
            1,
            1_000_000,
        ),
        max_sheets=_integer(
            table.get("max_sheets", 200),
            "ai_evidence_analysis.legacy_xls.max_sheets",
            1,
            256,
        ),
        max_rows_per_sheet=_integer(
            table.get("max_rows_per_sheet", 200_000),
            "ai_evidence_analysis.legacy_xls.max_rows_per_sheet",
            1,
            1_048_576,
        ),
        max_columns_per_sheet=_integer(
            table.get("max_columns_per_sheet", 256),
            "ai_evidence_analysis.legacy_xls.max_columns_per_sheet",
            1,
            256,
        ),
        max_cells=_integer(
            table.get("max_cells", 200_000),
            "ai_evidence_analysis.legacy_xls.max_cells",
            1,
            1_000_000,
        ),
        max_output_bytes=_integer(
            table.get("max_output_bytes", 1_048_576),
            "ai_evidence_analysis.legacy_xls.max_output_bytes",
            1_024,
            10_485_760,
        ),
        max_memory_bytes=_integer(
            table.get("max_memory_bytes", 536_870_912),
            "ai_evidence_analysis.legacy_xls.max_memory_bytes",
            67_108_864,
            2_147_483_648,
        ),
    )


def ai_evidence_analysis_settings(
    config: object,
) -> AIEvidenceAnalysisSettings | None:
    """Parse the exact opt-in and enforce every shipped tenant limit."""

    if not isinstance(config, Mapping):
        raise AIEvidenceAnalysisCompositionError("configuration must be a table")
    section = _table(config, "ai_evidence_analysis")
    if section is None:
        return None
    unknown = set(section) - _SECTION_KEYS
    if unknown:
        raise AIEvidenceAnalysisCompositionError(
            "ai_evidence_analysis key is unsupported"
        )
    enabled = section.get("enable", False)
    if type(enabled) is not bool:
        raise AIEvidenceAnalysisCompositionError(
            "ai_evidence_analysis.enable must be boolean"
        )
    if not enabled:
        return None
    gateway = _table(config, "evidence_gateway")
    if gateway is None or gateway.get("enable") is not True:
        raise AIEvidenceAnalysisCompositionError(
            "AI evidence analysis requires evidence_gateway.enable = true"
        )
    raw_media = section.get("enabled_media_types")
    if (
        isinstance(raw_media, (str, bytes))
        or not isinstance(raw_media, Sequence)
        or not raw_media
    ):
        raise AIEvidenceAnalysisCompositionError(
            "enabled_media_types must be a non-empty closed allowlist"
        )
    names = tuple(raw_media)
    if (
        len(names) != len(set(names))
        or any(not isinstance(name, str) or name not in _MEDIA_BY_NAME for name in names)
    ):
        raise AIEvidenceAnalysisCompositionError(
            "enabled_media_types must be a unique closed allowlist"
        )
    media = tuple(sorted(_MEDIA_BY_NAME[name] for name in names))
    parser_sandbox = _parser_sandbox_settings(section)
    ocr = _ocr_settings(section)
    legacy_xls = _legacy_xls_settings(section)
    if (ocr is not None or legacy_xls is not None) and parser_sandbox is None:
        raise AIEvidenceAnalysisCompositionError(
            "enabled local parsers require ai_evidence_analysis.parser_sandbox.enable = true"
        )
    if ocr is None and legacy_xls is None and parser_sandbox is not None:
        raise AIEvidenceAnalysisCompositionError(
            "parser_sandbox cannot be enabled without a local parser worker"
        )
    if ocr is not None and not any(
        item in media for item in (evidence.MEDIA_JPEG, evidence.MEDIA_PNG)
    ):
        raise AIEvidenceAnalysisCompositionError(
            "enabled OCR requires jpeg or png in enabled_media_types"
        )
    if legacy_xls is not None and evidence.MEDIA_XLS not in media:
        raise AIEvidenceAnalysisCompositionError(
            "enabled legacy XLS parsing requires xls in enabled_media_types"
        )
    if evidence.MEDIA_XLS in media and legacy_xls is None:
        raise AIEvidenceAnalysisCompositionError(
            "xls media requires ai_evidence_analysis.legacy_xls.enable = true"
        )
    return AIEvidenceAnalysisSettings(
        enabled_media_types=media,
        max_artifact_bytes=_integer(
            section.get("max_artifact_bytes", 52_428_800),
            "ai_evidence_analysis.max_artifact_bytes",
            1_024,
            104_857_600,
        ),
        max_artifacts_per_case=_integer(
            section.get("max_artifacts_per_case", 20),
            "ai_evidence_analysis.max_artifacts_per_case",
            1,
            100,
        ),
        max_authority_records=_integer(
            section.get("max_authority_records", 100_000),
            "ai_evidence_analysis.max_authority_records",
            4,
            1_000_000,
        ),
        max_extracted_text_bytes=_integer(
            section.get("max_extracted_text_bytes", 1_048_576),
            "ai_evidence_analysis.max_extracted_text_bytes",
            1_024,
            10_485_760,
        ),
        retention_seconds=_integer(
            section.get("retention_seconds", 31_536_000),
            "ai_evidence_analysis.retention_seconds",
            3_600,
            315_360_000,
        ),
        parser_sandbox=parser_sandbox,
        ocr=ocr,
        legacy_xls=legacy_xls,
    )


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            source_errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise AIEvidenceAnalysisCompositionError(
            "AI evidence-analysis configuration is unavailable"
        ) from exc
    if source_errors or not isinstance(config, Mapping):
        raise AIEvidenceAnalysisCompositionError(
            "AI evidence-analysis configuration is unavailable"
        )
    return config


def settings_for_tenant(tenant_id: str) -> AIEvidenceAnalysisSettings:
    tenant = canonical_tenant_id(tenant_id)
    settings = ai_evidence_analysis_settings(_load_tenant_config(tenant))
    if settings is None:
        raise AIEvidenceAnalysisCompositionError("ai_evidence_analysis_disabled")
    return settings


def ai_evidence_analysis_enabled(tenant_id: str) -> bool:
    try:
        return ai_evidence_analysis_settings(_load_tenant_config(tenant_id)) is not None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def ai_evidence_analysis_status_settings(tenant_id: str) -> Mapping[str, object]:
    """Return the tenant's closed media policy without opening any store."""

    settings = settings_for_tenant(tenant_id)
    return {
        "schema": "lightwork.ai-evidence.tenant-status-settings.v1",
        "supported_media": {
            media_type: settings.artifact_limit(media_type)
            for media_type in settings.enabled_media_types
        },
        "enabled_media_names": [
            _NAME_BY_MEDIA[media_type] for media_type in settings.enabled_media_types
        ],
        "parser_sandbox_configured": settings.parser_sandbox is not None,
        "ocr_configured": settings.ocr is not None,
        "legacy_xls_configured": settings.legacy_xls is not None,
        "authority_history_capacity": settings.max_authority_records,
        "authority_retention_seconds": settings.retention_seconds,
        "store_opened": False,
        "runtime_parser_probe_performed": False,
    }


class ByteBoundedLocalExtractionAdapter(evidence.BoundedLocalExtractionAdapter):
    """Local parser that enforces the configured UTF-8 byte limit exactly."""

    def __init__(self, *, maximum_bytes: int) -> None:
        self.maximum_bytes = _integer(
            maximum_bytes,
            "max_extracted_text_bytes",
            1_024,
            10_485_760,
        )
        super().__init__(
            enable_ocr=False,
            maximum_characters=min(
                self.maximum_bytes,
                _LOCAL_MAX_EXTRACTED_CHARACTERS,
            ),
        )

    def _bounded(self, text: str) -> str:
        if len(text.encode("utf-8")) > self.maximum_bytes:
            raise evidence.EvidenceAnalysisValidationError(
                "extracted text exceeds its byte bound"
            )
        return super()._bounded(text)

    def authority(self, *, valid_until: float) -> evidence.EvidenceAdapterAuthority:
        authority = super().authority(valid_until=valid_until)
        implementation = hashlib.sha256(
            (
                inspect.getsource(evidence.BoundedLocalExtractionAdapter)
                + inspect.getsource(type(self))
            ).encode("utf-8")
        ).hexdigest()
        authority = replace(
            authority,
            implementation_sha256=implementation,
            authority_sha256=_ZERO_DIGEST,
        )
        return replace(
            authority,
            authority_sha256=evidence.adapter_authority_sha256(authority),
        )


class EvidenceAuthorityRegistry:
    """Append-only tenant registry for every server-resolved authority.

    Payloads contain authority metadata and digests only.  There is no API or
    column capable of holding artifact bytes, extracted text, prompts, or
    provider credentials.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        settings: AIEvidenceAnalysisSettings,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(settings, AIEvidenceAnalysisSettings) or not callable(clock):
            raise AIEvidenceAnalysisCompositionError(
                "evidence authority registry dependencies are unavailable"
            )
        self.path = Path(path)
        self.tenant_id = canonical_tenant_id(tenant_id)
        self.tenant_sha256 = _text_sha256(self.tenant_id)
        self.settings = settings
        self._clock = clock
        ensure_private_directory(self.path.parent)
        with cross_process_lock(self.path, strict=True):
            self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
        except BaseException:
            connection.close()
            raise
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ai_evidence_authority_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ai_evidence_authority_records(
                    tenant_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    object_key TEXT NOT NULL,
                    registry_revision INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(tenant_id,kind,object_key,registry_revision)
                );
                CREATE INDEX IF NOT EXISTS ai_evidence_authority_current_idx
                    ON ai_evidence_authority_records(
                        tenant_id,kind,object_key,registry_revision DESC
                    );
                CREATE TABLE IF NOT EXISTS ai_evidence_authority_tombstones(
                    tenant_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    object_key_sha256 TEXT NOT NULL,
                    terminal_registry_revision INTEGER NOT NULL,
                    terminal_record_sha256 TEXT NOT NULL,
                    terminal_state TEXT NOT NULL,
                    authority_valid_until REAL NOT NULL,
                    compacted_at REAL NOT NULL,
                    retained_until REAL NOT NULL,
                    record_count INTEGER NOT NULL,
                    tombstone_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,kind,object_key_sha256)
                );
                CREATE INDEX IF NOT EXISTS ai_evidence_authority_tombstone_due_idx
                    ON ai_evidence_authority_tombstones(tenant_id,retained_until);
                CREATE TRIGGER IF NOT EXISTS ai_evidence_authority_no_update
                    BEFORE UPDATE ON ai_evidence_authority_records
                    BEGIN SELECT RAISE(ABORT,'immutable evidence authority'); END;
                CREATE TRIGGER IF NOT EXISTS ai_evidence_authority_tombstone_no_update
                    BEFORE UPDATE ON ai_evidence_authority_tombstones
                    BEGIN SELECT RAISE(ABORT,'immutable evidence authority tombstone'); END;
                DROP TRIGGER IF EXISTS ai_evidence_authority_no_delete;
                CREATE TRIGGER ai_evidence_authority_no_delete
                    BEFORE DELETE ON ai_evidence_authority_records
                    WHEN COALESCE((SELECT value FROM ai_evidence_authority_meta
                        WHERE key='delete_guard'),'closed') <> 'compacting'
                    BEGIN SELECT RAISE(ABORT,'immutable evidence authority'); END;
                DROP TRIGGER IF EXISTS ai_evidence_authority_tombstone_no_delete;
                CREATE TRIGGER ai_evidence_authority_tombstone_no_delete
                    BEFORE DELETE ON ai_evidence_authority_tombstones
                    WHEN COALESCE((SELECT value FROM ai_evidence_authority_meta
                        WHERE key='delete_guard'),'closed') <> 'compacting'
                    BEGIN SELECT RAISE(ABORT,'immutable evidence authority tombstone'); END;
                """
            )
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, 1, _REGISTRY_SCHEMA_VERSION):
                raise AIEvidenceAnalysisCompositionError(
                    f"unsupported evidence authority schema version {version}"
                )
            connection.execute(f"PRAGMA user_version={_REGISTRY_SCHEMA_VERSION}")
            connection.execute(
                "INSERT OR IGNORE INTO ai_evidence_authority_meta(key,value) "
                "VALUES('tenant_sha256',?)",
                (self.tenant_sha256,),
            )
            connection.executemany(
                "INSERT OR IGNORE INTO ai_evidence_authority_meta(key,value) "
                "VALUES(?,?)",
                (
                    ("delete_guard", "closed"),
                    ("compaction_sequence", "0"),
                    ("compaction_anchor_sha256", _ZERO_DIGEST),
                    ("compacted_records", "0"),
                    ("compacted_authorities", "0"),
                    ("purged_tombstones", "0"),
                ),
            )
            binding = connection.execute(
                "SELECT value FROM ai_evidence_authority_meta WHERE key='tenant_sha256'"
            ).fetchone()
            if binding is None or binding[0] != self.tenant_sha256:
                raise AIEvidenceAnalysisCompositionError(
                    "evidence authority registry belongs to another tenant"
                )
            guard = connection.execute(
                "SELECT value FROM ai_evidence_authority_meta WHERE key='delete_guard'"
            ).fetchone()
            if guard is None or guard[0] != "closed":
                raise AIEvidenceAnalysisCompositionError(
                    "evidence authority registry maintenance guard is invalid"
                )
        ensure_private_file(self.path)

    def _now(self) -> float:
        try:
            return _timestamp(self._clock(), "clock")
        except AIEvidenceAnalysisCompositionError:
            raise
        except Exception as exc:
            raise AIEvidenceAnalysisCompositionError(
                "evidence authority registry clock is unavailable"
            ) from exc

    def _authority_expiry(self, value: object, label: str) -> float:
        now = self._now()
        expires = _timestamp(value, label)
        if not now < expires <= now + _MAX_VALID_SECONDS:
            raise AIEvidenceAnalysisCompositionError(
                f"{label} is outside its lifetime bound"
            )
        return expires

    @staticmethod
    def _row_body(row: sqlite3.Row) -> dict[str, object]:
        return {
            "tenant_id": str(row["tenant_id"]),
            "kind": str(row["kind"]),
            "object_key": str(row["object_key"]),
            "registry_revision": int(row["registry_revision"]),
            "state": str(row["state"]),
            "payload_json": str(row["payload_json"]),
            "previous_sha256": str(row["previous_sha256"]),
            "created_at": float(row["created_at"]),
        }

    def _decode(self, row: sqlite3.Row) -> Mapping[str, Any]:
        body = self._row_body(row)
        if _sha256(body) != str(row["record_sha256"]):
            raise AIEvidenceAnalysisCompositionError(
                "evidence authority registry integrity check failed"
            )
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, ValueError) as exc:
            raise AIEvidenceAnalysisCompositionError(
                "evidence authority registry payload is invalid"
            ) from exc
        if not isinstance(payload, Mapping):
            raise AIEvidenceAnalysisCompositionError(
                "evidence authority registry payload is invalid"
            )
        return payload

    def _authority_valid_until(self, row: sqlite3.Row) -> float:
        payload = self._decode(row)
        raw = payload.get("authority")
        if not isinstance(raw, Mapping):
            raise AIEvidenceAnalysisCompositionError(
                "evidence authority registry payload is invalid"
            )
        expires = _timestamp(raw.get("valid_until"), "authority valid_until")
        revoked = raw.get("revoked")
        expected_revoked = str(row["state"]) == "revoked"
        if type(revoked) is not bool or revoked is not expected_revoked:
            raise AIEvidenceAnalysisCompositionError(
                "evidence authority registry state is invalid"
            )
        return expires

    def _object_key_sha256(self, kind: str, object_key: str) -> str:
        return _text_sha256(
            "lightwork.ai-evidence.retired-authority-key.v1:"
            f"{self.tenant_sha256}:{kind}:{object_key}"
        )

    def _tombstone_row(
        self,
        kind: str,
        object_key: str,
        *,
        connection: sqlite3.Connection,
    ) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM ai_evidence_authority_tombstones "
            "WHERE tenant_id=? AND kind=? AND object_key_sha256=?",
            (
                self.tenant_id,
                kind,
                self._object_key_sha256(kind, object_key),
            ),
        ).fetchone()

    @staticmethod
    def _meta_integer(connection: sqlite3.Connection, key: str) -> int:
        row = connection.execute(
            "SELECT value FROM ai_evidence_authority_meta WHERE key=?",
            (key,),
        ).fetchone()
        try:
            value = int(row[0]) if row is not None else -1
        except (TypeError, ValueError) as exc:
            raise AIEvidenceAnalysisCompositionError(
                "evidence authority registry compaction metadata is invalid"
            ) from exc
        if value < 0:
            raise AIEvidenceAnalysisCompositionError(
                "evidence authority registry compaction metadata is invalid"
            )
        return value

    @staticmethod
    def _meta_digest(connection: sqlite3.Connection, key: str) -> str:
        row = connection.execute(
            "SELECT value FROM ai_evidence_authority_meta WHERE key=?",
            (key,),
        ).fetchone()
        try:
            return _digest(None if row is None else row[0], key)
        except AIEvidenceAnalysisCompositionError as exc:
            raise AIEvidenceAnalysisCompositionError(
                "evidence authority registry compaction metadata is invalid"
            ) from exc

    def _current_row(
        self,
        kind: str,
        object_key: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> sqlite3.Row | None:
        selected_kind = _ref(kind, "authority kind")
        if selected_kind not in _REGISTRY_KINDS:
            raise AIEvidenceAnalysisCompositionError("authority kind is unsupported")
        selected_key = _ref(object_key, "authority key")
        owns_connection = connection is None
        selected_connection = connection or self._connect()
        try:
            return selected_connection.execute(
                "SELECT * FROM ai_evidence_authority_records "
                "WHERE tenant_id=? AND kind=? AND object_key=? "
                "ORDER BY registry_revision DESC LIMIT 1",
                (self.tenant_id, selected_kind, selected_key),
            ).fetchone()
        finally:
            if owns_connection:
                selected_connection.close()

    def _append(
        self,
        *,
        kind: str,
        object_key: str,
        state: str,
        payload: Mapping[str, Any],
        expected_registry_revision: int,
        artifact_case_ref: str | None = None,
    ) -> int:
        selected_kind = _ref(kind, "authority kind")
        if selected_kind not in _REGISTRY_KINDS:
            raise AIEvidenceAnalysisCompositionError("authority kind is unsupported")
        selected_key = _ref(object_key, "authority key")
        if state not in {"active", "revoked"}:
            raise AIEvidenceAnalysisCompositionError("authority state is invalid")
        selected_case: str | None = None
        if selected_kind == "artifact" and state == "active":
            selected_case = _ref(artifact_case_ref, "case_ref")
        elif artifact_case_ref is not None:
            raise AIEvidenceAnalysisCompositionError(
                "artifact case guard is invalid for this authority"
            )
        expected = _integer(
            expected_registry_revision,
            "expected_registry_revision",
            0,
            2_147_483_647,
        )
        payload_json = _canonical(dict(payload)).decode("ascii")
        created_at = self._now()
        with (
            cross_process_lock(self.path, strict=True),
            closing(self._connect()) as connection,
            connection,
        ):
            connection.execute("BEGIN IMMEDIATE")
            current = self._current_row(
                selected_kind,
                selected_key,
                connection=connection,
            )
            if self._tombstone_row(
                selected_kind,
                selected_key,
                connection=connection,
            ) is not None:
                raise AIEvidenceAnalysisAuthorityConflict(
                    "retired evidence authority identifier cannot be reused"
                )
            current_revision = 0 if current is None else int(current["registry_revision"])
            if current_revision != expected:
                raise AIEvidenceAnalysisAuthorityConflict(
                    "evidence authority registry revision changed"
                )
            record_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_evidence_authority_records "
                    "WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchone()[0]
            )
            # Terminal revocations remain admissible at the normal history
            # ceiling so an operator can always fail closed.  Each key can add
            # at most one such record, so this reserve is itself bounded.
            if state == "active" and record_count >= self.settings.max_authority_records:
                raise AIEvidenceAnalysisAuthorityConflict(
                    "evidence authority history capacity is reached; run retention maintenance"
                )
            if selected_case is not None and self._artifact_count_for_case(
                selected_case,
                connection=connection,
                exclude_object_key=selected_key,
            ) >= self.settings.max_artifacts_per_case:
                raise AIEvidenceAnalysisAuthorityConflict(
                    "evidence case artifact limit is reached"
                )
            previous = _ZERO_DIGEST if current is None else str(current["record_sha256"])
            revision = current_revision + 1
            body = {
                "tenant_id": self.tenant_id,
                "kind": selected_kind,
                "object_key": selected_key,
                "registry_revision": revision,
                "state": state,
                "payload_json": payload_json,
                "previous_sha256": previous,
                "created_at": created_at,
            }
            connection.execute(
                "INSERT INTO ai_evidence_authority_records VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    body["tenant_id"],
                    body["kind"],
                    body["object_key"],
                    body["registry_revision"],
                    body["state"],
                    body["payload_json"],
                    body["previous_sha256"],
                    _sha256(body),
                    body["created_at"],
                ),
            )
        return revision

    def _current_payload(self, kind: str, object_key: str) -> tuple[Mapping[str, Any], int]:
        row = self._current_row(kind, object_key)
        if row is None:
            with closing(self._connect()) as connection, connection:
                retired = self._tombstone_row(kind, object_key, connection=connection)
            if retired is not None:
                raise AIEvidenceAnalysisCompositionError(
                    f"{kind} authority is retired"
                )
            raise AIEvidenceAnalysisCompositionError(
                f"{kind} authority is unavailable"
            )
        return self._decode(row), int(row["registry_revision"])

    def _artifact_count_for_case(
        self,
        case_ref: str,
        *,
        connection: sqlite3.Connection,
        exclude_object_key: str,
    ) -> int:
        selected_case = _ref(case_ref, "case_ref")
        rows = connection.execute(
            "SELECT record.* FROM ai_evidence_authority_records AS record "
            "JOIN (SELECT object_key,MAX(registry_revision) AS current_revision "
            "FROM ai_evidence_authority_records WHERE tenant_id=? AND kind='artifact' "
            "GROUP BY object_key) AS current "
            "ON record.object_key=current.object_key "
            "AND record.registry_revision=current.current_revision "
            "WHERE record.tenant_id=? AND record.kind='artifact' "
            "AND record.state='active' AND record.object_key<>?",
            (self.tenant_id, self.tenant_id, exclude_object_key),
        ).fetchall()
        count = 0
        now = self._now()
        for row in rows:
            payload = self._decode(row)
            if (
                payload.get("case_ref") == selected_case
                and self._authority_valid_until(row) > now
            ):
                count += 1
        return count

    def enroll_artifact(
        self,
        *,
        artifact_id: str,
        case_ref: str,
        media_type: str,
        content_sha256: str,
        byte_length: int,
        source_ref: str,
        source_revision: int,
        acquired_at: float,
        valid_until: float,
        expected_registry_revision: int = 0,
    ) -> tuple[evidence.EvidenceArtifactAuthority, int]:
        selected_id = _ref(artifact_id, "artifact_id")
        selected_case = _ref(case_ref, "case_ref")
        if media_type not in self.settings.enabled_media_types:
            raise AIEvidenceAnalysisCompositionError(
                "evidence media type is disabled by tenant configuration"
            )
        length = _integer(
            byte_length,
            "byte_length",
            1,
            self.settings.artifact_limit(media_type),
        )
        acquired = _timestamp(acquired_at, "acquired_at")
        expires = self._authority_expiry(valid_until, "artifact authority valid_until")
        raw = evidence.EvidenceArtifactAuthority(
            tenant_sha256=self.tenant_sha256,
            artifact_id=selected_id,
            media_type=media_type,
            content_sha256=_digest(content_sha256, "content_sha256"),
            byte_length=length,
            source_ref=_ref(source_ref, "source_ref"),
            source_revision=_integer(
                source_revision,
                "source_revision",
                1,
                2_147_483_647,
            ),
            acquired_at=acquired,
            valid_until=expires,
            revoked=False,
            authority_sha256=_ZERO_DIGEST,
        )
        authority = replace(
            raw,
            authority_sha256=evidence.artifact_authority_sha256(raw),
        )
        revision = self._append(
            kind="artifact",
            object_key=selected_id,
            state="active",
            payload={"authority": asdict(authority), "case_ref": selected_case},
            expected_registry_revision=expected_registry_revision,
            artifact_case_ref=selected_case,
        )
        return authority, revision

    def resolve_artifact(
        self,
        tenant_id: str,
        artifact_id: str,
    ) -> evidence.EvidenceArtifactAuthority:
        if canonical_tenant_id(tenant_id) != self.tenant_id:
            raise evidence.EvidenceAnalysisNotFound("artifact authority is unavailable")
        payload, _revision = self._current_payload(
            "artifact",
            _ref(artifact_id, "artifact_id"),
        )
        try:
            authority = evidence.EvidenceArtifactAuthority(**dict(payload["authority"]))
        except (KeyError, TypeError) as exc:
            raise AIEvidenceAnalysisCompositionError(
                "artifact authority registry payload is invalid"
            ) from exc
        if (
            authority.tenant_sha256 != self.tenant_sha256
            or authority.authority_sha256
            != evidence.artifact_authority_sha256(authority)
        ):
            raise AIEvidenceAnalysisCompositionError(
                "artifact authority registry payload is invalid"
            )
        return authority

    @staticmethod
    def _slug(value: object, fallback: str) -> str:
        text = re.sub(r"[^A-Za-z0-9]+", "-", str(value or "")).strip("-").lower()[:100]
        return text or fallback

    def enroll_uploaded_artifact(
        self,
        content: bytes,
        *,
        media_type: str,
        display_name: str,
        matter: str,
        received_at: float,
        valid_seconds: int,
    ) -> tuple[evidence.EvidenceArtifactAuthority, int]:
        """Register an uploaded document by fingerprint, computed here.

        The bytes are hashed and measured, then dropped: only the digest,
        size and labels enter the append-only registry. The document name
        becomes a readable reference so pickers can show it.
        """

        if not isinstance(content, (bytes, bytearray)) or not content:
            raise AIEvidenceAnalysisCompositionError("uploaded evidence is empty")
        seconds = _integer(valid_seconds, "valid_seconds", 3_600, _MAX_VALID_SECONDS - 60)
        digest = hashlib.sha256(bytes(content)).hexdigest()
        now = self._now()
        received = _timestamp(received_at, "received_at")
        return self.enroll_artifact(
            artifact_id=f"{self._slug(display_name, 'document')}.{digest[:8]}",
            case_ref=self._slug(matter, "matter"),
            media_type=media_type,
            content_sha256=digest,
            byte_length=len(content),
            source_ref="direct-upload",
            source_revision=1,
            acquired_at=min(received, now),
            valid_until=now + seconds,
            expected_registry_revision=0,
        )

    def _current_object_keys(self, kind: str, limit: int) -> list[str]:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                "SELECT object_key FROM ai_evidence_authority_records "
                "WHERE tenant_id=? AND kind=? GROUP BY object_key "
                "ORDER BY object_key LIMIT ?",
                (self.tenant_id, kind, limit),
            ).fetchall()
        return [str(row["object_key"]) for row in rows]

    def list_usable_artifacts(self, *, limit: int = 200) -> list[dict[str, object]]:
        """Current, unrevoked, unexpired artifact authorities for pickers.

        Metadata and digests only (the same material an analysis record
        already carries); each row is re-verified through ``resolve_artifact``.
        """

        bounded = _integer(limit, "limit", 1, 500)
        now = self._now()
        items: list[dict[str, object]] = []
        for key in self._current_object_keys("artifact", bounded):
            try:
                authority = self.resolve_artifact(self.tenant_id, key)
                case_ref = self.artifact_case_ref(key)
            except AIEvidenceAnalysisCompositionError:
                continue
            if authority.revoked or authority.valid_until <= now:
                continue
            items.append(
                {
                    "artifact_id": authority.artifact_id,
                    "case_ref": case_ref,
                    "media_type": authority.media_type,
                    "content_sha256": authority.content_sha256,
                    "byte_length": authority.byte_length,
                    "source_ref": authority.source_ref,
                    "source_revision": authority.source_revision,
                    "acquired_at": authority.acquired_at,
                    "valid_until": authority.valid_until,
                    "authority_sha256": authority.authority_sha256,
                    "registry_revision": self.current_registry_revision("artifact", key),
                }
            )
        return items

    def list_usable_criteria(self, *, limit: int = 200) -> list[dict[str, object]]:
        """Current, unrevoked, unexpired criteria sets for pickers."""

        bounded = _integer(limit, "limit", 1, 500)
        now = self._now()
        items: list[dict[str, object]] = []
        for key in self._current_object_keys("criteria", bounded):
            try:
                authority = self.resolve_criteria(self.tenant_id, key)
            except AIEvidenceAnalysisCompositionError:
                continue
            if authority.revoked or authority.valid_until <= now:
                continue
            items.append(
                {
                    "criteria_set_id": authority.criteria_set_id,
                    "revision": authority.revision,
                    "criterion_ids": [item.criterion_id for item in authority.criteria],
                    "valid_until": authority.valid_until,
                    "authority_sha256": authority.authority_sha256,
                    "registry_revision": self.current_registry_revision("criteria", key),
                }
            )
        return items

    def artifact_case_ref(self, artifact_id: str) -> str:
        payload, _revision = self._current_payload(
            "artifact",
            _ref(artifact_id, "artifact_id"),
        )
        return _ref(payload.get("case_ref"), "case_ref")

    def revoke_artifact(
        self,
        artifact_id: str,
        *,
        expected_registry_revision: int,
    ) -> tuple[evidence.EvidenceArtifactAuthority, int]:
        selected = _ref(artifact_id, "artifact_id")
        payload, revision = self._current_payload("artifact", selected)
        if revision != expected_registry_revision:
            raise AIEvidenceAnalysisAuthorityConflict(
                "evidence authority registry revision changed"
            )
        authority = self.resolve_artifact(self.tenant_id, selected)
        if authority.revoked:
            return authority, revision
        revoked = replace(authority, revoked=True, authority_sha256=_ZERO_DIGEST)
        revoked = replace(
            revoked,
            authority_sha256=evidence.artifact_authority_sha256(revoked),
        )
        next_revision = self._append(
            kind="artifact",
            object_key=selected,
            state="revoked",
            payload={
                "authority": asdict(revoked),
                "case_ref": _ref(payload.get("case_ref"), "case_ref"),
            },
            expected_registry_revision=revision,
        )
        return revoked, next_revision

    @staticmethod
    def _criterion(value: evidence.EvidenceCriterion) -> evidence.EvidenceCriterion:
        if type(value) is not evidence.EvidenceCriterion:
            raise AIEvidenceAnalysisCompositionError("criterion contract is invalid")
        for selected, label in (
            (value.criterion_id, "criterion_id"),
            (value.control_ref, "control_ref"),
            (value.legal_basis_ref, "legal_basis_ref"),
            (value.stakeholder_requirement_ref, "stakeholder_requirement_ref"),
            (value.expected_fact_code, "expected_fact_code"),
            (value.gap_code, "gap_code"),
            (value.remediation_code, "remediation_code"),
        ):
            _ref(selected, label)
        for selected, label in (
            (value.expected_fact_code, "expected_fact_code"),
            (value.gap_code, "gap_code"),
            (value.remediation_code, "remediation_code"),
        ):
            words = {word for word in re.split(r"[_.:-]+", selected.lower()) if word}
            if words & _CONCLUSION_TERMS:
                raise AIEvidenceAnalysisCompositionError(
                    f"{label} cannot encode a legal or compliance conclusion"
                )
        for selected, label in (
            (value.control_sha256, "control_sha256"),
            (value.legal_basis_sha256, "legal_basis_sha256"),
            (value.stakeholder_requirement_sha256, "stakeholder_requirement_sha256"),
        ):
            _digest(selected, label)
        for selected, label in (
            (value.revision, "criterion revision"),
            (value.control_revision, "control revision"),
            (value.legal_basis_revision, "legal-basis revision"),
            (
                value.stakeholder_requirement_revision,
                "stakeholder requirement revision",
            ),
        ):
            _integer(selected, label, 1, 2_147_483_647)
        _integer(value.weight_bps, "criterion weight_bps", 1, 10_000)
        raw = replace(value, criterion_sha256=_ZERO_DIGEST)
        normalized = replace(
            raw,
            criterion_sha256=evidence.criterion_sha256(raw),
        )
        if value.criterion_sha256 not in {_ZERO_DIGEST, normalized.criterion_sha256}:
            raise AIEvidenceAnalysisCompositionError("criterion digest is invalid")
        return normalized

    def enroll_criteria(
        self,
        *,
        criteria_set_id: str,
        revision: int,
        criteria: Sequence[evidence.EvidenceCriterion],
        valid_until: float,
        expected_registry_revision: int = 0,
    ) -> tuple[evidence.EvidenceCriteriaAuthority, int]:
        selected_id = _ref(criteria_set_id, "criteria_set_id")
        selected_revision = _integer(
            revision,
            "criteria revision",
            1,
            2_147_483_647,
        )
        if isinstance(criteria, (str, bytes)) or not isinstance(criteria, Sequence):
            raise AIEvidenceAnalysisCompositionError("criteria contract is invalid")
        normalized = tuple(self._criterion(item) for item in criteria)
        identifiers = tuple(item.criterion_id for item in normalized)
        if (
            not 1 <= len(normalized) <= 128
            or identifiers != tuple(sorted(identifiers))
            or len(identifiers) != len(set(identifiers))
            or sum(item.weight_bps for item in normalized) != 10_000
        ):
            raise AIEvidenceAnalysisCompositionError(
                "criteria must be unique, sorted, bounded, and total 10000 basis points"
            )
        expires = self._authority_expiry(valid_until, "criteria authority valid_until")
        current_row = self._current_row("criteria", selected_id)
        if current_row is not None:
            current = self.resolve_criteria(self.tenant_id, selected_id)
            if selected_revision <= current.revision:
                raise AIEvidenceAnalysisAuthorityConflict(
                    "criteria authority revision must increase"
                )
        raw = evidence.EvidenceCriteriaAuthority(
            tenant_sha256=self.tenant_sha256,
            criteria_set_id=selected_id,
            revision=selected_revision,
            criteria=normalized,
            valid_until=expires,
            revoked=False,
            authority_sha256=_ZERO_DIGEST,
        )
        authority = replace(
            raw,
            authority_sha256=evidence.criteria_authority_sha256(raw),
        )
        registry_revision = self._append(
            kind="criteria",
            object_key=selected_id,
            state="active",
            payload={"authority": asdict(authority)},
            expected_registry_revision=expected_registry_revision,
        )
        return authority, registry_revision

    def resolve_criteria(
        self,
        tenant_id: str,
        criteria_set_id: str,
    ) -> evidence.EvidenceCriteriaAuthority:
        if canonical_tenant_id(tenant_id) != self.tenant_id:
            raise evidence.EvidenceAnalysisNotFound("criteria authority is unavailable")
        payload, _revision = self._current_payload(
            "criteria",
            _ref(criteria_set_id, "criteria_set_id"),
        )
        try:
            raw = dict(payload["authority"])
            raw_criteria = raw["criteria"]
            if not isinstance(raw_criteria, list):
                raise TypeError("criteria must be a list")
            raw["criteria"] = tuple(
                evidence.EvidenceCriterion(**dict(item)) for item in raw_criteria
            )
            authority = evidence.EvidenceCriteriaAuthority(**raw)
        except (KeyError, TypeError) as exc:
            raise AIEvidenceAnalysisCompositionError(
                "criteria authority registry payload is invalid"
            ) from exc
        normalized = tuple(self._criterion(item) for item in authority.criteria)
        identifiers = tuple(item.criterion_id for item in normalized)
        if (
            authority.tenant_sha256 != self.tenant_sha256
            or authority.criteria != normalized
            or not normalized
            or identifiers != tuple(sorted(identifiers))
            or len(identifiers) != len(set(identifiers))
            or sum(item.weight_bps for item in normalized) != 10_000
            or authority.authority_sha256
            != evidence.criteria_authority_sha256(authority)
        ):
            raise AIEvidenceAnalysisCompositionError(
                "criteria authority registry payload is invalid"
            )
        return authority

    def revoke_criteria(
        self,
        criteria_set_id: str,
        *,
        expected_registry_revision: int,
    ) -> tuple[evidence.EvidenceCriteriaAuthority, int]:
        selected = _ref(criteria_set_id, "criteria_set_id")
        _payload, revision = self._current_payload("criteria", selected)
        if revision != expected_registry_revision:
            raise AIEvidenceAnalysisAuthorityConflict(
                "evidence authority registry revision changed"
            )
        authority = self.resolve_criteria(self.tenant_id, selected)
        if authority.revoked:
            return authority, revision
        revoked = replace(authority, revoked=True, authority_sha256=_ZERO_DIGEST)
        revoked = replace(
            revoked,
            authority_sha256=evidence.criteria_authority_sha256(revoked),
        )
        next_revision = self._append(
            kind="criteria",
            object_key=selected,
            state="revoked",
            payload={"authority": asdict(revoked)},
            expected_registry_revision=revision,
        )
        return revoked, next_revision

    def enroll_reviewer(
        self,
        *,
        reviewer_ref: str,
        capabilities: Sequence[str],
        revision: int,
        valid_until: float,
        expected_registry_revision: int = 0,
    ) -> tuple[evidence.HumanReviewAuthority, int]:
        selected_ref = _ref(reviewer_ref, "reviewer_ref")
        reviewer_key = self._reviewer_key(selected_ref)
        if isinstance(capabilities, (str, bytes)) or not isinstance(
            capabilities,
            Sequence,
        ):
            raise AIEvidenceAnalysisCompositionError(
                "reviewer capabilities are invalid"
            )
        selected_capabilities = tuple(capabilities)
        if (
            not selected_capabilities
            or selected_capabilities != tuple(sorted(selected_capabilities))
            or len(selected_capabilities) != len(set(selected_capabilities))
            or not set(selected_capabilities).issubset(_REVIEW_CAPABILITIES)
        ):
            raise AIEvidenceAnalysisCompositionError(
                "reviewer capabilities are invalid"
            )
        selected_revision = _integer(
            revision,
            "reviewer authority revision",
            1,
            2_147_483_647,
        )
        expires = self._authority_expiry(valid_until, "reviewer authority valid_until")
        current_row = self._current_row("reviewer", reviewer_key)
        if current_row is not None:
            current = self.resolve_reviewer(self.tenant_id, selected_ref)
            if selected_revision <= current.revision:
                raise AIEvidenceAnalysisAuthorityConflict(
                    "reviewer authority revision must increase"
                )
        raw = evidence.HumanReviewAuthority(
            tenant_sha256=self.tenant_sha256,
            reviewer_sha256=_text_sha256(
                f"lightwork.ai-evidence.actor.v1:{self.tenant_id}:{selected_ref}"
            ),
            capabilities=selected_capabilities,
            revision=selected_revision,
            valid_until=expires,
            revoked=False,
            authority_sha256=_ZERO_DIGEST,
        )
        authority = replace(
            raw,
            authority_sha256=evidence.review_authority_sha256(raw),
        )
        registry_revision = self._append(
            kind="reviewer",
            object_key=reviewer_key,
            state="active",
            payload={"authority": asdict(authority)},
            expected_registry_revision=expected_registry_revision,
        )
        return authority, registry_revision

    @staticmethod
    def _reviewer_key(reviewer_ref: str) -> str:
        selected = _ref(reviewer_ref, "reviewer_ref")
        return _text_sha256(f"lightwork.ai-evidence.reviewer-key.v1:{selected}")

    def resolve_reviewer(
        self,
        tenant_id: str,
        reviewer_ref: str,
    ) -> evidence.HumanReviewAuthority:
        if canonical_tenant_id(tenant_id) != self.tenant_id:
            raise evidence.EvidenceAnalysisPermissionError(
                "human review authority is unavailable"
            )
        selected = _ref(reviewer_ref, "reviewer_ref")
        payload, _revision = self._current_payload(
            "reviewer",
            self._reviewer_key(selected),
        )
        try:
            raw = dict(payload["authority"])
            raw["capabilities"] = tuple(raw["capabilities"])
            authority = evidence.HumanReviewAuthority(**raw)
        except (KeyError, TypeError) as exc:
            raise AIEvidenceAnalysisCompositionError(
                "review authority registry payload is invalid"
            ) from exc
        expected_reviewer = _text_sha256(
            f"lightwork.ai-evidence.actor.v1:{self.tenant_id}:{selected}"
        )
        if (
            authority.tenant_sha256 != self.tenant_sha256
            or authority.reviewer_sha256 != expected_reviewer
            or authority.capabilities != tuple(sorted(authority.capabilities))
            or not authority.capabilities
            or not set(authority.capabilities).issubset(_REVIEW_CAPABILITIES)
            or authority.authority_sha256 != evidence.review_authority_sha256(authority)
        ):
            raise AIEvidenceAnalysisCompositionError(
                "review authority registry payload is invalid"
            )
        return authority

    def revoke_reviewer(
        self,
        reviewer_ref: str,
        *,
        expected_registry_revision: int,
    ) -> tuple[evidence.HumanReviewAuthority, int]:
        selected = _ref(reviewer_ref, "reviewer_ref")
        reviewer_key = self._reviewer_key(selected)
        _payload, revision = self._current_payload("reviewer", reviewer_key)
        if revision != expected_registry_revision:
            raise AIEvidenceAnalysisAuthorityConflict(
                "evidence authority registry revision changed"
            )
        authority = self.resolve_reviewer(self.tenant_id, selected)
        if authority.revoked:
            return authority, revision
        revoked = replace(authority, revoked=True, authority_sha256=_ZERO_DIGEST)
        revoked = replace(
            revoked,
            authority_sha256=evidence.review_authority_sha256(revoked),
        )
        next_revision = self._append(
            kind="reviewer",
            object_key=reviewer_key,
            state="revoked",
            payload={"authority": asdict(revoked)},
            expected_registry_revision=revision,
        )
        return revoked, next_revision

    @staticmethod
    def _adapter_key(stage: str, adapter_id: str, revision: int) -> str:
        selected_stage = _ref(stage, "adapter stage")
        if selected_stage not in {"analysis", "extraction"}:
            raise AIEvidenceAnalysisCompositionError("adapter stage is unsupported")
        selected_id = _ref(adapter_id, "adapter_id")
        selected_revision = _integer(
            revision,
            "adapter revision",
            1,
            2_147_483_647,
        )
        return _ref(
            f"{selected_stage}:{selected_id}:{selected_revision}",
            "adapter authority key",
        )

    def enroll_adapter(
        self,
        authority: evidence.EvidenceAdapterAuthority,
        *,
        expected_registry_revision: int = 0,
    ) -> int:
        if type(authority) is not evidence.EvidenceAdapterAuthority:
            raise AIEvidenceAnalysisCompositionError(
                "adapter authority contract is invalid"
            )
        expires = self._authority_expiry(
            authority.valid_until,
            "adapter authority valid_until",
        )
        if (
            authority.stage not in {"analysis", "extraction"}
            or authority.deterministic is not True
            or authority.network_access is not False
            or authority.untrusted_content_mode != "data_only"
            or authority.legal_conclusion_enabled is not False
            or authority.revoked is not False
            or authority.valid_until != expires
            or authority.authority_sha256
            != evidence.adapter_authority_sha256(authority)
        ):
            raise AIEvidenceAnalysisCompositionError(
                "adapter authority contract is unsafe or invalid"
            )
        key = self._adapter_key(
            authority.stage,
            authority.adapter_id,
            authority.revision,
        )
        return self._append(
            kind="adapter",
            object_key=key,
            state="active",
            payload={
                "authority": asdict(authority),
                "attestation_scope": "local_reference_self_pinned",
                "external_acceptance_verified": False,
            },
            expected_registry_revision=expected_registry_revision,
        )

    def resolve_adapter(
        self,
        tenant_id: str,
        stage: str,
        adapter_id: str,
        revision: int,
    ) -> evidence.EvidenceAdapterAuthority:
        if canonical_tenant_id(tenant_id) != self.tenant_id:
            raise evidence.EvidenceAnalysisConfigError(
                "current evidence adapter authority is unavailable"
            )
        key = self._adapter_key(stage, adapter_id, revision)
        payload, _registry_revision = self._current_payload("adapter", key)
        try:
            authority = evidence.EvidenceAdapterAuthority(**dict(payload["authority"]))
        except (KeyError, TypeError) as exc:
            raise AIEvidenceAnalysisCompositionError(
                "adapter authority registry payload is invalid"
            ) from exc
        if (
            payload.get("attestation_scope") != "local_reference_self_pinned"
            or payload.get("external_acceptance_verified") is not False
            or authority.authority_sha256
            != evidence.adapter_authority_sha256(authority)
        ):
            raise AIEvidenceAnalysisCompositionError(
                "adapter authority registry payload is invalid"
            )
        return authority

    def revoke_adapter(
        self,
        *,
        stage: str,
        adapter_id: str,
        revision: int,
        expected_registry_revision: int,
    ) -> tuple[evidence.EvidenceAdapterAuthority, int]:
        key = self._adapter_key(stage, adapter_id, revision)
        _payload, registry_revision = self._current_payload("adapter", key)
        if registry_revision != expected_registry_revision:
            raise AIEvidenceAnalysisAuthorityConflict(
                "evidence authority registry revision changed"
            )
        authority = self.resolve_adapter(
            self.tenant_id,
            stage,
            adapter_id,
            revision,
        )
        if authority.revoked:
            return authority, registry_revision
        revoked = replace(authority, revoked=True, authority_sha256=_ZERO_DIGEST)
        revoked = replace(
            revoked,
            authority_sha256=evidence.adapter_authority_sha256(revoked),
        )
        next_revision = self._append(
            kind="adapter",
            object_key=key,
            state="revoked",
            payload={
                "authority": asdict(revoked),
                "attestation_scope": "local_reference_self_pinned",
                "external_acceptance_verified": False,
            },
            expected_registry_revision=registry_revision,
        )
        return revoked, next_revision

    def current_registry_revision(self, kind: str, object_key: str) -> int:
        row = self._current_row(kind, object_key)
        if row is not None:
            return int(row["registry_revision"])
        selected_kind = _ref(kind, "authority kind")
        selected_key = _ref(object_key, "authority key")
        with closing(self._connect()) as connection, connection:
            retired = self._tombstone_row(
                selected_kind,
                selected_key,
                connection=connection,
            )
        return 0 if retired is None else int(retired["terminal_registry_revision"])

    def compact_expired(self, *, limit: int = 100) -> AuthorityCompactionResult:
        """Replace retention-due non-adapter chains with minimized tombstones.

        The raw authority payload/history remains available for a full tenant
        retention interval after authority expiry.  Compaction then retains a
        digest-only replay tombstone for one additional interval.  Deleting that
        tombstone folds its digest into the constant-size rolling anchor.
        Configured local adapter authorities are excluded: their explicit
        rotation/revocation lifecycle must never be converted into bootstrap.
        """

        bounded_limit = _integer(limit, "authority compaction limit", 1, 500)
        self.verify_integrity()
        now = self._now()
        records_before = 0
        records_after = 0
        compacted_records = 0
        compacted_authorities = 0
        purged_tombstones = 0
        tombstones_after = 0
        anchor = _ZERO_DIGEST
        with (
            cross_process_lock(self.path, strict=True),
            closing(self._connect()) as connection,
            connection,
        ):
            connection.execute("BEGIN IMMEDIATE")
            guard = connection.execute(
                "SELECT value FROM ai_evidence_authority_meta WHERE key='delete_guard'"
            ).fetchone()
            if guard is None or guard[0] != "closed":
                raise AIEvidenceAnalysisCompositionError(
                    "evidence authority registry maintenance guard is invalid"
                )
            records_before = int(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_evidence_authority_records WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchone()[0]
            )
            expired_tombstones = connection.execute(
                "SELECT * FROM ai_evidence_authority_tombstones "
                "WHERE tenant_id=? AND retained_until<=? "
                "ORDER BY retained_until,kind,object_key_sha256 LIMIT ?",
                (self.tenant_id, now, bounded_limit),
            ).fetchall()
            tombstone_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_evidence_authority_tombstones "
                    "WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchone()[0]
            )
            available_tombstones = max(
                0,
                self.settings.max_authority_records
                - (tombstone_count - len(expired_tombstones)),
            )
            current_rows = connection.execute(
                "SELECT record.* FROM ai_evidence_authority_records AS record "
                "JOIN (SELECT kind,object_key,MAX(registry_revision) AS current_revision "
                "FROM ai_evidence_authority_records WHERE tenant_id=? "
                "GROUP BY kind,object_key) AS current "
                "ON record.kind=current.kind AND record.object_key=current.object_key "
                "AND record.registry_revision=current.current_revision "
                "WHERE record.tenant_id=? AND record.kind<>'adapter' "
                "ORDER BY record.created_at,record.kind,record.object_key",
                (self.tenant_id, self.tenant_id),
            ).fetchall()
            selected: list[tuple[sqlite3.Row, float]] = []
            selection_limit = min(bounded_limit, available_tombstones)
            if selection_limit:
                for row in current_rows:
                    valid_until = self._authority_valid_until(row)
                    if valid_until + self.settings.retention_seconds <= now:
                        selected.append((row, valid_until))
                        if len(selected) >= selection_limit:
                            break

            tombstones: list[dict[str, object]] = []
            selected_keys: list[tuple[str, str]] = []
            for terminal_row, valid_until in selected:
                kind = str(terminal_row["kind"])
                object_key = str(terminal_row["object_key"])
                chain = connection.execute(
                    "SELECT * FROM ai_evidence_authority_records "
                    "WHERE tenant_id=? AND kind=? AND object_key=? "
                    "ORDER BY registry_revision",
                    (self.tenant_id, kind, object_key),
                ).fetchall()
                if not chain:
                    raise AIEvidenceAnalysisCompositionError(
                        "evidence authority registry chain is unavailable"
                    )
                retained_until = _timestamp(
                    now + self.settings.retention_seconds,
                    "authority tombstone retained_until",
                )
                body: dict[str, object] = {
                    "tenant_id": self.tenant_id,
                    "kind": kind,
                    "object_key_sha256": self._object_key_sha256(kind, object_key),
                    "terminal_registry_revision": int(
                        terminal_row["registry_revision"]
                    ),
                    "terminal_record_sha256": str(terminal_row["record_sha256"]),
                    "terminal_state": str(terminal_row["state"]),
                    "authority_valid_until": valid_until,
                    "compacted_at": now,
                    "retained_until": retained_until,
                    "record_count": len(chain),
                }
                body["tombstone_sha256"] = _sha256(body)
                tombstones.append(body)
                selected_keys.append((kind, object_key))
                compacted_records += len(chain)

            prior_anchor = self._meta_digest(
                connection,
                "compaction_anchor_sha256",
            )
            prior_sequence = self._meta_integer(connection, "compaction_sequence")
            purged_hashes = [str(row["tombstone_sha256"]) for row in expired_tombstones]
            if tombstones or expired_tombstones:
                sequence = prior_sequence + 1
                anchor = _sha256(
                    {
                        "schema": "lightwork.ai-evidence.authority-compaction-anchor.v1",
                        "tenant_sha256": self.tenant_sha256,
                        "sequence": sequence,
                        "previous_anchor_sha256": prior_anchor,
                        "event_at": now,
                        "compacted_tombstone_sha256s": [
                            str(item["tombstone_sha256"]) for item in tombstones
                        ],
                        "purged_tombstone_sha256s": purged_hashes,
                    }
                )
                connection.execute(
                    "UPDATE ai_evidence_authority_meta SET value='compacting' "
                    "WHERE key='delete_guard'"
                )
                for row in expired_tombstones:
                    connection.execute(
                        "DELETE FROM ai_evidence_authority_tombstones "
                        "WHERE tenant_id=? AND kind=? AND object_key_sha256=?",
                        (
                            self.tenant_id,
                            str(row["kind"]),
                            str(row["object_key_sha256"]),
                        ),
                    )
                for body in tombstones:
                    connection.execute(
                        "INSERT INTO ai_evidence_authority_tombstones "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            body["tenant_id"],
                            body["kind"],
                            body["object_key_sha256"],
                            body["terminal_registry_revision"],
                            body["terminal_record_sha256"],
                            body["terminal_state"],
                            body["authority_valid_until"],
                            body["compacted_at"],
                            body["retained_until"],
                            body["record_count"],
                            body["tombstone_sha256"],
                        ),
                    )
                for kind, object_key in selected_keys:
                    connection.execute(
                        "DELETE FROM ai_evidence_authority_records "
                        "WHERE tenant_id=? AND kind=? AND object_key=?",
                        (self.tenant_id, kind, object_key),
                    )
                compacted_authorities = len(tombstones)
                purged_tombstones = len(expired_tombstones)
                updates = {
                    "compaction_sequence": sequence,
                    "compaction_anchor_sha256": anchor,
                    "compacted_records": self._meta_integer(
                        connection,
                        "compacted_records",
                    )
                    + compacted_records,
                    "compacted_authorities": self._meta_integer(
                        connection,
                        "compacted_authorities",
                    )
                    + compacted_authorities,
                    "purged_tombstones": self._meta_integer(
                        connection,
                        "purged_tombstones",
                    )
                    + purged_tombstones,
                }
                connection.executemany(
                    "UPDATE ai_evidence_authority_meta SET value=? WHERE key=?",
                    ((str(value), key) for key, value in updates.items()),
                )
                connection.execute(
                    "UPDATE ai_evidence_authority_meta SET value='closed' "
                    "WHERE key='delete_guard'"
                )
            else:
                anchor = prior_anchor
            records_after = int(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_evidence_authority_records WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchone()[0]
            )
            tombstones_after = int(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_evidence_authority_tombstones "
                    "WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchone()[0]
            )
            if tombstones or expired_tombstones:
                # Commit the guarded deletion before SQLite's copy-and-replace
                # compaction.  Truncate the WAL so retired payload pages are not
                # left in the active registry sidecar after maintenance.
                connection.commit()
                connection.execute("VACUUM")
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        ensure_private_file(self.path)
        return AuthorityCompactionResult(
            schema="lightwork.ai-evidence.authority-compaction-result.v1",
            records_before=records_before,
            records_after=records_after,
            compacted_authorities=compacted_authorities,
            compacted_records=compacted_records,
            purged_tombstones=purged_tombstones,
            tombstones_after=tombstones_after,
            compaction_anchor_sha256=anchor,
        )

    def verify_integrity(self) -> AuthorityRegistryIntegrity:
        with closing(self._connect()) as connection, connection:
            binding = connection.execute(
                "SELECT value FROM ai_evidence_authority_meta WHERE key='tenant_sha256'"
            ).fetchone()
            if binding is None or binding[0] != self.tenant_sha256:
                raise AIEvidenceAnalysisCompositionError(
                    "evidence authority registry belongs to another tenant"
                )
            guard = connection.execute(
                "SELECT value FROM ai_evidence_authority_meta WHERE key='delete_guard'"
            ).fetchone()
            if guard is None or guard[0] != "closed":
                raise AIEvidenceAnalysisCompositionError(
                    "evidence authority registry maintenance guard is invalid"
                )
            rows = connection.execute(
                "SELECT * FROM ai_evidence_authority_records WHERE tenant_id=? "
                "ORDER BY kind,object_key,registry_revision",
                (self.tenant_id,),
            ).fetchall()
            tombstone_rows = connection.execute(
                "SELECT * FROM ai_evidence_authority_tombstones WHERE tenant_id=? "
                "ORDER BY kind,object_key_sha256",
                (self.tenant_id,),
            ).fetchall()
            compaction_sequence = self._meta_integer(connection, "compaction_sequence")
            compaction_anchor = self._meta_digest(
                connection,
                "compaction_anchor_sha256",
            )
            compacted_records = self._meta_integer(connection, "compacted_records")
            compacted_authorities = self._meta_integer(
                connection,
                "compacted_authorities",
            )
            purged_tombstones = self._meta_integer(connection, "purged_tombstones")
        previous_by_key: dict[tuple[str, str], str] = {}
        revision_by_key: dict[tuple[str, str], int] = {}
        current_by_key: dict[tuple[str, str], sqlite3.Row] = {}
        hashes: list[str] = []
        for row in rows:
            kind = str(row["kind"])
            object_key = str(row["object_key"])
            key = (kind, object_key)
            expected_revision = revision_by_key.get(key, 0) + 1
            expected_previous = previous_by_key.get(key, _ZERO_DIGEST)
            if (
                kind not in _REGISTRY_KINDS
                or int(row["registry_revision"]) != expected_revision
                or str(row["previous_sha256"]) != expected_previous
            ):
                raise AIEvidenceAnalysisCompositionError(
                    "evidence authority registry chain is invalid"
                )
            self._authority_valid_until(row)
            record_sha256 = str(row["record_sha256"])
            revision_by_key[key] = expected_revision
            previous_by_key[key] = record_sha256
            current_by_key[key] = row
            hashes.append(record_sha256)
        tombstone_hashes: list[str] = []
        tombstone_keys: set[tuple[str, str]] = set()
        for row in tombstone_rows:
            kind = str(row["kind"])
            key_digest = _digest(row["object_key_sha256"], "object_key_sha256")
            body = {
                "tenant_id": str(row["tenant_id"]),
                "kind": kind,
                "object_key_sha256": key_digest,
                "terminal_registry_revision": int(row["terminal_registry_revision"]),
                "terminal_record_sha256": _digest(
                    row["terminal_record_sha256"],
                    "terminal_record_sha256",
                ),
                "terminal_state": str(row["terminal_state"]),
                "authority_valid_until": float(row["authority_valid_until"]),
                "compacted_at": float(row["compacted_at"]),
                "retained_until": float(row["retained_until"]),
                "record_count": int(row["record_count"]),
            }
            if (
                body["tenant_id"] != self.tenant_id
                or kind not in _REGISTRY_KINDS - {"adapter"}
                or body["terminal_registry_revision"] < 1
                or body["terminal_state"] not in {"active", "revoked"}
                or body["record_count"] < 1
                or body["retained_until"] <= body["compacted_at"]
                or body["compacted_at"]
                < body["authority_valid_until"] + self.settings.retention_seconds
                or str(row["tombstone_sha256"]) != _sha256(body)
            ):
                raise AIEvidenceAnalysisCompositionError(
                    "evidence authority tombstone integrity check failed"
                )
            tombstone_key = (kind, key_digest)
            if tombstone_key in tombstone_keys:
                raise AIEvidenceAnalysisCompositionError(
                    "evidence authority tombstone chain is invalid"
                )
            tombstone_keys.add(tombstone_key)
            tombstone_hashes.append(str(row["tombstone_sha256"]))
        if (
            len(rows) > self.settings.max_authority_records + len(current_by_key)
            or len(tombstone_rows) > self.settings.max_authority_records
            or compacted_records < sum(int(row["record_count"]) for row in tombstone_rows)
            or compacted_authorities < len(tombstone_rows)
            or purged_tombstones > compacted_authorities
            or (compaction_sequence == 0)
            != (
                compaction_anchor == _ZERO_DIGEST
                and compacted_records == 0
                and compacted_authorities == 0
                and purged_tombstones == 0
            )
        ):
            raise AIEvidenceAnalysisCompositionError(
                "evidence authority registry compaction metadata is invalid"
            )
        now = self._now()
        live_by_key = {
            key: row
            for key, row in current_by_key.items()
            if row["state"] == "active" and self._authority_valid_until(row) > now
        }
        active_artifacts = sum(1 for kind, _key in live_by_key if kind == "artifact")
        terminal = _sha256(
            {
                "schema": "lightwork.ai-evidence.authority-registry-terminal.v2",
                "tenant_sha256": self.tenant_sha256,
                "record_sha256s": hashes,
                "tombstone_sha256s": tombstone_hashes,
                "compaction_sequence": compaction_sequence,
                "compaction_anchor_sha256": compaction_anchor,
                "compacted_records": compacted_records,
                "compacted_authorities": compacted_authorities,
                "purged_tombstones": purged_tombstones,
            }
        )
        body = {
            "schema": "lightwork.ai-evidence.authority-registry-integrity.v2",
            "records": len(rows),
            "live_authorities": len(live_by_key),
            "retained_expired_authorities": len(current_by_key) - len(live_by_key),
            "active_artifacts": active_artifacts,
            "tombstones": len(tombstone_rows),
            "compacted_records": compacted_records,
            "compacted_authorities": compacted_authorities,
            "purged_tombstones": purged_tombstones,
            "capacity_limit": self.settings.max_authority_records,
            "compaction_anchor_sha256": compaction_anchor,
            "terminal_sha256": terminal,
        }
        return AuthorityRegistryIntegrity(
            **body,
            verification_sha256=_sha256(body),
        )


class ConfiguredEvidenceAnalysisStore:
    """Tenant-settings guard around the durable core store."""

    def __init__(
        self,
        store: evidence.EvidenceAnalysisStore,
        *,
        settings: AIEvidenceAnalysisSettings,
        registry: EvidenceAuthorityRegistry,
    ) -> None:
        if store.tenant_id != registry.tenant_id:
            raise AIEvidenceAnalysisCompositionError(
                "evidence-analysis store tenant binding is invalid"
            )
        self._store = store
        self.settings = settings
        self.registry = registry
        self.tenant_id = store.tenant_id
        self.path = store.path

    def analyze(self, tenant_id: str, *, artifact: evidence.EvidenceArtifact, **kwargs: Any):
        tenant = canonical_tenant_id(tenant_id)
        if tenant != self.tenant_id:
            raise evidence.EvidenceAnalysisNotFound("evidence analysis is unavailable")
        maximum = self.settings.artifact_limit(artifact.media_type)
        if not 1 <= len(artifact.content) <= maximum:
            raise evidence.EvidenceAnalysisValidationError(
                "evidence artifact exceeds its tenant byte limit"
            )
        # Requiring an enrolled case association closes the previously unwired
        # max_artifacts_per_case setting without adding a caller-controlled case
        # selector to the analysis request.
        self.registry.artifact_case_ref(artifact.artifact_id)
        return self._store.analyze(tenant, artifact=artifact, **kwargs)

    def get(self, *args: Any, **kwargs: Any):
        return self._store.get(*args, **kwargs)

    def get_released(self, *args: Any, **kwargs: Any):
        return self._store.get_released(*args, **kwargs)

    def review(self, *args: Any, **kwargs: Any):
        return self._store.review(*args, **kwargs)

    def revoke(self, *args: Any, **kwargs: Any):
        return self._store.revoke(*args, **kwargs)

    def history(self, *args: Any, **kwargs: Any):
        return self._store.history(*args, **kwargs)

    def list_analyses(self, *args: Any, **kwargs: Any):
        """Read current bounded heads without bypassing tenant configuration."""

        return self._store.list_analyses(*args, **kwargs)

    def context_record_count(self, *args: Any, **kwargs: Any):
        return self._store.context_record_count(*args, **kwargs)

    def retention_due(self, *args: Any, **kwargs: Any):
        return self._store.retention_due(*args, **kwargs)

    def purge_expired(self, *args: Any, **kwargs: Any):
        return self._store.purge_expired(*args, **kwargs)

    def verify_integrity(self, *args: Any, **kwargs: Any):
        return self._store.verify_integrity(*args, **kwargs)


@dataclass(frozen=True, slots=True)
class EvidenceAnalysisComposition:
    tenant_id: str
    settings: AIEvidenceAnalysisSettings
    registry: EvidenceAuthorityRegistry
    extraction_adapter: GovernedLocalExtractionAdapter
    analysis_adapter: evidence.DeterministicCriteriaAnalysisAdapter
    extraction_authority: evidence.EvidenceAdapterAuthority
    analysis_authority: evidence.EvidenceAdapterAuthority
    store: ConfiguredEvidenceAnalysisStore


def _registry_path(tenant_id: str) -> Path:
    return data_dir(
        "ai_evidence_analysis",
        "authority-registry.sqlite3",
        tenant=tenant_id,
    )


def _analysis_path(tenant_id: str) -> Path:
    return data_dir(
        "ai_evidence_analysis",
        "analyses.sqlite3",
        tenant=tenant_id,
    )


def _same_snapshot(
    tenant_id: str,
    expected: AIEvidenceAnalysisSettings,
) -> None:
    selected = settings_for_tenant(tenant_id)
    if selected != expected:
        raise AIEvidenceAnalysisCompositionError(
            "AI evidence-analysis tenant configuration changed"
        )


def _local_adapters(
    settings: AIEvidenceAnalysisSettings,
) -> tuple[
    GovernedLocalExtractionAdapter,
    evidence.DeterministicCriteriaAnalysisAdapter,
]:
    return (
        GovernedLocalExtractionAdapter(
            maximum_bytes=settings.max_extracted_text_bytes,
            sandbox=settings.parser_sandbox,
            ocr=settings.ocr,
            legacy_xls=settings.legacy_xls,
        ),
        evidence.DeterministicCriteriaAnalysisAdapter(),
    )


def _adapter_identity(
    adapter: GovernedLocalExtractionAdapter
    | evidence.DeterministicCriteriaAnalysisAdapter,
    *,
    now: float,
) -> evidence.EvidenceAdapterAuthority:
    return adapter.authority(valid_until=now + 3_600)


def _require_adapter_enrolled(
    registry: EvidenceAuthorityRegistry,
    identity: evidence.EvidenceAdapterAuthority,
) -> None:
    # The registry key includes the adapter revision, so an upgrade to a new
    # revision has no enrollment yet. Read-only paths must refuse until the
    # adapter is enrolled again rather than reporting a generic unavailability.
    key = registry._adapter_key(  # noqa: SLF001 - registry-owned enrollment check
        identity.stage,
        identity.adapter_id,
        identity.revision,
    )
    if registry.current_registry_revision("adapter", key) == 0:
        raise AIEvidenceAnalysisCompositionError(
            "local evidence adapter authority is not enrolled for this revision; "
            "after an upgrade the local evidence adapter must be enrolled again; "
            "an analysis or authority request enrolls it on first use, and a global "
            "administrator can enroll it now with "
            "POST /api/v1/ai-evidence-analysis/authorities/bootstrap"
        )


def bootstrap_local_adapter_authorities(
    registry: EvidenceAuthorityRegistry,
    *,
    clock: Callable[[], float] = time.time,
) -> tuple[evidence.EvidenceAdapterAuthority, evidence.EvidenceAdapterAuthority]:
    """Enroll exact local adapters once; never resurrect a revoked authority."""

    now = _timestamp(clock(), "clock")
    extraction, analysis = _local_adapters(registry.settings)
    candidates = (
        _adapter_identity(extraction, now=now),
        _adapter_identity(analysis, now=now),
    )
    enrolled: list[evidence.EvidenceAdapterAuthority] = []
    for candidate in candidates:
        key = registry._adapter_key(  # noqa: SLF001 - registry-owned bootstrap
            candidate.stage,
            candidate.adapter_id,
            candidate.revision,
        )
        current_revision = registry.current_registry_revision("adapter", key)
        if current_revision == 0:
            # Adapter authority lifetime is bounded but independent of analysis
            # retention. Re-enrollment after expiry is an explicit rotation.
            candidate = replace(
                candidate,
                valid_until=now + _MAX_VALID_SECONDS,
                authority_sha256=_ZERO_DIGEST,
            )
            candidate = replace(
                candidate,
                authority_sha256=evidence.adapter_authority_sha256(candidate),
            )
            registry.enroll_adapter(candidate)
            enrolled.append(candidate)
            continue
        current = registry.resolve_adapter(
            registry.tenant_id,
            candidate.stage,
            candidate.adapter_id,
            candidate.revision,
        )
        expected = (
            extraction.authority(valid_until=current.valid_until)
            if candidate.stage == "extraction"
            else analysis.authority(valid_until=current.valid_until)
        )
        if current != expected or current.revoked or current.valid_until <= now:
            raise AIEvidenceAnalysisCompositionError(
                "local evidence adapter authority changed, expired, or was revoked"
            )
        enrolled.append(current)
    return enrolled[0], enrolled[1]


def rotate_local_adapter_authority(
    registry: EvidenceAuthorityRegistry,
    *,
    stage: str,
    adapter_id: str,
    revision: int,
    expected_registry_revision: int,
    clock: Callable[[], float] | None = None,
) -> tuple[evidence.EvidenceAdapterAuthority, int]:
    """Renew one exact local adapter authority without undoing revocation."""

    if not isinstance(registry, EvidenceAuthorityRegistry):
        raise AIEvidenceAnalysisCompositionError(
            "local evidence adapter rotation dependencies are unavailable"
        )
    selected_clock = registry._clock if clock is None else clock  # noqa: SLF001
    if not callable(selected_clock):  # pragma: no cover - registry invariant
        raise AIEvidenceAnalysisCompositionError(
            "local evidence adapter rotation dependencies are unavailable"
        )
    key = registry._adapter_key(stage, adapter_id, revision)  # noqa: SLF001
    expected_revision = _integer(
        expected_registry_revision,
        "expected_registry_revision",
        1,
        2_147_483_647,
    )
    if registry.current_registry_revision("adapter", key) != expected_revision:
        raise AIEvidenceAnalysisAuthorityConflict(
            "evidence authority registry revision changed"
        )
    current = registry.resolve_adapter(
        registry.tenant_id,
        stage,
        adapter_id,
        revision,
    )
    if current.revoked:
        raise AIEvidenceAnalysisCompositionError(
            "revoked local evidence adapter authority cannot be renewed"
        )
    extraction, analysis = _local_adapters(registry.settings)
    adapter: (
        GovernedLocalExtractionAdapter
        | evidence.DeterministicCriteriaAnalysisAdapter
    )
    adapter = extraction if stage == "extraction" else analysis
    exact = adapter.authority(valid_until=current.valid_until)
    if (
        current != exact
        or exact.adapter_id != adapter_id
        or exact.revision != revision
    ):
        raise AIEvidenceAnalysisCompositionError(
            "local evidence adapter identity changed and requires a code revision"
        )
    now = _timestamp(selected_clock(), "clock")
    next_valid_until = now + _MAX_VALID_SECONDS
    if next_valid_until <= current.valid_until:
        raise AIEvidenceAnalysisAuthorityConflict(
            "local evidence adapter authority renewal is a no-change operation"
        )
    renewed = adapter.authority(valid_until=next_valid_until)
    next_revision = registry.enroll_adapter(
        renewed,
        expected_registry_revision=expected_revision,
    )
    return renewed, next_revision


def build_ai_evidence_analysis_composition(
    *,
    tenant_id: str,
    config: Mapping[str, Any],
    registry_path: str | Path | None = None,
    analysis_path: str | Path | None = None,
    clock: Callable[[], float] = time.time,
    bootstrap_local_adapters: bool = True,
    config_gate: Callable[[], None] | None = None,
) -> EvidenceAnalysisComposition:
    """Construct one restart-safe tenant composition from an exact snapshot."""

    tenant = canonical_tenant_id(tenant_id)
    settings = ai_evidence_analysis_settings(config)
    if settings is None:
        raise AIEvidenceAnalysisCompositionError("ai_evidence_analysis_disabled")
    if not callable(clock):
        raise TypeError("clock must be callable")
    if config_gate is not None and not callable(config_gate):
        raise TypeError("config_gate must be callable")
    registry = EvidenceAuthorityRegistry(
        Path(registry_path) if registry_path is not None else _registry_path(tenant),
        tenant_id=tenant,
        settings=settings,
        clock=clock,
    )
    extraction_adapter, analysis_adapter = _local_adapters(settings)
    if bootstrap_local_adapters:
        extraction_authority, analysis_authority = bootstrap_local_adapter_authorities(
            registry,
            clock=clock,
        )
    else:
        now = _timestamp(clock(), "clock")
        extraction_identity = _adapter_identity(extraction_adapter, now=now)
        analysis_identity = _adapter_identity(analysis_adapter, now=now)
        _require_adapter_enrolled(registry, extraction_identity)
        _require_adapter_enrolled(registry, analysis_identity)
        extraction_authority = registry.resolve_adapter(
            tenant,
            extraction_identity.stage,
            extraction_identity.adapter_id,
            extraction_identity.revision,
        )
        analysis_authority = registry.resolve_adapter(
            tenant,
            analysis_identity.stage,
            analysis_identity.adapter_id,
            analysis_identity.revision,
        )
        if (
            extraction_authority
            != extraction_adapter.authority(valid_until=extraction_authority.valid_until)
            or analysis_authority
            != analysis_adapter.authority(valid_until=analysis_authority.valid_until)
            or extraction_authority.valid_until <= now
            or analysis_authority.valid_until <= now
        ):
            raise AIEvidenceAnalysisCompositionError(
                "local evidence adapter authority changed, expired, or was revoked"
            )

    def gate() -> None:
        # Tests and explicit builders can pass a frozen snapshot without relying
        # on ambient process configuration. The installed app path below wraps
        # this builder with the live tenant snapshot check.
        if settings is None:  # pragma: no cover - immutable construction guard
            raise AIEvidenceAnalysisCompositionError("ai_evidence_analysis_disabled")
        if config_gate is not None:
            config_gate()

    core_store = evidence.EvidenceAnalysisStore(
        Path(analysis_path) if analysis_path is not None else _analysis_path(tenant),
        tenant_id=tenant,
        artifact_authority_resolver=registry.resolve_artifact,
        criteria_authority_resolver=registry.resolve_criteria,
        review_authority_resolver=registry.resolve_reviewer,
        adapter_authority_resolver=registry.resolve_adapter,
        extraction_adapter=extraction_adapter,
        analysis_adapter=analysis_adapter,
        extraction_adapter_authority=extraction_authority,
        analysis_adapter_authority=analysis_authority,
        config_gate=gate,
        clock=clock,
    )
    store = ConfiguredEvidenceAnalysisStore(
        core_store,
        settings=settings,
        registry=registry,
    )
    return EvidenceAnalysisComposition(
        tenant_id=tenant,
        settings=settings,
        registry=registry,
        extraction_adapter=extraction_adapter,
        analysis_adapter=analysis_adapter,
        extraction_authority=extraction_authority,
        analysis_authority=analysis_authority,
        store=store,
    )


def _installed_composition(
    tenant_id: str,
    *,
    bootstrap_local_adapters: bool,
) -> EvidenceAnalysisComposition:
    tenant = canonical_tenant_id(tenant_id)
    config = _load_tenant_config(tenant)
    expected = ai_evidence_analysis_settings(config)
    if expected is None:
        raise AIEvidenceAnalysisCompositionError("ai_evidence_analysis_disabled")
    composition = build_ai_evidence_analysis_composition(
        tenant_id=tenant,
        config=config,
        bootstrap_local_adapters=bootstrap_local_adapters,
        config_gate=lambda: _same_snapshot(tenant, expected),
    )
    # Re-read immediately after construction to ensure the admitted snapshot did
    # not change while paths/authorities were being resolved.
    _same_snapshot(tenant, expected)
    if composition.settings != expected:
        raise AIEvidenceAnalysisCompositionError(
            "AI evidence-analysis tenant configuration changed"
        )
    return composition


def ai_evidence_analysis_readiness(tenant_id: str) -> bool:
    """Verify local composition without provisioning or claiming acceptance."""

    try:
        tenant = canonical_tenant_id(tenant_id)
        settings = settings_for_tenant(tenant)
        path = _registry_path(tenant)
        if not path.is_file() or not _analysis_path(tenant).is_file():
            return False
        composition = _installed_composition(
            tenant,
            bootstrap_local_adapters=False,
        )
        if composition.settings != settings:
            return False
        composition.registry.verify_integrity()
        composition.store.verify_integrity(tenant)
        return True
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def ai_evidence_analysis_lifetime(
    tenant_id: str,
    _actor_ref: str,
    _request: Any,
) -> tuple[float, float]:
    settings = settings_for_tenant(tenant_id)
    now = time.time()
    valid_until = now + min(settings.retention_seconds, _MAX_VALID_SECONDS)
    retained_until = now + min(settings.retention_seconds, _MAX_RETENTION_SECONDS)
    return valid_until, max(valid_until, retained_until)


def ai_evidence_analysis_store_for(
    tenant_id: str,
    _actor_ref: str,
    _request: Any,
) -> ConfiguredEvidenceAnalysisStore:
    return _installed_composition(
        tenant_id,
        bootstrap_local_adapters=True,
    ).store


def ai_evidence_analysis_context_store_for(
    tenant_id: str,
) -> ConfiguredEvidenceAnalysisStore:
    """Open existing evidence authority without enrolling or rotating adapters."""

    return _installed_composition(
        tenant_id,
        bootstrap_local_adapters=False,
    ).store


def ai_evidence_analysis_artifact_limit(
    tenant_id: str,
    media_type: str,
) -> int:
    """Transport-safe byte limit seam for the mounted upload API."""

    return settings_for_tenant(tenant_id).artifact_limit(media_type)


def ai_evidence_analysis_registry_for(tenant_id: str) -> EvidenceAuthorityRegistry:
    return _installed_composition(
        tenant_id,
        bootstrap_local_adapters=True,
    ).registry


def run_ai_evidence_analysis_maintenance(
    tenant_id: str,
    *,
    limit: int = 100,
) -> EvidenceMaintenanceResult:
    """Integrity-check, purge due records, re-check, and return bounded counts."""

    tenant = canonical_tenant_id(tenant_id)
    bounded_limit = _integer(limit, "maintenance limit", 1, 500)
    composition = _installed_composition(
        tenant,
        bootstrap_local_adapters=False,
    )
    registry_before = composition.registry.verify_integrity()
    before = composition.store.verify_integrity(tenant)
    purged = composition.store.purge_expired(tenant, limit=bounded_limit)
    compacted = composition.registry.compact_expired(limit=bounded_limit)
    registry_after = composition.registry.verify_integrity()
    after = composition.store.verify_integrity(tenant)
    return EvidenceMaintenanceResult(
        schema="lightwork.ai-evidence.maintenance-result.v2",
        tenant_id=tenant,
        registry_records=registry_after.records,
        registry_records_before=registry_before.records,
        live_authorities=registry_after.live_authorities,
        retained_expired_authorities=registry_after.retained_expired_authorities,
        authority_tombstones=registry_after.tombstones,
        compacted_authorities=compacted.compacted_authorities,
        compacted_authority_records=compacted.compacted_records,
        purged_authority_tombstones=compacted.purged_tombstones,
        authority_compaction_anchor_sha256=(
            registry_after.compaction_anchor_sha256
        ),
        analyses_before=before.analyses,
        purged_analysis_ids=tuple(purged.analysis_ids),
        purged_analyses=len(purged.analysis_ids),
        purged_history_records=purged.history_records,
        purged_operations=purged.operations,
        analyses_after=after.analyses,
        integrity_verified=True,
    )


def install_ai_evidence_analysis_composition(app: Any) -> None:
    """Install lazy stock seams; preserve explicit deployment overrides."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    marker = "ai_evidence_analysis_composition_installed"
    if getattr(state, marker, False):
        return
    defaults = {
        "ai_evidence_analysis_enabled_probe": ai_evidence_analysis_enabled,
        "ai_evidence_analysis_store_factory": ai_evidence_analysis_store_for,
        "ai_evidence_analysis_lifetime_resolver": ai_evidence_analysis_lifetime,
        "ai_evidence_analysis_readiness_probe": ai_evidence_analysis_readiness,
        "ai_evidence_analysis_status_settings_resolver": (
            ai_evidence_analysis_status_settings
        ),
        "ai_evidence_analysis_artifact_limit_resolver": (
            ai_evidence_analysis_artifact_limit
        ),
        "ai_evidence_analysis_authority_registry_factory": (
            ai_evidence_analysis_registry_for
        ),
        "ai_evidence_analysis_maintenance_runner": (
            run_ai_evidence_analysis_maintenance
        ),
    }
    for name, value in defaults.items():
        if getattr(state, name, None) is None:
            setattr(state, name, value)
    setattr(state, marker, True)


__all__ = [
    "AIEvidenceAnalysisAuthorityConflict",
    "AIEvidenceAnalysisCompositionError",
    "AIEvidenceAnalysisSettings",
    "AuthorityCompactionResult",
    "AuthorityRegistryIntegrity",
    "ByteBoundedLocalExtractionAdapter",
    "ConfiguredEvidenceAnalysisStore",
    "EvidenceAnalysisComposition",
    "EvidenceAuthorityRegistry",
    "EvidenceMaintenanceResult",
    "ai_evidence_analysis_artifact_limit",
    "ai_evidence_analysis_context_store_for",
    "ai_evidence_analysis_enabled",
    "ai_evidence_analysis_lifetime",
    "ai_evidence_analysis_readiness",
    "ai_evidence_analysis_registry_for",
    "ai_evidence_analysis_settings",
    "ai_evidence_analysis_store_for",
    "ai_evidence_analysis_status_settings",
    "bootstrap_local_adapter_authorities",
    "build_ai_evidence_analysis_composition",
    "install_ai_evidence_analysis_composition",
    "run_ai_evidence_analysis_maintenance",
    "rotate_local_adapter_authority",
    "settings_for_tenant",
]
