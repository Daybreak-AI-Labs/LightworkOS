"""Production composition for stock privacy-rights source adapters.

The composition is lazy and tenant exact.  Importing or attaching it performs
no provider I/O, opens no rights store, and resolves no secret or raw subject.
An authenticated admin run builds the closed provider adapters, resolves a
deployment-owned subject authority, leases short-lived credential material,
and executes the core worker.  Retrieval bytes may flow only into the stock
encrypted governed-document vault or an equivalently explicit injected sink.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from maverick import privacy_rights_orchestration as rights
from maverick import privacy_rights_source_adapters as adapters
from maverick import privacy_rights_source_worker as worker
from maverick.file_lock import ensure_private_directory, ensure_private_file
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope
from maverick.sqlite_closing import ClosingConnection

_PROVIDERS = frozenset(
    {
        "microsoft_graph_users",
        "google_workspace_users",
        "salesforce_contacts",
        "servicenow_users",
    }
)
_CAPABILITIES = frozenset({"discover", "retrieve", "delete", "verify_delete"})
_SECRET_REF_RE = re.compile(
    r"(?:env|vault|secret):([A-Z][A-Z0-9_]{0,127})\Z"
)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_monotonic = time.monotonic


class PrivacyRightsSourceCompositionError(
    worker.PrivacyRightsSourceWorkerConfigError
):
    """A tenant source composition is unavailable or changed."""


@dataclass(frozen=True, slots=True)
class SourceAdapterSettings:
    source_id: str
    provider: str
    origin: str
    credential_ref: str
    capabilities: tuple[str, ...]
    config_binding_sha256: str

    @property
    def adapter_ref(self) -> str:
        return f"stock:{self.provider}:v2:{self.config_binding_sha256}"


@dataclass(frozen=True, slots=True)
class PrivacyRightsSourceSettings:
    enabled: bool
    sources: tuple[SourceAdapterSettings, ...]
    limits: adapters.AdapterLimits
    batch_size: int
    lease_seconds: int
    retry_delay_seconds: int
    claim_history_retention_seconds: int
    target_custody_retention_seconds: int
    config_sha256: str


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source configuration is not canonical"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise PrivacyRightsSourceCompositionError(f"{label} is outside its bound")
    return value


def _identifier(value: object, label: str) -> str:
    selected = str(value or "").strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", selected) is None:
        raise PrivacyRightsSourceCompositionError(f"{label} is invalid")
    return selected


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            loaded = config_module.load_config()
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights tenant configuration is unavailable"
        ) from exc
    if errors or not isinstance(loaded, Mapping):
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights tenant configuration is invalid"
        )
    return loaded


def settings_from_config(config: Mapping[str, Any]) -> PrivacyRightsSourceSettings:
    privacy = config.get("privacy_automation")
    rights_section = (
        privacy.get("rights_orchestration") if isinstance(privacy, Mapping) else None
    )
    section = (
        rights_section.get("source_adapters")
        if isinstance(rights_section, Mapping)
        else None
    )
    if section is None:
        material: Mapping[str, object] = {"enable": False, "providers": {}}
        return PrivacyRightsSourceSettings(
            enabled=False,
            sources=(),
            limits=adapters.AdapterLimits(),
            batch_size=10,
            lease_seconds=60,
            retry_delay_seconds=30,
            claim_history_retention_seconds=86_400,
            target_custody_retention_seconds=30 * 24 * 3_600,
            config_sha256=_canonical_sha256(material),
        )
    if (
        not isinstance(privacy, Mapping)
        or privacy.get("enable") is not True
        or not isinstance(rights_section, Mapping)
        or rights_section.get("enable") is not True
    ):
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source adapters require enabled rights orchestration"
        )
    if not isinstance(section, Mapping):
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source adapters must be a table"
        )
    allowed = {
        "enable",
        "providers",
        "timeout_seconds",
        "max_response_bytes",
        "max_retrieval_bytes",
        "max_records",
        "batch_size",
        "lease_seconds",
        "retry_delay_seconds",
        "claim_history_retention_seconds",
        "target_custody_retention_seconds",
    }
    if set(section) - allowed:
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source adapters contain an unknown key"
        )
    enabled = section.get("enable", False)
    if type(enabled) is not bool:
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source adapter enable must be boolean"
        )
    raw_providers = section.get("providers", {})
    if not isinstance(raw_providers, Mapping) or set(raw_providers) - _PROVIDERS:
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source provider table is invalid"
        )
    material = {
        "schema": "lightwork.privacy-rights-source-config.v1",
        "section": dict(section),
    }
    config_binding_sha256 = _canonical_sha256(material)
    sources: list[SourceAdapterSettings] = []
    for provider in sorted(raw_providers):
        raw = raw_providers[provider]
        if not isinstance(raw, Mapping) or set(raw) - {
            "enable",
            "source_id",
            "origin",
            "credential_ref",
            "capabilities",
        }:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights source provider binding is invalid"
            )
        provider_enabled = raw.get("enable", False)
        if type(provider_enabled) is not bool:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights source provider enable must be boolean"
            )
        if not provider_enabled:
            continue
        source_id = _identifier(raw.get("source_id"), "source_id")
        origin = str(raw.get("origin") or "").strip()
        credential_ref = str(raw.get("credential_ref") or "").strip()
        if _SECRET_REF_RE.fullmatch(credential_ref) is None:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights source credential_ref is invalid"
            )
        raw_capabilities = raw.get("capabilities")
        if (
            not isinstance(raw_capabilities, list)
            or not raw_capabilities
            or any(not isinstance(item, str) for item in raw_capabilities)
        ):
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights source capabilities are invalid"
            )
        capabilities = tuple(sorted(raw_capabilities))
        if (
            len(set(capabilities)) != len(capabilities)
            or not set(capabilities) <= _CAPABILITIES
        ):
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights source capabilities are invalid"
            )
        sources.append(
            SourceAdapterSettings(
                source_id=source_id,
                provider=provider,
                origin=origin,
                credential_ref=credential_ref,
                capabilities=capabilities,
                config_binding_sha256=config_binding_sha256,
            )
        )
    if len({source.source_id for source in sources}) != len(sources):
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source IDs must be unique"
        )
    if enabled and not sources:
        raise PrivacyRightsSourceCompositionError(
            "enabled privacy-rights source adapters require a provider"
        )
    timeout = section.get("timeout_seconds", 15.0)
    limits = adapters.AdapterLimits(
        timeout_seconds=timeout,
        max_response_bytes=_integer(
            section.get("max_response_bytes", 1_048_576),
            "max_response_bytes",
            1_024,
            4_194_304,
        ),
        max_retrieval_bytes=_integer(
            section.get("max_retrieval_bytes", 8_388_608),
            "max_retrieval_bytes",
            1_024,
            33_554_432,
        ),
        max_records=_integer(
            section.get("max_records", 200), "max_records", 1, 1_000
        ),
    )
    if limits.max_retrieval_bytes < limits.max_response_bytes:
        raise PrivacyRightsSourceCompositionError(
            "max_retrieval_bytes must be at least max_response_bytes"
        )
    lease_seconds = _integer(
        section.get("lease_seconds", 60), "lease_seconds", 1, 3_600
    )
    minimum_safe_lease = math.ceil(float(limits.timeout_seconds) * 2) + 5
    if lease_seconds < minimum_safe_lease:
        raise PrivacyRightsSourceCompositionError(
            "lease_seconds is shorter than bounded lookup and mutation I/O"
        )
    return PrivacyRightsSourceSettings(
        enabled=enabled,
        sources=tuple(sources),
        limits=limits,
        batch_size=_integer(section.get("batch_size", 10), "batch_size", 1, 100),
        lease_seconds=lease_seconds,
        retry_delay_seconds=_integer(
            section.get("retry_delay_seconds", 30),
            "retry_delay_seconds",
            0,
            604_800,
        ),
        claim_history_retention_seconds=_integer(
            section.get("claim_history_retention_seconds", 86_400),
            "claim_history_retention_seconds",
            60,
            30 * 24 * 3_600,
        ),
        target_custody_retention_seconds=_integer(
            section.get(
                "target_custody_retention_seconds", 30 * 24 * 3_600
            ),
            "target_custody_retention_seconds",
            3_600,
            10 * 365 * 24 * 3_600,
        ),
        config_sha256=config_binding_sha256,
    )


def settings_for_tenant(tenant_id: str) -> PrivacyRightsSourceSettings:
    return settings_from_config(_load_tenant_config(tenant_id))


class PinnedPrivacyRightsHTTPTransport:
    """DNS-pinned, redirect-free, bounded GET/DELETE provider transport."""

    dns_pinned = True
    redirects_followed = False

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
        max_response_bytes: int,
        allow_redirects: bool,
    ) -> adapters.HTTPResponse:
        from maverick.enterprise import enterprise_egress_denial
        from maverick.tools._ssrf import BlockedHost, safe_client

        selected_method = str(method or "").upper()
        parsed = urlsplit(str(url or ""))
        if os.getenv("MAVERICK_FETCH_ALLOW_PRIVATE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights transport refuses private-fetch override"
            )
        if (
            selected_method not in {"GET", "DELETE"}
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or body is not None
            or allow_redirects is not False
        ):
            raise worker.PrivacyRightsSourceWorkerProtocolError(
                "privacy-rights provider request is uncontrolled"
            )
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or not 0.1 <= float(timeout) <= 60.0
            or isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or not 1_024 <= max_response_bytes <= 33_554_432
        ):
            raise worker.PrivacyRightsSourceWorkerProtocolError(
                "privacy-rights provider bounds are invalid"
            )
        denial = enterprise_egress_denial(url, tool="privacy_rights_source_adapters")
        if denial:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights provider egress is denied"
            )
        started = _monotonic()
        try:
            with safe_client(url, timeout=timeout, follow_redirects=False) as client:
                with client.stream(
                    selected_method,
                    url,
                    headers=dict(headers),
                ) as response:
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            declared_size = int(declared)
                        except ValueError:
                            raise worker.PrivacyRightsSourceWorkerProtocolError(
                                "privacy-rights provider content length is invalid"
                            ) from None
                        if declared_size < 0 or declared_size > max_response_bytes:
                            raise worker.PrivacyRightsSourceWorkerProtocolError(
                                "privacy-rights provider response is oversized"
                            )
                    chunks: list[bytes] = []
                    observed = 0
                    for chunk in response.iter_bytes():
                        if _monotonic() - started > float(timeout):
                            raise TimeoutError("privacy-rights response timed out")
                        observed += len(chunk)
                        if observed > max_response_bytes:
                            raise worker.PrivacyRightsSourceWorkerProtocolError(
                                "privacy-rights provider response is oversized"
                            )
                        chunks.append(chunk)
                    safe_headers = {
                        str(key).lower(): value
                        for key, value in response.headers.items()
                        if str(key).lower()
                        in {"content-type", "content-length", "retry-after"}
                        and isinstance(value, str)
                        and len(value) <= 4_096
                        and _CONTROL_RE.search(value) is None
                    }
                    return adapters.HTTPResponse(
                        status_code=int(response.status_code),
                        headers=safe_headers,
                        body=b"".join(chunks),
                        # safe_client may surface its pinned IP internally. It
                        # never follows redirects, so the request URL is final.
                        final_url=url,
                    )
        except BlockedHost as exc:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights provider host is blocked"
            ) from exc


class EncryptedMutationTargetCustody:
    """Deployment-owned encrypted custody for immutable provider target IDs."""

    def __init__(
        self,
        *,
        tenant_id: str,
        path: str | Path,
        retention_seconds: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.tenant_id = canonical_tenant_id(tenant_id)
        self.path = Path(path)
        self.retention_seconds = _integer(
            retention_seconds,
            "target_custody_retention_seconds",
            3_600,
            10 * 365 * 24 * 3_600,
        )
        if not callable(clock):
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights target custody clock is unavailable"
            )
        self.clock = clock
        ensure_private_directory(self.path.parent)
        with self._connect() as connection:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS privacy_rights_mutation_targets(
                    target_ref TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL UNIQUE,
                    provider TEXT NOT NULL,
                    encrypted_target BLOB NOT NULL,
                    ciphertext_sha256 TEXT NOT NULL,
                    target_binding_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    retained_until REAL NOT NULL,
                    row_sha256 TEXT NOT NULL
                );
                COMMIT;
                """
            )
        ensure_private_file(self.path)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30.0, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _row_material(row: Mapping[str, object]) -> Mapping[str, object]:
        return {
            "schema": "lightwork.privacy-rights-target-custody.v1",
            "target_ref": row["target_ref"],
            "tenant_id": row["tenant_id"],
            "case_id": row["case_id"],
            "source_id": row["source_id"],
            "operation_id": row["operation_id"],
            "provider": row["provider"],
            "ciphertext_sha256": row["ciphertext_sha256"],
            "target_binding_sha256": row["target_binding_sha256"],
            "created_at": row["created_at"],
            "retained_until": row["retained_until"],
        }

    def _verified_row(self, row: sqlite3.Row) -> None:
        encrypted = bytes(row["encrypted_target"])
        if (
            row["tenant_id"] != self.tenant_id
            or not isinstance(row["retained_until"], (int, float))
            or not math.isfinite(float(row["retained_until"]))
            or hashlib.sha256(encrypted).hexdigest() != row["ciphertext_sha256"]
            or _canonical_sha256(self._row_material(row)) != row["row_sha256"]
        ):
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights target custody integrity failed"
            )

    @staticmethod
    def _target_material(
        *,
        tenant_id: str,
        case_id: str,
        source_id: str,
        provider: str,
        operation_id: str,
        target_id: str,
    ) -> Mapping[str, object]:
        return {
            "schema": "lightwork.privacy-rights-mutation-target.v1",
            "tenant_id": tenant_id,
            "case_id": case_id,
            "source_id": source_id,
            "provider": provider,
            "operation_id": operation_id,
            "target_id": target_id,
        }

    def store(
        self,
        *,
        tenant_id: str,
        case_id: str,
        source_id: str,
        operation_id: str,
        provider: str,
        target_id: str,
        target_binding_sha256: str,
    ) -> adapters.MutationTargetReceipt:
        tenant = canonical_tenant_id(tenant_id)
        if tenant != self.tenant_id or provider not in _PROVIDERS:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights target custody binding is invalid"
            )
        for value, label in (
            (case_id, "case_id"),
            (source_id, "source_id"),
            (operation_id, "operation_id"),
            (target_id, "target_id"),
        ):
            _identifier(value, label)
        expected_binding = _canonical_sha256(
            self._target_material(
                tenant_id=tenant,
                case_id=case_id,
                source_id=source_id,
                provider=provider,
                operation_id=operation_id,
                target_id=target_id,
            )
        )
        if (
            re.fullmatch(r"[0-9a-f]{64}", target_binding_sha256) is None
            or expected_binding != target_binding_sha256
        ):
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights target custody digest is invalid"
            )
        target_ref = "target:" + hashlib.sha256(
            f"{tenant}\x00{case_id}\x00{source_id}\x00{operation_id}".encode()
        ).hexdigest()[:40]
        now = float(self.clock())
        if not math.isfinite(now) or now <= 0:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights target custody clock is invalid"
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM privacy_rights_mutation_targets "
                "WHERE target_ref=?",
                (target_ref,),
            ).fetchone()
            if current is not None:
                self._verified_row(current)
                if float(current["retained_until"]) <= now:
                    raise PrivacyRightsSourceCompositionError(
                        "privacy-rights target custody record expired"
                    )
                if any(
                    current[key] != value
                    for key, value in {
                        "tenant_id": tenant,
                        "case_id": case_id,
                        "source_id": source_id,
                        "operation_id": operation_id,
                        "provider": provider,
                        "target_binding_sha256": target_binding_sha256,
                    }.items()
                ):
                    raise PrivacyRightsSourceCompositionError(
                        "privacy-rights target custody operation changed"
                    )
                return adapters.MutationTargetReceipt(
                    opaque_ref=target_ref,
                    target_binding_sha256=target_binding_sha256,
                    tenant_bound=True,
                    encrypted_at_rest=True,
                    retention_enforced=True,
                )
            from maverick.crypto_at_rest import seal

            with tenant_scope(tenant=tenant):
                encrypted = seal(target_id.encode("utf-8"))
            row: dict[str, object] = {
                "target_ref": target_ref,
                "tenant_id": tenant,
                "case_id": case_id,
                "source_id": source_id,
                "operation_id": operation_id,
                "provider": provider,
                "encrypted_target": encrypted,
                "ciphertext_sha256": hashlib.sha256(encrypted).hexdigest(),
                "target_binding_sha256": target_binding_sha256,
                "created_at": now,
                "retained_until": now + self.retention_seconds,
            }
            row_sha256 = _canonical_sha256(self._row_material(row))
            connection.execute(
                "INSERT INTO privacy_rights_mutation_targets VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (*row.values(), row_sha256),
            )
        return adapters.MutationTargetReceipt(
            opaque_ref=target_ref,
            target_binding_sha256=target_binding_sha256,
            tenant_bound=True,
            encrypted_at_rest=True,
            retention_enforced=True,
        )

    def resolve(
        self,
        *,
        tenant_id: str,
        case_id: str,
        source_id: str,
        operation_id: str,
        provider: str,
        target_ref: str,
        target_binding_sha256: str,
    ) -> str:
        tenant = canonical_tenant_id(tenant_id)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM privacy_rights_mutation_targets "
                "WHERE target_ref=?",
                (_identifier(target_ref, "target_ref"),),
            ).fetchone()
        if row is None:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights target custody record is unavailable"
            )
        self._verified_row(row)
        now = float(self.clock())
        if not math.isfinite(now) or float(row["retained_until"]) <= now:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights target custody record expired"
            )
        if any(
            row[key] != value
            for key, value in {
                "tenant_id": tenant,
                "case_id": _identifier(case_id, "case_id"),
                "source_id": _identifier(source_id, "source_id"),
                "operation_id": _identifier(operation_id, "operation_id"),
                "provider": provider,
                "target_binding_sha256": target_binding_sha256,
            }.items()
        ):
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights target custody binding changed"
            )
        from maverick.crypto_at_rest import unseal

        with tenant_scope(tenant=tenant):
            raw = unseal(bytes(row["encrypted_target"]))
        try:
            target_id = raw.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights target custody content is invalid"
            ) from exc
        _identifier(target_id, "target_id")
        if _canonical_sha256(
            self._target_material(
                tenant_id=tenant,
                case_id=case_id,
                source_id=source_id,
                provider=provider,
                operation_id=operation_id,
                target_id=target_id,
            )
        ) != target_binding_sha256:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights target custody digest changed"
            )
        return target_id


class GovernedVaultRetrievalSink:
    """Adapt the stock encrypted document vault to retrieval-artifact custody."""

    def __init__(
        self,
        *,
        tenant_id: str,
        vault: object,
        principal_ref: str,
        index_path: str | Path | None = None,
    ) -> None:
        self.tenant_id = canonical_tenant_id(tenant_id)
        self.vault = vault
        self.principal_ref = _identifier(principal_ref, "principal_ref")
        self.index_path = None if index_path is None else Path(index_path)
        self._memory: dict[str, adapters.ArtifactReceipt] = {}
        if self.index_path is not None:
            ensure_private_directory(self.index_path.parent)
            with self._index_connect() as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS privacy_rights_retrieval_index("
                    "operation_sha256 TEXT PRIMARY KEY,document_ref TEXT NOT NULL,"
                    "content_sha256 TEXT NOT NULL,record_count INTEGER NOT NULL,"
                    "safe_display_name TEXT NOT NULL)"
                )
            ensure_private_file(self.index_path)

    def _index_connect(self) -> sqlite3.Connection:
        if self.index_path is None:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights retrieval index is unavailable"
            )
        connection = sqlite3.connect(
            self.index_path, timeout=30.0, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _receipt(
        document_ref: object,
        *,
        sha256: str,
        record_count: int,
    ) -> adapters.ArtifactReceipt:
        return adapters.ArtifactReceipt(
            opaque_ref=_identifier(document_ref, "document_ref"),
            sha256=sha256,
            record_count=record_count,
            tenant_bound=True,
            encrypted_at_rest=True,
            retention_enforced=True,
        )

    def store(  # noqa: C901
        self,
        *,
        tenant_id: str,
        case_id: str,
        source_id: str,
        operation_id: str,
        content_type: str,
        body: bytes,
        sha256: str,
        record_count: int,
    ) -> adapters.ArtifactReceipt:
        tenant = canonical_tenant_id(tenant_id)
        if tenant != self.tenant_id:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights retrieval crossed its tenant"
            )
        for value, label in (
            (case_id, "case_id"),
            (source_id, "source_id"),
            (operation_id, "operation_id"),
        ):
            _identifier(value, label)
        if (
            not isinstance(body, bytes)
            or not body
            or hashlib.sha256(body).hexdigest() != sha256
            or not str(content_type or "").lower().startswith("application/json")
            or isinstance(record_count, bool)
            or not isinstance(record_count, int)
            or record_count < 0
        ):
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights retrieval artifact is invalid"
            )
        display_digest = hashlib.sha256(
            f"{case_id}\x00{source_id}\x00{operation_id}".encode()
        ).hexdigest()
        display_name = f"privacy-rights-{display_digest[:24]}.json"
        operation_sha256 = hashlib.sha256(
            f"{tenant}\x00{case_id}\x00{source_id}\x00{operation_id}".encode()
        ).hexdigest()
        in_memory = self._memory.get(operation_sha256)
        if in_memory is not None:
            if in_memory.sha256 != sha256 or in_memory.record_count != record_count:
                raise PrivacyRightsSourceCompositionError(
                    "privacy-rights retrieval operation changed"
                )
            return in_memory
        index_connection: sqlite3.Connection | None = None
        try:
            if self.index_path is not None:
                index_connection = self._index_connect()
                index_connection.execute("BEGIN IMMEDIATE")
                indexed = index_connection.execute(
                    "SELECT * FROM privacy_rights_retrieval_index "
                    "WHERE operation_sha256=?",
                    (operation_sha256,),
                ).fetchone()
                if indexed is not None:
                    if (
                        indexed["content_sha256"] != sha256
                        or indexed["record_count"] != record_count
                        or indexed["safe_display_name"] != display_name
                    ):
                        raise PrivacyRightsSourceCompositionError(
                            "privacy-rights retrieval operation changed"
                        )
                    record = self.vault.get(indexed["document_ref"])
                    if (
                        getattr(record, "content_sha256", None) != sha256
                        or getattr(record, "byte_size", None) != len(body)
                    ):
                        raise PrivacyRightsSourceCompositionError(
                            "privacy-rights retrieval custody receipt is invalid"
                        )
                    receipt = self._receipt(
                        indexed["document_ref"],
                        sha256=sha256,
                        record_count=record_count,
                    )
                    self._memory[operation_sha256] = receipt
                    index_connection.commit()
                    index_connection.close()
                    return receipt
                # Recover an ingest that committed before orchestration state did.
                list_documents = getattr(self.vault, "list_documents", None)
                if callable(list_documents):
                    listed = tuple(list_documents(state="active", limit=500))
                    candidates = [
                        item
                        for item in listed
                        if getattr(item, "safe_display_name", None) == display_name
                    ]
                    matches = [
                        item
                        for item in candidates
                        if getattr(item, "content_sha256", None) == sha256
                        and getattr(item, "byte_size", None) == len(body)
                    ]
                    if candidates and len(matches) != len(candidates):
                        raise PrivacyRightsSourceCompositionError(
                            "privacy-rights retrieval operation changed"
                        )
                    if len(matches) > 1:
                        raise PrivacyRightsSourceCompositionError(
                            "privacy-rights retrieval custody is ambiguous"
                        )
                    if matches:
                        record = matches[0]
                        index_connection.execute(
                            "INSERT INTO privacy_rights_retrieval_index "
                            "VALUES(?,?,?,?,?)",
                            (
                                operation_sha256,
                                record.document_ref,
                                sha256,
                                record_count,
                                display_name,
                            ),
                        )
                        receipt = self._receipt(
                            record.document_ref,
                            sha256=sha256,
                            record_count=record_count,
                        )
                        self._memory[operation_sha256] = receipt
                        index_connection.commit()
                        index_connection.close()
                        return receipt
                    count_records = getattr(self.vault, "context_record_count", None)
                    if (
                        (callable(count_records) and count_records() > len(listed))
                        or (not callable(count_records) and len(listed) >= 500)
                    ):
                        raise PrivacyRightsSourceCompositionError(
                            "privacy-rights retrieval recovery scan is incomplete"
                        )
            record = self.vault.ingest(
                body,
                principal_ref=self.principal_ref,
                product_area="privacy_automation",
                record_type="privacy_rights_source_retrieval",
                safe_display_name=display_name,
                media_type="application/json",
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            if index_connection is not None:
                index_connection.rollback()
                index_connection.close()
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights retrieval custody is unavailable"
            ) from exc
        if (
            getattr(record, "content_sha256", None) != sha256
            or getattr(record, "byte_size", None) != len(body)
        ):
            if index_connection is not None:
                index_connection.rollback()
                index_connection.close()
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights retrieval custody receipt is invalid"
            )
        receipt = self._receipt(
            getattr(record, "document_ref", None),
            sha256=sha256,
            record_count=record_count,
        )
        if index_connection is not None:
            try:
                index_connection.execute(
                    "INSERT INTO privacy_rights_retrieval_index VALUES(?,?,?,?,?)",
                    (
                        operation_sha256,
                        receipt.opaque_ref,
                        sha256,
                        record_count,
                        display_name,
                    ),
                )
                index_connection.commit()
            except (KeyboardInterrupt, SystemExit):
                index_connection.rollback()
                index_connection.close()
                raise
            except Exception as exc:
                index_connection.rollback()
                index_connection.close()
                raise PrivacyRightsSourceCompositionError(
                    "privacy-rights retrieval custody index is unavailable"
                ) from exc
            index_connection.close()
        self._memory[operation_sha256] = receipt
        return receipt


def _transport_for(app: Any, tenant_id: str) -> adapters.HTTPTransport:
    factory = getattr(app.state, "privacy_rights_source_transport_factory", None)
    if factory is None:
        return PinnedPrivacyRightsHTTPTransport()
    if not callable(factory):
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source transport factory is invalid"
        )
    selected = factory(tenant_id)
    if not callable(getattr(selected, "request", None)):
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source transport is invalid"
        )
    return selected


def _subject_resolver_for(app: Any, tenant_id: str, request: object):
    factory = getattr(
        app.state, "privacy_rights_source_subject_resolver_factory", None
    )
    if callable(factory):
        selected = factory(tenant_id=tenant_id, request=request)
    else:
        selected = getattr(app.state, "privacy_rights_source_subject_resolver", None)
    if not callable(selected):
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights subject authority is unavailable"
        )
    return selected


def _artifact_sink_for(app: Any, tenant_id: str, principal_ref: str):
    factory = getattr(app.state, "privacy_rights_source_artifact_sink_factory", None)
    if factory is not None and not callable(factory):
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights retrieval sink factory is invalid"
        )
    if callable(factory):
        selected = factory(tenant_id=tenant_id, principal_ref=principal_ref)
        if not callable(getattr(selected, "store", None)):
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights retrieval sink is invalid"
            )
        return selected
    try:
        from .governed_document_vault_composition import governed_document_vault_store

        vault = governed_document_vault_store(tenant_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights retrieval sink is unavailable"
        ) from exc
    return GovernedVaultRetrievalSink(
        tenant_id=tenant_id,
        vault=vault,
        principal_ref=principal_ref,
        index_path=data_dir(
            "privacy_automation",
            "privacy-rights-retrieval-index.sqlite3",
            tenant=tenant_id,
        ),
    )


def _target_custody_for(
    app: Any,
    tenant_id: str,
    settings: PrivacyRightsSourceSettings,
    clock: Callable[[], float],
):
    factory = getattr(
        app.state, "privacy_rights_source_target_custody_factory", None
    )
    if factory is not None and not callable(factory):
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights target custody factory is invalid"
        )
    if callable(factory):
        selected = factory(tenant_id=tenant_id)
        if (
            not callable(getattr(selected, "store", None))
            or not callable(getattr(selected, "resolve", None))
        ):
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights target custody is invalid"
            )
        return selected
    return EncryptedMutationTargetCustody(
        tenant_id=tenant_id,
        path=data_dir(
            "privacy_automation",
            "privacy-rights-target-custody.sqlite3",
            tenant=tenant_id,
        ),
        retention_seconds=settings.target_custody_retention_seconds,
        clock=clock,
    )


def _credential_for(
    app: Any,
    settings: PrivacyRightsSourceSettings,
    expected_tenant_id: str,
    tenant_id: str,
    source_id: str,
    credential_ref: str,
) -> str:
    source = next(
        (item for item in settings.sources if item.source_id == source_id), None
    )
    if (
        source is None
        or source.credential_ref != credential_ref
        or canonical_tenant_id(tenant_id) != expected_tenant_id
    ):
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source credential binding is invalid"
        )
    custom = getattr(app.state, "privacy_rights_source_credential_resolver", None)
    if custom is not None:
        if not callable(custom):
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights credential resolver is invalid"
            )
        return custom(tenant_id, source_id, credential_ref)
    match = _SECRET_REF_RE.fullmatch(credential_ref)
    if match is None:
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source credential reference is invalid"
        )
    from maverick.secret_provider import get_secret

    selected = get_secret(match.group(1))
    if not isinstance(selected, str) or not selected.strip():
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source credential is unavailable"
        )
    return selected.strip()


def build_worker(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> worker.PrivacyRightsSourceWorker:
    tenant = canonical_tenant_id(tenant_id)
    principal = _identifier(principal_ref, "principal_ref")
    settings = settings_for_tenant(tenant)
    if not settings.enabled:
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source adapters are disabled"
        )
    transport = _transport_for(app, tenant)
    subject_resolver = _subject_resolver_for(app, tenant, request)
    clock = getattr(app.state, "privacy_rights_source_clock", time.time)
    if not callable(clock):
        raise PrivacyRightsSourceCompositionError(
            "privacy-rights source clock is unavailable"
        )
    sink = (
        _artifact_sink_for(app, tenant, principal)
        if any("retrieve" in source.capabilities for source in settings.sources)
        else None
    )
    target_custody = (
        _target_custody_for(app, tenant, settings, clock)
        if any("delete" in source.capabilities for source in settings.sources)
        else None
    )
    configured = {source.source_id: source for source in settings.sources}

    def same_config() -> None:
        if settings_for_tenant(tenant).config_sha256 != settings.config_sha256:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights source configuration changed"
            )

    def store_factory(requested_tenant: str, worker_ref: str):
        same_config()
        if canonical_tenant_id(requested_tenant) != tenant:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights source worker crossed its tenant"
            )
        actor = _identifier(worker_ref, "worker_ref")
        return rights.PrivacyRightsOrchestrationStore(
            data_dir(
                "privacy_automation",
                "privacy-rights-orchestration.sqlite3",
                tenant=tenant,
            ),
            config_gate=rights.require_enabled,
            principal_resolver=lambda: actor,
            clock=clock,
            claim_history_retention_seconds=(
                settings.claim_history_retention_seconds
            ),
        )

    def adapter_resolver(requested_tenant: str, source_id: str):
        same_config()
        if canonical_tenant_id(requested_tenant) != tenant:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights source adapter crossed its tenant"
            )
        source = configured.get(source_id)
        if source is None:
            raise PrivacyRightsSourceCompositionError(
                "privacy-rights source adapter is not configured"
            )
        selected = adapters.StockPrivacyRightsSourceAdapter(
            provider=source.provider,
            origin=source.origin,
            transport=transport,
            artifact_sink=sink,
            target_custody=target_custody,
            limits=settings.limits,
        )
        authority = worker.adapter_authority_sha256(
            tenant_id=tenant,
            source_id=source.source_id,
            adapter_ref=source.adapter_ref,
            credential_ref=source.credential_ref,
            capabilities=source.capabilities,
        )
        return worker.AdapterBinding(
            tenant_id=tenant,
            source_id=source.source_id,
            adapter_ref=source.adapter_ref,
            credential_ref=source.credential_ref,
            capabilities=source.capabilities,
            authority_sha256=authority,
            adapter=selected,
            provider_contract=f"stock:{source.provider}:v2-exact-target",
        )

    return worker.PrivacyRightsSourceWorker(
        store_factory=store_factory,
        subject_resolver=subject_resolver,
        credential_resolver=lambda requested_tenant, source_id, credential_ref: (
            _credential_for(
                app,
                settings,
                tenant,
                requested_tenant,
                source_id,
                credential_ref,
            )
        ),
        adapter_resolver=adapter_resolver,
        owned_source_ids=tuple(sorted(configured)),
        clock=clock,
        default_batch_size=settings.batch_size,
        maximum_batch_size=settings.batch_size,
        default_lease_seconds=settings.lease_seconds,
        minimum_lease_seconds=(
            math.ceil(float(settings.limits.timeout_seconds) * 2) + 5
        ),
        maximum_lease_seconds=settings.lease_seconds,
        default_retry_delay_seconds=settings.retry_delay_seconds,
        maximum_retry_delay_seconds=settings.retry_delay_seconds,
    )


def readiness(app: Any, tenant_id: str) -> Mapping[str, object]:
    """Return configuration readiness without opening storage or provider I/O."""

    tenant = canonical_tenant_id(tenant_id)
    try:
        settings = settings_for_tenant(tenant)
        # Constructing adapters validates exact origins and local transport
        # proof only; it resolves no secret and invokes no request.
        transport = PinnedPrivacyRightsHTTPTransport()
        for source in settings.sources:
            adapters.StockPrivacyRightsSourceAdapter(
                provider=source.provider,
                origin=source.origin,
                transport=transport,
                limits=settings.limits,
            )
        config_valid = True
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        settings = None
        config_valid = False
    subject_ready = callable(
        getattr(app.state, "privacy_rights_source_subject_resolver_factory", None)
    ) or callable(
        getattr(app.state, "privacy_rights_source_subject_resolver", None)
    )
    custom_sink = callable(
        getattr(app.state, "privacy_rights_source_artifact_sink_factory", None)
    )
    local_sink = False
    if settings is not None and any(
        "retrieve" in source.capabilities for source in settings.sources
    ):
        try:
            from .governed_document_vault_composition import (
                governed_document_vault_enabled,
            )

            local_sink = governed_document_vault_enabled(tenant)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            local_sink = False
    retrieval_required = bool(
        settings
        and any("retrieve" in source.capabilities for source in settings.sources)
    )
    configured = bool(settings and settings.enabled and settings.sources)
    artifact_ready = not retrieval_required or custom_sink or local_sink
    mutation_required = bool(
        settings
        and any("delete" in source.capabilities for source in settings.sources)
    )
    target_custody_configured = not mutation_required or callable(
        getattr(
            app.state,
            "privacy_rights_source_target_custody_factory",
            None,
        )
    ) or bool(settings)
    configuration_ready = (
        configured
        and config_valid
        and subject_ready
        and artifact_ready
        and target_custody_configured
    )
    return {
        "schema": "lightwork.privacy-rights-source-readiness.v1",
        "tenant_id": tenant,
        "enabled": bool(settings and settings.enabled),
        "configured": configured,
        "ready": False,
        "configuration_preflight_ready": configuration_ready,
        "executable_ready": False,
        "config_valid": config_valid,
        "config_sha256": settings.config_sha256 if settings else None,
        "configured_sources": (
            [
                {
                    "source_id": source.source_id,
                    "provider": source.provider,
                    "adapter_ref": source.adapter_ref,
                    "credential_ref": source.credential_ref,
                    "capabilities": list(source.capabilities),
                }
                for source in settings.sources
            ]
            if settings
            else []
        ),
        "subject_authority_resolver_installed": subject_ready,
        "retrieval_artifact_sink_ready": artifact_ready,
        "stock_encrypted_vault_sink_configured": local_sink,
        "encrypted_target_custody_configured": target_custody_configured,
        "credential_preflight_performed": False,
        "execution_preflight_required": configuration_ready,
        "credential_values_resolved": False,
        "status_probe_opened_store": False,
        "status_probe_invoked_provider": False,
        "status_probe_resolved_secret": False,
        "provider_writes_performed": False,
        "provider_writes_possible": bool(
            settings
            and any("delete" in source.capabilities for source in settings.sources)
        ),
        "live_provider_acceptance_verified": False,
        "estate_completeness_claimed": False,
    }


def attach_privacy_rights_source_composition(app: Any) -> None:
    state = app.state

    def install(name: str, value: Callable[..., object]) -> None:
        current = getattr(state, name, None)
        if current is None:
            setattr(state, name, value)
        elif not callable(current):
            raise TypeError(f"{name} must be callable")

    install(
        "privacy_rights_source_worker_factory",
        lambda **kwargs: build_worker(app, **kwargs),
    )
    install(
        "privacy_rights_source_readiness_probe",
        lambda tenant_id: readiness(app, tenant_id),
    )


__all__ = [
    "EncryptedMutationTargetCustody",
    "GovernedVaultRetrievalSink",
    "PinnedPrivacyRightsHTTPTransport",
    "PrivacyRightsSourceCompositionError",
    "PrivacyRightsSourceSettings",
    "SourceAdapterSettings",
    "attach_privacy_rights_source_composition",
    "build_worker",
    "readiness",
    "settings_for_tenant",
    "settings_from_config",
]
