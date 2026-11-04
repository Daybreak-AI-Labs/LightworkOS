"""Offline, tenant-bound adapters for the six unified-audit sources.

The suite stores do not currently share a public tenant-wide cursor/head
contract. These built-in adapters therefore require an explicitly injected,
source-owned history reader. They never inspect another subsystem's private
SQLite tables. Missing readers remain visible as incomplete coverage and are
not represented as registered core sources.

Only normalized action codes, sequences, timestamps, and SHA-256 commitments
cross the reader seam. This module has no HTTP registration, credential
resolution, or network path.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from maverick.paths import InvalidTenantError, canonical_tenant_id
from maverick.unified_audit import (
    SOURCE_ACTION_CODES,
    SOURCE_LIMITATION_CODES,
    DomainAuditSource,
    SourceAuthority,
    SourcePage,
    SourceRecord,
    SourceVerifier,
    build_source_page,
    build_source_record,
)

SOURCE_IDS = (
    "ai_governance",
    "consent_preferences",
    "data_use_governance",
    "privacy_automation",
    "tech_risk_compliance",
    "third_party_management",
)

_SOURCE_ID_SET = frozenset(SOURCE_IDS)
_GENESIS_SHA256 = "0" * 64
_MAX_PAGE_RECORDS = 500

# Public aliases keep dashboard callers on the core's single closed vocabulary.
ACTION_CODES = SOURCE_ACTION_CODES
LIMITATION_CODES = SOURCE_LIMITATION_CODES


class UnifiedAuditSourceAdapterError(RuntimeError):
    """A source cannot safely furnish a contract-validated digest-only page."""

    def __init__(self, error_code: str) -> None:
        super().__init__(error_code)
        self.error_code = error_code


@dataclass(frozen=True, slots=True)
class AuthoritativeAuditPage:
    """Source-owned page metadata plus normalized digest-only records.

    The adapter reconstructs the core page and requires ``page_sha256`` to
    match; page counts, ranges, and cursors are never trusted directly.
    """

    tenant_id: str
    source_id: str
    suite_id: str
    authority_revision: int
    authority_sha256: str
    source_schema_version: int
    after_sequence: int
    first_sequence: int
    last_sequence: int
    record_count: int
    prior_sha256: str
    head_sha256: str
    previous_page_sha256: str
    page_sha256: str
    terminal: bool
    complete: bool
    truncated: bool
    watermark: float
    limitations: tuple[str, ...]
    records: tuple[SourceRecord, ...]


@runtime_checkable
class AuthoritativeAuditHistoryReader(Protocol):
    """Lawful enumeration/head seam implemented by a suite's owning store."""

    def resolve_authority(
        self,
        *,
        tenant_id: str,
        source_id: str,
        suite_id: str,
    ) -> SourceAuthority: ...

    def read_history_page(
        self,
        *,
        tenant_id: str,
        source_id: str,
        suite_id: str,
        authority_revision: int,
        authority_sha256: str,
        source_schema_version: int,
        after_sequence: int,
        prior_sha256: str,
        previous_page_sha256: str,
        limit: int,
    ) -> AuthoritativeAuditPage: ...


@dataclass(frozen=True, slots=True)
class UnifiedAuditSourceStatus:
    schema: str
    source_id: str
    available: bool
    reader_available: bool
    verifier_available: bool
    page_contract_validated: bool
    source_page_complete: bool
    independently_verified: bool
    complete: bool
    truncated: bool
    limitations: tuple[str, ...]
    authority_revision: int | None
    authority_sha256: str | None
    source_schema_version: int | None
    pages_read: int
    record_count: int | None
    first_sequence: int | None
    last_sequence: int | None
    prior_sha256: str | None
    head_sha256: str | None
    previous_page_sha256: str | None
    page_sha256: str | None
    watermark: float | None


def _missing_status(
    source_id: str,
    *,
    reader_available: bool,
    verifier_available: bool,
) -> UnifiedAuditSourceStatus:
    limitations = []
    if not reader_available:
        limitations.append("authoritative_history_reader_unavailable")
    if not verifier_available:
        limitations.append("source_integrity_unverified")
    return UnifiedAuditSourceStatus(
        schema="lightwork.unified-audit-source-adapter-status.v1",
        source_id=source_id,
        available=reader_available and verifier_available,
        reader_available=reader_available,
        verifier_available=verifier_available,
        page_contract_validated=False,
        source_page_complete=False,
        independently_verified=False,
        complete=False,
        truncated=False,
        limitations=tuple(sorted(limitations)),
        authority_revision=None,
        authority_sha256=None,
        source_schema_version=None,
        pages_read=0,
        record_count=None,
        first_sequence=None,
        last_sequence=None,
        prior_sha256=None,
        head_sha256=None,
        previous_page_sha256=None,
        page_sha256=None,
        watermark=None,
    )


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (InvalidTenantError, TypeError) as exc:
        raise UnifiedAuditSourceAdapterError("source_tenant_invalid") from exc


def _source_id(value: object) -> str:
    if not isinstance(value, str) or value not in _SOURCE_ID_SET:
        raise UnifiedAuditSourceAdapterError("source_id_invalid")
    return value


def _integer(value: object, *, minimum: int, maximum: int, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise UnifiedAuditSourceAdapterError(code)
    return value


def _digest(value: object, *, code: str = "source_page_invalid") -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise UnifiedAuditSourceAdapterError(code)
    try:
        int(value, 16)
    except ValueError as exc:
        raise UnifiedAuditSourceAdapterError(code) from exc
    if value != value.lower():
        raise UnifiedAuditSourceAdapterError(code)
    return value


def _limitations(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or len(value) > len(LIMITATION_CODES):
        raise UnifiedAuditSourceAdapterError("source_page_invalid")
    if (
        any(not isinstance(item, str) or item not in LIMITATION_CODES for item in value)
        or tuple(sorted(set(value))) != value
    ):
        raise UnifiedAuditSourceAdapterError("source_page_invalid")
    return value


def _authority_exact(
    value: object,
    *,
    tenant_id: str,
    source_id: str,
) -> SourceAuthority:
    if type(value) is not SourceAuthority:
        raise UnifiedAuditSourceAdapterError("source_authority_invalid")
    authority = value
    if (
        authority.tenant_id != tenant_id
        or authority.source_id != source_id
        or authority.suite_id != source_id
        or _integer(
            authority.authority_revision,
            minimum=1,
            maximum=2**31 - 1,
            code="source_authority_invalid",
        )
        != authority.authority_revision
        or _integer(
            authority.source_schema_version,
            minimum=1,
            maximum=2**31 - 1,
            code="source_authority_invalid",
        )
        != authority.source_schema_version
        or _digest(authority.authority_sha256, code="source_authority_invalid") == _GENESIS_SHA256
    ):
        raise UnifiedAuditSourceAdapterError("source_authority_invalid")
    return authority


def _authority_equal(left: SourceAuthority, right: SourceAuthority) -> bool:
    return (
        left.tenant_id == right.tenant_id
        and left.source_id == right.source_id
        and left.suite_id == right.suite_id
        and left.authority_revision == right.authority_revision
        and left.source_schema_version == right.source_schema_version
        and hmac.compare_digest(left.authority_sha256, right.authority_sha256)
    )


class TenantBoundUnifiedAuditSource:
    """Turn one source-owned page into a contract-validated core ``SourcePage``."""

    __slots__ = (
        "_lock",
        "_max_page_records",
        "_reader",
        "_source_id",
        "_status",
        "_tenant_id",
    )

    def __init__(
        self,
        *,
        tenant_id: str,
        source_id: str,
        reader: AuthoritativeAuditHistoryReader,
        max_page_records: int,
    ) -> None:
        self._tenant_id = _tenant(tenant_id)
        self._source_id = _source_id(source_id)
        if not isinstance(reader, AuthoritativeAuditHistoryReader):
            raise UnifiedAuditSourceAdapterError("source_reader_invalid")
        self._reader = reader
        self._max_page_records = _integer(
            max_page_records,
            minimum=1,
            maximum=_MAX_PAGE_RECORDS,
            code="source_page_limit_invalid",
        )
        self._lock = threading.RLock()
        self._status = replace(
            _missing_status(
                self._source_id,
                reader_available=True,
                verifier_available=True,
            ),
            limitations=("source_page_incomplete",),
        )

    def _mark_incomplete(self, error_code: str) -> None:
        limitation = error_code if error_code in LIMITATION_CODES else "source_history_unavailable"
        with self._lock:
            self._status = replace(
                self._status,
                page_contract_validated=False,
                source_page_complete=False,
                independently_verified=False,
                complete=False,
                limitations=(limitation,),
            )

    def _resolve_authority(self) -> SourceAuthority:
        try:
            value = self._reader.resolve_authority(
                tenant_id=self._tenant_id,
                source_id=self._source_id,
                suite_id=self._source_id,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except UnifiedAuditSourceAdapterError:
            raise
        except Exception as exc:
            raise UnifiedAuditSourceAdapterError("source_authority_invalid") from exc
        return _authority_exact(
            value,
            tenant_id=self._tenant_id,
            source_id=self._source_id,
        )

    def authority(self) -> SourceAuthority:
        try:
            authority = self._resolve_authority()
        except UnifiedAuditSourceAdapterError as exc:
            self._mark_incomplete(exc.error_code)
            raise
        with self._lock:
            self._status = replace(
                self._status,
                authority_revision=authority.authority_revision,
                authority_sha256=authority.authority_sha256,
                source_schema_version=authority.source_schema_version,
            )
        return authority

    @staticmethod
    def _records_exact(
        page: AuthoritativeAuditPage,
        *,
        after_sequence: int,
        prior_sha256: str,
        limit: int,
    ) -> None:
        if (
            not isinstance(page.records, tuple)
            or len(page.records) != page.record_count
            or page.record_count > limit
        ):
            raise UnifiedAuditSourceAdapterError("source_page_invalid")
        sequence = after_sequence + 1
        previous = prior_sha256
        for record in page.records:
            if (
                type(record) is not SourceRecord
                or record.action not in ACTION_CODES
                or isinstance(record.occurred_at, bool)
                or not isinstance(record.occurred_at, (int, float))
            ):
                raise UnifiedAuditSourceAdapterError("source_page_invalid")
            try:
                expected = build_source_record(
                    sequence=record.sequence,
                    occurred_at=record.occurred_at,
                    action=record.action,
                    actor_sha256=_digest(record.actor_sha256),
                    resource_sha256=_digest(record.resource_sha256),
                    payload_sha256=_digest(record.payload_sha256),
                    previous_sha256=_digest(record.previous_sha256),
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise UnifiedAuditSourceAdapterError("source_page_invalid") from exc
            if (
                record.sequence != sequence
                or not hmac.compare_digest(record.previous_sha256, previous)
                or not hmac.compare_digest(record.record_sha256, expected.record_sha256)
            ):
                raise UnifiedAuditSourceAdapterError("source_page_invalid")
            previous = record.record_sha256
            sequence += 1

    @staticmethod
    def _page_shape_exact(page: AuthoritativeAuditPage, *, limit: int) -> None:
        _integer(
            page.authority_revision,
            minimum=1,
            maximum=2**31 - 1,
            code="source_page_invalid",
        )
        _integer(
            page.source_schema_version,
            minimum=1,
            maximum=2**31 - 1,
            code="source_page_invalid",
        )
        _digest(page.authority_sha256)
        for value in (
            page.after_sequence,
            page.first_sequence,
            page.last_sequence,
            page.record_count,
        ):
            _integer(
                value,
                minimum=0,
                maximum=2**63 - 1,
                code="source_page_invalid",
            )
        for value in (
            page.prior_sha256,
            page.head_sha256,
            page.previous_page_sha256,
            page.page_sha256,
        ):
            _digest(value)
        limitations = _limitations(page.limitations)
        if any(type(value) is not bool for value in (page.terminal, page.complete, page.truncated)):
            raise UnifiedAuditSourceAdapterError("source_page_invalid")
        if page.complete and (not page.terminal or page.truncated or limitations):
            raise UnifiedAuditSourceAdapterError("source_page_invalid")
        if (page.truncated or not page.complete) and not limitations:
            raise UnifiedAuditSourceAdapterError("source_page_invalid")
        if not page.terminal and page.record_count != limit:
            raise UnifiedAuditSourceAdapterError("source_page_invalid")
        if page.records:
            if (
                page.first_sequence != page.after_sequence + 1
                or page.last_sequence != page.after_sequence + page.record_count
            ):
                raise UnifiedAuditSourceAdapterError("source_page_invalid")
        elif (
            page.first_sequence != page.after_sequence or page.last_sequence != page.after_sequence
        ):
            raise UnifiedAuditSourceAdapterError("source_page_invalid")

    def read_page(
        self,
        *,
        after_sequence: int,
        prior_sha256: str,
        previous_page_sha256: str,
        limit: int,
    ) -> SourcePage:
        after = _integer(
            after_sequence,
            minimum=0,
            maximum=2**63 - 1,
            code="source_page_invalid",
        )
        prior = _digest(prior_sha256)
        previous_page = _digest(previous_page_sha256)
        bounded = _integer(
            limit,
            minimum=1,
            maximum=self._max_page_records,
            code="source_page_limit_invalid",
        )
        try:
            authority = self._resolve_authority()
            page = self._reader.read_history_page(
                tenant_id=self._tenant_id,
                source_id=self._source_id,
                suite_id=self._source_id,
                authority_revision=authority.authority_revision,
                authority_sha256=authority.authority_sha256,
                source_schema_version=authority.source_schema_version,
                after_sequence=after,
                prior_sha256=prior,
                previous_page_sha256=previous_page,
                limit=bounded,
            )
            if type(page) is not AuthoritativeAuditPage:
                raise UnifiedAuditSourceAdapterError("source_page_invalid")
            if (
                page.tenant_id != self._tenant_id
                or page.source_id != self._source_id
                or page.suite_id != self._source_id
                or page.authority_revision != authority.authority_revision
                or page.source_schema_version != authority.source_schema_version
                or not hmac.compare_digest(page.authority_sha256, authority.authority_sha256)
                or page.after_sequence != after
                or not hmac.compare_digest(page.prior_sha256, prior)
                or not hmac.compare_digest(page.previous_page_sha256, previous_page)
            ):
                raise UnifiedAuditSourceAdapterError("source_page_invalid")
            self._page_shape_exact(page, limit=bounded)
            self._records_exact(
                page,
                after_sequence=after,
                prior_sha256=prior,
                limit=bounded,
            )
            try:
                built = build_source_page(
                    authority,
                    after_sequence=after,
                    prior_sha256=prior,
                    previous_page_sha256=previous_page,
                    records=page.records,
                    terminal=page.terminal,
                    complete=page.complete,
                    truncated=page.truncated,
                    watermark=page.watermark,
                    limitations=page.limitations,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise UnifiedAuditSourceAdapterError("source_page_invalid") from exc
            if (
                built.first_sequence != page.first_sequence
                or built.last_sequence != page.last_sequence
                or built.record_count != page.record_count
                or not hmac.compare_digest(built.head_sha256, page.head_sha256)
                or not hmac.compare_digest(built.page_sha256, page.page_sha256)
            ):
                raise UnifiedAuditSourceAdapterError("source_page_invalid")
            authority_after = self._resolve_authority()
            if not _authority_equal(authority, authority_after):
                raise UnifiedAuditSourceAdapterError("source_authority_changed")
        except (KeyboardInterrupt, SystemExit):
            raise
        except UnifiedAuditSourceAdapterError as exc:
            self._mark_incomplete(exc.error_code)
            raise
        except Exception as exc:
            self._mark_incomplete("source_history_unavailable")
            raise UnifiedAuditSourceAdapterError("source_history_unavailable") from exc
        with self._lock:
            self._status = UnifiedAuditSourceStatus(
                schema="lightwork.unified-audit-source-adapter-status.v1",
                source_id=self._source_id,
                available=True,
                reader_available=True,
                verifier_available=True,
                page_contract_validated=True,
                source_page_complete=page.complete,
                independently_verified=False,
                complete=False,
                truncated=page.truncated,
                limitations=page.limitations,
                authority_revision=authority.authority_revision,
                authority_sha256=authority.authority_sha256,
                source_schema_version=authority.source_schema_version,
                pages_read=self._status.pages_read + 1,
                record_count=page.record_count,
                first_sequence=page.first_sequence,
                last_sequence=page.last_sequence,
                prior_sha256=page.prior_sha256,
                head_sha256=page.head_sha256,
                previous_page_sha256=page.previous_page_sha256,
                page_sha256=built.page_sha256,
                watermark=page.watermark,
            )
        return built

    def status(self) -> UnifiedAuditSourceStatus:
        with self._lock:
            return self._status


class UnifiedAuditSourceComposition:
    """Fixed source slots plus explicit unavailable/incomplete coverage."""

    __slots__ = (
        "_adapters",
        "_missing",
        "_reader_source_ids",
        "_sources",
        "_tenant_sha256",
        "_verifier_source_ids",
        "_verifiers",
    )

    def __init__(
        self,
        *,
        tenant_id: str,
        adapters: Mapping[str, TenantBoundUnifiedAuditSource],
        verifiers: Mapping[str, SourceVerifier],
        reader_source_ids: frozenset[str],
        verifier_source_ids: frozenset[str],
    ) -> None:
        tenant = _tenant(tenant_id)
        if (
            set(adapters) - _SOURCE_ID_SET
            or set(verifiers) != set(adapters)
            or reader_source_ids - _SOURCE_ID_SET
            or verifier_source_ids - _SOURCE_ID_SET
            or set(adapters) != reader_source_ids & verifier_source_ids
        ):
            raise UnifiedAuditSourceAdapterError("source_id_invalid")
        concrete: dict[str, TenantBoundUnifiedAuditSource] = {}
        sources: dict[str, DomainAuditSource] = {}
        for source_id, adapter in adapters.items():
            if type(adapter) is not TenantBoundUnifiedAuditSource:
                raise UnifiedAuditSourceAdapterError("source_adapter_invalid")
            if adapter._tenant_id != tenant or adapter._source_id != source_id:
                raise UnifiedAuditSourceAdapterError("source_adapter_mismatch")
            concrete[source_id] = adapter
            sources[source_id] = adapter
        checked_verifiers: dict[str, SourceVerifier] = {}
        for source_id, verifier in verifiers.items():
            if not isinstance(verifier, SourceVerifier):
                raise UnifiedAuditSourceAdapterError("source_verifier_invalid")
            checked_verifiers[source_id] = verifier
        self._adapters = MappingProxyType(concrete)
        self._sources = MappingProxyType(sources)
        self._verifiers = MappingProxyType(checked_verifiers)
        self._reader_source_ids = reader_source_ids
        self._verifier_source_ids = verifier_source_ids
        self._missing = MappingProxyType(
            {
                source_id: _missing_status(
                    source_id,
                    reader_available=source_id in reader_source_ids,
                    verifier_available=source_id in verifier_source_ids,
                )
                for source_id in SOURCE_IDS
                if source_id not in sources
            }
        )
        self._tenant_sha256 = hashlib.sha256(
            f"lightwork.unified-audit-source-adapters.v1:{tenant}".encode()
        ).hexdigest()

    @property
    def sources(self) -> Mapping[str, DomainAuditSource]:
        return self._sources

    @property
    def verifiers(self) -> Mapping[str, SourceVerifier]:
        return self._verifiers

    def status(self) -> Mapping[str, object]:
        statuses = tuple(
            self._adapters[source_id].status()
            if source_id in self._adapters
            else self._missing[source_id]
            for source_id in SOURCE_IDS
        )
        return {
            "schema": "lightwork.unified-audit-source-composition-status.v1",
            "tenant_sha256": self._tenant_sha256,
            "source_count": len(self._sources),
            "reader_count": len(self._reader_source_ids),
            "verifier_count": len(self._verifier_source_ids),
            "required_source_count": len(SOURCE_IDS),
            "source_pages_complete": len(self._sources) == len(SOURCE_IDS)
            and all(item.source_page_complete for item in statuses),
            # Independent verifier acceptance and signed-sink currentness are
            # owned by the core projector/store, never inferred here.
            "complete": False,
            "independent_verification_accepted": False,
            "sources": tuple(asdict(item) for item in statuses),
            "network_io": False,
            "private_store_tables_read": False,
            "live_source_interoperability_verified": False,
        }


def build_unified_audit_source_composition(
    *,
    tenant_id: str,
    readers: Mapping[str, AuthoritativeAuditHistoryReader],
    verifiers: Mapping[str, SourceVerifier] | None = None,
    max_page_records: int = 500,
) -> UnifiedAuditSourceComposition:
    """Expose only fixed sources with both a reader and independent verifier."""

    tenant = _tenant(tenant_id)
    selected_readers = dict(readers)
    selected_verifiers = {} if verifiers is None else dict(verifiers)
    if set(selected_readers) - _SOURCE_ID_SET or set(selected_verifiers) - _SOURCE_ID_SET:
        raise UnifiedAuditSourceAdapterError("source_id_invalid")
    for reader in selected_readers.values():
        if not isinstance(reader, AuthoritativeAuditHistoryReader):
            raise UnifiedAuditSourceAdapterError("source_reader_invalid")
    for verifier in selected_verifiers.values():
        if not isinstance(verifier, SourceVerifier):
            raise UnifiedAuditSourceAdapterError("source_verifier_invalid")
    maximum = _integer(
        max_page_records,
        minimum=1,
        maximum=_MAX_PAGE_RECORDS,
        code="source_page_limit_invalid",
    )
    eligible = set(selected_readers) & set(selected_verifiers)
    adapters = {
        source_id: TenantBoundUnifiedAuditSource(
            tenant_id=tenant,
            source_id=source_id,
            reader=selected_readers[source_id],
            max_page_records=maximum,
        )
        for source_id in eligible
    }
    return UnifiedAuditSourceComposition(
        tenant_id=tenant,
        adapters=adapters,
        verifiers={source_id: selected_verifiers[source_id] for source_id in eligible},
        reader_source_ids=frozenset(selected_readers),
        verifier_source_ids=frozenset(selected_verifiers),
    )


__all__ = [
    "ACTION_CODES",
    "AuthoritativeAuditHistoryReader",
    "AuthoritativeAuditPage",
    "LIMITATION_CODES",
    "SOURCE_IDS",
    "TenantBoundUnifiedAuditSource",
    "UnifiedAuditSourceAdapterError",
    "UnifiedAuditSourceComposition",
    "UnifiedAuditSourceStatus",
    "build_unified_audit_source_composition",
]
