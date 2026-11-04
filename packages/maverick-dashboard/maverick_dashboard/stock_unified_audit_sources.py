"""Stock, read-only unified-audit authorities for six governance suites.

Each backend reuses a source-owned history API or the central signed audit
reader.  The shared :mod:`maverick.suite_audit_capture` contract keeps this
capture layer reusable by inventory and other governance projections.  These
stock sources deliberately disclose that each canonical history is narrower
than an entire OneTrust-sized suite and that local retention is not an accepted
off-host/WORM boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import time
from dataclasses import fields

from maverick.paths import canonical_tenant_id
from maverick.stock_suite_audit_capture import (
    STOCK_SOURCE_SCHEMA_VERSIONS,
    StockSuiteAuditCaptureProvider,
)
from maverick.suite_audit_capture import (
    SuiteAuditCapture,
    SuiteAuditCaptureError,
    SuiteAuditCaptureProvider,
)
from maverick.unified_audit import (
    GENESIS_SHA256,
    SOURCE_LIMITATION_CODES,
    SourceAuthority,
    SourcePage,
    SourceVerification,
    build_source_page,
)

from .unified_audit_sources import (
    SOURCE_IDS,
    AuthoritativeAuditPage,
    UnifiedAuditSourceAdapterError,
)

_SOURCE_SCHEMA_VERSIONS = STOCK_SOURCE_SCHEMA_VERSIONS


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _clock_value(clock) -> float:
    try:
        value = clock()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise SuiteAuditCaptureError("source_head_unavailable") from exc
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SuiteAuditCaptureError("source_head_unavailable")
    selected = float(value)
    if not math.isfinite(selected) or selected <= 0:
        raise SuiteAuditCaptureError("source_head_unavailable")
    return selected


class StockUnifiedAuditHistoryReader:
    """Authoritative reader over one reusable stock capture provider."""

    def __init__(
        self,
        *,
        tenant_id: str,
        source_id: str,
        provider: SuiteAuditCaptureProvider,
    ) -> None:
        self._tenant_id = canonical_tenant_id(tenant_id)
        if source_id not in SOURCE_IDS or not isinstance(
            provider,
            SuiteAuditCaptureProvider,
        ):
            raise UnifiedAuditSourceAdapterError("source_reader_invalid")
        self._source_id = source_id
        self._provider = provider

    def _authority(self) -> SourceAuthority:
        return SourceAuthority(
            tenant_id=self._tenant_id,
            source_id=self._source_id,
            suite_id=self._source_id,
            authority_revision=1,
            authority_sha256=_sha(
                "lightwork.stock-unified-audit-authority.v1:"
                f"{self._provider.provider_identity_sha256}:{self._source_id}"
            ),
            source_schema_version=_SOURCE_SCHEMA_VERSIONS[self._source_id],
        )

    def resolve_authority(
        self,
        *,
        tenant_id: str,
        source_id: str,
        suite_id: str,
    ) -> SourceAuthority:
        if (
            canonical_tenant_id(tenant_id) != self._tenant_id
            or source_id != self._source_id
            or suite_id != self._source_id
        ):
            raise UnifiedAuditSourceAdapterError("source_authority_invalid")
        return self._authority()

    def _capture(self) -> SuiteAuditCapture:
        try:
            return self._provider.capture(
                tenant_id=self._tenant_id,
                source_id=self._source_id,
            )
        except SuiteAuditCaptureError as exc:
            code = (
                exc.error_code
                if exc.error_code in SOURCE_LIMITATION_CODES
                else "source_history_unavailable"
            )
            raise UnifiedAuditSourceAdapterError(code) from exc

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
    ) -> AuthoritativeAuditPage:
        authority = self.resolve_authority(
            tenant_id=tenant_id,
            source_id=source_id,
            suite_id=suite_id,
        )
        if (
            authority_revision != authority.authority_revision
            or source_schema_version != authority.source_schema_version
            or not hmac.compare_digest(authority_sha256, authority.authority_sha256)
            or isinstance(after_sequence, bool)
            or not isinstance(after_sequence, int)
            or after_sequence < 0
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit < 1
        ):
            raise UnifiedAuditSourceAdapterError("source_page_invalid")
        before = self._capture()
        if after_sequence > before.record_count:
            raise UnifiedAuditSourceAdapterError("source_page_invalid")
        expected_prior = (
            GENESIS_SHA256
            if after_sequence == 0
            else before.records[after_sequence - 1].record_sha256
        )
        if not hmac.compare_digest(prior_sha256, expected_prior):
            raise UnifiedAuditSourceAdapterError("source_page_invalid")
        selected = before.records[after_sequence : after_sequence + limit]
        terminal = after_sequence + len(selected) == before.record_count
        limitations = tuple(
            sorted(
                set(before.limitations)
                | ({"more_records_available"} if not terminal else set())
            )
        )
        built = build_source_page(
            authority,
            after_sequence=after_sequence,
            prior_sha256=prior_sha256,
            previous_page_sha256=previous_page_sha256,
            records=selected,
            terminal=terminal,
            complete=terminal and before.complete,
            truncated=not terminal,
            watermark=before.observed_at,
            limitations=limitations,
        )
        after = self._capture()
        if (
            after.source_revision != before.source_revision
            or after.record_count != before.record_count
            or not hmac.compare_digest(after.head_sha256, before.head_sha256)
            or not hmac.compare_digest(after.capture_sha256, before.capture_sha256)
        ):
            raise UnifiedAuditSourceAdapterError("source_authority_changed")
        return AuthoritativeAuditPage(
            **{
                field.name: getattr(built, field.name)
                for field in fields(AuthoritativeAuditPage)
            }
        )


class StockUnifiedAuditVerifier:
    """Separate local re-reader; it never trusts the reader's capture object."""

    def __init__(
        self,
        *,
        tenant_id: str,
        source_id: str,
        provider: SuiteAuditCaptureProvider,
        clock=time.time,
    ) -> None:
        self._reader = StockUnifiedAuditHistoryReader(
            tenant_id=tenant_id,
            source_id=source_id,
            provider=provider,
        )
        self._provider = provider
        self._clock = clock
        self._identity = _sha(
            "lightwork.stock-unified-audit-verifier.v1:"
            f"{provider.provider_identity_sha256}:{source_id}"
        )

    @property
    def verifier_identity_sha256(self) -> str:
        return self._identity

    def verify_page(
        self,
        *,
        authority: SourceAuthority,
        page: SourcePage,
    ) -> SourceVerification:
        expected_authority = self._reader._authority()
        if authority != expected_authority or (
            page.tenant_id != authority.tenant_id
            or page.source_id != authority.source_id
            or page.suite_id != authority.suite_id
        ):
            raise UnifiedAuditSourceAdapterError("source_authority_invalid")
        try:
            capture = self._provider.capture(
                tenant_id=authority.tenant_id,
                source_id=authority.source_id,
            )
        except SuiteAuditCaptureError as exc:
            raise UnifiedAuditSourceAdapterError(exc.error_code) from exc
        if page.after_sequence > capture.record_count:
            raise UnifiedAuditSourceAdapterError("source_page_invalid")
        expected_prior = (
            GENESIS_SHA256
            if page.after_sequence == 0
            else capture.records[page.after_sequence - 1].record_sha256
        )
        expected_records = capture.records[
            page.after_sequence : page.after_sequence + page.record_count
        ]
        terminal = page.after_sequence + page.record_count == capture.record_count
        limitations = tuple(
            sorted(
                set(capture.limitations)
                | ({"more_records_available"} if not terminal else set())
            )
        )
        expected_page = build_source_page(
            authority,
            after_sequence=page.after_sequence,
            prior_sha256=expected_prior,
            previous_page_sha256=page.previous_page_sha256,
            records=expected_records,
            terminal=terminal,
            complete=terminal and capture.complete,
            truncated=not terminal,
            watermark=capture.observed_at,
            limitations=limitations,
        )
        if expected_page != page:
            raise UnifiedAuditSourceAdapterError("source_integrity_unverified")
        return SourceVerification(
            tenant_id=authority.tenant_id,
            source_id=authority.source_id,
            authority_revision=authority.authority_revision,
            authority_sha256=authority.authority_sha256,
            source_schema_version=authority.source_schema_version,
            page_sha256=page.page_sha256,
            verified_at=max(_clock_value(self._clock), page.watermark),
            assurance_level="self_asserted",
            verifier_identity_sha256=self._identity,
            trust_root_revision=0,
            key_id_sha256=GENESIS_SHA256,
            anchor_sha256=GENESIS_SHA256,
            snapshot_head_sha256=capture.head_sha256,
            snapshot_record_count=capture.record_count,
            retention_complete=False,
            limitations=limitations,
        )


def build_stock_unified_audit_authorities(
    *,
    tenant_id: str,
    verifier_clock=time.time,
) -> tuple[
    dict[str, StockUnifiedAuditHistoryReader],
    dict[str, StockUnifiedAuditVerifier],
]:
    """Build six lazy readers plus independently instantiated re-verifiers."""

    tenant = canonical_tenant_id(tenant_id)
    reader_provider = StockSuiteAuditCaptureProvider()
    verifier_provider = StockSuiteAuditCaptureProvider()
    readers = {
        source_id: StockUnifiedAuditHistoryReader(
            tenant_id=tenant,
            source_id=source_id,
            provider=reader_provider,
        )
        for source_id in SOURCE_IDS
    }
    verifiers = {
        source_id: StockUnifiedAuditVerifier(
            tenant_id=tenant,
            source_id=source_id,
            provider=verifier_provider,
            clock=verifier_clock,
        )
        for source_id in SOURCE_IDS
    }
    return readers, verifiers


__all__ = [
    "StockSuiteAuditCaptureProvider",
    "StockUnifiedAuditHistoryReader",
    "StockUnifiedAuditVerifier",
    "build_stock_unified_audit_authorities",
]
