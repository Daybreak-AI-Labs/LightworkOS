"""Reusable stock captures over six canonical governance-suite histories.

This module owns no dashboard, API, scheduler or unified-audit sink behavior.
It opens the exact tenant-scoped source histories lazily and returns the shared
:mod:`maverick.suite_audit_capture` contract, so projections such as unified
audit and governance inventory can independently re-read the same digest-only
snapshot. Each stock history is deliberately narrower than its complete suite.
"""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from types import MappingProxyType

from .paths import InvalidTenantError, canonical_tenant_id, data_dir, tenant_scope
from .suite_audit_capture import (
    CAPTURE_PROVIDER_SCHEMA,
    SuiteAuditCapture,
    SuiteAuditCaptureError,
    build_suite_audit_capture,
)
from .unified_audit import (
    GENESIS_SHA256,
    REQUIRED_SUITES,
    SOURCE_ACTION_CODES,
    SourceRecord,
    build_source_record,
)

STOCK_SOURCE_IDS = tuple(REQUIRED_SUITES)
STOCK_PARTIAL_LIMITATIONS = (
    "source_history_incomplete",
    "source_retention_unverified",
)
STOCK_SOURCE_SCHEMA_VERSIONS = MappingProxyType(
    {
        "ai_governance": 1,
        "consent_preferences": 1,
        "data_use_governance": 1,
        "privacy_automation": 1,
        "tech_risk_compliance": 2,
        "third_party_management": 1,
    }
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise SuiteAuditCaptureError("source_integrity_unverified")
    try:
        int(value, 16)
    except ValueError as exc:
        raise SuiteAuditCaptureError("source_integrity_unverified") from exc
    return value


def _source_action(action: object) -> str:
    if not isinstance(action, str) or not action or len(action) > 128:
        raise SuiteAuditCaptureError("source_integrity_unverified")
    lowered = action.lower()
    selected = (
        "record_created"
        if any(token in lowered for token in ("create", "open", "register", "enroll"))
        else "record_deleted"
        if any(token in lowered for token in ("delete", "erase", "purge"))
        else "approval_granted"
        if any(token in lowered for token in ("approve", "authorize", "attest"))
        else "approval_denied"
        if any(token in lowered for token in ("deny", "reject", "revoke"))
        else "evidence_recorded"
        if any(token in lowered for token in ("evidence", "collect", "observe", "export"))
        else "risk_changed"
        if "risk" in lowered
        else "policy_changed"
        if "policy" in lowered
        else "status_changed"
        if any(token in lowered for token in ("close", "complete", "transition", "state"))
        else "record_changed"
    )
    if selected not in SOURCE_ACTION_CODES:  # pragma: no cover - closed constant guard
        raise SuiteAuditCaptureError("source_integrity_unverified")
    return selected


class StockSuiteAuditCaptureProvider:
    """Open exact tenant stores lazily and return validated digest captures."""

    def __init__(self) -> None:
        self._identity = _sha(
            f"{CAPTURE_PROVIDER_SCHEMA}:lightwork-stock-six-suite:v1"
        )

    @property
    def provider_identity_sha256(self) -> str:
        return self._identity

    @staticmethod
    def _required_path(path: Path) -> Path:
        try:
            if not path.is_file():
                raise SuiteAuditCaptureError("source_history_unavailable")
        except OSError as exc:
            raise SuiteAuditCaptureError("source_history_unavailable") from exc
        return path

    def _ai_governance(self, tenant_id: str) -> tuple[SourceRecord, ...]:
        from maverick.ai_governance_loop import AIGovernanceLoopStore

        path = self._required_path(
            data_dir("ai_governance", "governance-loop.sqlite3", tenant=tenant_id)
        )
        try:
            store = AIGovernanceLoopStore(
                path,
                tenant_id=tenant_id,
                config_gate=lambda: None,
            )
            store.verify_unified_audit_history()
            return store.unified_audit_records()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise SuiteAuditCaptureError("source_integrity_unverified") from exc

    def _consent_preferences(self, tenant_id: str) -> tuple[SourceRecord, ...]:
        from maverick import consent_storage
        from maverick.consent_preferences import ConsentPreferenceStore

        path = data_dir(
            "consent_preferences",
            "consent-preferences.sqlite3",
            tenant=tenant_id,
        )
        if consent_storage.shared():
            if not consent_storage.store_exists(path):
                raise SuiteAuditCaptureError("source_history_unavailable")
        else:
            path = self._required_path(path)
        try:
            return ConsentPreferenceStore(path).unified_audit_records(tenant_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise SuiteAuditCaptureError("source_integrity_unverified") from exc

    def _data_use_governance(self, tenant_id: str) -> tuple[SourceRecord, ...]:
        from maverick.data_use_governance import DataUseGovernanceStore

        path = self._required_path(
            data_dir(
                "data_use_governance",
                "data-use-governance.sqlite3",
                tenant=tenant_id,
            )
        )
        try:
            return DataUseGovernanceStore(path).unified_audit_records(tenant_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise SuiteAuditCaptureError("source_integrity_unverified") from exc

    @staticmethod
    def _central_signed_records(
        tenant_id: str,
        *,
        event_kind: str,
    ) -> tuple[SourceRecord, ...]:
        from maverick.audit import reader
        from maverick.audit.signing import verify_anchors, verify_chain

        audit_dir = data_dir("audit", tenant=tenant_id)
        try:
            paths = reader.day_files(audit_dir)
        except OSError as exc:
            raise SuiteAuditCaptureError("source_history_unavailable") from exc
        if not paths:
            raise SuiteAuditCaptureError("source_history_unavailable")
        # The signing registry is tenant-scoped through ambient path context.
        # Pin the explicit source tenant while verifying so a background sweep
        # cannot accidentally trust another tenant's local public-key registry.
        with tenant_scope(tenant=tenant_id):
            for path in paths:
                if verify_chain(path):
                    raise SuiteAuditCaptureError("source_integrity_unverified")
            if verify_anchors(audit_dir):
                raise SuiteAuditCaptureError("source_integrity_unverified")

        previous = GENESIS_SHA256
        records: list[SourceRecord] = []
        try:
            with tenant_scope(tenant=tenant_id):
                events = reader.iter_events(
                    all_days=True,
                    tenant=tenant_id,
                    strict=True,
                )
                for event in events:
                    if event.get("kind") != event_kind:
                        continue
                    if event.get("tenant") != tenant_id:
                        raise SuiteAuditCaptureError("source_authority_invalid")
                    event_id = event.get("event_id")
                    record_type = event.get("record_type")
                    record_id = event.get("record_id")
                    actor = event.get("actor")
                    if not all(
                        isinstance(value, str) and value
                        for value in (event_id, record_type, record_id, actor)
                    ):
                        raise SuiteAuditCaptureError("source_integrity_unverified")
                    occurred_at = event.get("occurred_at")
                    if (
                        isinstance(occurred_at, bool)
                        or not isinstance(occurred_at, (int, float))
                        or not math.isfinite(float(occurred_at))
                        or float(occurred_at) <= 0
                    ):
                        raise SuiteAuditCaptureError("source_integrity_unverified")
                    payload_sha256 = _digest(event.get("record_sha256"))
                    resource_sha256 = _sha(f"{record_type}:{record_id}")
                    record = build_source_record(
                        sequence=len(records) + 1,
                        occurred_at=float(occurred_at),
                        action=_source_action(event.get("action")),
                        actor_sha256=_sha(actor),
                        resource_sha256=resource_sha256,
                        payload_sha256=payload_sha256,
                        previous_sha256=previous,
                    )
                    records.append(record)
                    previous = record.record_sha256
        except SuiteAuditCaptureError:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise SuiteAuditCaptureError("source_integrity_unverified") from exc
        return tuple(records)

    def _privacy_automation(self, tenant_id: str) -> tuple[SourceRecord, ...]:
        from maverick.audit.events import EventKind

        return self._central_signed_records(
            tenant_id,
            event_kind=EventKind.PRIVACY_RECORD_CHANGED,
        )

    def _tech_risk_compliance(self, tenant_id: str) -> tuple[SourceRecord, ...]:
        from maverick.trc_continuous_evidence import ContinuousEvidenceStore

        path = self._required_path(
            data_dir(
                "tech_risk_compliance",
                "continuous-evidence.sqlite3",
                tenant=tenant_id,
            )
        )
        try:
            store = ContinuousEvidenceStore(
                path,
                tenant_id=tenant_id,
                principal_resolver=lambda: "service:stock-unified-audit-reader",
                config_gate=lambda: None,
            )
            return store.unified_audit_records()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise SuiteAuditCaptureError("source_integrity_unverified") from exc

    def _third_party_management(self, tenant_id: str) -> tuple[SourceRecord, ...]:
        from maverick.third_party_lifecycle import ThirdPartyLifecycleStore

        path = self._required_path(
            data_dir(
                "third_party_management",
                "third-party-lifecycle.sqlite3",
                tenant=tenant_id,
            )
        )
        try:
            store = ThirdPartyLifecycleStore(
                path,
                config_gate=lambda: None,
                principal_resolver=lambda: "service:stock-unified-audit-reader",
            )
            return store.unified_audit_records(tenant_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise SuiteAuditCaptureError("source_integrity_unverified") from exc

    def capture(self, *, tenant_id: str, source_id: str) -> SuiteAuditCapture:
        try:
            tenant = canonical_tenant_id(tenant_id)
        except (InvalidTenantError, TypeError, ValueError) as exc:
            raise SuiteAuditCaptureError("source_authority_invalid") from exc
        if source_id not in STOCK_SOURCE_IDS:
            raise SuiteAuditCaptureError("source_authority_invalid")
        reader = getattr(self, f"_{source_id}", None)
        if not callable(reader):  # pragma: no cover - fixed registry guard
            raise SuiteAuditCaptureError("source_history_unavailable")
        records = reader(tenant)
        if not isinstance(records, tuple) or any(
            type(record) is not SourceRecord for record in records
        ):
            raise SuiteAuditCaptureError("source_integrity_unverified")
        # A capture digest must be stable across independent re-reads when the
        # source did not change.  Bind the watermark to source history, not to
        # wall-clock read time (which would manufacture drift on every call).
        watermark = max((record.occurred_at for record in records), default=1.0)
        return build_suite_audit_capture(
            tenant_id=tenant,
            source_id=source_id,
            source_revision=len(records) + 1,
            source_schema_version=STOCK_SOURCE_SCHEMA_VERSIONS[source_id],
            observed_at=watermark,
            records=records,
            complete=False,
            retention_complete=False,
            integrity_verified=True,
            limitations=STOCK_PARTIAL_LIMITATIONS,
        )


__all__ = [
    "STOCK_PARTIAL_LIMITATIONS",
    "STOCK_SOURCE_IDS",
    "STOCK_SOURCE_SCHEMA_VERSIONS",
    "StockSuiteAuditCaptureProvider",
]
