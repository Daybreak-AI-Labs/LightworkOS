"""Stock cross-suite source bindings for packaged governance agents.

This composition reads current metadata from Lightwork's existing authorities;
it does not create a parallel index and does not persist projected content.
Each reader emits only bounded governance metadata while pinning the digest of
the full authoritative record.  Sensitive document bytes, assessment answers,
incident narrative, vendor profile ciphertext, credentials, and contract
sensitive fields are never copied into agent context.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from maverick import governance_agent_context as context
from maverick import governance_agents
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


class GovernanceAgentCrossSuiteCompositionError(
    context.GovernanceContextProjectionConfigError
):
    """The stock source composition cannot establish exact tenant authority."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise context.SourceUnavailable("integrity_unverified") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _mapping(value: object) -> dict[str, object]:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, Mapping):
        return dict(value)
    raise context.SourceUnavailable("integrity_unverified")


def _number(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise context.SourceUnavailable("integrity_unverified")
    return float(value)


def _revision(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 2_147_483_647
    ):
        raise context.SourceUnavailable("integrity_unverified")
    return value


def _record(
    tenant_id: str,
    *,
    record_id: str,
    revision: object,
    updated_at: object,
    authority_sha256: object,
    projection: Mapping[str, object],
) -> context.AuthoritativeContextRecord:
    if not isinstance(record_id, str) or not record_id.strip():
        raise context.SourceUnavailable("integrity_unverified")
    if not isinstance(authority_sha256, str) or _DIGEST_RE.fullmatch(
        authority_sha256
    ) is None:
        raise context.SourceUnavailable("integrity_unverified")
    selected_record_id = record_id
    if _ID_RE.fullmatch(selected_record_id) is None:
        prefix = re.sub(r"[^A-Za-z0-9_.:-]", "-", record_id.split(".", 1)[0])[:32]
        prefix = prefix if prefix and prefix[0].isalnum() else "record"
        selected_record_id = (
            f"{prefix}.{hashlib.sha256(record_id.encode('utf-8')).hexdigest()}"
        )
    return context.AuthoritativeContextRecord(
        tenant_id=tenant_id,
        record_id=selected_record_id,
        revision=_revision(revision),
        updated_at=_number(updated_at),
        authority_sha256=authority_sha256,
        projection=dict(projection),
    )


def _capture(
    tenant_id: str,
    source_id: str,
    records: Sequence[context.AuthoritativeContextRecord],
    *,
    total_records: int,
    observed_at: float,
    maximum_records: int | None = None,
) -> context.AuthoritativeSourceCapture:
    ordered = tuple(sorted(records, key=lambda item: item.record_id))
    if maximum_records is not None:
        if isinstance(maximum_records, bool) or maximum_records < 1:
            raise GovernanceAgentCrossSuiteCompositionError(
                "source record limit is invalid"
            )
        ordered = ordered[:maximum_records]
    partial = total_records > len(ordered)
    return context.AuthoritativeSourceCapture(
        tenant_id=tenant_id,
        source_id=source_id,
        availability="partial" if partial else "available",
        records=ordered,
        total_records=total_records,
        observed_at=observed_at,
        reason_code="record_limit" if partial else None,
    )


def _load_settings(tenant_id: str) -> context.GovernanceContextProjectionSettings:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise GovernanceAgentCrossSuiteCompositionError(
            "cross-suite context configuration is unavailable"
        ) from exc
    if errors or not isinstance(config, Mapping):
        raise GovernanceAgentCrossSuiteCompositionError(
            "cross-suite context configuration is unavailable"
        )
    return context.GovernanceContextProjectionSettings.from_mapping(config)


class StockCrossSuiteSourceReaders:
    """Readers over stock source stores, with no semantic writes."""

    def __init__(self, app: Any, *, clock: Callable[[], float] = time.time) -> None:
        state = getattr(app, "state", None)
        if state is None or not callable(clock):
            raise TypeError("app state and source clock are required")
        self._app = app
        self._clock = clock

    def _now(self) -> float:
        value = self._clock()
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) < 0
        ):
            raise GovernanceAgentCrossSuiteCompositionError(
                "cross-suite context clock is invalid"
            )
        return float(value)

    @staticmethod
    def _feature_enabled(module: Any, tenant_id: str) -> bool:
        try:
            with tenant_scope(tenant=tenant_id):
                return module.enabled() is True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise context.SourceUnavailable("not_configured") from exc

    def privacy_incidents(
        self, tenant_id: str, limit: int
    ) -> context.AuthoritativeSourceCapture:
        from maverick import privacy_ops

        tenant = canonical_tenant_id(tenant_id)
        if not self._feature_enabled(privacy_ops, tenant):
            raise context.SourceUnavailable("feature_disabled")
        try:
            with tenant_scope(tenant=tenant):
                heads = privacy_ops.privacy_program_context_heads(
                    limit_per_register=limit,
                    register_names=("incidents",),
                )["incidents"]
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise context.SourceUnavailable("integrity_unverified") from exc
        rows = heads["records"]
        records: list[context.AuthoritativeContextRecord] = []
        for raw in rows if isinstance(rows, Sequence) else ():
            value = _mapping(raw)
            identifier = str(value.get("id") or "")
            notification = value.get("notification")
            notifiable = (
                notification.get("notifiable")
                if isinstance(notification, Mapping)
                else None
            )
            logical = {key: item for key, item in value.items() if key != "_audit_pending"}
            records.append(
                _record(
                    tenant,
                    record_id=f"incident.{identifier}",
                    revision=value.get("revision"),
                    updated_at=(
                        value.get("closed_at")
                        or value.get("notification_decided_at")
                        or value.get("created_at")
                    ),
                    authority_sha256=_sha256(logical),
                    projection={
                        "status": value.get("status"),
                        "severity": value.get("severity"),
                        "affected_estimate": value.get("affected_estimate"),
                        "notify_deadline_at": value.get("notify_deadline_at"),
                        "notification_decided": notification is not None,
                        "notifiable": notifiable,
                        "created_at": value.get("created_at"),
                        "closed_at": value.get("closed_at"),
                        "narrative_included": False,
                    },
                )
            )
        return _capture(
            tenant,
            "privacy.incidents",
            records,
            total_records=int(heads["total_records"]),
            observed_at=self._now(),
        )

    def privacy_program(
        self, tenant_id: str, limit: int
    ) -> context.AuthoritativeSourceCapture:
        from maverick import privacy_ops

        tenant = canonical_tenant_id(tenant_id)
        if not self._feature_enabled(privacy_ops, tenant):
            raise context.SourceUnavailable("feature_disabled")
        registers = ("ai_systems", "dpa_reviews", "dsars", "ropa")
        per_register = max(1, limit // len(registers))
        try:
            with tenant_scope(tenant=tenant):
                heads = privacy_ops.privacy_program_context_heads(
                    limit_per_register=per_register,
                    register_names=registers,
                )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise context.SourceUnavailable("integrity_unverified") from exc
        records: list[context.AuthoritativeContextRecord] = []
        total = 0
        safe_fields = (
            "status",
            "tier",
            "risk_tier",
            "inherent_risk",
            "residual_risk",
            "kind",
            "due_at",
            "fulfilled_at",
            "closed_at",
            "review_required",
            "reviewed_at",
            "source",
        )
        for register in registers:
            head = heads[register]
            total += int(head["total_records"])
            rows = head["records"]
            for raw in rows if isinstance(rows, Sequence) else ():
                value = _mapping(raw)
                identifier = str(value.get("id") or "")
                logical = {
                    key: item for key, item in value.items() if key != "_audit_pending"
                }
                records.append(
                    _record(
                        tenant,
                        record_id=f"{register}.{identifier}",
                        revision=value.get("revision"),
                        updated_at=(
                            value.get("updated_at")
                            or value.get("closed_at")
                            or value.get("created_at")
                        ),
                        authority_sha256=_sha256(logical),
                        projection={
                            "register": register,
                            **{
                                field: value.get(field)
                                for field in safe_fields
                                if field in value
                            },
                            "raw_subject_included": False,
                            "raw_document_included": False,
                        },
                    )
                )
        return _capture(
            tenant,
            "privacy.program",
            records,
            total_records=total,
            observed_at=self._now(),
            maximum_records=limit,
        )

    def assessments(
        self, tenant_id: str, limit: int
    ) -> context.AuthoritativeSourceCapture:
        from maverick import assessment

        tenant = canonical_tenant_id(tenant_id)
        try:
            with tenant_scope(tenant=tenant):
                rows, total = assessment.list_saved_heads(limit=limit)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise context.SourceUnavailable("integrity_unverified") from exc
        records: list[context.AuthoritativeContextRecord] = []
        for raw in rows:
            value = _mapping(raw)
            result = value.get("result")
            result_map = dict(result) if isinstance(result, Mapping) else {}
            identifier = str(value.get("id") or "")
            logical = {key: item for key, item in value.items() if key != "_audit_pending"}
            subject = str(value.get("subject") or "")
            records.append(
                _record(
                    tenant,
                    record_id=f"assessment.{identifier}",
                    revision=value.get("revision"),
                    updated_at=(value.get("decided_at") or value.get("created_at")),
                    authority_sha256=_sha256(logical),
                    projection={
                        "assessment_type": value.get("type"),
                        "status": value.get("status"),
                        "subject_sha256": hashlib.sha256(subject.encode()).hexdigest(),
                        "inherent_risk": result_map.get("inherent_risk"),
                        "residual_risk": result_map.get("residual_risk"),
                        "risk_rating": result_map.get("risk_rating"),
                        "finding_count": len(result_map.get("findings") or []),
                        "template_revision": value.get("template_revision"),
                        "template_digest": value.get("template_digest"),
                        "decided_at": value.get("decided_at"),
                        "next_review_at": value.get("next_review_at"),
                        "answers_included": False,
                        "comments_included": False,
                    },
                )
            )
        return _capture(
            tenant,
            "assessments.register",
            records,
            total_records=total,
            observed_at=self._now(),
        )

    def documents(
        self, tenant_id: str, limit: int
    ) -> context.AuthoritativeSourceCapture:
        from .governed_document_vault_composition import (
            governed_document_vault_enabled,
            governed_document_vault_store,
        )

        tenant = canonical_tenant_id(tenant_id)
        if not governed_document_vault_enabled(tenant):
            raise context.SourceUnavailable("feature_disabled")
        path = data_dir("governed-document-vault", "vault.sqlite3", tenant=tenant)
        if not path.is_file():
            raise context.SourceUnavailable("store_absent")
        try:
            store = governed_document_vault_store(tenant)
            rows = store.list_documents(limit=limit)
            total = store.context_record_count()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise context.SourceUnavailable("integrity_unverified") from exc
        records = tuple(
            _record(
                tenant,
                record_id=f"document.{row.document_ref}",
                revision=row.authority_revision,
                updated_at=row.updated_at,
                authority_sha256=row.authority_sha256,
                projection={
                    "product_area": row.product_area,
                    "record_type": row.record_type,
                    "media_type": row.media_type,
                    "byte_size": row.byte_size,
                    "content_sha256": row.content_sha256,
                    "content_revision": row.content_revision,
                    "authority_revision": row.authority_revision,
                    "state": row.state,
                    "retained_until": row.retained_until,
                    "safe_display_name_included": False,
                    "document_bytes_included": False,
                },
            )
            for row in rows
        )
        return _capture(
            tenant,
            "documents.vault",
            records,
            total_records=total,
            observed_at=self._now(),
        )

    def evidence_analysis(
        self, tenant_id: str, limit: int
    ) -> context.AuthoritativeSourceCapture:
        from .ai_evidence_analysis_composition import (
            ai_evidence_analysis_context_store_for,
            ai_evidence_analysis_enabled,
        )

        tenant = canonical_tenant_id(tenant_id)
        if not ai_evidence_analysis_enabled(tenant):
            raise context.SourceUnavailable("feature_disabled")
        path = data_dir("ai_evidence_analysis", "analyses.sqlite3", tenant=tenant)
        registry = data_dir(
            "ai_evidence_analysis", "authority-registry.sqlite3", tenant=tenant
        )
        if not path.is_file() and not registry.is_file():
            raise context.SourceUnavailable("store_absent")
        if not path.is_file() or not registry.is_file():
            raise context.SourceUnavailable("integrity_unverified")
        try:
            store = ai_evidence_analysis_context_store_for(tenant)
            rows = store.list_analyses(tenant, limit=limit)
            total = store.context_record_count(tenant)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise context.SourceUnavailable("integrity_unverified") from exc
        records: list[context.AuthoritativeContextRecord] = []
        for row in rows:
            records.append(
                _record(
                    tenant,
                    record_id=f"evidence.{row.analysis_id}",
                    revision=row.revision,
                    updated_at=row.updated_at,
                    authority_sha256=row.integrity_sha256,
                    projection={
                        "status": row.status,
                        "artifact_id": row.artifact.artifact_id,
                        "artifact_sha256": row.artifact.content_sha256,
                        "criteria_set_id": row.criteria_authority.criteria_set_id,
                        "criteria_revision": row.criteria_authority.revision,
                        "score_bps": row.justification.score_bps,
                        "maximum_bps": row.justification.maximum_bps,
                        "gap_codes": sorted({gap.gap_code for gap in row.gaps}),
                        "human_review_required": row.human_review_required,
                        "review_decision": row.review_decision,
                        "legal_or_compliance_conclusion": (
                            row.legal_or_compliance_conclusion
                        ),
                        "valid_until": row.valid_until,
                        "retained_until": row.retained_until,
                        "extracted_text_included": False,
                        "raw_artifact_included": False,
                    },
                )
            )
        return _capture(
            tenant,
            "evidence.analysis",
            records,
            total_records=total,
            observed_at=self._now(),
        )

    @staticmethod
    def _lifecycle_path(tenant_id: str) -> Path:
        return data_dir(
            "third_party_management",
            "third-party-lifecycle.sqlite3",
            tenant=tenant_id,
        )

    def third_party_lifecycle(
        self, tenant_id: str, limit: int
    ) -> context.AuthoritativeSourceCapture:
        from maverick import third_party_lifecycle as lifecycle

        tenant = canonical_tenant_id(tenant_id)
        if not self._feature_enabled(lifecycle, tenant):
            raise context.SourceUnavailable("feature_disabled")
        path = self._lifecycle_path(tenant)
        if not path.is_file():
            raise context.SourceUnavailable("store_absent")
        try:
            store = lifecycle.ThirdPartyLifecycleStore(
                path,
                principal_resolver=lambda: "service:governance-agent-context",
            )
            counts = store.context_record_counts(tenant)
            per_kind = max(1, limit // 3)
            assessments = store.list_assessments(tenant, limit=per_kind)
            lifecycles = store.list_lifecycles(tenant, limit=per_kind)
            plans = store.list_offboarding_plans(tenant, limit=per_kind)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise context.SourceUnavailable("integrity_unverified") from exc
        records: list[context.AuthoritativeContextRecord] = []
        for row in assessments:
            records.append(
                _record(
                    tenant,
                    record_id=f"lifecycle_assessment.{row.assessment_id}",
                    revision=row.revision,
                    updated_at=row.updated_at,
                    authority_sha256=row.integrity_sha256,
                    projection={
                        "record_kind": "assessment",
                        "vendor_ref": row.vendor_ref,
                        "template_id": row.template_id,
                        "template_version": row.template_version,
                        "route": row.route,
                        "highest_severity": row.highest_severity,
                        "reason_codes": list(row.reason_codes),
                        "open_task_count": sum(
                            1 for task in row.tasks if task.get("status") == "open"
                        ),
                        "response_count": len(row.responses),
                        "response_values_included": False,
                    },
                )
            )
        for row in lifecycles:
            records.append(
                _record(
                    tenant,
                    record_id=f"lifecycle.{row.lifecycle_id}",
                    revision=row.revision,
                    updated_at=row.updated_at,
                    authority_sha256=row.integrity_sha256,
                    projection={
                        "record_kind": "lifecycle",
                        "vendor_ref": row.vendor_ref,
                        "stage": row.stage,
                        "dependency_count": len(row.dependencies),
                        "open_dependency_count": sum(
                            1
                            for dependency in row.dependencies
                            if dependency.get("status") != "complete"
                        ),
                        "offboarding_plan_id": row.offboarding_plan_id,
                    },
                )
            )
        for row in plans:
            records.append(
                _record(
                    tenant,
                    record_id=f"offboarding.{row.plan_id}",
                    revision=row.revision,
                    updated_at=row.updated_at,
                    authority_sha256=row.integrity_sha256,
                    projection={
                        "record_kind": "offboarding_plan",
                        "lifecycle_id": row.lifecycle_id,
                        "state": row.state,
                        "legal_hold": row.legal_hold,
                        "open_task_count": sum(
                            1 for task in row.tasks if task.get("status") != "complete"
                        ),
                        "blocker_codes": list(row.blockers),
                        "completion_attested": row.completion_attestation_ref is not None,
                    },
                )
            )
        return _capture(
            tenant,
            "third_party.lifecycle",
            records,
            total_records=sum(counts.values()),
            observed_at=self._now(),
            maximum_records=limit,
        )

    def _contract_path(self, tenant_id: str) -> Path:
        factory = getattr(
            self._app.state,
            "third_party_contracts_store_path_factory",
            None,
        )
        if callable(factory):
            try:
                value = factory(tenant_id=tenant_id, request=None)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise context.SourceUnavailable("authority_unavailable") from exc
            if not isinstance(value, (str, Path)):
                raise context.SourceUnavailable("authority_unavailable")
            return Path(value)
        return data_dir(
            "third_party_management",
            "contracts",
            "contract-engagement.sqlite3",
            tenant=tenant_id,
        )

    def third_party_contracts(
        self, tenant_id: str, limit: int
    ) -> context.AuthoritativeSourceCapture:
        from maverick import third_party_contracts as contracts

        tenant = canonical_tenant_id(tenant_id)
        if not self._feature_enabled(contracts, tenant):
            raise context.SourceUnavailable("feature_disabled")
        path = self._contract_path(tenant)
        if not path.is_file():
            raise context.SourceUnavailable("store_absent")
        try:
            store = contracts.ThirdPartyContractStore(
                path,
                tenant_id=tenant,
                vendor_authority_resolver=lambda *_args: (_ for _ in ()).throw(
                    contracts.ThirdPartyContractPermissionDenied(
                        "read-only context authority cannot resolve mutations"
                    )
                ),
                principal_resolver=lambda: "service:governance-agent-context",
                maintenance_authorizer=lambda: False,
                config_gate=lambda: None,
            )
            rows = store.list_records(tenant, limit=limit)
            total = store.context_record_count(tenant)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise context.SourceUnavailable("integrity_unverified") from exc
        records = tuple(
            _record(
                tenant,
                record_id=f"contract.{row.record_id}",
                revision=row.revision,
                updated_at=row.updated_at,
                authority_sha256=row.integrity_sha256,
                projection={
                    "record_kind": row.record_kind,
                    "vendor_id": row.vendor_id,
                    "vendor_revision": row.vendor_revision,
                    "vendor_criticality": row.vendor_criticality,
                    "vendor_jurisdiction_codes": list(
                        row.vendor_jurisdiction_codes
                    ),
                    "status": row.status,
                    "owner_ref": row.owner_ref,
                    "lifecycle": dict(row.lifecycle),
                    "computed_values": dict(row.computed_values),
                    "sensitive_field_count": len(row.sensitive_field_ids),
                    "sensitive_values_included": False,
                    "raw_documents_included": False,
                },
            )
            for row in rows
        )
        return _capture(
            tenant,
            "third_party.contracts",
            records,
            total_records=total,
            observed_at=self._now(),
        )

    @staticmethod
    def _intelligence_path(tenant_id: str) -> Path:
        return data_dir(
            "third_party_management",
            "third-party-intelligence.sqlite3",
            tenant=tenant_id,
        )

    def _intelligence_store(self, tenant_id: str):
        from maverick import third_party_intelligence as intelligence

        if not self._feature_enabled(intelligence, tenant_id):
            raise context.SourceUnavailable("feature_disabled")
        path = self._intelligence_path(tenant_id)
        if not path.is_file():
            return None
        try:
            store = intelligence.ThirdPartyIntelligenceStore(path)
            return store
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise context.SourceUnavailable("integrity_unverified") from exc

    def third_party_intelligence(
        self, tenant_id: str, limit: int
    ) -> context.AuthoritativeSourceCapture:
        tenant = canonical_tenant_id(tenant_id)
        store = self._intelligence_store(tenant)
        if store is None:
            raise context.SourceUnavailable("store_absent")
        counts = store.context_record_counts(tenant)
        groups = 6
        per_kind = max(1, limit // groups)
        sources = store.list_sources(tenant, limit=per_kind)
        snapshots = store.list_source_snapshots(tenant, limit=per_kind)
        vendors = store.list_vendors(tenant, limit=per_kind)
        runs = store.list_screening_runs(tenant, limit=per_kind)
        decisions = store.list_risk_decisions(tenant, limit=per_kind)
        cases = store.list_edd_cases(tenant, limit=per_kind)
        records: list[context.AuthoritativeContextRecord] = []
        for row in sources:
            records.append(
                _record(
                    tenant,
                    record_id=f"intelligence_source.{row.source_id}",
                    revision=row.revision,
                    updated_at=row.updated_at,
                    authority_sha256=row.integrity_sha256,
                    projection={
                        "record_kind": "source",
                        "provider": row.provider,
                        "kind": row.kind,
                        "purposes": list(row.purposes),
                        "territories": list(row.territories),
                        "state": row.state,
                        "credential_reference_included": False,
                        "license_text_included": False,
                    },
                )
            )
        for row in snapshots:
            records.append(
                _record(
                    tenant,
                    record_id=f"intelligence_snapshot.{row.snapshot_id}",
                    revision=row.source_revision,
                    updated_at=row.created_at,
                    authority_sha256=row.integrity_sha256,
                    projection={
                        "record_kind": "source_snapshot",
                        "source_id": row.source_id,
                        "source_revision": row.source_revision,
                        "dataset_revision": row.dataset_revision,
                        "observed_at": row.observed_at,
                        "valid_until": row.valid_until,
                        "completeness": row.completeness,
                        "record_count": row.record_count,
                        "evidence_sha256": row.evidence_sha256,
                    },
                )
            )
        for row in vendors:
            records.append(
                _record(
                    tenant,
                    record_id=f"vendor.{row.vendor_id}",
                    revision=row.revision,
                    updated_at=row.updated_at,
                    authority_sha256=row.integrity_sha256,
                    projection={
                        "record_kind": "vendor",
                        "territories": list(row.territories),
                        "service_categories": list(row.service_categories),
                        "inherent_risk_level": row.inherent_risk_level,
                        "criticality": row.criticality,
                        "data_access_level": row.data_access_level,
                        "state": row.state,
                        "display_label_included": False,
                        "encrypted_profile_included": False,
                    },
                )
            )
        for row in runs:
            records.append(
                _record(
                    tenant,
                    record_id=f"screening_run.{row.run_id}",
                    revision=row.revision,
                    updated_at=row.completed_at or row.initiated_at,
                    authority_sha256=row.integrity_sha256,
                    projection={
                        "record_kind": "screening_run",
                        "vendor_id": row.vendor_id,
                        "requested_kinds": list(row.requested_kinds),
                        "state": row.state,
                        "snapshot_bindings": dict(row.snapshot_bindings),
                        "completed_at": row.completed_at,
                    },
                )
            )
        for row in decisions:
            records.append(
                _record(
                    tenant,
                    record_id=f"risk_decision.{row.decision_id}",
                    revision=row.revision,
                    updated_at=row.decided_at,
                    authority_sha256=row.integrity_sha256,
                    projection={
                        "record_kind": "risk_decision",
                        "vendor_id": row.vendor_id,
                        "run_id": row.run_id,
                        "policy_id": row.policy_id,
                        "policy_version": row.policy_version,
                        "status": row.status,
                        "score": row.score,
                        "factors": dict(row.factors),
                        "reason_codes": list(row.reason_codes),
                        "autoapproved": row.autoapproved,
                        "evidence_sha256": row.evidence_sha256,
                    },
                )
            )
        for row in cases:
            records.append(
                _record(
                    tenant,
                    record_id=f"edd_case.{row.case_id}",
                    revision=row.revision,
                    updated_at=row.updated_at,
                    authority_sha256=row.integrity_sha256,
                    projection={
                        "record_kind": "edd_case",
                        "vendor_id": row.vendor_id,
                        "severity": row.severity,
                        "state": row.state,
                        "task_count": len(row.tasks),
                        "evidence_count": len(row.evidence),
                        "decision": row.decision,
                        "decision_rationale_included": False,
                    },
                )
            )
        total = sum(
            counts[name]
            for name in (
                "sources",
                "source_snapshots",
                "vendors",
                "screening_runs",
                "risk_decisions",
                "edd_cases",
            )
        )
        return _capture(
            tenant,
            "third_party.intelligence",
            records,
            total_records=total,
            observed_at=self._now(),
            maximum_records=limit,
        )

    def third_party_monitors(
        self, tenant_id: str, limit: int
    ) -> context.AuthoritativeSourceCapture:
        tenant = canonical_tenant_id(tenant_id)
        store = self._intelligence_store(tenant)
        if store is None:
            raise context.SourceUnavailable("store_absent")
        counts = store.context_record_counts(tenant)
        per_kind = max(1, limit // 2)
        monitors = store.list_monitors(tenant, limit=per_kind)
        alerts = store.list_monitoring_alerts(tenant, limit=per_kind)
        records: list[context.AuthoritativeContextRecord] = []
        for row in monitors:
            records.append(
                _record(
                    tenant,
                    record_id=f"monitor.{row.monitor_id}",
                    revision=row.revision,
                    updated_at=row.updated_at,
                    authority_sha256=row.integrity_sha256,
                    projection={
                        "record_kind": "monitor",
                        "vendor_id": row.vendor_id,
                        "source_bindings": dict(row.source_bindings),
                        "cadence_seconds": row.cadence_seconds,
                        "next_run_at": row.next_run_at,
                        "state": row.state,
                        "last_observation_sha256": row.last_observation_sha256,
                        "destination_reference_included": False,
                    },
                )
            )
        for row in alerts:
            records.append(
                _record(
                    tenant,
                    record_id=f"monitoring_alert.{row.alert_id}",
                    revision=1,
                    updated_at=row.created_at,
                    authority_sha256=row.integrity_sha256,
                    projection={
                        "record_kind": "monitoring_alert",
                        "monitor_id": row.monitor_id,
                        "vendor_id": row.vendor_id,
                        "previous_observation_sha256": (
                            row.previous_observation_sha256
                        ),
                        "observation_sha256": row.observation_sha256,
                        "evidence_sha256": row.evidence_sha256,
                        "snapshot_bindings": dict(row.snapshot_bindings),
                        "citation_count": len(row.citations),
                        "citation_content_included": False,
                    },
                )
            )
        return _capture(
            tenant,
            "third_party.monitors",
            records,
            total_records=counts["monitors"] + counts["monitoring_alerts"],
            observed_at=self._now(),
            maximum_records=limit,
        )

    def definitions(self) -> tuple[context.ContextSourceDefinition, ...]:
        """Return the complete, sorted stock source plan for five agent kinds."""

        return (
            context.ContextSourceDefinition(
                source_id="assessments.register",
                source_kind="assessment",
                agent_kinds=("privacy_risk_assessment", "program_copilot"),
                required=True,
                reader=self.assessments,
            ),
            context.ContextSourceDefinition(
                source_id="documents.vault",
                source_kind="document",
                agent_kinds=(
                    "breach_response",
                    "knowledgebase_governance",
                    "privacy_risk_assessment",
                    "program_copilot",
                ),
                required=True,
                reader=self.documents,
            ),
            context.ContextSourceDefinition(
                source_id="evidence.analysis",
                source_kind="document",
                agent_kinds=(
                    "knowledgebase_governance",
                    "privacy_risk_assessment",
                    "program_copilot",
                ),
                required=True,
                reader=self.evidence_analysis,
            ),
            context.ContextSourceDefinition(
                source_id="privacy.incidents",
                source_kind="incident",
                agent_kinds=("breach_response",),
                required=True,
                reader=self.privacy_incidents,
            ),
            context.ContextSourceDefinition(
                source_id="privacy.program",
                source_kind="metric",
                agent_kinds=("privacy_risk_assessment", "program_copilot"),
                required=True,
                reader=self.privacy_program,
            ),
            context.ContextSourceDefinition(
                source_id="third_party.contracts",
                source_kind="vendor",
                agent_kinds=("third_party_risk",),
                required=True,
                reader=self.third_party_contracts,
            ),
            context.ContextSourceDefinition(
                source_id="third_party.intelligence",
                source_kind="provider_signal",
                agent_kinds=("third_party_risk",),
                required=True,
                reader=self.third_party_intelligence,
            ),
            context.ContextSourceDefinition(
                source_id="third_party.lifecycle",
                source_kind="vendor",
                agent_kinds=("third_party_risk",),
                required=True,
                reader=self.third_party_lifecycle,
            ),
            context.ContextSourceDefinition(
                source_id="third_party.monitors",
                source_kind="risk",
                agent_kinds=("third_party_risk",),
                required=True,
                reader=self.third_party_monitors,
            ),
        )


class GovernanceAgentCrossSuiteComposition:
    """Tenant-configured projection plus compatibility context resolver."""

    def __init__(
        self,
        definitions: Sequence[context.ContextSourceDefinition],
        *,
        settings_resolver: Callable[
            [str], context.GovernanceContextProjectionSettings
        ] = _load_settings,
        previous_context_resolver: Callable[
            [str, Sequence[Mapping[str, object]]],
            Sequence[governance_agents.GovernanceContextItem],
        ]
        | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not callable(settings_resolver) or not callable(clock):
            raise TypeError("settings resolver and clock must be callable")
        if previous_context_resolver is not None and not callable(
            previous_context_resolver
        ):
            raise TypeError("previous context resolver must be callable")
        self.definitions = tuple(definitions)
        self._settings_resolver = settings_resolver
        self._previous_context_resolver = previous_context_resolver
        self._clock = clock

    def _projection(
        self, tenant_id: str
    ) -> context.AuthoritativeCrossSuiteContextProjection:
        tenant = canonical_tenant_id(tenant_id)
        try:
            settings = self._settings_resolver(tenant)
        except context.GovernanceContextProjectionError:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise GovernanceAgentCrossSuiteCompositionError(
                "cross-suite context settings are unavailable"
            ) from exc
        return context.AuthoritativeCrossSuiteContextProjection(
            self.definitions,
            settings=settings,
            clock=self._clock,
        )

    def preview(
        self, tenant_id: str, agent_kind: str
    ) -> context.GovernanceContextProjection:
        return self._projection(tenant_id).capture(tenant_id, agent_kind)

    def resolve_context(
        self,
        tenant_id: str,
        references: Sequence[Mapping[str, object]],
        expected_agent_kind: str | None = None,
    ) -> tuple[governance_agents.GovernanceContextItem, ...]:
        if isinstance(references, (str, bytes)) or not isinstance(
            references, Sequence
        ):
            raise context.GovernanceContextProjectionValidationError(
                "context references are invalid"
            )
        cross_suite: list[Mapping[str, object]] = []
        legacy: list[Mapping[str, object]] = []
        for reference in references:
            source_ref = reference.get("source_ref") if isinstance(reference, Mapping) else None
            if isinstance(source_ref, str) and source_ref.startswith(
                context.REFERENCE_PREFIX
            ):
                cross_suite.append(reference)
            else:
                legacy.append(reference)
        resolved: dict[str, governance_agents.GovernanceContextItem] = {}
        if cross_suite:
            if expected_agent_kind is None:
                raise GovernanceAgentCrossSuiteCompositionError(
                    "cross-suite context requires a policy agent-kind binding"
                )
            items = self._projection(tenant_id).resolve_references(
                tenant_id,
                cross_suite,
                expected_agent_kind,
            )
            resolved.update((item.item_id, item) for item in items)
        if legacy:
            if self._previous_context_resolver is None:
                raise GovernanceAgentCrossSuiteCompositionError(
                    "non-cross-suite context authority is unavailable"
                )
            try:
                items = self._previous_context_resolver(tenant_id, legacy)
            except (KeyboardInterrupt, SystemExit):
                raise
            except governance_agents.GovernanceAgentError:
                raise
            except Exception as exc:
                raise GovernanceAgentCrossSuiteCompositionError(
                    "non-cross-suite context authority is unavailable"
                ) from exc
            for item in items:
                if not isinstance(item, governance_agents.GovernanceContextItem):
                    raise GovernanceAgentCrossSuiteCompositionError(
                        "non-cross-suite context authority is invalid"
                    )
                resolved[item.item_id] = item
        try:
            return tuple(resolved[str(reference["item_id"])] for reference in references)
        except (KeyError, TypeError) as exc:
            raise GovernanceAgentCrossSuiteCompositionError(
                "context authority did not resolve every exact reference"
            ) from exc

    def readiness(self, tenant_id: str) -> dict[str, object]:
        return self._projection(tenant_id).readiness(tenant_id)

    def verify_sources(self, tenant_id: str) -> dict[str, object]:
        return self._projection(tenant_id).verify_sources(tenant_id)

    def recover(self, tenant_id: str) -> dict[str, object]:
        return self._projection(tenant_id).recover(tenant_id)


def install_governance_agent_cross_suite_context(
    app: Any,
    *,
    definitions: Sequence[context.ContextSourceDefinition] | None = None,
    settings_resolver: Callable[
        [str], context.GovernanceContextProjectionSettings
    ] = _load_settings,
    clock: Callable[[], float] = time.time,
) -> GovernanceAgentCrossSuiteComposition:
    """Attach stock preview, current resolution, readiness and recovery seams."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    existing = getattr(state, "governance_agent_cross_suite_composition", None)
    if existing is not None:
        if not isinstance(existing, GovernanceAgentCrossSuiteComposition):
            raise GovernanceAgentCrossSuiteCompositionError(
                "cross-suite context composition marker is invalid"
            )
        return existing
    previous = getattr(state, "governance_agent_context_resolver", None)
    if previous is not None and not callable(previous):
        raise GovernanceAgentCrossSuiteCompositionError(
            "existing governance-agent context resolver is invalid"
        )
    selected = (
        tuple(definitions)
        if definitions is not None
        else StockCrossSuiteSourceReaders(app, clock=clock).definitions()
    )
    composition = GovernanceAgentCrossSuiteComposition(
        selected,
        settings_resolver=settings_resolver,
        previous_context_resolver=previous,
        clock=clock,
    )
    state.governance_agent_context_resolver = composition.resolve_context
    state.governance_agent_cross_suite_preview_resolver = composition.preview
    state.governance_agent_cross_suite_readiness = composition.readiness
    state.governance_agent_cross_suite_maintenance = composition.verify_sources
    state.governance_agent_cross_suite_recovery = composition.recover
    state.governance_agent_cross_suite_composition = composition
    return composition


__all__ = [
    "GovernanceAgentCrossSuiteComposition",
    "GovernanceAgentCrossSuiteCompositionError",
    "StockCrossSuiteSourceReaders",
    "install_governance_agent_cross_suite_context",
]
