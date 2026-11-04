"""Focused no-network tests for native provider audit reconciliation."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from maverick import data_use_provider_audit as audit
from maverick.data_use_provider_adapters import (
    PROVIDER_RESULT_SCHEMA,
    ProviderBindingStore,
)

TENANT = "Acme Café"


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


class Clock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _enroll(store: ProviderBindingStore, provider: str, tenant: str = TENANT):
    common = {
        "asset_id": "customers",
        "schema": "PUBLIC" if provider == "snowflake" else "default",
        "table": "CUSTOMERS" if provider == "snowflake" else "customers",
        "principal": "ANALYST_ROLE" if provider == "snowflake" else "analyst-group",
        "compute_id": "GOVERNANCE_WH" if provider == "snowflake" else "warehouse-1",
        "field_map": {"email": "EMAIL" if provider == "snowflake" else "email"},
        "mask_bindings": {
            "hash_sha256": (
                "GOV.POLICY.MASK_SHA256"
                if provider == "snowflake"
                else "governance.policy.mask_sha256"
            )
        },
        "row_filter_bindings": {},
        "catalog_snapshot_sha256": _sha(f"{provider}-catalog"),
        "field_inventory_complete": True,
        "credential_key_id": "audit-key-1",
        "credential_revision": 3,
        "credential_authority_sha256": _sha("credential-authority"),
        "expected_revision": 0,
        "idempotency_key": f"enroll-{provider}",
    }
    if provider == "snowflake":
        return store.enroll_snowflake(
            tenant,
            "native-customers",
            origin="https://acct1.snowflakecomputing.com",
            account_or_workspace_id="acct1",
            catalog="APP_DB",
            state_anchor="GOV.TAGS.DATA_USE_STATE",
            **common,
        )
    return store.enroll_databricks(
        tenant,
        "native-customers",
        origin="https://adb-123.cloud.databricks.com",
        account_or_workspace_id="adb-123",
        catalog="main",
        **common,
    )


def _seed_operation(
    bindings: ProviderBindingStore,
    binding: dict[str, Any],
    provider: str,
    *,
    no_change: bool = False,
    operation: str = "apply",
) -> tuple[str, dict[str, Any]]:
    idem = _sha(f"{provider}-{operation}-idem")
    request_sha = _sha(f"{provider}-{operation}-request")
    target = _sha(f"{provider}-{operation}-target")
    object_sha256 = _sha(
        {
            key: binding[key]
            for key in (
                "provider_id",
                "account_or_workspace_id",
                "catalog",
                "schema_name",
                "table",
            )
        }
    )
    receipts: list[dict[str, Any]] = []
    if not no_change:
        references = (
            (_sha("query-1"), _sha("query-2"))
            if provider == "snowflake"
            else (_sha("statement-1"), _sha("statement-2"))
        )
        for index, (kind, control, state) in enumerate(
            (
                ("masking_policy", _sha("mask-control"), None),
                ("state_anchor", target, target),
            )
        ):
            receipts.append(
                {
                    "request": {"path_sha256": _sha(f"path-{index}"), "safe_read": False},
                    "response": {
                        "status_code": 200,
                        "body_sha256": _sha(f"body-{index}"),
                        "provider_statement_sha256": references[index],
                        "audit_change_kind": kind,
                        "audit_control_sha256": control,
                        "audit_object_sha256": object_sha256,
                        "audit_state_sha256": state,
                    },
                }
            )
    result = {
        "schema": PROVIDER_RESULT_SCHEMA,
        "tenant_id": TENANT,
        "provider_id": provider,
        "adapter_id": f"{provider}-data-use-native-v1",
        "binding_id": binding["binding_id"],
        "binding_revision": binding["revision"],
        "binding_sha256": binding["binding_sha256"],
        "compilation_id": "duc-control-1",
        "ir_sha256": _sha("control-ir"),
        "operation": operation,
        "idempotency_sha256": idem,
        "request_sha256": request_sha,
        "target_state_sha256": target,
        "observed_before_sha256": target if no_change else None,
        "observed_after_sha256": target,
        "reconciliation": "no_change" if no_change else "converged",
        "no_change": no_change,
        "provider_writes_possible": True,
        "credential_material_recorded": False,
        "http_receipts": receipts,
        "http_receipts_sha256": _sha(receipts),
        "rollback_mode": "compiled_safe_deny" if operation == "rollback" else None,
        "restored_prior_native_state": False,
        "live_provider_acceptance_verified": False,
        "result_sha256": "",
    }
    result["result_sha256"] = _sha(
        {key: value for key, value in result.items() if key != "result_sha256"}
    )
    assert (
        bindings.claim_operation(
            tenant_id=TENANT,
            provider_id=provider,
            binding_id=binding["binding_id"],
            idempotency_sha256=idem,
            request_sha256=request_sha,
        )
        is None
    )
    bindings.finish_operation(
        tenant_id=TENANT,
        provider_id=provider,
        binding_id=binding["binding_id"],
        idempotency_sha256=idem,
        request_sha256=request_sha,
        result=result,
    )
    return idem, result


class Authorities:
    def __init__(
        self,
        binding: dict[str, Any],
        operation_idem: str,
        result: dict[str, Any],
        *,
        no_change: bool = False,
    ) -> None:
        self.binding = binding
        self.operation_idem = operation_idem
        self.result = result
        self.revoked = False
        self.read_revision = 5
        self.control_revision = 7
        self.mask_control = _sha("mask-control")
        self.state_control = result["target_state_sha256"]
        self.changes = (
            ()
            if no_change
            else (
                audit.ProviderAuditExpectedChange(
                    "masking_policy",
                    self.mask_control,
                    audit.expected_change_sha256("masking_policy", self.mask_control),
                ),
                audit.ProviderAuditExpectedChange(
                    "state_anchor",
                    self.state_control,
                    audit.expected_change_sha256("state_anchor", self.state_control),
                ),
            )
        )

    def control(self, provider, binding_id, operation_idem, result):
        assert provider == self.binding["provider_id"]
        assert binding_id == self.binding["binding_id"]
        assert operation_idem == self.operation_idem
        assert result == self.result
        correlation = audit.operation_correlation_sha256(
            provider_id=provider,
            binding_sha256=self.binding["binding_sha256"],
            operation_idempotency_sha256=operation_idem,
            operation_request_sha256=result["request_sha256"],
        )
        value = audit.ProviderAuditControlAuthority(
            tenant_id=TENANT,
            provider_id=provider,
            binding_id=binding_id,
            binding_revision=self.binding["revision"],
            binding_sha256=self.binding["binding_sha256"],
            operation_idempotency_sha256=operation_idem,
            operation_request_sha256=result["request_sha256"],
            operation_result_sha256=_sha(result),
            compilation_id=result["compilation_id"],
            ir_sha256=result["ir_sha256"],
            operation=result["operation"],
            target_state_sha256=result["target_state_sha256"],
            correlation_sha256=correlation,
            expected_changes=self.changes,
            revision=self.control_revision,
            valid_until=5_000.0,
            revoked=self.revoked,
            authority_sha256="0" * 64,
        )
        return replace(value, authority_sha256=audit.control_authority_sha256(value))

    def read(self, provider, binding_id):
        value = audit.ProviderAuditReadAuthority(
            tenant_id=TENANT,
            provider_id=provider,
            binding_id=binding_id,
            binding_revision=self.binding["revision"],
            binding_sha256=self.binding["binding_sha256"],
            credential_key_id_sha256=self.binding["credential_key_id_sha256"],
            credential_revision=self.binding["credential_revision"],
            credential_authority_sha256=self.binding["credential_authority_sha256"],
            capability="provider_audit_read",
            capability_revision=self.read_revision,
            valid_until=5_000.0,
            revoked=self.revoked,
            authority_sha256="0" * 64,
        )
        return replace(value, authority_sha256=audit.read_authority_sha256(value))


class CredentialOwner:
    def __init__(self, binding: dict[str, Any]) -> None:
        self.binding = binding
        self.authorization = "Bearer raw-audit-secret"
        self.calls = 0

    def lease(self, *, provider_id, tenant_id, binding_id):
        assert provider_id == self.binding["provider_id"]
        assert tenant_id == TENANT
        assert binding_id == self.binding["binding_id"]
        self.calls += 1
        return audit.ProviderAuditCredentialLease(
            authorization=self.authorization,
            credential_key_id_sha256=self.binding["credential_key_id_sha256"],
            credential_revision=self.binding["credential_revision"],
            credential_authority_sha256=self.binding["credential_authority_sha256"],
            expires_at=5_000.0,
        )


class Transport:
    def __init__(self, batches: list[object]) -> None:
        self.batches = batches
        self.requests = []
        self.credentials = []

    def read(self, request, credential):
        self.requests.append(request)
        self.credentials.append(credential)
        value = self.batches.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def _watermark_resolver(binding: dict[str, Any]):
    def resolve(provider_id: str, binding_id: str, covered_until: float):
        candidate = audit.ProviderAuditAcceptedWatermark(
            tenant_sha256=hashlib.sha256(TENANT.encode("utf-8")).hexdigest(),
            watermark_kind=(
                "snowflake_configured_latency"
                if provider_id == "snowflake"
                else "databricks_accepted_delivery"
            ),
            provider_id=provider_id,
            binding_id=binding_id,
            binding_revision=binding["revision"],
            binding_sha256=binding["binding_sha256"],
            covered_until=covered_until,
            authority_sha256="0" * 64,
            expires_at=1_900.0,
        )
        return replace(
            candidate,
            authority_sha256=audit.accepted_watermark_sha256(candidate),
        )

    return resolve


def _environment_for_provider(tmp_path: Path, provider: str):
    clock = Clock()
    bindings = ProviderBindingStore(tmp_path / f"bindings-{provider}.sqlite", clock=clock)
    binding = _enroll(bindings, provider)
    idem, result = _seed_operation(bindings, binding, provider)
    authorities = Authorities(binding, idem, result)
    store = audit.DataUseProviderAuditStore(
        tmp_path / f"audit-{provider}.sqlite",
        tenant_id=TENANT,
        binding_store=bindings,
        control_authority_resolver=authorities.control,
        read_authority_resolver=authorities.read,
        watermark_authority_resolver=_watermark_resolver(binding),
        config_gate=lambda: None,
        clock=clock,
    )
    return provider, clock, bindings, binding, idem, result, authorities, store


@pytest.fixture(params=["snowflake", "databricks"])
def environment(tmp_path: Path, request):
    return _environment_for_provider(tmp_path, request.param)


def _register(environment, *, max_attempts: int = 5):
    provider, _clock, _bindings, _binding, idem, _result, _authorities, store = environment
    return store.register_operation(
        provider_id=provider,
        binding_id="native-customers",
        operation_idempotency_sha256=idem,
        audit_deadline=1_100.0,
        retained_until=2_000.0,
        idempotency_key=f"register-{provider}",
        max_attempts=max_attempts,
    )


def test_registration_lookup_returns_current_revision_and_rejects_unknown_key(
    environment,
) -> None:
    provider, _clock, _bindings, _binding, _idem, _result, _authorities, store = environment
    expectation = _register(environment)
    assert store.get_expectation_for_registration(f"register-{provider}") == expectation
    cancelled = store.cancel_expectation(
        expectation.expectation_id,
        expected_revision=expectation.revision,
        reason_code="operator_request",
        idempotency_key=f"cancel-{provider}",
    )
    assert store.get_expectation_for_registration(f"register-{provider}") == cancelled
    with pytest.raises(audit.DataUseProviderAuditNotFound, match="does not exist"):
        store.get_expectation_for_registration(f"missing-{provider}")


def _event(expectation, authorities, *, kind, event_number, **changes):
    common = {
        "event_id_sha256": _sha(f"event-{event_number}"),
        "occurred_at": 1_010.0 + event_number,
        "correlation_sha256": expectation.correlation_sha256,
        "object_sha256": expectation.object_sha256,
        "change_kind": kind,
        "control_sha256": (
            authorities.state_control if kind == "state_anchor" else authorities.mask_control
        ),
        "outcome": "succeeded",
        "state_sha256": expectation.target_state_sha256 if kind == "state_anchor" else None,
        **changes,
    }
    if expectation.provider_id == "snowflake":
        return audit.SnowflakeAuditEvent(
            source_view="query_history",
            query_id_sha256=_sha(f"query-{event_number}"),
            object_change_corroborated=True,
            **common,
        )
    return audit.DatabricksAuditEvent(
        source_table="system.query.history",
        request_id_sha256=None,
        statement_id_sha256=_sha(f"statement-{event_number}"),
        **common,
    )


def _batch(expectation, events, *, complete=True, covered_until=1_100.0):
    cursor = (
        audit.ProviderAuditCursor(
            occurred_at=events[-1].occurred_at,
            event_id_sha256=events[-1].event_id_sha256,
        )
        if events
        else audit.ProviderAuditCursor(
            expectation.cursor_occurred_at,
            expectation.cursor_event_id_sha256,
        )
    )
    watermark = None
    if complete:
        candidate = audit.ProviderAuditAcceptedWatermark(
            tenant_sha256=expectation.tenant_sha256,
            watermark_kind=(
                "snowflake_configured_latency"
                if expectation.provider_id == "snowflake"
                else "databricks_accepted_delivery"
            ),
            provider_id=expectation.provider_id,
            binding_id=expectation.binding_id,
            binding_revision=expectation.binding_revision,
            binding_sha256=expectation.binding_sha256,
            covered_until=covered_until,
            authority_sha256="0" * 64,
            expires_at=1_900.0,
        )
        watermark = replace(
            candidate,
            authority_sha256=audit.accepted_watermark_sha256(candidate),
        )
    return audit.ProviderAuditBatch(
        events=tuple(events),
        next_cursor=cursor,
        covered_until=covered_until,
        complete=complete,
        provider_receipt_sha256=_sha("provider-read-receipt"),
        watermark=watermark,
    )


def test_default_off_gate_and_honest_boundaries(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(audit, "load_config", dict)
    assert audit.enabled() is False
    with pytest.raises(audit.DataUseProviderAuditConfigError):
        audit.DataUseProviderAuditStore(
            tmp_path / "disabled.sqlite",
            tenant_id=TENANT,
            binding_store=object(),
            control_authority_resolver=lambda *_args: None,
            read_authority_resolver=lambda *_args: None,
        )
    boundaries = audit.DataUseProviderAuditStore.product_boundaries()
    assert boundaries["provider_writes"] is False
    assert boundaries["built_in_network_transport"] is False
    assert boundaries["raw_sql_persisted"] is False
    assert boundaries["live_provider_acceptance"] is False
    assert boundaries["provider_sources"]["databricks"] == [
        "system.query.history",
        "system.access.audit",
    ]
    assert boundaries["provider_source_roles"]["databricks"] == {
        "primary": "system.query.history",
        "supplemental": ["system.access.audit"],
    }


@pytest.mark.parametrize("count", [255, 256, 257])
def test_expected_change_capacity_is_aligned_above_legacy_256_boundary(count: int) -> None:
    changes = tuple(
        audit.ProviderAuditExpectedChange(
            "masking_policy",
            _sha(f"control-{index}"),
            audit.expected_change_sha256("masking_policy", _sha(f"control-{index}")),
        )
        for index in range(count)
    )

    assert len(audit._expected_changes(changes)) == count


def test_registration_is_exact_idempotent_and_digest_only(environment) -> None:
    first = _register(environment)
    second = _register(environment)
    assert first == second
    assert first.state == "queued"
    assert first.binding_revision == 1
    assert first.capability_revision == 5
    assert first.control_authority_revision == 7
    raw = first.__class__.__name__.lower() + first.expectation_id.lower()
    database = Path(environment[-1].path).read_bytes().lower()
    assert b"raw-audit-secret" not in database
    for forbidden in (
        b"analyst_role",
        b"analyst-group",
        b"app_db",
        b"snowflakecomputing.com",
        b"cloud.databricks.com",
    ):
        assert forbidden not in database
    assert "credential" not in raw


@pytest.mark.parametrize("provider", ["snowflake", "databricks"])
def test_worker_correlates_closed_native_events_without_raw_material(tmp_path, provider) -> None:
    clock = Clock()
    bindings = ProviderBindingStore(tmp_path / "bindings.sqlite", clock=clock)
    binding = _enroll(bindings, provider)
    idem, result = _seed_operation(bindings, binding, provider)
    authorities = Authorities(binding, idem, result)
    store = audit.DataUseProviderAuditStore(
        tmp_path / "audit.sqlite",
        tenant_id=TENANT,
        binding_store=bindings,
        control_authority_resolver=authorities.control,
        read_authority_resolver=authorities.read,
        watermark_authority_resolver=_watermark_resolver(binding),
        config_gate=lambda: None,
        clock=clock,
    )
    environment = (provider, clock, bindings, binding, idem, result, authorities, store)
    expectation = _register(environment)
    events = [
        _event(expectation, authorities, kind="masking_policy", event_number=1),
        _event(expectation, authorities, kind="state_anchor", event_number=2),
    ]
    owner = CredentialOwner(binding)
    transport = Transport([_batch(expectation, events)])
    outcome = audit.DataUseProviderAuditWorker(
        store,
        credential_owner=owner,
        transport=transport,
    ).run_once(worker_id="audit-worker")
    assert outcome.converged == 1
    assert store.get_expectation(expectation.expectation_id).state == "converged"
    evidence = store.list_event_evidence(expectation.expectation_id)
    assert {item["relation"] for item in evidence} == {"matched"}
    assert {item["provider_reference_kind"] for item in evidence} == {
        "snowflake_query_id" if provider == "snowflake" else "databricks_statement_id"
    }
    assert all(
        "request_id_sha256" not in item and "statement_id_sha256" not in item for item in evidence
    )
    assert owner.calls == 1
    assert transport.requests[0].provider_id == provider
    serialized = json.dumps(evidence, sort_keys=True)
    assert "raw-audit-secret" not in serialized
    assert "select " not in serialized.lower()


def test_worker_accepts_authority_noop_before_resolving_credentials(environment) -> None:
    expectation = _register(environment)
    owner = CredentialOwner(environment[3])

    class PreviewTransport(Transport):
        def __init__(self):
            super().__init__([])
            self.preview_calls = 0

        def read_without_credential(self, _request):
            self.preview_calls += 1
            return _batch(expectation, [], complete=False)

        def read(self, *_args):
            raise AssertionError("authority no-op must not resolve or use a credential")

    transport = PreviewTransport()

    result = audit.DataUseProviderAuditWorker(
        environment[-1],
        credential_owner=owner,
        transport=transport,
    ).run_once(worker_id="audit-worker")

    assert result.retried == 1
    assert transport.preview_calls == 1
    assert owner.calls == 0


def test_worker_passes_deadline_inside_claim_lease_to_bounded_transport(environment) -> None:
    expectation = _register(environment)
    events = [
        _event(expectation, environment[-2], kind="masking_policy", event_number=1),
        _event(expectation, environment[-2], kind="state_anchor", event_number=2),
    ]
    owner = CredentialOwner(environment[3])

    class DeadlineTransport(Transport):
        def __init__(self):
            super().__init__([_batch(expectation, events)])
            self.deadlines: list[float] = []

        def read_with_deadline(self, request, credential, *, deadline):
            self.deadlines.append(deadline)
            return super().read(request, credential)

        def read(self, *_args):
            raise AssertionError("bounded transport must receive the claim deadline")

    transport = DeadlineTransport()

    result = audit.DataUseProviderAuditWorker(
        environment[-1],
        credential_owner=owner,
        transport=transport,
    ).run_once(worker_id="audit-worker", lease_seconds=60)

    assert result.converged == 1
    assert transport.deadlines == [1_055.0]
    assert owner.calls == 1


def test_databricks_sources_normalize_only_their_closed_reference_kind() -> None:
    common = {
        "event_id_sha256": _sha("event-query-history"),
        "occurred_at": 1_010.0,
        "correlation_sha256": _sha("correlation"),
        "object_sha256": _sha("object"),
        "change_kind": "masking_policy",
        "control_sha256": _sha("control"),
        "outcome": "succeeded",
    }
    statement_sha256 = _sha("raw-statement-id-never-persist")
    query_event = audit.DatabricksAuditEvent(
        source_table="system.query.history",
        request_id_sha256=None,
        statement_id_sha256=statement_sha256,
        **common,
    )
    query_payload, _integrity = audit.DataUseProviderAuditStore._normalized_event(
        "databricks", query_event
    )
    assert query_payload["schema"] == audit.DATABRICKS_EVENT_SCHEMA
    assert set(query_payload) == {
        "schema",
        "provider_id",
        "source",
        "event_id_sha256",
        "provider_reference_kind",
        "provider_reference_sha256",
        "occurred_at",
        "correlation_sha256",
        "object_sha256",
        "change_kind",
        "control_sha256",
        "outcome",
        "state_sha256",
    }
    assert query_payload["source"] == "system.query.history"
    assert query_payload["provider_reference_kind"] == "databricks_statement_id"
    assert query_payload["provider_reference_sha256"] == statement_sha256
    assert "statement_id_sha256" not in query_payload
    assert "request_id_sha256" not in query_payload

    request_sha256 = _sha("raw-request-id-never-persist")
    access_event = audit.DatabricksAuditEvent(
        source_table="system.access.audit",
        event_id_sha256=_sha("event-access-audit"),
        request_id_sha256=request_sha256,
        occurred_at=1_011.0,
        correlation_sha256=common["correlation_sha256"],
        object_sha256=common["object_sha256"],
        change_kind="masking_policy",
        control_sha256=common["control_sha256"],
        outcome="succeeded",
    )
    access_payload, _integrity = audit.DataUseProviderAuditStore._normalized_event(
        "databricks", access_event
    )
    assert access_payload["source"] == "system.access.audit"
    assert access_payload["provider_reference_kind"] == "databricks_request_id"
    assert access_payload["provider_reference_sha256"] == request_sha256
    assert "statement_id_sha256" not in access_payload
    assert "request_id_sha256" not in access_payload


@pytest.mark.parametrize(
    ("source", "request_reference", "statement_reference", "message"),
    [
        ("system.query.history", _sha("mixed-request"), _sha("statement"), "cannot include"),
        ("system.query.history", None, None, "statement_id_sha256"),
        ("system.access.audit", _sha("request"), _sha("mixed-statement"), "cannot include"),
        ("system.access.audit", None, None, "request_id_sha256"),
        ("system.query.history", None, "raw-statement-id", "must be a lowercase SHA-256"),
        ("system.access.audit", "raw-request-id", None, "must be a lowercase SHA-256"),
        ("system.query.audit", None, _sha("statement"), "source is unsupported"),
    ],
)
def test_databricks_source_rejects_mixed_missing_and_unsupported_references(
    source,
    request_reference,
    statement_reference,
    message,
) -> None:
    event = audit.DatabricksAuditEvent(
        source_table=source,
        event_id_sha256=_sha("event"),
        request_id_sha256=request_reference,
        statement_id_sha256=statement_reference,
        occurred_at=1_010.0,
        correlation_sha256=_sha("correlation"),
        object_sha256=_sha("object"),
        change_kind="masking_policy",
        control_sha256=_sha("control"),
        outcome="succeeded",
    )
    with pytest.raises(audit.DataUseProviderAuditValidationError, match=message):
        audit.DataUseProviderAuditStore._normalized_event("databricks", event)


def test_databricks_cross_source_duplicate_event_id_is_ambiguous(tmp_path: Path) -> None:
    environment = _environment_for_provider(tmp_path, "databricks")
    expectation = _register(environment)
    authorities = environment[-2]
    query_event = _event(
        expectation,
        authorities,
        kind="masking_policy",
        event_number=1,
    )
    access_event = replace(
        query_event,
        source_table="system.access.audit",
        request_id_sha256=_sha("raw-access-request-duplicate"),
        statement_id_sha256=None,
    )
    claim = environment[-1].claim_ready(worker_id="worker")[0]
    result = environment[-1].record_batch(
        claim,
        _batch(expectation, [query_event, access_event]),
    )
    assert result.state == "ambiguous"
    evidence = environment[-1].list_event_evidence(expectation.expectation_id)
    assert len(evidence) == 1
    assert evidence[0]["provider_reference_kind"] == "databricks_statement_id"


def test_databricks_cross_source_semantic_duplicate_fails_closed_without_raw_ids(
    tmp_path: Path,
) -> None:
    environment = _environment_for_provider(tmp_path, "databricks")
    expectation = _register(environment)
    authorities = environment[-2]
    raw_statement_id = "01f0-raw-statement-id"
    raw_request_id = "raw-request-id-from-access-audit"
    query_event = replace(
        _event(
            expectation,
            authorities,
            kind="masking_policy",
            event_number=1,
        ),
        statement_id_sha256=_sha(raw_statement_id),
    )
    access_event = replace(
        query_event,
        source_table="system.access.audit",
        event_id_sha256=_sha("access-event-2"),
        occurred_at=1_012.0,
        request_id_sha256=_sha(raw_request_id),
        statement_id_sha256=None,
    )
    claim = environment[-1].claim_ready(worker_id="worker")[0]
    result = environment[-1].record_batch(
        claim,
        _batch(expectation, [query_event, access_event]),
    )
    assert result.state == "ambiguous"
    evidence = environment[-1].list_event_evidence(expectation.expectation_id)
    assert {item["relation"] for item in evidence} == {"ambiguous"}
    assert {item["provider_reference_kind"] for item in evidence} == {
        "databricks_statement_id",
        "databricks_request_id",
    }
    assert {item["provider_reference_sha256"] for item in evidence} == {
        _sha(raw_statement_id),
        _sha(raw_request_id),
    }
    serialized = json.dumps(evidence, sort_keys=True)
    database = Path(environment[-1].path).read_bytes()
    for raw_reference in (raw_statement_id, raw_request_id):
        assert raw_reference not in serialized
        assert raw_reference.encode("utf-8") not in database
    assert "statement_id_sha256" not in serialized
    assert "request_id_sha256" not in serialized


def test_no_change_requires_complete_empty_window(tmp_path: Path) -> None:
    provider = "snowflake"
    clock = Clock()
    bindings = ProviderBindingStore(tmp_path / "bindings.sqlite", clock=clock)
    binding = _enroll(bindings, provider)
    idem, result = _seed_operation(bindings, binding, provider, no_change=True)
    authorities = Authorities(binding, idem, result, no_change=True)
    store = audit.DataUseProviderAuditStore(
        tmp_path / "audit.sqlite",
        tenant_id=TENANT,
        binding_store=bindings,
        control_authority_resolver=authorities.control,
        read_authority_resolver=authorities.read,
        watermark_authority_resolver=_watermark_resolver(binding),
        config_gate=lambda: None,
        clock=clock,
    )
    env = (provider, clock, bindings, binding, idem, result, authorities, store)
    expectation = _register(env)
    worker = audit.DataUseProviderAuditWorker(
        store,
        credential_owner=CredentialOwner(binding),
        transport=Transport([_batch(expectation, [])]),
    )
    assert worker.run_once(worker_id="worker").no_change == 1
    assert store.get_expectation(expectation.expectation_id).state == "no_change"


@pytest.mark.parametrize(
    ("mutation", "expected_state"),
    [
        ("missing", "missing"),
        ("extra", "drift"),
        ("drift", "drift"),
        ("ambiguous", "ambiguous"),
    ],
)
def test_reconciliation_findings_fail_closed(environment, mutation, expected_state) -> None:
    expectation = _register(environment)
    authorities = environment[-2]
    if mutation == "missing":
        events = [_event(expectation, authorities, kind="masking_policy", event_number=1)]
    elif mutation == "extra":
        events = [
            _event(
                expectation,
                authorities,
                kind="grant",
                event_number=1,
                control_sha256=_sha("unexpected-grant"),
            )
        ]
    elif mutation == "drift":
        events = [
            _event(
                expectation,
                authorities,
                kind="masking_policy",
                event_number=1,
                control_sha256=_sha("wrong-control"),
            )
        ]
    else:
        events = [
            _event(
                expectation,
                authorities,
                kind="masking_policy",
                event_number=1,
                correlation_sha256=None,
            )
        ]
    claim = environment[-1].claim_ready(worker_id="worker")[0]
    result = environment[-1].record_batch(claim, _batch(expectation, events))
    assert result.state == expected_state
    assert result.state != "converged"


def test_event_dedup_and_exact_batch_replay_are_idempotent(environment) -> None:
    expectation = _register(environment)
    authorities = environment[-2]
    events = [
        _event(expectation, authorities, kind="masking_policy", event_number=1),
        _event(expectation, authorities, kind="state_anchor", event_number=2),
    ]
    claim = environment[-1].claim_ready(worker_id="worker")[0]
    batch = _batch(expectation, events)
    first = environment[-1].record_batch(claim, batch)
    second = environment[-1].record_batch(claim, batch)
    assert second == first
    assert len(environment[-1].list_event_evidence(expectation.expectation_id)) == 2


def test_complete_batch_requires_independently_resolved_watermark(environment) -> None:
    expectation = _register(environment)
    authorities = environment[-2]
    event = _event(expectation, authorities, kind="masking_policy", event_number=1)
    batch = _batch(expectation, [event])
    assert batch.watermark is not None
    self_signed = replace(batch.watermark, expires_at=batch.watermark.expires_at + 1)
    self_signed = replace(
        self_signed,
        authority_sha256=audit.accepted_watermark_sha256(self_signed),
    )
    claim = environment[-1].claim_ready(worker_id="worker")[0]

    with pytest.raises(
        audit.DataUseProviderAuditValidationError,
        match="independently authorized",
    ):
        environment[-1].record_batch(claim, replace(batch, watermark=self_signed))


def test_valid_partial_checkpoint_does_not_consume_failure_attempts(environment) -> None:
    expectation = _register(environment, max_attempts=1)
    claim = environment[-1].claim_ready(worker_id="worker")[0]
    assert environment[-1].get_expectation(expectation.expectation_id).attempts == 1

    result = environment[-1].record_batch(
        claim,
        _batch(expectation, [], complete=False, covered_until=expectation.cursor_occurred_at),
    )

    assert result.state == "queued"
    assert result.attempts == 0
    assert result.completed_at is None


def test_snowflake_query_history_requires_access_history_corroboration(
    tmp_path: Path,
) -> None:
    environment = _environment_for_provider(tmp_path, "snowflake")
    expectation = _register(environment)
    event = replace(
        _event(
            expectation,
            environment[-2],
            kind="masking_policy",
            event_number=1,
        ),
        object_change_corroborated=False,
    )
    claim = environment[-1].claim_ready(worker_id="worker")[0]

    result = environment[-1].record_batch(claim, _batch(expectation, [event]))

    assert result.state == "ambiguous"


def test_retry_lease_recovery_dead_letter_and_replay(environment) -> None:
    expectation = _register(environment, max_attempts=2)
    store = environment[-1]
    first_claim = store.claim_ready(worker_id="crashed", lease_seconds=1)[0]
    environment[1].advance(2)
    recovered = store.claim_ready(worker_id="recovery", lease_seconds=10)[0]
    assert recovered.expectation_id == first_claim.expectation_id
    dead = store.fail_claim(
        recovered,
        error_code="provider_temporarily_unavailable",
        retryable=True,
        backoff_seconds=0,
    )
    assert dead.state == "dead_letter"
    replayed = store.replay_dead_letter(
        expectation.expectation_id,
        expected_revision=dead.revision,
        idempotency_key="replay-dead-letter",
    )
    assert replayed.state == "queued"
    assert replayed.attempts == 0


def test_capability_or_key_drift_cancels_before_provider_read(environment) -> None:
    expectation = _register(environment)
    authorities = environment[-2]
    authorities.read_revision += 1
    owner = CredentialOwner(environment[3])
    transport = Transport([])
    result = audit.DataUseProviderAuditWorker(
        environment[-1],
        credential_owner=owner,
        transport=transport,
    ).run_once(worker_id="worker")
    assert result.cancelled == 1
    assert environment[-1].get_expectation(expectation.expectation_id).state == "cancelled"
    assert owner.calls == 0
    assert transport.requests == []


def test_closed_event_types_cursor_bounds_and_permanent_failures(environment) -> None:
    expectation = _register(environment)
    claim = environment[-1].claim_ready(worker_id="worker")[0]
    wrong = audit.DatabricksAuditEvent(
        source_table="system.access.audit",
        event_id_sha256=_sha("wrong"),
        request_id_sha256=_sha("request"),
        occurred_at=1_010.0,
        correlation_sha256=expectation.correlation_sha256,
        object_sha256=expectation.object_sha256,
        change_kind="masking_policy",
        control_sha256=environment[-2].mask_control,
        outcome="succeeded",
    )
    if expectation.provider_id == "snowflake":
        with pytest.raises(audit.DataUseProviderAuditValidationError):
            environment[-1].record_batch(claim, _batch(expectation, [wrong]))
    else:
        backwards = audit.ProviderAuditBatch(
            events=(),
            next_cursor=audit.ProviderAuditCursor(1.0, "0" * 64),
            covered_until=1_100.0,
            complete=False,
            provider_receipt_sha256=_sha("receipt"),
        )
        with pytest.raises(audit.DataUseProviderAuditValidationError):
            environment[-1].record_batch(claim, backwards)


def test_tenant_isolation_integrity_retention_and_delete_guard(environment, tmp_path) -> None:
    expectation = _register(environment)
    store = environment[-1]
    assert store.verify_integrity().expectations == 1
    foreign = audit.DataUseProviderAuditStore(
        store.path,
        tenant_id="Other Tenant",
        binding_store=environment[2],
        control_authority_resolver=environment[-2].control,
        read_authority_resolver=environment[-2].read,
        config_gate=lambda: None,
        clock=environment[1],
    )
    with pytest.raises(audit.DataUseProviderAuditNotFound):
        foreign.get_expectation(expectation.expectation_id)
    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.OperationalError):
            connection.execute(
                "DELETE FROM provider_audit_expectations WHERE expectation_id=?",
                (expectation.expectation_id,),
            )
    environment[1].value = 2_001.0
    assert store.purge_expired(cutoff=2_001.0) == 1
    verification = store.verify_integrity()
    assert verification.expectations == 0
    assert verification.audit_events >= 2


def test_integrity_detects_current_payload_tampering(environment) -> None:
    expectation = _register(environment)
    store = environment[-1]
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE provider_audit_expectations SET payload_json='{}' WHERE expectation_id=?",
            (expectation.expectation_id,),
        )
        connection.commit()
    with pytest.raises(audit.DataUseProviderAuditIntegrityError):
        store.get_expectation(expectation.expectation_id)
