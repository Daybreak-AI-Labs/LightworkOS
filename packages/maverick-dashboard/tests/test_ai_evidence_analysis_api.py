from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import ai_evidence_analysis as evidence
from maverick_dashboard import ai_evidence_analysis_api as api

TENANT = "tenant-evidence"
NOW = 2_100_000_000.0
BASE = "/api/v1/ai-evidence-analysis"
RAW_SECRET = "raw-upload-secret-must-not-escape"


def _ns(**kwargs):
    return SimpleNamespace(**kwargs)


def _record(*, status: str = "pending_review", revision: int = 1):
    digest = "a" * 64
    criterion = _ns(
        criterion_id="criterion-access",
        revision=3,
        control_ref="control-access",
        control_revision=7,
        control_sha256="1" * 64,
        legal_basis_ref="legal-basis-access",
        legal_basis_revision=5,
        legal_basis_sha256="2" * 64,
        stakeholder_requirement_ref="stakeholder-access",
        stakeholder_requirement_revision=4,
        stakeholder_requirement_sha256="3" * 64,
        expected_fact_code="FACT.access",
        gap_code="gap-access",
        remediation_code="remediate-access",
        weight_bps=10_000,
        criterion_sha256="4" * 64,
    )
    adapter = _ns(
        adapter_id="server-adapter",
        revision=2,
        authority_sha256="5" * 64,
        deterministic=True,
        network_access=False,
        untrusted_content_mode="data_only",
        legal_conclusion_enabled=False,
        implementation_sha256="should-not-be-returned",
        configuration_sha256="should-not-be-returned",
    )
    return _ns(
        analysis_id="EVA-0123456789abcdef",
        tenant_sha256="tenant-digest-must-not-be-returned",
        submitter_sha256="submitter-digest-must-not-be-returned",
        raw_content=RAW_SECRET.encode(),
        artifact=_ns(
            artifact_id="artifact-one",
            media_type=evidence.MEDIA_TEXT,
            content_sha256="6" * 64,
            byte_length=44,
            source_ref="source-vault",
            source_revision=2,
            acquired_at=NOW - 20,
            artifact_authority_sha256="7" * 64,
            descriptor_sha256="8" * 64,
        ),
        criteria_authority=_ns(
            criteria_set_id="criteria-one",
            revision=9,
            authority_sha256="9" * 64,
            criteria=(criterion,),
        ),
        extraction_adapter_authority=adapter,
        analysis_adapter_authority=adapter,
        extraction=_ns(
            facts=(
                _ns(
                    fact_id="fact-access",
                    fact_code="FACT.access",
                    locator_sha256="a" * 64,
                    value_sha256="b" * 64,
                    confidence_bps=10_000,
                    fact_sha256="c" * 64,
                ),
            )
        ),
        adapter_analysis=_ns(
            assessments=(
                _ns(
                    criterion_id="criterion-access",
                    criterion_sha256="4" * 64,
                    disposition="evidence_supported",
                    fact_ids=("fact-access",),
                    confidence_bps=10_000,
                    rationale_code="direct_evidence",
                    assessment_sha256="d" * 64,
                ),
            )
        ),
        summary=_ns(
            total_criteria=1,
            evidence_supported=1,
            evidence_partial=0,
            evidence_missing=0,
            indeterminate=0,
            extracted_fact_count=1,
            summary_sha256="e" * 64,
        ),
        justification=_ns(
            methodology="weighted_evidence_coverage_bps_v1",
            score_bps=10_000,
            maximum_bps=10_000,
            score_sha256="f" * 64,
            components=(
                _ns(
                    criterion_id="criterion-access",
                    weight_bps=10_000,
                    coverage_bps=10_000,
                    confidence_bps=10_000,
                    provenance_bps=10_000,
                    component_score_bps=10_000,
                    component_sha256="0" * 64,
                ),
            ),
        ),
        gaps=(),
        provenance=(
            _ns(
                sequence=1,
                stage="artifact_authority",
                input_sha256="0" * 64,
                output_sha256="1" * 64,
                previous_link_sha256="0" * 64,
                link_sha256="2" * 64,
            ),
        ),
        provenance_sha256="2" * 64,
        status=status,
        revision=revision,
        human_review_required=True,
        review_decision=None if status == "pending_review" else "approve",
        review_authority=None if status == "pending_review" else _ns(private="reviewer"),
        reviewed_at=None if status == "pending_review" else NOW,
        revocation_authority=None,
        revocation_reason_code=None,
        revoked_at=None,
        legal_or_compliance_conclusion=False,
        notice=evidence.NON_CONCLUSION_NOTICE,
        valid_until=NOW + 1_000,
        retained_until=NOW + 2_000,
        created_at=NOW,
        updated_at=NOW,
        previous_integrity_sha256=None,
        integrity_sha256=digest,
    )


class Store:
    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []
        self.record = _record()
        self.failure: Exception | None = None

    def _call(self, name: str, args: tuple[object, ...], kwargs: dict[str, object]):
        self.calls.append((name, args, kwargs))
        if self.failure is not None:
            raise self.failure
        return self.record

    def analyze(self, *args, **kwargs):
        return self._call("analyze", args, kwargs)

    def get(self, *args, **kwargs):
        return self._call("get", args, kwargs)

    def get_released(self, *args, **kwargs):
        return self._call("get_released", args, kwargs)

    def review(self, *args, **kwargs):
        return self._call("review", args, kwargs)

    def revoke(self, *args, **kwargs):
        return self._call("revoke", args, kwargs)

    def list_analyses(self, *args, **kwargs):
        self.calls.append(("list_analyses", args, kwargs))
        return (self.record,)

    def history(self, *args, **kwargs):
        self.calls.append(("history", args, kwargs))
        return (self.record, _record(status="review_approved", revision=2))

    def retention_due(self, *args, **kwargs):
        self.calls.append(("retention_due", args, kwargs))
        return (self.record.analysis_id,)

    def purge_expired(self, *args, **kwargs):
        self.calls.append(("purge_expired", args, kwargs))
        return _ns(
            analysis_ids=(self.record.analysis_id,),
            history_records=1,
            operations=2,
        )

    def verify_integrity(self, *args, **kwargs):
        self.calls.append(("verify_integrity", args, kwargs))
        return _ns(
            schema=evidence.INTEGRITY_SCHEMA,
            analyses=1,
            history_records=1,
            operations=2,
            terminal_sha256="a" * 64,
            verification_sha256="b" * 64,
        )


def _metadata(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "lightwork.ai-evidence.upload-metadata.v1",
        "artifact_id": "artifact-one",
        "source_ref": "source-vault",
        "source_revision": 2,
        "acquired_at": NOW - 20,
        "expected_artifact_authority_sha256": "1" * 64,
        "criteria_set_id": "criteria-one",
        "expected_criteria_revision": 9,
        "expected_criteria_authority_sha256": "2" * 64,
        "idempotency_key": "upload-operation-one",
    }
    value.update(updates)
    return value


def _upload_headers(metadata: dict[str, object] | None = None) -> dict[str, str]:
    return {
        "Content-Type": evidence.MEDIA_TEXT,
        "X-Lightwork-Evidence-Metadata": json.dumps(metadata or _metadata()),
    }


@pytest.fixture()
def environment(monkeypatch: pytest.MonkeyPatch):
    state = _ns(
        enabled=True,
        factory_calls=[],
        lifetime_calls=[],
        permissions=[],
        subject="user:submitter",
        stores=[],
        media_settings={
            "schema": "lightwork.ai-evidence.tenant-status-settings.v1",
            "supported_media": {evidence.MEDIA_TEXT: 4_096},
            "enabled_media_names": ["text"],
            "parser_sandbox_configured": False,
            "ocr_configured": False,
            "legacy_xls_configured": False,
            "authority_history_capacity": 100_000,
            "authority_retention_seconds": 31_536_000,
            "store_opened": False,
            "runtime_parser_probe_performed": False,
        },
    )
    monkeypatch.setattr(api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(
        api,
        "require_permission",
        lambda _request, permission: state.permissions.append(permission),
    )
    def factory(tenant_id: str, actor_ref: str, request: Request):
        state.factory_calls.append((tenant_id, actor_ref, request))
        store = Store(tenant_id)
        state.stores.append(store)
        return store

    def lifetime(tenant_id: str, actor_ref: str, request: Request):
        state.lifetime_calls.append((tenant_id, actor_ref, request))
        return NOW + 1_000, NOW + 2_000

    deps = api.AiEvidenceAnalysisDependencies(
        store_for=factory,
        enabled_probe=lambda _tenant: state.enabled,
        lifetime_for=lifetime,
        status_settings_for=lambda _tenant: dict(state.media_settings),
    )
    app = FastAPI()

    @app.middleware("http")
    async def _principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal=state.subject)
        return await call_next(request)

    app.include_router(api.create_ai_evidence_analysis_router(deps), prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    return client, state, app


def test_status_is_honest_and_never_opens_a_store(environment) -> None:
    client, state, _app = environment

    response = client.get(f"{BASE}/status")

    assert response.status_code == 200
    body = response.json()
    assert body["schema"] == "lightwork.ai-evidence.api-status.v1"
    assert body["enabled"] is True
    assert body["ready"] is False
    assert body["configured_for_operation_attempt"] is True
    assert body["operational_composition_verified"] is False
    assert body["configuration"] == {
        "enabled_probe_configured": True,
        "store_factory_configured": True,
        "lifetime_policy_configured": True,
        "store_opened_for_status": False,
        "selected_adapter_authorities_resolved_for_status": False,
        "tenant_media_policy_probe_configured": True,
        "tenant_media_policy_resolved_for_status": True,
    }
    assert body["supported_media"] == {evidence.MEDIA_TEXT: 4_096}
    assert body["tenant_media_policy"]["enabled_media_names"] == ["text"]
    assert body["boundaries"]["multipart_temp_spooling_used"] is False
    assert body["boundaries"]["raw_artifact_content_persisted"] is False
    assert body["boundaries"]["human_review_required"] is True
    assert body["boundaries"]["legal_or_compliance_conclusion"] is False
    assert body["boundaries"]["supported_media_scope"] == "tenant_enabled_only"
    assert body["boundaries"]["legacy_xls_local_parser_available"] is False
    assert state.factory_calls == []
    assert response.headers["cache-control"] == "no-store, private, max-age=0"

    state.enabled = False
    disabled = client.get(f"{BASE}/status")
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    assert disabled.json()["ready"] is False
    assert state.factory_calls == []


def test_status_consumes_side_effect_free_readiness_probe(environment) -> None:
    client, state, app = environment
    calls: list[str] = []
    app.state.ai_evidence_analysis_readiness_probe = lambda tenant: (
        calls.append(tenant) or True
    )

    response = client.get(f"{BASE}/status")

    assert response.status_code == 200
    assert response.json()["ready"] is True
    assert response.json()["operational_composition_verified"] is True
    assert calls == [TENANT]
    assert state.factory_calls == []


def test_status_reports_only_tenant_enabled_media_and_readiness_bound_legacy_xls(
    environment,
) -> None:
    client, state, app = environment
    state.media_settings = {
        **state.media_settings,
        "supported_media": {
            evidence.MEDIA_TEXT: 4_096,
            evidence.MEDIA_XLS: 8_192,
        },
        "enabled_media_names": ["text", "xls"],
        "parser_sandbox_configured": True,
        "legacy_xls_configured": True,
    }
    app.state.ai_evidence_analysis_readiness_probe = lambda _tenant: True

    body = client.get(f"{BASE}/status").json()

    assert body["ready"] is True
    assert body["supported_media"] == {
        evidence.MEDIA_TEXT: 4_096,
        evidence.MEDIA_XLS: 8_192,
    }
    assert evidence.MEDIA_PDF not in body["supported_media"]
    assert body["boundaries"]["legacy_xls_local_parser_configured"] is True
    assert body["boundaries"]["legacy_xls_local_parser_available"] is True
    assert body["boundaries"]["local_parser_customer_acceptance_verified"] is False
    assert state.factory_calls == []


def test_upload_enforces_tenant_transport_limit_before_analysis(environment) -> None:
    client, state, app = environment
    app.state.ai_evidence_analysis_artifact_limit_resolver = (
        lambda tenant, media_type: 8
        if tenant == TENANT and media_type == evidence.MEDIA_TEXT
        else 1
    )

    response = client.post(
        f"{BASE}/analyses",
        headers=_upload_headers(),
        content=b"nine-byte",
    )

    assert response.status_code == 413
    assert state.stores[0].calls == []


def test_status_distinguishes_python_ocr_wrapper_from_external_binary(
    environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _state, _app = environment
    original_find_spec = api.importlib.util.find_spec

    monkeypatch.setattr(
        api.importlib.util,
        "find_spec",
        lambda name: original_find_spec(name),
    )
    monkeypatch.setattr(api.shutil, "which", lambda _name: None)

    body = client.get(f"{BASE}/status").json()

    assert "pytesseract" not in body["local_parser_packages_detected"]
    assert body["external_parser_binaries_detected"]["tesseract"] is False
    assert body["ready"] is False


def test_raw_upload_uses_server_tenant_actor_lifetime_and_safe_projection(environment) -> None:
    client, state, _app = environment
    raw = f"LIGHTWORK_EVIDENCE_FACT:FACT.access\n{RAW_SECRET}".encode()

    response = client.post(f"{BASE}/analyses", headers=_upload_headers(), content=raw)

    assert response.status_code == 201
    payload = response.json()
    rendered = response.text
    assert payload["status"] == "pending_review"
    assert payload["artifact"]["artifact_id"] == "artifact-one"
    assert payload["criteria"]["items"][0]["control_revision"] == 7
    assert payload["findings"][0]["disposition"] == "evidence_supported"
    assert payload["human_review"]["required"] is True
    assert payload["legal_or_compliance_conclusion"] is False
    for forbidden in (
        RAW_SECRET,
        TENANT,
        state.subject,
        "tenant-digest-must-not-be-returned",
        "submitter-digest-must-not-be-returned",
        "should-not-be-returned",
    ):
        assert forbidden not in rendered

    tenant, actor, request = state.factory_calls[0]
    assert tenant == TENANT
    assert actor.startswith("ai-evidence-api.")
    assert isinstance(request, Request)
    assert state.lifetime_calls[0][:2] == (TENANT, actor)
    store = state.stores[0]
    name, args, kwargs = store.calls[0]
    assert name == "analyze"
    assert args == (TENANT,)
    artifact = kwargs["artifact"]
    assert type(artifact) is evidence.EvidenceArtifact
    assert artifact.content == raw
    assert artifact.media_type == evidence.MEDIA_TEXT
    assert kwargs["submitter_ref"] == actor
    assert kwargs["valid_until"] == NOW + 1_000
    assert kwargs["retained_until"] == NOW + 2_000
    assert "tenant_id" not in kwargs
    assert "extraction_adapter" not in kwargs
    assert "analysis_adapter" not in kwargs


@pytest.mark.parametrize(
    "forbidden",
    [
        {"tenant_id": "tenant-attacker"},
        {"actor_ref": "attacker"},
        {"reviewer_ref": "attacker"},
        {"extraction_adapter": "caller-model"},
        {"analysis_adapter_authority": {"trusted": True}},
        {"valid_until": NOW + 90_000},
        {"retained_until": NOW + 90_000},
        {"source_revision": "2"},
        {"expected_criteria_revision": "9"},
        {"acquired_at": str(NOW - 20)},
        {"idempotency_key": 7},
    ],
)
def test_upload_metadata_rejects_authority_and_policy_fields(environment, forbidden) -> None:
    client, state, _app = environment

    response = client.post(
        f"{BASE}/analyses",
        headers=_upload_headers(_metadata(**forbidden)),
        content=b"bounded",
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "evidence upload metadata is invalid"
    assert all(not store.calls for store in state.stores)


def test_upload_rejects_query_unsupported_encoded_and_oversize_content(
    environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, state, _app = environment

    assert (
        client.post(
            f"{BASE}/analyses?tenant_id=attacker",
            headers=_upload_headers(),
            content=b"bounded",
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"{BASE}/analyses",
            headers={**_upload_headers(), "Content-Type": "application/octet-stream"},
            content=b"bounded",
        ).status_code
        == 415
    )
    assert (
        client.post(
            f"{BASE}/analyses",
            headers={**_upload_headers(), "Content-Encoding": "gzip"},
            content=b"bounded",
        ).status_code
        == 415
    )
    monkeypatch.setattr(evidence, "artifact_byte_limit", lambda _media: 4)
    oversized = client.post(
        f"{BASE}/analyses",
        headers=_upload_headers(),
        content=b"12345",
    )
    assert oversized.status_code == 413
    assert all(not store.calls for store in state.stores)


def test_missing_or_misbound_server_composition_fails_closed(environment) -> None:
    client, state, app = environment
    app.state.ai_evidence_analysis_store_factory = None

    no_lifetime_app = FastAPI()
    no_lifetime_app.include_router(
        api.create_ai_evidence_analysis_router(
            api.AiEvidenceAnalysisDependencies(
                store_for=lambda tenant, _actor, _request: Store(tenant),
                enabled_probe=lambda _tenant: True,
            )
        ),
        prefix="/api/v1",
    )
    no_lifetime = TestClient(no_lifetime_app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    no_lifetime_response = no_lifetime.post(
        f"{BASE}/analyses", headers=_upload_headers(), content=b"bounded"
    )
    assert no_lifetime_response.status_code == 503
    assert "retention policy" in no_lifetime_response.json()["detail"]

    app.state.ai_evidence_analysis_store_factory = lambda _tenant, _actor, _request: Store(
        "tenant-misbound"
    )
    misbound = client.get(f"{BASE}/analyses/EVA-0123456789abcdef")
    assert misbound.status_code == 503
    assert misbound.json()["detail"] == "AI evidence-analysis authority is unavailable"

    state.enabled = False
    disabled = client.get(f"{BASE}/analyses/EVA-0123456789abcdef")
    assert disabled.status_code == 403
    assert disabled.json()["detail"] == "ai_evidence_analysis_disabled"


def test_review_revoke_reads_integrity_and_retention_use_closed_server_authority(
    environment,
) -> None:
    client, state, _app = environment
    identifier = "EVA-0123456789abcdef"

    get_response = client.get(f"{BASE}/analyses/{identifier}")
    released = client.get(f"{BASE}/analyses/{identifier}/released")
    history = client.get(f"{BASE}/analyses/{identifier}/history")
    review = client.post(
        f"{BASE}/analyses/{identifier}/review",
        json={
            "expected_revision": 1,
            "decision": "approve",
            "idempotency_key": "review-operation-one",
        },
    )
    revoke = client.post(
        f"{BASE}/analyses/{identifier}/revoke",
        json={
            "expected_revision": 2,
            "reason_code": "source-revoked",
            "idempotency_key": "revoke-operation-one",
        },
    )
    integrity = client.get(f"{BASE}/integrity")
    due = client.get(f"{BASE}/retention/due?limit=10")
    purged = client.post(f"{BASE}/retention/purge", json={"limit": 10})

    assert all(
        item.status_code == 200
        for item in (get_response, released, history, review, revoke, integrity, due, purged)
    )
    assert history.json()["count"] == 2
    assert integrity.json()["verification_sha256"] == "b" * 64
    assert due.json()["as_of"] == "server_clock"
    assert purged.json()["analyses"] == 1
    assert purged.json()["as_of"] == "server_clock"
    assert {"view", "operate", "admin", "audit"}.issubset(set(state.permissions))

    review_store = state.stores[3]
    assert review_store.calls[0][0] == "review"
    review_actor = state.factory_calls[3][1]
    assert review_store.calls[0][2]["reviewer_ref"] == review_actor
    revoke_store = state.stores[4]
    assert revoke_store.calls[0][0] == "revoke"
    assert revoke_store.calls[0][2]["reviewer_ref"] == state.factory_calls[4][1]

    extra = client.post(
        f"{BASE}/analyses/{identifier}/review",
        json={
            "expected_revision": 1,
            "decision": "approve",
            "idempotency_key": "review-operation-two",
            "reviewer_ref": "caller-selected",
        },
    )
    assert extra.status_code == 422


def test_retention_purge_uses_composed_authority_maintenance_when_installed(
    environment,
) -> None:
    client, state, app = environment
    calls: list[tuple[str, int]] = []

    def maintenance(tenant_id: str, *, limit: int):
        calls.append((tenant_id, limit))
        return _ns(
            schema="lightwork.ai-evidence.maintenance-result.v2",
            tenant_id=tenant_id,
            registry_records=7,
            registry_records_before=10,
            live_authorities=5,
            retained_expired_authorities=2,
            authority_tombstones=3,
            compacted_authorities=2,
            compacted_authority_records=3,
            purged_authority_tombstones=1,
            authority_compaction_anchor_sha256="c" * 64,
            analyses_before=2,
            purged_analysis_ids=("EVA-purged-one",),
            purged_analyses=1,
            purged_history_records=2,
            purged_operations=3,
            analyses_after=1,
            integrity_verified=True,
        )

    app.state.ai_evidence_analysis_maintenance_runner = maintenance

    response = client.post(f"{BASE}/retention/purge", json={"limit": 12})

    assert response.status_code == 200
    assert calls == [(TENANT, 12)]
    assert response.json()["analysis_ids"] == ["EVA-purged-one"]
    assert response.json()["authority_registry_records_before"] == 10
    assert response.json()["authority_registry_records_after"] == 7
    assert response.json()["compacted_authorities"] == 2
    assert response.json()["authority_compaction_anchor_sha256"] == "c" * 64
    assert state.stores[-1].calls == []


def test_dependency_errors_are_sanitized_and_principal_binding_changes(environment) -> None:
    client, state, app = environment
    first = client.get(f"{BASE}/analyses/EVA-0123456789abcdef")
    assert first.status_code == 200
    first_actor = state.factory_calls[-1][1]

    state.subject = "user:other"
    second = client.get(f"{BASE}/analyses/EVA-0123456789abcdef")
    assert second.status_code == 200
    assert state.factory_calls[-1][1] != first_actor

    broken = Store(TENANT)
    broken.failure = evidence.EvidenceAnalysisConfigError(RAW_SECRET)
    app.state.ai_evidence_analysis_store_factory = lambda _tenant, _actor, _request: broken
    failed = client.get(f"{BASE}/analyses/EVA-0123456789abcdef")
    assert failed.status_code == 503
    assert failed.json()["detail"] == "AI evidence-analysis dependency is unavailable"
    assert RAW_SECRET not in failed.text


def test_status_without_composition_reports_not_ready_without_constructing_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    app = FastAPI()
    app.include_router(api.create_ai_evidence_analysis_router(), prefix="/api/v1")
    response = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get(f"{BASE}/status")

    assert response.status_code == 200
    assert response.json()["enabled"] is False
    assert response.json()["ready"] is False
    assert response.json()["configured_for_operation_attempt"] is False
    assert response.json()["operational_composition_verified"] is False
    assert response.json()["configuration"] == {
        "enabled_probe_configured": False,
        "store_factory_configured": False,
        "lifetime_policy_configured": False,
        "store_opened_for_status": False,
        "selected_adapter_authorities_resolved_for_status": False,
        "tenant_media_policy_probe_configured": False,
        "tenant_media_policy_resolved_for_status": False,
    }
    assert response.json()["supported_media"] == {}


def test_api_round_trip_with_real_core_store_and_distinct_human_reviewer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = b"LIGHTWORK_EVIDENCE_FACT:FACT.access"

    def digest(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    criterion_raw = evidence.EvidenceCriterion(
        criterion_id="criterion-access",
        revision=3,
        control_ref="control-access",
        control_revision=7,
        control_sha256=digest("control-access-7"),
        legal_basis_ref="legal-basis-access",
        legal_basis_revision=5,
        legal_basis_sha256=digest("legal-basis-access-5"),
        stakeholder_requirement_ref="stakeholder-access",
        stakeholder_requirement_revision=4,
        stakeholder_requirement_sha256=digest("stakeholder-access-4"),
        expected_fact_code="FACT.access",
        gap_code="gap-access",
        remediation_code="remediate-access",
        weight_bps=10_000,
        criterion_sha256="0" * 64,
    )
    criterion = replace(
        criterion_raw,
        criterion_sha256=evidence.criterion_sha256(criterion_raw),
    )
    criteria_raw = evidence.EvidenceCriteriaAuthority(
        tenant_sha256=digest(TENANT),
        criteria_set_id="criteria-one",
        revision=9,
        criteria=(criterion,),
        valid_until=NOW + 5_000,
        revoked=False,
        authority_sha256="0" * 64,
    )
    criteria = replace(
        criteria_raw,
        authority_sha256=evidence.criteria_authority_sha256(criteria_raw),
    )
    artifact_raw = evidence.EvidenceArtifactAuthority(
        tenant_sha256=digest(TENANT),
        artifact_id="artifact-one",
        media_type=evidence.MEDIA_TEXT,
        content_sha256=hashlib.sha256(raw).hexdigest(),
        byte_length=len(raw),
        source_ref="source-vault",
        source_revision=2,
        acquired_at=NOW - 20,
        valid_until=NOW + 5_000,
        revoked=False,
        authority_sha256="0" * 64,
    )
    artifact_authority = replace(
        artifact_raw,
        authority_sha256=evidence.artifact_authority_sha256(artifact_raw),
    )
    local_extraction = evidence.BoundedLocalExtractionAdapter()
    local_analysis = evidence.DeterministicCriteriaAnalysisAdapter()
    extraction_authority = local_extraction.authority(valid_until=NOW + 5_000)
    analysis_authority = local_analysis.authority(valid_until=NOW + 5_000)

    def adapter_authority(
        _tenant: str,
        stage: str,
        adapter_id: str,
        revision: int,
    ):
        selected = extraction_authority if stage == "extraction" else analysis_authority
        assert selected.adapter_id == adapter_id
        assert selected.revision == revision
        return selected

    def review_authority(_tenant: str, reviewer_ref: str):
        raw_authority = evidence.HumanReviewAuthority(
            tenant_sha256=digest(TENANT),
            reviewer_sha256=digest(f"lightwork.ai-evidence.actor.v1:{TENANT}:{reviewer_ref}"),
            capabilities=("approve", "reject", "revoke"),
            revision=1,
            valid_until=NOW + 5_000,
            revoked=False,
            authority_sha256="0" * 64,
        )
        return replace(
            raw_authority,
            authority_sha256=evidence.review_authority_sha256(raw_authority),
        )

    store = evidence.EvidenceAnalysisStore(
        tmp_path / "api-real-evidence.sqlite3",
        tenant_id=TENANT,
        artifact_authority_resolver=lambda _tenant, _artifact: artifact_authority,
        criteria_authority_resolver=lambda _tenant, _criteria: criteria,
        review_authority_resolver=review_authority,
        adapter_authority_resolver=adapter_authority,
        extraction_adapter=local_extraction,
        analysis_adapter=local_analysis,
        extraction_adapter_authority=extraction_authority,
        analysis_adapter_authority=analysis_authority,
        config_gate=lambda: None,
        clock=lambda: NOW,
        id_factory=lambda: "EVA-real-round-trip",
    )
    state = _ns(subject="user:submitter")
    monkeypatch.setattr(api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    app = FastAPI()

    @app.middleware("http")
    async def _principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal=state.subject)
        return await call_next(request)

    app.include_router(
        api.create_ai_evidence_analysis_router(
            api.AiEvidenceAnalysisDependencies(
                store_for=lambda _tenant, _actor, _request: store,
                enabled_probe=lambda _tenant: True,
                lifetime_for=lambda _tenant, _actor, _request: (
                    NOW + 1_000,
                    NOW + 2_000,
                ),
            )
        ),
        prefix="/api/v1",
    )
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    upload_metadata = _metadata(
        expected_artifact_authority_sha256=artifact_authority.authority_sha256,
        expected_criteria_authority_sha256=criteria.authority_sha256,
        idempotency_key="real-upload-operation",
    )

    analyzed = client.post(
        f"{BASE}/analyses",
        headers=_upload_headers(upload_metadata),
        content=raw,
    )
    assert analyzed.status_code == 201
    assert analyzed.json()["analysis_id"] == "EVA-real-round-trip"
    assert analyzed.json()["summary"]["evidence_supported"] == 1
    assert analyzed.json()["criteria"]["items"][0]["expected_fact_code"] == "FACT.access"
    assert analyzed.json()["status"] == "pending_review"

    state.subject = "user:independent-reviewer"
    reviewed = client.post(
        f"{BASE}/analyses/EVA-real-round-trip/review",
        json={
            "expected_revision": 1,
            "decision": "approve",
            "idempotency_key": "real-review-operation",
        },
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "review_approved"
    assert reviewed.json()["human_review"] == {
        "required": True,
        "decision": "approve",
        "authority_recorded": True,
        "reviewed_at": NOW,
    }
    released = client.get(f"{BASE}/analyses/EVA-real-round-trip/released")
    assert released.status_code == 200
    assert released.json()["integrity_sha256"] == reviewed.json()["integrity_sha256"]
    persisted = store.path.read_bytes()
    assert raw not in persisted
    assert b"user:submitter" not in persisted
    assert b"user:independent-reviewer" not in persisted


def test_analysis_list_is_view_scoped_to_the_callers_workspace_and_safe(environment) -> None:
    client, state, _app = environment
    response = client.get(f"{BASE}/analyses?status=pending_review&limit=5")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["count"] == 1
    assert body["items"][0]["analysis_id"] == "EVA-0123456789abcdef"
    assert state.permissions == ["view"]
    store = state.stores[0]
    assert store.tenant_id == TENANT
    assert store.calls == [("list_analyses", (TENANT,), {"status": "pending_review", "limit": 5})]
    text = response.text
    assert RAW_SECRET not in text and "tenant-digest-must-not-be-returned" not in text
    assert client.get(f"{BASE}/analyses?status=anything").status_code == 422
    state.enabled = False
    assert client.get(f"{BASE}/analyses").status_code == 403
