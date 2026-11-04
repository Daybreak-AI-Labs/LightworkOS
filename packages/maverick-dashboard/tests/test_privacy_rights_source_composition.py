from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick import privacy_rights_orchestration as rights
from maverick import privacy_rights_source_adapters as adapters
from maverick import privacy_rights_source_worker as worker
from maverick_dashboard import privacy_rights_source_composition as composition


def _config(*, capabilities=None, retrieve: bool = False):
    selected = capabilities or (["retrieve", "discover"] if retrieve else ["discover"])
    return {
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {
                "enable": True,
                "source_adapters": {
                    "enable": True,
                    "timeout_seconds": 12.0,
                    "max_response_bytes": 65_536,
                    "max_retrieval_bytes": 1_048_576,
                    "max_records": 50,
                    "batch_size": 5,
                    "lease_seconds": 30,
                    "retry_delay_seconds": 15,
                    "providers": {
                        "microsoft_graph_users": {
                            "enable": True,
                            "source_id": "directory",
                            "origin": "https://graph.microsoft.com",
                            "credential_ref": "env:GRAPH_RIGHTS_TOKEN",
                            "capabilities": selected,
                        }
                    },
                },
            },
        }
    }


def _settings(*, capabilities=None):
    return composition.settings_from_config(_config(capabilities=capabilities))


def test_settings_are_closed_sorted_bounded_and_secret_reference_only() -> None:
    settings = _settings(capabilities=["verify_delete", "delete", "discover"])
    assert settings.enabled is True
    assert settings.batch_size == 5
    assert settings.lease_seconds == 30
    assert settings.retry_delay_seconds == 15
    assert len(settings.config_sha256) == 64
    source = settings.sources[0]
    assert source.provider == "microsoft_graph_users"
    assert source.adapter_ref == (
        f"stock:microsoft_graph_users:v2:{settings.config_sha256}"
    )
    assert source.capabilities == ("delete", "discover", "verify_delete")
    assert source.credential_ref == "env:GRAPH_RIGHTS_TOKEN"

    invalid = _config()
    invalid["privacy_automation"]["rights_orchestration"]["source_adapters"][
        "providers"
    ]["invented_provider"] = {}
    with pytest.raises(composition.PrivacyRightsSourceCompositionError):
        composition.settings_from_config(invalid)

    raw_secret = _config()
    raw_secret["privacy_automation"]["rights_orchestration"]["source_adapters"][
        "providers"
    ]["microsoft_graph_users"]["credential_ref"] = "plaintext-token"
    with pytest.raises(composition.PrivacyRightsSourceCompositionError):
        composition.settings_from_config(raw_secret)


def test_pinned_transport_refuses_private_override_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "true")
    transport = composition.PinnedPrivacyRightsHTTPTransport()
    with pytest.raises(
        composition.PrivacyRightsSourceCompositionError,
        match="private-fetch override",
    ):
        transport.request(
            "GET",
            "https://graph.microsoft.com/v1.0/users/example",
            headers={"accept": "application/json"},
            body=None,
            timeout=5,
            max_response_bytes=65_536,
            allow_redirects=False,
        )


def test_governed_vault_sink_returns_only_encrypted_tenant_bound_receipt() -> None:
    body = b'{"id":"graph-user-1"}'
    digest = hashlib.sha256(body).hexdigest()
    calls: list[dict[str, object]] = []

    class Vault:
        def ingest(self, content, **kwargs):
            calls.append({"content": content, **kwargs})
            return SimpleNamespace(
                document_ref="doc_opaque-retrieval",
                content_sha256=hashlib.sha256(content).hexdigest(),
                byte_size=len(content),
            )

    sink = composition.GovernedVaultRetrievalSink(
        tenant_id="tenant-a",
        vault=Vault(),
        principal_ref="source-worker",
    )
    receipt = sink.store(
        tenant_id="tenant-a",
        case_id="case-1",
        source_id="directory",
        operation_id="operation:1",
        content_type="application/json; charset=utf-8",
        body=body,
        sha256=digest,
        record_count=1,
    )
    assert receipt.opaque_ref == "doc_opaque-retrieval"
    assert receipt.sha256 == digest
    assert receipt.tenant_bound is True
    assert receipt.encrypted_at_rest is True
    assert receipt.retention_enforced is True
    assert receipt.raw_data_returned is False
    assert calls[0]["product_area"] == "privacy_automation"
    assert calls[0]["record_type"] == "privacy_rights_source_retrieval"
    with pytest.raises(composition.PrivacyRightsSourceCompositionError):
        sink.store(
            tenant_id="tenant-b",
            case_id="case-1",
            source_id="directory",
            operation_id="operation:1",
            content_type="application/json",
            body=body,
            sha256=digest,
            record_count=1,
        )


def test_readiness_is_side_effect_free_and_requires_subject_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: settings)
    app = SimpleNamespace(state=SimpleNamespace())

    unavailable = composition.readiness(app, "tenant-a")
    assert unavailable["configured"] is True
    assert unavailable["ready"] is False
    assert unavailable["status_probe_opened_store"] is False
    assert unavailable["status_probe_invoked_provider"] is False
    assert unavailable["status_probe_resolved_secret"] is False

    app.state.privacy_rights_source_subject_resolver = lambda *_args: None
    available = composition.readiness(app, "tenant-a")
    assert available["ready"] is False
    assert available["configuration_preflight_ready"] is True
    assert available["executable_ready"] is False
    assert available["credential_preflight_performed"] is False
    assert available["credential_values_resolved"] is False
    assert available["live_provider_acceptance_verified"] is False


def test_composed_worker_executes_enrolled_source_without_persisting_raw_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest_key = "k" * 32
    monkeypatch.setenv("MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY", digest_key)
    database = tmp_path / "privacy-rights.sqlite3"
    settings = _settings()
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: settings)
    monkeypatch.setattr(rights, "require_enabled", lambda: None)
    monkeypatch.setattr(
        composition,
        "data_dir",
        lambda *_args, **_kwargs: database,
    )
    actor = {"value": "planner"}
    store = rights.PrivacyRightsOrchestrationStore(
        database,
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        digest_key_resolver=lambda _tenant: digest_key.encode(),
        clock=lambda: 2_000_000_000.0,
        token_factory=lambda: "lease-token",
    )
    source = store.enroll_source(
        "tenant-a",
        "directory",
        adapter_ref=settings.sources[0].adapter_ref,
        credential_ref="env:GRAPH_RIGHTS_TOKEN",
        capabilities=["discover"],
        expected_revision=0,
        idempotency_key="source",
    )
    case = store.open_case(
        "tenant-a",
        "case-1",
        request_version=1,
        external_request_ref="request-1",
        subject_reference="person@example.test",
        rights=["access"],
        retained_until=2_000_000_600.0,
        idempotency_key="case",
    )
    case = store.set_identity_verification(
        "tenant-a",
        case.case_id,
        status="verified",
        evidence_sha256=hashlib.sha256(b"identity").hexdigest(),
        evidence_ref="identity:1",
        expected_revision=case.revision,
        idempotency_key="identity",
    )
    task = store.plan_source_tasks(
        "tenant-a",
        case.case_id,
        source.source_id,
        phases=["discover"],
        max_attempts=3,
        expected_case_revision=case.revision,
        idempotency_key="plan",
    )[0]
    subject_digest = hmac.new(
        digest_key.encode(),
        b"tenant-a\x00subject_reference\x00person@example.test",
        hashlib.sha256,
    ).hexdigest()

    class Transport:
        dns_pinned = True
        redirects_followed = False

        def request(self, _method, url, **_kwargs):
            return adapters.HTTPResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                body=json.dumps(
                    {"id": "graph-user-1", "mail": "person@example.test"}
                ).encode(),
                final_url=url,
            )

    app = SimpleNamespace(
        state=SimpleNamespace(
            privacy_rights_source_transport_factory=lambda _tenant: Transport(),
            privacy_rights_source_clock=lambda: 2_000_000_000.0,
            privacy_rights_source_credential_resolver=(
                lambda _tenant, _source, _ref: "transient-token"
            ),
            privacy_rights_source_subject_resolver_factory=(
                lambda **_kwargs: (
                    lambda tenant, case_id, _source_id: worker.SubjectBinding(
                        tenant_id=tenant,
                        case_id=case_id,
                        subject_reference="person@example.test",
                        authority_sha256=subject_digest,
                        expires_at=2_000_000_060.0,
                    )
                )
            ),
        )
    )
    runtime = composition.build_worker(
        app,
        tenant_id="tenant-a",
        principal_ref="source-worker",
        request=object(),
    )
    result = runtime.run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-1",
    )
    assert result.completed == 1
    assert result.raw_subject_persisted is False
    assert result.credential_values_persisted is False
    assert store.get_task("tenant-a", task.task_id).state == "complete"
    persisted = database.read_bytes()
    wal = Path(f"{database}-wal")
    if wal.exists():
        persisted += wal.read_bytes()
    assert b"person@example.test" not in persisted
    assert b"transient-token" not in persisted


def test_attach_installs_lazy_factories_without_resolving_any_authority() -> None:
    app = SimpleNamespace(state=SimpleNamespace())
    composition.attach_privacy_rights_source_composition(app)
    assert callable(app.state.privacy_rights_source_worker_factory)
    assert callable(app.state.privacy_rights_source_readiness_probe)


def test_retrieval_sink_recovers_one_artifact_after_post_ingest_index_failure(
    tmp_path: Path,
) -> None:
    body = b'{"id":"graph-user-1"}'
    digest = hashlib.sha256(body).hexdigest()

    class Vault:
        def __init__(self) -> None:
            self.documents: list[SimpleNamespace] = []
            self.ingest_calls = 0

        def ingest(self, content, **kwargs):
            self.ingest_calls += 1
            record = SimpleNamespace(
                document_ref=f"doc-retrieval-{self.ingest_calls}",
                content_sha256=hashlib.sha256(content).hexdigest(),
                byte_size=len(content),
                safe_display_name=kwargs["safe_display_name"],
            )
            self.documents.append(record)
            return record

        def list_documents(self, *, state, limit):
            assert state == "active"
            return tuple(self.documents[:limit])

        def get(self, document_ref):
            return next(
                item for item in self.documents if item.document_ref == document_ref
            )

    index_path = tmp_path / "retrieval-index.sqlite3"
    vault = Vault()
    first = composition.GovernedVaultRetrievalSink(
        tenant_id="tenant-a",
        vault=vault,
        principal_ref="source-worker",
        index_path=index_path,
    )
    with sqlite3.connect(index_path) as connection:
        connection.execute(
            "CREATE TRIGGER fail_retrieval_index BEFORE INSERT ON "
            "privacy_rights_retrieval_index BEGIN "
            "SELECT RAISE(FAIL, 'simulated index failure'); END"
        )
    arguments = {
        "tenant_id": "tenant-a",
        "case_id": "case-1",
        "source_id": "directory",
        "operation_id": "operation:1",
        "content_type": "application/json",
        "body": body,
        "sha256": digest,
        "record_count": 1,
    }
    with pytest.raises(
        composition.PrivacyRightsSourceCompositionError,
        match="custody index",
    ):
        first.store(**arguments)
    assert vault.ingest_calls == 1

    with sqlite3.connect(index_path) as connection:
        connection.execute("DROP TRIGGER fail_retrieval_index")
    recovered_sink = composition.GovernedVaultRetrievalSink(
        tenant_id="tenant-a",
        vault=vault,
        principal_ref="source-worker",
        index_path=index_path,
    )
    recovered = recovered_sink.store(**arguments)
    repeated = recovered_sink.store(**arguments)
    assert recovered == repeated
    assert recovered.opaque_ref == "doc-retrieval-1"
    assert vault.ingest_calls == 1

    changed = dict(arguments)
    changed_body = b'{"id":"replacement-user"}'
    changed["body"] = changed_body
    changed["sha256"] = hashlib.sha256(changed_body).hexdigest()
    with pytest.raises(
        composition.PrivacyRightsSourceCompositionError,
        match="operation changed",
    ):
        recovered_sink.store(**changed)
    assert vault.ingest_calls == 1


def test_production_target_custody_is_encrypted_exact_and_operation_immutable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", bytes(range(32)).hex())
    path = tmp_path / "target-custody.sqlite3"
    custody = composition.EncryptedMutationTargetCustody(
        tenant_id="tenant-a",
        path=path,
        retention_seconds=3_600,
        clock=lambda: 2_000_000_000.0,
    )

    def binding(target_id: str) -> str:
        return composition._canonical_sha256(
            {
                "schema": "lightwork.privacy-rights-mutation-target.v1",
                "tenant_id": "tenant-a",
                "case_id": "case-1",
                "source_id": "directory",
                "provider": "microsoft_graph_users",
                "operation_id": "operation:1",
                "target_id": target_id,
            }
        )

    target_binding = binding("immutable-user-a")
    receipt = custody.store(
        tenant_id="tenant-a",
        case_id="case-1",
        source_id="directory",
        operation_id="operation:1",
        provider="microsoft_graph_users",
        target_id="immutable-user-a",
        target_binding_sha256=target_binding,
    )
    assert custody.resolve(
        tenant_id="tenant-a",
        case_id="case-1",
        source_id="directory",
        operation_id="operation:1",
        provider="microsoft_graph_users",
        target_ref=receipt.opaque_ref,
        target_binding_sha256=target_binding,
    ) == "immutable-user-a"
    persisted = path.read_bytes()
    wal = Path(f"{path}-wal")
    if wal.exists():
        persisted += wal.read_bytes()
    assert b"immutable-user-a" not in persisted
    with pytest.raises(
        composition.PrivacyRightsSourceCompositionError,
        match="operation changed",
    ):
        custody.store(
            tenant_id="tenant-a",
            case_id="case-1",
            source_id="directory",
            operation_id="operation:1",
            provider="microsoft_graph_users",
            target_id="replacement-user-b",
            target_binding_sha256=binding("replacement-user-b"),
        )


def test_server_owned_worker_defaults_and_caps_are_enforced_before_store_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: settings)
    app = SimpleNamespace(
        state=SimpleNamespace(
            privacy_rights_source_subject_resolver=lambda *_args: None,
            privacy_rights_source_transport_factory=lambda _tenant: SimpleNamespace(
                dns_pinned=True,
                redirects_followed=False,
                request=lambda *_args, **_kwargs: None,
            ),
        )
    )
    runtime = composition.build_worker(
        app,
        tenant_id="tenant-a",
        principal_ref="source-worker",
        request=object(),
    )
    for kwargs, label in (
        ({"limit": settings.batch_size + 1}, "limit"),
        ({"lease_seconds": 28}, "lease_seconds"),
        (
            {"retry_delay_seconds": settings.retry_delay_seconds + 1},
            "retry_delay_seconds",
        ),
    ):
        with pytest.raises(
            worker.PrivacyRightsSourceWorkerProtocolError,
            match=label,
        ):
            runtime.run_once(
                "tenant-a",
                worker_ref="source-worker",
                run_id=f"run-cap-{label}",
                **kwargs,
            )
