from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import no_code_grc_studio as studio
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard import no_code_grc_studio_api as api

BASE = "/api/v1/compliance/grc-studio"
NOW = 2_000_000_000.0


def blueprint() -> dict[str, object]:
    return {
        "schema": studio.BLUEPRINT_SCHEMA,
        "studio_id": "enterprise-grc",
        "name_ref": "enterprise-name",
        "description_ref": None,
        "objects": [
            {
                "object_id": "risk",
                "kind": "risk",
                "label_ref": "risk-label",
                "description_ref": None,
                "fields": [
                    {
                        "field_id": "severity",
                        "label_ref": "severity-label",
                        "field_type": "single_choice",
                        "required": True,
                        "sensitivity": "internal",
                        "options": ["low", "high"],
                        "reference_kind": None,
                        "default": "low",
                    }
                ],
            }
        ],
        "forms": [
            {
                "form_id": "risk-form",
                "object_id": "risk",
                "title_ref": "risk-form-title",
                "sections": [
                    {
                        "section_id": "core",
                        "label_ref": "core-label",
                        "field_ids": ["severity"],
                    }
                ],
            }
        ],
        "rules": [],
        "collector_bindings": [],
        "report_views": [],
    }


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from maverick_dashboard import rbac

    rbac.set_role("user:operator", "operator")
    actor = {"value": "author"}
    store = studio.GRCStudioStore(
        tmp_path / "grc.sqlite3",
        tenant_id="tenant-a",
        integrity_key=b"k" * 32,
        principal_resolver=lambda: actor["value"],
        maintenance_authorizer=lambda: True,
        config_gate=lambda: None,
        clock=lambda: NOW,
        retention_seconds=86_400,
        recovery_directory=tmp_path / "recovery",
    )
    state = SimpleNamespace(enabled=True, ready=True, factory_calls=[], actor=actor, store=store)
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(api, "_principal", lambda _request, _tenant: "grc-principal")
    monkeypatch.setattr(api, "require_permission", lambda *_: None)
    monkeypatch.setattr(api, "require_global_permission", lambda *_: None)
    # Draft saves bind the workspace's studio settings; this workspace has them on.
    from maverick_dashboard import no_code_grc_studio_composition as composition
    enabled_settings = composition.grc_studio_settings(
        {"tech_risk_compliance": {"enable": True, "grc_studio": {"enable": True}}})
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: enabled_settings)

    def factory(*, tenant_id: str, principal_ref: str, request: Request):
        state.factory_calls.append((tenant_id, principal_ref, request))
        return store

    dependencies = api.GRCStudioDependencies(
        store_factory=factory,
        enabled_probe=lambda _tenant: state.enabled,
        readiness_probe=lambda _tenant: state.ready,
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = VerifiedPrincipal(sub=("user:operator").removeprefix("user:"), issuer="https://idp.test", audience="lightwork")
        return await call_next(request)

    app.include_router(api.create_no_code_grc_studio_router(dependencies), prefix="/api/v1")
    # Studio changes must come from the page itself (same-origin check).
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), state


def test_status_is_store_free_and_honest(environment) -> None:
    client, state = environment
    response = client.get(f"{BASE}/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["ready"] is True
    assert payload["store_opened_for_status"] is False
    assert payload["arbitrary_code_supported"] is False
    assert payload["arbitrary_html_css_supported"] is False
    assert payload["runtime_projection_apply_configured"] is False
    assert state.factory_calls == []
    assert response.headers["cache-control"].startswith("no-store")


def test_full_lifecycle_list_history_and_active_pointer(environment) -> None:
    client, state = environment
    created = client.post(
        f"{BASE}/studios/enterprise-grc/versions",
        json={
            "blueprint": blueprint(),
            "expected_latest_version": 0,
            "operation_id": "create-v1",
        },
    )
    assert created.status_code == 200
    version = created.json()
    submitted = client.post(
        f"{BASE}/studios/enterprise-grc/versions/1/submit",
        json={
            "expected_revision": version["revision"],
            "expected_integrity_sha256": version["integrity_sha256"],
            "operation_id": "submit-v1",
        },
    ).json()
    state.actor["value"] = "reviewer"
    reviewed = client.post(
        f"{BASE}/studios/enterprise-grc/versions/1/review",
        json={
            "accepted": True,
            "rationale_ref": "review-ok",
            "expected_revision": submitted["revision"],
            "expected_integrity_sha256": submitted["integrity_sha256"],
            "operation_id": "review-v1",
        },
    )
    assert reviewed.status_code == 200
    state.actor["value"] = "approver"
    approved = client.post(
        f"{BASE}/studios/enterprise-grc/versions/1/approve",
        json={
            "approval_ref": "board-approved",
            "expected_revision": reviewed.json()["revision"],
            "expected_integrity_sha256": reviewed.json()["integrity_sha256"],
            "operation_id": "approve-v1",
        },
    ).json()
    published = client.post(
        f"{BASE}/studios/enterprise-grc/versions/1/publish",
        json={
            "expected_revision": approved["revision"],
            "expected_integrity_sha256": approved["integrity_sha256"],
            "expected_active_version": 0,
            "expected_active_blueprint_sha256": None,
            "expected_pointer_revision": 0,
            "operation_id": "publish-v1",
        },
    )
    assert published.status_code == 200
    assert published.json()["state"] == "published"
    listed = client.get(BASE)
    assert listed.status_code == 200 and listed.json()["count"] == 1
    active = client.get(f"{BASE}/studios/enterprise-grc/active")
    assert active.status_code == 200
    assert active.json()["pointer"]["active_version"] == 1
    history = client.get(f"{BASE}/studios/enterprise-grc/versions/1/history")
    assert history.status_code == 200 and history.json()["count"] == 5
    integrity = client.get(f"{BASE}/operations/integrity")
    assert integrity.status_code == 200 and integrity.json()["verified"] is True


def test_strict_schema_disabled_and_unready_fail_before_store(environment) -> None:
    client, state = environment
    injected = {
        "blueprint": blueprint(),
        "expected_latest_version": 0,
        "operation_id": "create-injected",
        "tenant_id": "tenant-b",
    }
    assert client.post(f"{BASE}/studios/enterprise-grc/versions", json=injected).status_code == 422

    state.ready = False
    before = len(state.factory_calls)
    response = client.post(
        f"{BASE}/studios/enterprise-grc/versions",
        json={"blueprint": blueprint(), "expected_latest_version": 0, "operation_id": "unready"},
    )
    assert response.status_code == 503 and len(state.factory_calls) == before
    state.ready = True
    state.enabled = False
    response = client.get(BASE)
    assert response.status_code == 403 and len(state.factory_calls) == before


def test_projection_uses_server_resolved_target_authority(environment) -> None:
    client, state = environment
    created = state.store.create_version(
        "tenant-a",
        "enterprise-grc",
        blueprint=blueprint(),
        expected_latest_version=0,
        operation_id="direct-create",
    )
    created = state.store.submit_for_review(
        "tenant-a",
        "enterprise-grc",
        1,
        expected_revision=created.revision,
        expected_integrity_sha256=created.integrity_sha256,
        operation_id="direct-submit",
    )
    state.actor["value"] = "reviewer"
    created = state.store.review(
        "tenant-a",
        "enterprise-grc",
        1,
        accepted=True,
        rationale_ref="ok",
        expected_revision=created.revision,
        expected_integrity_sha256=created.integrity_sha256,
        operation_id="direct-review",
    )
    state.actor["value"] = "approver"
    created = state.store.approve(
        "tenant-a",
        "enterprise-grc",
        1,
        approval_ref="board",
        expected_revision=created.revision,
        expected_integrity_sha256=created.integrity_sha256,
        operation_id="direct-approve",
    )
    created = state.store.publish(
        "tenant-a",
        "enterprise-grc",
        1,
        expected_revision=created.revision,
        expected_integrity_sha256=created.integrity_sha256,
        expected_active_version=0,
        expected_active_blueprint_sha256=None,
        expected_pointer_revision=0,
        operation_id="direct-publish",
    )
    authority = studio.issue_runtime_target_authority(
        tenant_id="tenant-a",
        target_kind="questionnaire",
        target_id="scope-target",
        target_revision=2,
        target_integrity_sha256="b" * 64,
        allowed_blueprint_sha256=created.blueprint_sha256,
        valid_until=NOW + 100,
    )
    client.app.state.grc_studio_target_authority_resolver_factory = lambda **_kwargs: (
        lambda *_args: authority
    )
    response = client.post(
        f"{BASE}/operations/projections/preview",
        json={
            "studio_id": "enterprise-grc",
            "projection_kind": "questionnaire",
            "definition_id": "risk-form",
            "target_id": "scope-target",
            "target_revision": 2,
            "expected_active_version": 1,
            "expected_blueprint_sha256": created.blueprint_sha256,
        },
    )
    assert response.status_code == 200
    assert response.json()["target_authority_sha256"] == authority.authority_sha256
    assert response.json()["payload"]["definition"]["form_id"] == "risk-form"

    apply_calls: list[str] = []

    def applier_factory(**_kwargs):
        def apply(**kwargs):
            apply_calls.append(kwargs["operation_id"])
            return {
                "schema": studio.APPLY_RECEIPT_SCHEMA,
                "operation_id": kwargs["operation_id"],
                "applied": True,
                "projection_sha256": kwargs["projection"]["projection_sha256"],
                "authority_sha256": kwargs["target_authority_sha256"],
                "target_revision_before": kwargs["expected_target_revision"],
                "target_revision_after": kwargs["expected_target_revision"] + 1,
                "target_integrity_sha256_after": "c" * 64,
            }

        return apply

    client.app.state.grc_studio_projection_applier_factory = applier_factory
    apply_body = {
        "studio_id": "enterprise-grc",
        "projection_kind": "questionnaire",
        "definition_id": "risk-form",
        "target_id": "scope-target",
        "target_revision": 2,
        "expected_active_version": 1,
        "expected_blueprint_sha256": created.blueprint_sha256,
        "operation_id": "apply-risk-form",
    }
    applied = client.post(f"{BASE}/operations/projections/apply", json=apply_body)
    assert applied.status_code == 200 and applied.json()["applied"] is True
    replay = client.post(f"{BASE}/operations/projections/apply", json=apply_body)
    assert replay.status_code == 200 and replay.json() == applied.json()
    assert apply_calls == ["apply-risk-form"]
    assert (
        client.post(
            f"{BASE}/operations/projections/apply",
            json={**apply_body, "target_authority_sha256": authority.authority_sha256},
        ).status_code
        == 422
    )


def test_backup_list_is_admin_scoped_and_newest_first(environment, monkeypatch) -> None:
    client, _state = environment
    assert client.get(f"{BASE}/operations/recovery/backups").json()["items"] == []
    created = client.post(f"{BASE}/operations/recovery/backups")
    assert created.status_code == 200, created.text
    listed = client.get(f"{BASE}/operations/recovery/backups")
    assert listed.status_code == 200
    assert listed.headers["cache-control"].startswith("no-store")
    assert [row["backup_id"] for row in listed.json()["items"]] == [created.json()["backup_id"]]

    def deny(_request, permission):
        if permission == "admin":
            raise api.HTTPException(status_code=403, detail="denied")

    monkeypatch.setattr(api, "require_global_permission", deny)
    assert client.get(f"{BASE}/operations/recovery/backups").status_code == 403


def _with_collector(collector_id: str, version: int, digest: str) -> dict[str, object]:
    value = blueprint()
    value["collector_bindings"] = [
        {
            "binding_id": f"link-{collector_id}",
            "collector_id": collector_id,
            "collector_version": version,
            "collector_integrity_sha256": digest,
            "object_id": "risk",
            "field_mappings": [
                {"source_path": ["findings", "severity"], "target_field_id": "severity", "mode": "replace"}
            ],
            "control_refs": ["ctl-1"],
        }
    ]
    return value


def test_sources_list_approved_collectors_and_adapter_destinations(
    environment, tmp_path: Path, monkeypatch
) -> None:
    client, state = environment
    digest = "b" * 64
    for studio_id, expected in (("enterprise-grc", 0), ("second-grc", 0)):
        value = _with_collector("cloud-scan", 2, digest)
        value["studio_id"] = studio_id
        created = client.post(
            f"{BASE}/studios/{studio_id}/versions",
            json={"blueprint": value, "expected_latest_version": expected, "operation_id": f"c-{studio_id}"},
        )
        assert created.status_code == 200, created.text
    # Another workspace's collector sharing the same database never appears.
    other = studio.GRCStudioStore(
        tmp_path / "grc.sqlite3",
        tenant_id="tenant-b",
        integrity_key=b"k" * 32,
        principal_resolver=lambda: "author",
        maintenance_authorizer=lambda: True,
        config_gate=lambda: None,
        clock=lambda: NOW,
        retention_seconds=86_400,
        recovery_directory=tmp_path / "recovery-b",
    )
    other.create_version(
        "tenant-b", "enterprise-grc",
        blueprint=_with_collector("other-tenant-scan", 1, "c" * 64),
        expected_latest_version=0, operation_id="c-other",
    )

    listed = client.get(f"{BASE}/sources")
    assert listed.status_code == 200, listed.text
    assert listed.headers["cache-control"].startswith("no-store")
    payload = listed.json()
    # A collector merely linked in a blueprint is not offered: only current,
    # independently approved evidence sources are, and only while continuous
    # evidence is on.
    assert payload["collectors"] == []
    assert payload["collectors_notice"] == "Continuous evidence is turned off. Other blueprint choices remain available."
    assert payload["destinations"] == [] and payload["destinations_listed"] is False

    from maverick import config as maverick_config

    approved = {"collector_id": "cloud-scan", "collector_version": 2, "collector_integrity_sha256": digest,
                "label": "Cloud scan", "definition_id": "cloud-scan", "outputs": [], "controls": []}
    asked = []
    with monkeypatch.context() as on:
        on.setattr(maverick_config, "load_config", lambda *a, **k: {
            "tech_risk_compliance": {"enable": True, "continuous_evidence": {"enable": True}}})
        on.setattr(maverick_config, "config_source_errors", lambda *a, **k: [])
        on.setattr(api, "_approved_collectors", lambda _request, tenant: asked.append(tenant) or [approved])
        payload = client.get(f"{BASE}/sources").json()
    assert payload["collectors"] == [approved] and payload["collectors_notice"] == ""
    assert asked == ["tenant-a"]  # this workspace's approved sources only

    class Resolver:
        def __call__(self, *_args):  # pragma: no cover - not used for listing
            raise AssertionError

        def list_targets(self, tenant):
            assert tenant == "tenant-a"
            return [
                {"target_kind": "questionnaire", "target_id": "vendor-portal", "target_revision": 4, "label": "Vendor portal"},
                {"target_kind": "report", "target_id": "../escape", "target_revision": 1},
                {"target_kind": "unknown", "target_id": "x", "target_revision": 1},
                {"target_kind": "report", "target_id": "board", "target_revision": True},
            ]

    client.app.state.grc_studio_target_authority_resolver_factory = lambda **_kwargs: Resolver()
    payload = client.get(f"{BASE}/sources").json()
    assert payload["destinations_listed"] is True
    assert payload["destinations"] == [
        {"target_kind": "questionnaire", "target_id": "vendor-portal", "target_revision": 4, "label": "Vendor portal"}
    ]

    def broken(**_kwargs):
        raise RuntimeError("adapter down")

    client.app.state.grc_studio_target_authority_resolver_factory = broken
    payload = client.get(f"{BASE}/sources").json()
    assert payload["destinations"] == [] and payload["destinations_listed"] is False


def test_sources_need_view_permission_and_an_enabled_studio(environment, monkeypatch) -> None:
    client, state = environment
    seen = []

    def deny(_request, permission):
        seen.append(permission)
        raise api.HTTPException(status_code=403, detail="denied")

    monkeypatch.setattr(api, "require_permission", deny)
    assert client.get(f"{BASE}/sources").status_code == 403
    assert seen == ["view"]
    assert state.factory_calls == []
    monkeypatch.setattr(api, "require_permission", lambda *_: None)
    state.enabled = False
    assert client.get(f"{BASE}/sources").status_code == 403
