"""Role, projection, and transition tests for the in-app promotion controls."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from maverick.candidate_promotion import CandidatePromotionConflict
from maverick_dashboard import candidate_promotion_api as api

BASE = "/api/v1/research/promotions"
CONTEXT = "c" * 64
SHA = "a" * 64


def _row(**changes):
    value = {
        "candidate_id": "candidate-1",
        "requested_by": "user:researcher@example.test",
        "candidate_principal": "agent:candidate-1",
        "manifest_sha256": "1" * 64,
        "policy_sha256": "2" * 64,
        "state": "awaiting_review",
        "revision": 1,
        "created_at": 10.0,
        "updated_at": 10.0,
        "manifest": {
            "study": {
                "conclusion": "qualified",
                "report_sha256": "3" * 64,
                "conclusion_evidence_sha256": "4" * 64,
                "evaluator_id": "sealed-evaluator",
                "evaluator_version": "v1",
                "metric_protocol_sha256": "5" * 64,
            },
            "run": {
                "run_id": "run-1",
                "run_manifest_sha256": "6" * 64,
                "registry_binding_sha256": "7" * 64,
                "result_sha256": "8" * 64,
                "output_artifact_sha256": "9" * 64,
                "authority_sha256": "0" * 64,
                "lineage": [
                    {
                        "kind": "dataset",
                        "asset_id": "cases",
                        "version": "v1",
                        "manifest_sha256": "a" * 64,
                        "required_action_if_revoked": "retrain",
                    }
                ],
            },
            "target": {
                "target_id": "installed-app",
                "expected_active_sha256": "b" * 64,
                "state_schema": "lightwork.state.v1",
                "queued_intent_schema": "lightwork.intents.v1",
                "external_reconciliation_schema": "lightwork.reconciliation.v1",
            },
            "resources": {
                "max_memory_bytes": 1024,
                "max_storage_bytes": 2048,
                "max_cpu_cores": 1.0,
                "required_providers": [],
            },
            "artifacts": [
                {
                    "artifact_id": "candidate-bundle",
                    "kind": "bundle",
                    "source_ref": "artifact:private/path",
                    "sha256": "9" * 64,
                    "size_bytes": 42,
                }
            ],
        },
        "review": None,
        "block": None,
        "deployment": {
            "before": {
                "target_id": "installed-app",
                "active_artifact_sha256": "b" * 64,
                "state_schema": "lightwork.state.v1",
                "queued_intent_schema": "lightwork.intents.v1",
                "rollback_handle": "private-rollback-handle",
                "rollback_compatible": True,
                "evidence_sha256": "c" * 64,
            }
        },
        "events": [],
    }
    value.update(changes)
    return value


class Service:
    def __init__(self):
        self.calls = []
        self.row = _row()

    def list(self, tenant, actor, *, limit):
        self.calls.append(("list", tenant, actor, limit))
        return [self.row]

    def proposal_options(self, tenant, actor):
        self.calls.append(("proposal_options", tenant, actor))
        return {
            "completed_runs": ["run-1"],
            "target_presets": [
                {"preset_id": "installed-app", "target_id": "installed-app"}
            ],
        }

    def inspect(self, tenant, actor, candidate_id):
        self.calls.append(("inspect", tenant, actor, candidate_id))
        return self.row

    def request(self, tenant, actor, **kwargs):
        self.calls.append(("request", tenant, actor, kwargs))
        self.row = _row(
            candidate_id=kwargs["candidate_id"],
            requested_by=actor,
            candidate_principal="user:research-worker@example.test",
            manifest={
                "study": {
                    "report_sha256": "3" * 64,
                    "conclusion": "qualified",
                    "conclusion_evidence_sha256": "4" * 64,
                    "evaluator_id": "sealed-evaluator",
                    "evaluator_version": "v1",
                    "metric_protocol_sha256": "5" * 64,
                },
                "run": {
                    "run_id": kwargs["run_id"],
                    "output_artifact_sha256": "9" * 64,
                    "lineage": [],
                },
                "target": _row()["manifest"]["target"],
                "resources": _row()["manifest"]["resources"],
                "artifacts": _row()["manifest"]["artifacts"],
            },
        )
        return self.row

    def review(self, tenant, actor, candidate_id, **kwargs):
        self.calls.append(("review", tenant, actor, candidate_id, kwargs))
        self.row = _row(
            state="authorized" if kwargs["approve"] else "denied",
            revision=2,
            review={
                "reviewed_by": actor,
                "approved": kwargs["approve"],
                "reason_code": kwargs["reason_code"],
                "note": kwargs["note"],
                "evidence_sha256": kwargs["evidence_sha256"],
                "decision_sha256": "d" * 64,
                "reviewed_at": 11.0,
                "expires_at": 20.0,
                "authorization_sha256": "e" * 64,
            },
        )
        return self.row

    def _transition(self, name, tenant, actor, candidate_id, **kwargs):
        self.calls.append((name, tenant, actor, candidate_id, kwargs))
        return _row(state=name, revision=2)

    def stage(self, *args, **kwargs):
        return self._transition("staged", *args, **kwargs)

    def activate(self, *args, **kwargs):
        return self._transition("canary", *args, **kwargs)

    def assess_canary(self, *args, **kwargs):
        return self._transition("active", *args, **kwargs)

    def rollback(self, *args, **kwargs):
        return self._transition("rolled_back", *args, **kwargs)

    def reconcile(self, *args, **kwargs):
        return self._transition("reconciled", *args, **kwargs)


@pytest.fixture
def client(monkeypatch):
    application = FastAPI()
    application.include_router(api.router, prefix="/api/v1/research")
    service = Service()
    application.state.candidate_promotions = service
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(api, "require_global_permission", lambda _request, _permission: None)
    monkeypatch.setattr(api, "has_global_permission", lambda _request, _permission: True)
    monkeypatch.setattr(api, "caller_principal", lambda _request: "user:operator@example.test")
    monkeypatch.setattr(api, "current_tenant_id_strict", lambda: "tenant-a")
    monkeypatch.setattr(api, "context_for", lambda _request: CONTEXT)
    from maverick_dashboard import app as app_module

    monkeypatch.setattr(app_module, "_require_same_origin", lambda _request: None)
    with TestClient(application, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as value:
        yield value, service, application


def _body(**changes):
    value = {"context": CONTEXT, "confirm": True, "expected_revision": 1}
    value.update(changes)
    return value


def _proposal(**changes):
    value = {
        "context": CONTEXT,
        "confirm": True,
        "candidate_id": "candidate-new",
        "run_id": "run-1",
        "target_preset": "installed-app",
    }
    value.update(changes)
    return value


def test_research_page_proposal_has_only_safe_server_record_selectors():
    source = (
        Path(api.__file__).parent / "templates" / "research.html"
    ).read_text(encoding="utf-8")
    form = source.split('id="research-promotion-form"', 1)[1].split("</form>", 1)[0]
    assert set(re.findall(r'name="([^"]+)"', form)) == {
        "candidate_id",
        "run_id",
        "target_preset",
    }
    for forbidden in (
        "report_sha256",
        "conclusion_evidence_sha256",
        "evaluator_id",
        "artifact_sha256",
        "expected_active_sha256",
    ):
        assert forbidden not in form


def test_overview_is_readable_when_trusted_composition_is_not_configured(client):
    customer, _, application = client
    del application.state.candidate_promotions
    response = customer.get(BASE)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    assert response.json() == {
        "context": CONTEXT,
        "available": False,
        "can_manage": True,
        "can_propose": False,
        "completed_runs": [],
        "target_presets": [],
        "items": [],
        "detail": (
            "Install trusted study, target preset, artifact, policy, and deployment adapters "
            "before proposing candidates."
        ),
    }


def test_request_sends_only_safe_names_and_server_resolves_all_claims(client):
    customer, service, _ = client

    response = customer.post(BASE, json=_proposal())

    assert response.status_code == 201, response.text
    call = service.calls[-1]
    assert call[:3] == ("request", "tenant-a", "user:operator@example.test")
    values = call[3]
    assert values["candidate_id"] == "candidate-new"
    assert values["run_id"] == "run-1"
    assert values["target_preset"] == "installed-app"
    assert set(values) == {"candidate_id", "run_id", "target_preset"}
    assert response.json()["study"]["evaluator_id"] == "sealed-evaluator"


def test_fabricated_study_and_browser_authority_fields_cannot_reach_service(client):
    customer, service, _ = client
    fabricated = _proposal(
        study={
            "report_sha256": "1" * 64,
            "conclusion": "qualified",
            "conclusion_evidence_sha256": "2" * 64,
            "evaluator_id": "browser-authored",
            "evaluator_version": "v1",
            "metric_protocol_sha256": "3" * 64,
        }
    )
    response = customer.post(BASE, json=fabricated)
    assert response.status_code == 422
    assert service.calls == []

    injected = _proposal(tenant="tenant-b", principal="user:attacker")
    response = customer.post(BASE, json=injected)
    assert response.status_code == 422
    assert service.calls == []


def test_overview_projects_evidence_without_locations_authority_or_rollback_handles(client):
    customer, service, _ = client
    response = customer.get(BASE)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["available"] is True and payload["can_manage"] is True
    assert service.calls == [
        ("list", "tenant-a", "user:operator@example.test", 100),
        ("proposal_options", "tenant-a", "user:operator@example.test"),
    ]
    assert payload["completed_runs"] == ["run-1"]
    assert payload["target_presets"][0]["preset_id"] == "installed-app"
    serialized = response.text
    assert "private/path" not in serialized
    assert "private-rollback-handle" not in serialized
    assert "authorization_sha256" not in serialized
    assert payload["items"][0]["lineage"][0]["required_action_if_revoked"] == "retrain"


def test_review_uses_current_server_identity_and_derives_bound_evidence(client):
    customer, service, _ = client
    response = customer.post(
        BASE + "/candidate-1/review",
        json=_body(
            approve=True,
            reason_code="reviewed_scope",
            note="Verified the exact result, rights, target, and rollback plan.",
        ),
    )
    assert response.status_code == 200, response.text
    call = service.calls[-1]
    assert call[:4] == (
        "review",
        "tenant-a",
        "user:operator@example.test",
        "candidate-1",
    )
    assert call[4]["note"].startswith("Verified the exact result")
    assert re.fullmatch(r"[a-f0-9]{64}", call[4]["evidence_sha256"])
    assert response.json()["review"]["note"].startswith("Verified the exact result")


def test_browser_cannot_supply_tenant_principal_or_authority(client):
    customer, service, _ = client
    body = _body(
        approve=True,
        reason_code="reviewed_scope",
        note="Reviewed.",
        tenant="tenant-b",
        principal="user:attacker@example.test",
        authorization_sha256=SHA,
    )
    response = customer.post(BASE + "/candidate-1/review", json=body)
    assert response.status_code == 422
    assert service.calls == []
    assert "tenant-b" not in response.text and "attacker" not in response.text


@pytest.mark.parametrize(
    ("path", "expected_call", "extra"),
    [
        ("stage", "staged", {}),
        ("activate", "canary", {}),
        ("canary", "active", {}),
        ("rollback", "rolled_back", {"reason_code": "operator_requested"}),
        ("reconcile", "reconciled", {}),
    ],
)
def test_operator_transitions_keep_exact_revision_and_server_identity(
    client, path, expected_call, extra
):
    customer, service, _ = client
    response = customer.post(BASE + "/candidate-1/" + path, json=_body(**extra))
    assert response.status_code == 200, response.text
    call = service.calls[-1]
    assert call[:4] == (
        expected_call,
        "tenant-a",
        "user:operator@example.test",
        "candidate-1",
    )
    assert call[4]["expected_revision"] == 1


def test_stale_context_and_non_admin_stop_before_service_effect(client, monkeypatch):
    customer, service, _ = client
    stale = customer.post(BASE + "/candidate-1/stage", json=_body(context="f" * 64))
    assert stale.status_code == 409
    assert service.calls == []
    monkeypatch.setattr(
        api,
        "require_global_permission",
        lambda _request, _permission: (_ for _ in ()).throw(HTTPException(403, "denied")),
    )
    denied = customer.post(BASE + "/candidate-1/stage", json=_body())
    assert denied.status_code == 403
    assert service.calls == []


def test_conflict_is_actionable_and_never_retried(client):
    customer, service, _ = client

    def conflict(*_args, **_kwargs):
        raise CandidatePromotionConflict("candidate revision changed")

    service.stage = conflict
    response = customer.post(BASE + "/candidate-1/stage", json=_body())
    assert response.status_code == 409
    assert response.json()["detail"] == "candidate revision changed"
