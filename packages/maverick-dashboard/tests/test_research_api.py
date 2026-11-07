"""Actual authenticated research routes with a doubled container only."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time

import pytest
from fastapi.testclient import TestClient
from maverick import config, governed_records, world_model
from maverick.sandbox.research import ResearchResult, _input_digest

BASE = "/api/v1/research"
ORIGIN = "http://127.0.0.1:8765"
OWNER = "user:research-owner@example.test"


@pytest.fixture
def client(tmp_path, monkeypatch):
    for key in tuple(os.environ):
        if key.startswith(("MAVERICK_", "LIGHTWORK_")) or key.endswith("_API_KEY"):
            monkeypatch.delenv(key, raising=False)
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "config.toml").write_text(
        '[research_execution]\nenable = true\nimage_id = "sha256:' + "2" * 64 + '"\n'
        '[research_execution.evaluators.smoke]\nversion = "v1"\nstdout_sha256 = "'
        + hashlib.sha256(b"answer\n").hexdigest()
        + '"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(profile))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_VOICE_AUTO_FETCH", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    governed_records._reset_process_authority_pin_for_testing()
    calls = []

    class Runner:
        def __init__(self, image, *, limits):
            self.image_id = image

        def run(self, files, *, budget, entrypoint, effect_guard):
            from maverick.paths import current_tenant_id_strict

            budget.record_tool_call()
            with effect_guard():
                calls.append((current_tenant_id_strict(), files))
            policy = {
                "schema": "lightwork.research-linux-container-policy.v2",
                "entrypoint": entrypoint,
            }
            policy_sha256 = hashlib.sha256(
                json.dumps(policy, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            ).hexdigest()
            return ResearchResult(
                "fake-container",
                self.image_id,
                _input_digest(files),
                policy_sha256,
                entrypoint,
                0,
                "completed",
                "answer\n",
                "",
                7,
                True,
                policy,
            )

    from maverick_dashboard import research_api
    from maverick_dashboard.app import app

    monkeypatch.setattr(research_api, "ResearchContainerRunner", Runner)
    with TestClient(
        app,
        base_url=ORIGIN,
        client=("127.0.0.1", 53210),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    ) as customer:
        enrolled = customer.post(
            "/auth/local-owner",
            data={
                "email": OWNER.removeprefix("user:"),
                "password": "Disposable owner " + secrets.token_hex(16),  # pragma: allowlist secret
                "confirm": "yes",  # pragma: allowlist secret
            },
        )
        assert enrolled.status_code == 303, enrolled.text
        # The owner starts in the first workspace; the browser client sends its guard.
        customer.headers["X-Lightwork-Expected-Tenant"] = "local"
        for tenant in ("research-a", "research-b"):
            assert (
                customer.post(
                    "/api/v1/admin/tenants",
                    json={
                        "id": tenant,
                        "display_name": tenant,
                        "plan": "free",
                    },
                ).status_code
                == 201
            )
            assert (
                customer.put(
                    f"/api/v1/admin/tenants/{tenant}/roles/{OWNER}", json={"role": "admin"}
                ).status_code
                == 204
            )
        _select(customer, "research-a")
        yield customer, calls
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def _select(client, tenant):
    response = client.put("/api/v1/workspace/active-tenant", json={"tenant_id": tenant})
    assert response.status_code == 200, response.text
    client.headers["X-Lightwork-Expected-Tenant"] = tenant


def _body(client):
    response = client.get(BASE)
    assert response.status_code == 200, response.text
    return {
        "context": response.json()["context"],
        "confirm": True,
        "files": {"main.py": "print('answer')"},
        "evaluator_id": "smoke",
        "idempotency_key": "request-1",
    }


def _dispatch_body(client, row):
    review = client.get(BASE + "/review/" + row["id"])
    assert review.status_code == 200, review.text
    return {
        "context": client.get(BASE).json()["context"],
        "confirm": True,
        "expected_revision": row["revision"],
        "review_sha256": review.json()["review_sha256"],
    }


def test_authenticated_submission_restart_dispatch_and_separate_evaluator(client):
    customer, calls = client
    submitted = customer.post(BASE + "/jobs", json=_body(customer))
    assert submitted.status_code == 201, submitted.text
    row = submitted.json()
    assert calls == []  # Submission never executes candidate code.
    reread = customer.get(BASE + "/jobs/" + row["id"])
    assert reread.status_code == 200 and reread.json()["status"] == "queued"
    review = customer.get(BASE + "/review/" + row["id"])
    assert review.status_code == 200 and review.json()["files"] == {"main.py": "print('answer')"}
    response = customer.post(
        BASE + "/jobs/" + row["id"] + "/run", json=_dispatch_body(customer, row)
    )
    assert response.status_code == 200, response.text
    assert response.json()["evaluation"]["counts"]["passed"] == 1
    assert calls[0][0] == "research-a" and len(calls) == 1
    assert "print('answer')" not in response.text


def test_cross_workspace_replay_and_foreign_job_do_not_materialize(client):
    customer, calls = client
    body = _body(customer)
    row = customer.post(BASE + "/jobs", json=body).json()
    _select(customer, "research-b")
    assert customer.post(BASE + "/jobs", json=body).status_code == 409
    assert customer.get(BASE + "/jobs/" + row["id"]).status_code == 404
    assert calls == []


def test_source_cannot_select_image_environment_or_evaluator_expectation(client):
    customer, calls = client
    body = _body(customer)
    for field in ("image_id", "stdout_sha256", "environment", "tenant", "principal"):
        response = customer.post(BASE + "/jobs", json={**body, field: "untrusted"})
        assert response.status_code == 422, response.text
    assert calls == []


def test_current_membership_is_required_and_queued_role_drift_prevents_effects(client):
    from maverick_dashboard import invites, rbac, workspace_tenants

    customer, calls = client
    owner_session = customer.cookies.get("mvk_session")
    researcher = "user:role-drift-researcher@example.test"
    rbac.set_role(researcher, "viewer")
    rbac.set_tenant_role("research-a", researcher, "operator")
    workspace_tenants.set_selection(researcher, "research-a")
    customer.cookies.clear()
    customer.cookies.set(
        "mvk_session", invites.mint_local_session(researcher.removeprefix("user:"))
    )
    body = _body(customer)
    row = customer.post(BASE + "/jobs", json=body).json()
    customer.cookies.clear()
    customer.cookies.set("mvk_session", owner_session)
    payload = _dispatch_body(customer, row)
    # The separate administrator remains authorized while the worker re-resolves
    # the submitter's changed tenant membership.
    rbac.set_tenant_role("research-a", researcher, "viewer")
    response = customer.post(BASE + "/jobs/" + row["id"] + "/run", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "review_required"
    assert calls == []


def test_unauthenticated_research_has_no_local_auth_off_bypass(client):
    customer, calls = client
    customer.cookies.clear()
    response = customer.get(BASE)
    assert response.status_code in (401, 403), response.text
    assert calls == []


def test_workspace_researcher_can_submit_but_cannot_dispatch_or_edit_oracle(client):
    from maverick_dashboard import invites, rbac, workspace_tenants

    customer, calls = client
    researcher = "user:researcher@example.test"
    rbac.set_role(researcher, "viewer")
    rbac.set_tenant_role("research-a", researcher, "operator")
    workspace_tenants.set_selection(researcher, "research-a")
    customer.cookies.clear()
    customer.cookies.set(
        "mvk_session", invites.mint_local_session(researcher.removeprefix("user:"))
    )
    assert customer.get(BASE).json()["can_dispatch"] is False
    body = _body(customer)
    submitted = customer.post(BASE + "/jobs", json=body)
    assert submitted.status_code == 201, submitted.text
    row = submitted.json()
    denied = customer.post(
        BASE + "/jobs/" + row["id"] + "/run",
        json={
            "context": body["context"],
            "confirm": True,
            "expected_revision": row["revision"],
            "review_sha256": "0" * 64,
        },
    )
    assert denied.status_code == 403, denied.text
    assert calls == []


def test_administrator_discovers_reviews_and_cancels_researcher_job_in_app(client):
    from maverick_dashboard import invites, rbac, workspace_tenants

    customer, calls = client
    owner_session = customer.cookies.get("mvk_session")
    researcher = "user:queue-researcher@example.test"
    rbac.set_role(researcher, "viewer")
    rbac.set_tenant_role("research-a", researcher, "operator")
    workspace_tenants.set_selection(researcher, "research-a")
    customer.cookies.clear()
    customer.cookies.set(
        "mvk_session", invites.mint_local_session(researcher.removeprefix("user:"))
    )
    row = customer.post(BASE + "/jobs", json=_body(customer)).json()
    customer.cookies.clear()
    customer.cookies.set("mvk_session", owner_session)
    overview = customer.get(BASE)
    assert overview.status_code == 200
    queued = next(item for item in overview.json()["review_queue"] if item["id"] == row["id"])
    assert queued["submitted_by"] == researcher
    assert "files" not in queued and "review_sha256" not in queued
    reviewed = customer.get(BASE + "/review/" + row["id"])
    assert reviewed.status_code == 200 and reviewed.json()["files"]["main.py"] == "print('answer')"
    cancelled = customer.post(
        BASE + "/jobs/" + row["id"] + "/cancel",
        json={
            "context": overview.json()["context"],
            "confirm": True,
            "expected_revision": row["revision"],
        },
    )
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
    assert calls == []


def test_requestless_dispatch_resolver_denies_global_admin_with_viewer_membership(client):
    from maverick_dashboard import rbac, research_api

    customer, calls = client
    row = customer.post(BASE + "/jobs", json=_body(customer)).json()
    review_sha256 = customer.get(BASE + "/review/" + row["id"]).json()["review_sha256"]
    rbac.set_tenant_role("research-a", OWNER, "viewer")
    with pytest.raises(PermissionError, match="membership"):
        research_api._service().review("research-a", OWNER, row["id"])
    with pytest.raises(PermissionError, match="membership"):
        research_api._service().run(
            "research-a",
            row["id"],
            expected_revision=row["revision"],
            dispatcher=OWNER,
            review_sha256=review_sha256,
        )
    assert calls == []


def test_app_role_mutation_waits_for_effect_authority_fence(client):
    from maverick.authority_effects import authority_effect_fence
    from maverick_dashboard import rbac

    principal = "user:fence-probe@example.test"
    started, changed = threading.Event(), threading.Event()

    def mutate():
        started.set()
        rbac.set_tenant_role("research-a", principal, "operator")
        changed.set()

    with authority_effect_fence():
        worker = threading.Thread(target=mutate, daemon=True)
        worker.start()
        assert started.wait(2)
        assert not changed.wait(0.1)
    assert changed.wait(2)
    worker.join(timeout=2)
    assert rbac.get_tenant_role("research-a", principal) == "operator"


def test_damaged_execution_profile_preserves_overview_and_recovery_queue(client, monkeypatch):
    from maverick.research_jobs import ResearchUnavailable
    from maverick_dashboard import research_api

    customer, _ = client
    row = customer.post(BASE + "/jobs", json=_body(customer)).json()
    monkeypatch.setattr(
        research_api,
        "configured_profile",
        lambda: (_ for _ in ()).throw(ResearchUnavailable("damaged")),
    )
    overview = customer.get(BASE)
    assert overview.status_code == 200, overview.text
    assert overview.json()["execution_available"] is False
    assert overview.json()["can_dispatch"] is False
    assert any(item["id"] == row["id"] for item in overview.json()["jobs"])
    assert any(item["id"] == row["id"] for item in overview.json()["review_queue"])


def test_dispatcher_revocation_during_threadpool_handoff_denies_candidate(client, monkeypatch):
    from maverick_dashboard import research_api

    customer, calls = client
    row = customer.post(BASE + "/jobs", json=_body(customer)).json()
    payload = _dispatch_body(customer, row)
    original = research_api.resolve_dispatch_authority
    state = {"calls": 0}

    def drifting(tenant, principal):
        state["calls"] += 1
        if state["calls"] > 1:
            raise PermissionError("dispatcher revoked")
        return original(tenant, principal)

    monkeypatch.setattr(research_api, "resolve_dispatch_authority", drifting)
    response = customer.post(BASE + "/jobs/" + row["id"] + "/run", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "review_required"
    assert response.json()["dispatched_by"] == OWNER and calls == []


def test_revocation_after_queue_invalidates_existing_controller_authority(client):
    from maverick_dashboard import (
        invites,
        rbac,
        research_api,
        session_revocation,
        workspace_tenants,
    )

    customer, calls = client
    owner_session = customer.cookies.get("mvk_session")
    researcher = "user:revoked-researcher@example.test"
    rbac.set_role(researcher, "viewer")
    rbac.set_tenant_role("research-a", researcher, "operator")
    workspace_tenants.set_selection(researcher, "research-a")
    customer.cookies.clear()
    customer.cookies.set(
        "mvk_session", invites.mint_local_session(researcher.removeprefix("user:"))
    )
    row = customer.post(BASE + "/jobs", json=_body(customer)).json()
    customer.cookies.clear()
    customer.cookies.set("mvk_session", owner_session)
    review_sha256 = customer.get(BASE + "/review/" + row["id"]).json()["review_sha256"]
    session_revocation.revoke_principal(researcher.removeprefix("user:"))
    # A separate named administrator dispatches; the submitter is revoked.
    result = research_api._service().run(
        "research-a",
        row["id"],
        expected_revision=row["revision"],
        dispatcher=OWNER,
        review_sha256=review_sha256,
    )
    assert result["status"] == "review_required" and calls == []


def test_deprovisioned_submitter_is_refused_by_requestless_controller(client, monkeypatch):
    from maverick_dashboard import invites, rbac, research_api, scim_groups, workspace_tenants

    customer, calls = client
    owner_session = customer.cookies.get("mvk_session")
    researcher = "user:deprovisioned-researcher@example.test"
    rbac.set_role(researcher, "viewer")
    rbac.set_tenant_role("research-a", researcher, "operator")
    workspace_tenants.set_selection(researcher, "research-a")
    customer.cookies.clear()
    customer.cookies.set(
        "mvk_session", invites.mint_local_session(researcher.removeprefix("user:"))
    )
    row = customer.post(BASE + "/jobs", json=_body(customer)).json()
    customer.cookies.clear()
    customer.cookies.set("mvk_session", owner_session)
    review_sha256 = customer.get(BASE + "/review/" + row["id"]).json()["review_sha256"]
    monkeypatch.setattr(
        scim_groups,
        "active_for_principal",
        lambda principal: False if principal == researcher else None,
    )
    result = research_api._service().run(
        "research-a",
        row["id"],
        expected_revision=row["revision"],
        dispatcher=OWNER,
        review_sha256=review_sha256,
    )
    assert result["status"] == "review_required" and calls == []


def test_malformed_candidate_validation_never_echoes_submitted_source(client):
    customer, calls = client
    marker = "private-candidate-marker"
    body = _body(customer)
    for payload in ({**body, marker: marker}, {**body, "files": {marker: {"source": marker}}}):
        response = customer.post(BASE + "/jobs", json=payload)
        assert response.status_code == 422, response.text
        assert marker not in response.text
    assert calls == []


def test_research_page_asset_and_visible_navigation_are_customer_reachable(client):
    customer, _ = client
    page = customer.get("/research")
    assert page.status_code == 200, page.text
    assert 'id="research-lab"' in page.text
    assert 'src="/static/lightwork-research.js?v=' in page.text  # served with a cache-busting version
    assert 'src="/static/lightwork-research-workspace.js?v=' in page.text  # served with a cache-busting version
    assert 'src="/static/lightwork-candidate-promotions.js?v=' in page.text  # served with a cache-busting version
    assert 'src="/static/lightwork-research-plain.js?v=' in page.text  # served with a cache-busting version
    from test_support.plain_language import developer_terms, visible_text
    assert developer_terms(page.text) == []
    text = visible_text(page.text)
    for banned in ("SHA-256", "Unix seconds", "bytes", "Dataset ID", "Run ID", "Seed", "Evaluator ID"):
        assert banned not in text, banned
    for label in ("Dataset name", "License or contract document", "What it may be used for",
                  "Time limit", "Storage limit", "Saved program"):
        assert label in text, label
    assert 'type="file" data-fingerprint-for="license_evidence_sha256"' in page.text
    plain = customer.get("/static/lightwork-research-plain.js")
    assert plain.status_code == 200 and "/api/v1/research-files/fingerprint" in plain.text
    asset = customer.get("/static/lightwork-research.js")
    assert asset.status_code == 200
    assert "application/javascript" in asset.headers["content-type"]
    assert "could not be opened for review" in asset.text
    workspace_asset = customer.get("/static/lightwork-research-workspace.js")
    assert workspace_asset.status_code == 200
    assert "blocked before data access" in workspace_asset.text
    promotion_asset = customer.get("/static/lightwork-candidate-promotions.js")
    assert promotion_asset.status_code == 200
    assert "Approve exact candidate" in promotion_asset.text

    from maverick_dashboard import ui_visibility

    # The lab is governed but not ready for customers: no sidebar tab and no
    # finder entry, while the page stays enforced and reachable by URL.
    entry = ui_visibility.page_for("/research")
    assert entry and entry["label"] == "Research lab"
    assert ui_visibility.customer_ready(entry) is False
    assert "/research" not in {
        link["href"] for group in ui_visibility.nav_groups("operator") for link in group["links"]
    }
    assert "/research" not in {
        link["href"] for group in ui_visibility.finder_pages("operator") for link in group["links"]
    }


def test_administrator_can_disable_damaged_settings_and_stale_revision_is_refused(client):
    customer, calls = client
    row = customer.post(BASE + "/jobs", json=_body(customer)).json()
    overview = customer.get(BASE).json()
    settings_sha256 = overview["settings"]["settings_sha256"]
    # Invalid remnants are ignored only for disable, so damaged nested fields
    # cannot trap the installation administrator behind their own validation.
    disabled = customer.put(
        BASE + "/settings",
        json={
            "context": overview["context"],
            "confirm": True,
            "expected_settings_sha256": settings_sha256,
            "enable": False,
            "image_id": "",
            "evaluators": [{"id": "", "version": "", "stdout_sha256": ""}],
            "limits": {"timeout_seconds": "broken"},
        },
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["settings"]["enabled"] is False
    recovered = customer.get(BASE).json()
    assert recovered["execution_available"] is False
    assert any(item["id"] == row["id"] for item in recovered["jobs"])
    assert any(item["id"] == row["id"] for item in recovered["review_queue"])
    assert calls == []

    stale = customer.put(
        BASE + "/settings",
        json={
            "context": recovered["context"],
            "confirm": True,
            "expected_settings_sha256": settings_sha256,
            "enable": False,
        },
    )
    assert stale.status_code == 409, stale.text


def test_administrator_can_save_a_complete_bounded_execution_profile(client):
    customer, _ = client
    overview = customer.get(BASE).json()
    payload = {
        "context": overview["context"],
        "confirm": True,
        "expected_settings_sha256": overview["settings"]["settings_sha256"],
        "enable": True,
        "image_id": "sha256:" + "7" * 64,
        "queue_seconds": 600,
        "evaluators": [{"id": "smoke", "version": "v2", "stdout_sha256": "8" * 64}],
        "limits": {
            "timeout_seconds": 5.0,
            "output_bytes": 4096,
            "memory_bytes": 67108864,
            "scratch_bytes": 2097152,
            "pids": 16,
            "cpus": 0.25,
        },
    }
    response = customer.put(BASE + "/settings", json=payload)
    assert response.status_code == 200, response.text
    saved = response.json()["settings"]
    assert saved["valid"] is True and saved["image_id"] == payload["image_id"]
    assert saved["evaluators"] == payload["evaluators"]
    assert saved["limits"] == payload["limits"]


def test_workspace_operator_cannot_change_installation_research_profile(client):
    from maverick_dashboard import invites, rbac, workspace_tenants

    customer, _ = client
    operator = "user:settings-operator@example.test"
    rbac.set_role(operator, "viewer")
    rbac.set_tenant_role("research-a", operator, "operator")
    workspace_tenants.set_selection(operator, "research-a")
    customer.cookies.clear()
    customer.cookies.set("mvk_session", invites.mint_local_session(operator.removeprefix("user:")))
    overview = customer.get(BASE).json()
    denied = customer.put(
        BASE + "/settings",
        json={
            "context": overview["context"],
            "confirm": True,
            "expected_settings_sha256": "0" * 64,
            "enable": False,
        },
    )
    assert denied.status_code == 403, denied.text


def test_operator_overlay_profile_is_read_only_in_the_app(client, monkeypatch, tmp_path):
    customer, _ = client
    operator = tmp_path / "research-operator-overlay.toml"
    operator.write_text(
        '[research_execution]\nenable = true\nimage_id = "sha256:' + "9" * 64 + '"\n'
        '[research_execution.evaluators.operator]\nversion = "v3"\nstdout_sha256 = "'
        + "a" * 64
        + '"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv(config.CONFIG_OVERLAY_ENV, str(operator))
    config.reset_config_cache()

    overview = customer.get(BASE).json()
    assert overview["execution_available"] is True
    assert overview["settings"]["source"] == "operator_overlay"
    assert overview["settings"]["writable"] is False
    assert overview["settings"]["evaluators"] == [
        {"id": "operator", "version": "v3", "stdout_sha256": "a" * 64}
    ]
    refused = customer.put(
        BASE + "/settings",
        json={
            "context": overview["context"],
            "confirm": True,
            "expected_settings_sha256": overview["settings"]["settings_sha256"],
            "enable": False,
        },
    )
    assert refused.status_code == 409, refused.text
    assert "operator config overlay" in refused.json()["detail"]
    config.reset_config_cache()


def _governed_workspace_services(monkeypatch):
    from maverick.research_registry import (
        DataUseAuthority,
        RegistryReviewAuthority,
        ResearchRegistry,
    )
    from maverick.research_runs import (
        ResearchRunAuthority,
        ResearchRuns,
        ResearchWorkerAuthority,
    )
    from maverick_dashboard import research_workspace_api

    expires_at = time.time() + 3600
    state = {"rights": True}

    def data_use(tenant, decision_id, decision_sha256):
        if not state["rights"]:
            from maverick.research_registry import ResearchRegistryDenied

            raise ResearchRegistryDenied("synthetic rights revoked")
        material = {
            "tenant": tenant,
            "decision_id": decision_id,
            "decision_sha256": decision_sha256,
            "asset_id": "synthetic-cases",
            "action": "analyze",
            "purpose_codes": ("product_research",),
            "expires_at": expires_at,
        }
        return DataUseAuthority(
            **material,
            authority_sha256=hashlib.sha256(
                json.dumps(material, sort_keys=True).encode()
            ).hexdigest(),
        )

    registry = ResearchRegistry(
        data_use_resolver=data_use,
        review_authority_resolver=lambda tenant, principal: RegistryReviewAuthority(
            tenant, principal, hashlib.sha256(f"review:{tenant}:{principal}".encode()).hexdigest()
        ),
    )
    runs = ResearchRuns(
        registry=registry,
        authority_resolver=lambda tenant, principal: ResearchRunAuthority(
            tenant, principal, hashlib.sha256(f"run:{tenant}:{principal}".encode()).hexdigest()
        ),
        worker_authority_resolver=lambda tenant, principal: ResearchWorkerAuthority(
            tenant, principal, hashlib.sha256(f"worker:{tenant}:{principal}".encode()).hexdigest()
        ),
    )
    monkeypatch.setattr(research_workspace_api, "_registry_service", lambda state=None: registry)
    monkeypatch.setattr(research_workspace_api, "_run_service", lambda state=None: runs)
    return registry, runs, state


def _workspace_context(customer):
    response = customer.get(BASE)
    assert response.status_code == 200, response.text
    return response.json()["context"]


def test_governed_registry_run_and_export_are_available_without_cli(client, monkeypatch):
    from maverick_dashboard import invites, rbac, workspace_tenants

    customer, _ = client
    _, _, governance = _governed_workspace_services(monkeypatch)
    owner_session = customer.cookies.get("mvk_session")
    researcher = "user:registry-maker@example.test"
    rbac.set_role(researcher, "viewer")
    rbac.set_tenant_role("research-a", researcher, "operator")
    workspace_tenants.set_selection(researcher, "research-a")
    customer.cookies.clear()
    customer.cookies.set(
        "mvk_session", invites.mint_local_session(researcher.removeprefix("user:"))
    )
    content_sha = "1" * 64
    registered = customer.post(
        BASE + "/registry/datasets",
        json={
            "context": _workspace_context(customer),
            "confirm": True,
            "dataset_id": "synthetic-cases",
            "version": "v1",
            "source_ref": "artifact:synthetic-cases/v1",
            "content_sha256": content_sha,
            "license_id": "internal-test",
            "license_evidence_sha256": "2" * 64,
            "allowed_purposes": ["product_research"],
            "usage_constraints": ["local_only"],
            "data_use_action": "analyze",
            "data_use_decision_id": "decision-1",
            "data_use_decision_sha256": "3" * 64,
            "parent_datasets": [],
            "provenance_kind": "synthetic",
            "synthetic_generator_id": "fixture-generator",
            "synthetic_generator_version": "v1",
            "synthetic_generator_sha256": "4" * 64,
            "synthetic_config_sha256": "5" * 64,
            "synthetic_seed": 17,
        },
    )
    assert registered.status_code == 201, registered.text
    asset = registered.json()
    assert asset["state"] == "draft"
    assert asset["synthetic_provenance"]["seed"] == 17
    assert "approver_authority" not in registered.text

    customer.cookies.clear()
    customer.cookies.set("mvk_session", owner_session)
    approved = customer.post(
        BASE + "/registry/approve",
        json={
            "context": _workspace_context(customer),
            "confirm": True,
            "reference": asset["reference"],
            "expected_revision": asset["revision"],
        },
    )
    assert approved.status_code == 200, approved.text
    asset = approved.json()
    assert asset["state"] == "approved" and asset["approval"]["approved_by"] == OWNER

    planned = customer.post(
        BASE + "/governed-runs",
        json={
            "context": _workspace_context(customer),
            "confirm": True,
            "run_id": "ui-run-1",
            "run_version": "v1",
            "experiment_id": "synthetic-baseline",
            "experiment_version": "v1",
            "purpose": "product_research",
            "action": "analyze",
            "code_revision": "a" * 40,
            "code_sha256": "6" * 64,
            "environment_id": "local-sandbox",
            "environment_version": "v1",
            "environment_sha256": "7" * 64,
            "seed": 23,
            "dataset_refs": [asset["reference"]],
            "model_ref": None,
            "resource_caps": {
                "max_wall_seconds": 60,
                "max_provider_calls": 0,
                "max_storage_bytes": 1048576,
                "max_cost": "0",
                "currency": "USD",
            },
            "metric_protocol_sha256": "8" * 64,
        },
    )
    assert planned.status_code == 201, planned.text
    run = planned.json()
    assert run["status"] == "planned"
    assert run["cost_summary"] == {
        "effective_amounts": {},
        "incomplete": False,
        "effective_event_count": 0,
    }
    queued = customer.post(
        BASE + "/governed-runs/ui-run-1/queue",
        json={
            "context": _workspace_context(customer),
            "confirm": True,
            "expected_revision": run["revision"],
        },
    )
    assert queued.status_code == 200, queued.text
    run = queued.json()
    assert run["status"] == "queued"
    refused = customer.post(
        BASE + "/governed-runs/ui-run-1/start",
        json={
            "context": _workspace_context(customer),
            "confirm": True,
            "expected_revision": run["revision"],
        },
    )
    assert refused.status_code == 503
    current = customer.get(BASE + "/governed-runs/ui-run-1")
    assert current.status_code == 200 and current.json()["status"] == "queued"

    first = customer.get(BASE + "/governed-runs/ui-run-1/export")
    second = customer.get(BASE + "/governed-runs/ui-run-1/export")
    assert first.status_code == 200 and first.content == second.content
    exported = first.json()
    assert exported["data_statement"]["contains_raw_customer_data"] is False
    assert exported["data_statement"]["raw_deletion_claims_weight_influence_removed"] is False
    assert exported["projection_statement"] == {
        "contains_authority_credentials": False,
        "contains_resource_cost_source_locations": False,
        "resource_cost_source_locations_represented_by_sha256": True,
    }
    assert "submit_authority" not in first.text
    overview = customer.get(BASE).json()
    assert overview["registry"]["datasets"][0]["state"] == "approved"
    assert overview["governed_runs"][0]["run_id"] == "ui-run-1"
    # The fixture's installation profile turns the packaged executor on, so
    # the overview reports it; turning the profile off reports it unavailable.
    assert overview["governed_execution"]["state"] == "configured"
    profile = os.environ["MAVERICK_HOME"] + "/config.toml"
    with open(profile, "w", encoding="utf-8") as handle:
        handle.write("[research_execution]\nenable = false\n")
    config.reset_config_cache()
    disabled = customer.get(BASE).json()["governed_execution"]
    assert disabled["available"] is False and disabled["state"] == "unavailable"

    governance["rights"] = False
    blocked = customer.get(BASE).json()
    assert blocked["registry"]["datasets"][0]["eligibility"]["state"] == "blocked"
    refused_export = customer.get(BASE + "/governed-runs/ui-run-1/export")
    assert refused_export.status_code == 409


def test_installed_source_registration_binds_the_current_projected_checksum(
    client, monkeypatch
):
    from maverick_dashboard import research_workspace_api

    customer, _ = client
    _, _, governance = _governed_workspace_services(monkeypatch)
    projected_sha256 = "9" * 64
    inspected = []

    def inspect(tenant, source_ref):
        inspected.append((tenant, source_ref))
        return {"content_sha256": projected_sha256}

    monkeypatch.setattr(research_workspace_api, "inspect_existing_source", inspect)

    def payload(version, source_ref, *, content_sha256="omitted"):
        body = {
            "context": _workspace_context(customer),
            "confirm": True,
            "dataset_id": "synthetic-cases",
            "version": version,
            "source_ref": source_ref,
            "license_id": "internal-test",
            "license_evidence_sha256": "2" * 64,
            "allowed_purposes": ["product_research"],
            "usage_constraints": ["local_only"],
            "data_use_action": "analyze",
            "data_use_decision_id": "decision-1",
            "data_use_decision_sha256": "3" * 64,
            "parent_datasets": [],
            "provenance_kind": "source",
        }
        if content_sha256 != "omitted":
            body["content_sha256"] = content_sha256
        return body

    source_ref = "catalog:evidence-graph/node-7"
    created = customer.post(
        BASE + "/registry/datasets",
        json=payload("installed-v1", source_ref),
    )
    assert created.status_code == 201, created.text
    assert created.json()["content_sha256"] == projected_sha256
    assert created.json()["source_ref"] == source_ref
    assert inspected == [("research-a", source_ref)]

    governance["rights"] = False
    blocked_before_projection = customer.post(
        BASE + "/registry/datasets",
        json=payload("installed-revoked", source_ref),
    )
    assert blocked_before_projection.status_code == 409
    assert "revoked" in blocked_before_projection.json()["detail"]
    assert inspected == [("research-a", source_ref)]
    governance["rights"] = True

    changed = customer.post(
        BASE + "/registry/datasets",
        json=payload("installed-v2", source_ref, content_sha256="8" * 64),
    )
    assert changed.status_code == 409
    assert source_ref not in changed.text

    unsupported = customer.post(
        BASE + "/registry/datasets",
        json=payload("unprojected-v1", "artifact:tenant-a/source"),
    )
    assert unsupported.status_code == 422
    assert "content SHA-256 is required" in unsupported.json()["detail"]


def test_governed_workspace_never_crosses_tenants(client, monkeypatch):
    customer, _ = client
    _governed_workspace_services(monkeypatch)
    _select(customer, "research-a")
    payload = {
        "context": _workspace_context(customer),
        "confirm": True,
        "dataset_id": "synthetic-cases",
        "version": "isolated",
        "source_ref": "artifact:tenant-a/isolated",
        "content_sha256": "1" * 64,
        "license_id": "internal-test",
        "license_evidence_sha256": "2" * 64,
        "allowed_purposes": ["product_research"],
        "usage_constraints": ["local_only"],
        "data_use_action": "analyze",
        "data_use_decision_id": "decision-1",
        "data_use_decision_sha256": "3" * 64,
        "parent_datasets": [],
        "provenance_kind": "synthetic",
        "synthetic_generator_id": "fixture-generator",
        "synthetic_generator_version": "v1",
        "synthetic_generator_sha256": "4" * 64,
        "synthetic_config_sha256": "5" * 64,
        "synthetic_seed": 1,
    }
    created = customer.post(BASE + "/registry/datasets", json=payload)
    assert created.status_code == 201, created.text
    reference = created.json()["reference"]
    _select(customer, "research-b")
    overview = customer.get(BASE)
    assert overview.status_code == 200
    assert overview.json()["registry"]["datasets"] == []
    path = "/registry/dataset/synthetic-cases/isolated/impact"
    denied = customer.get(BASE + path, params={"manifest_sha256": reference["manifest_sha256"]})
    assert denied.status_code == 404
    assert "tenant-a" not in denied.text


def test_governed_workspace_validation_does_not_echo_sensitive_fields(client, monkeypatch):
    customer, _ = client
    _governed_workspace_services(monkeypatch)
    marker = "https://secret.example.test/private-customer-location"
    response = customer.post(
        BASE + "/registry/datasets",
        json={
            "context": _workspace_context(customer),
            "confirm": True,
            "dataset_id": "bad",
            "version": "v1",
            "source_ref": marker,
            "content_sha256": "not-a-digest",
        },
    )
    assert response.status_code == 422
    assert marker not in response.text


def test_external_model_registration_is_pinned_and_projected_in_app(client, monkeypatch):
    customer, _ = client
    _governed_workspace_services(monkeypatch)
    response = customer.post(
        BASE + "/registry/models",
        json={
            "context": _workspace_context(customer),
            "confirm": True,
            "model_id": "baseline-model",
            "version": "v1",
            "source_ref": "artifact:models/baseline/v1",
            "artifact_sha256": "1" * 64,
            "license_id": "apache-2.0",
            "license_evidence_sha256": "2" * 64,
            "allowed_purposes": ["product_research"],
            "usage_constraints": ["local_only"],
            "provider_model_identity": "local/baseline",
            "immutable_provider_revision": "rev-17",
            "observed_from": None,
            "observed_until": None,
            "reproducibility_limitation": None,
            "dataset_lineage": [],
            "dataset_lineage_purpose": None,
            "model_lineage": [],
            "provenance_kind": "external",
            "training_receipt_id": None,
            "training_receipt_sha256": None,
            "training_dataset_sha256": None,
        },
    )
    assert response.status_code == 201, response.text
    model = response.json()
    assert model["kind"] == "model" and model["state"] == "draft"
    assert model["immutable_provider_revision"] == "rev-17"
    assert model["provider_model_identity"] == "local/baseline"
    assert "training_receipt_authority" not in response.text


def test_run_projection_keeps_exact_cost_but_redacts_its_source_location():
    from maverick_dashboard.research_workspace_api import _run_projection

    marker = "https://billing.example.test/customer-private-invoice"
    cost = {
        "category": "compute",
        "basis": "invoice",
        "quantity": "1",
        "unit": "calls",
        "amount": "4.25",
        "currency": "USD",
        "evidence_sha256": "1" * 64,
        "source_ref": marker,
        "incomplete_reason": None,
        "schema": "lightwork.research-resource-cost.v1",
    }
    record = {
        "run_id": "run-redaction",
        "created_by": OWNER,
        "status": "failed",
        "revision": 3,
        "created_at": 1.0,
        "updated_at": 2.0,
        "manifest_sha256": "2" * 64,
        "manifest": {"dataset_refs": [], "resource_caps": {}},
        "cost_summary": {
            "effective_amounts": {"USD": "4.25"},
            "incomplete": False,
            "effective_event_count": 1,
        },
        "attempts": [
            {
                "number": 1,
                "status": "failed",
                "version_binding": {},
                "registry_binding": None,
                "dispatch_receipt": None,
                "events": [],
                "costs": [
                    {
                        "sequence": 1,
                        "event_key": "finish.result.1",
                        "recorded_at": 2.0,
                        "recorded_by": OWNER,
                        "correction_of": None,
                        "previous_event_sha256": None,
                        "event_sha256": "3" * 64,
                        "cost": cost,
                    }
                ],
                "metrics": [],
                "terminal": {"outcome": "failed", "costs": [cost], "result_sha256": "4" * 64},
            }
        ],
    }
    projected = _run_projection(record)
    encoded = json.dumps(projected, sort_keys=True)
    assert marker not in encoded
    assert projected["cost_summary"]["effective_amounts"] == {"USD": "4.25"}
    assert projected["attempts"][0]["costs"][0]["cost"]["amount"] == "4.25"
    assert (
        projected["attempts"][0]["terminal"]["costs"][0]["source_ref_sha256"]
        == hashlib.sha256(marker.encode()).hexdigest()
    )


def test_data_use_picker_revalidates_current_authority(monkeypatch):
    from maverick import data_use_governance
    from maverick.research_registry import DataUseAuthority, ResearchRegistryDenied
    from maverick_dashboard import research_workspace_api

    monkeypatch.setattr(config, "data_use_governance_enabled", lambda: True)
    monkeypatch.setattr(
        governed_records,
        "configured_governed_records_backend",
        lambda: "local",
    )

    class Store:
        def __init__(self, _path):
            pass

        def list_records(self, tenant, record_type, *, limit):
            assert (tenant, record_type, limit) == ("tenant-a", "decision", 101)
            return [
                {
                    "outcome": "allow",
                    "decision_id": "current-decision",
                    "decision_sha256": "1" * 64,
                },
                {
                    "outcome": "allow",
                    "decision_id": "stale-decision",
                    "decision_sha256": "2" * 64,
                },
            ]

    monkeypatch.setattr(data_use_governance, "DataUseGovernanceStore", Store)

    def resolve(tenant, decision_id, decision_sha256):
        if decision_id == "stale-decision":
            raise ResearchRegistryDenied("source authority drifted")
        assert (tenant, decision_sha256) == ("tenant-a", "1" * 64)
        return DataUseAuthority(
            tenant="tenant-a",
            decision_id="current-decision",
            decision_sha256="1" * 64,
            asset_id="dataset-one",
            action="analyze",
            purpose_codes=("product_research",),
            expires_at=time.time() + 600,
            authority_sha256="3" * 64,
        )

    monkeypatch.setattr(research_workspace_api, "resolve_data_use_authority", resolve)
    projected = research_workspace_api._data_use_choices("tenant-a")

    assert projected["state"] == "available"
    assert [item["decision_id"] for item in projected["items"]] == ["current-decision"]
    assert projected["items"][0]["purpose_codes"] == ["product_research"]
