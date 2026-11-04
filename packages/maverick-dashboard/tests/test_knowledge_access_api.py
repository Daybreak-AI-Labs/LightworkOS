"""APP10 authenticated knowledge UI/API boundaries."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from maverick import config, governed_records, knowledge_access, world_model
from maverick.knowledge_access import (
    KnowledgeAccessService,
    KnowledgeActorAuthority,
    KnowledgeDocument,
)
from maverick.research_registry import (
    DataUseAuthority,
    RegistryReviewAuthority,
    ResearchRegistry,
    ResearchRegistryDenied,
)
from maverick_dashboard import knowledge_access_api

BASE = "/api/v1/knowledge-access"
ORIGIN = "http://127.0.0.1:8765"
OWNER = "user:knowledge-owner@example.test"
PURPOSE = "product_research"
FUTURE = 4_102_444_800.0


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def customer(tmp_path, monkeypatch):
    for key in tuple(os.environ):
        if key.startswith(("MAVERICK_", "LIGHTWORK_")) or key.endswith("_API_KEY"):
            monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(home / "config.toml"))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_VOICE_AUTO_FETCH", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    governed_records._reset_process_authority_pin_for_testing()

    rights: dict[tuple[str, str], dict] = {}

    def data_use(tenant, decision_id, decision_sha256):
        asset_id = decision_id.removeprefix("decision-")
        state = rights.get((tenant, asset_id))
        if state is None or not state["allowed"]:
            raise ResearchRegistryDenied("fixture rights revoked")
        if decision_sha256 != _sha(f"{tenant}:{decision_id}"):
            raise ResearchRegistryDenied("fixture decision changed")
        return DataUseAuthority(
            tenant=tenant,
            decision_id=decision_id,
            decision_sha256=decision_sha256,
            asset_id=asset_id,
            action=state["action"],
            purpose_codes=(PURPOSE,),
            expires_at=state["expires_at"],
            authority_sha256=_sha(f"authority:{tenant}:{asset_id}"),
        )

    registry = ResearchRegistry(
        data_use_resolver=data_use,
        review_authority_resolver=lambda tenant, actor: RegistryReviewAuthority(
            tenant,
            actor,
            _sha(f"review:{tenant}:{actor}"),
        ),
    )

    def content(tenant, reference, admission):
        label = reference.asset_id.replace("-", " ").replace("_", " ")
        return KnowledgeDocument(
            tenant=tenant,
            reference=reference,
            content_sha256=admission.content_sha256,
            title=f"<script>{tenant} {label}</script>",
            summary=f"Private {tenant} derived summary for {reference.asset_id}.",
            claim_state="verified",
            observed_at=1_700_000_000.0,
            verified_at=1_700_000_100.0,
        )

    service = KnowledgeAccessService(
        registry=registry,
        content_resolver=content,
        actor_authority_resolver=lambda tenant, actor, action, purpose: (
            KnowledgeActorAuthority(
                tenant=tenant,
                principal=actor,
                action=action,
                purpose=purpose,
                authorization_sha256=_sha(
                    f"actor:{tenant}:{actor}:{action}:{purpose}"
                ),
            )
        ),
    )

    from maverick_dashboard.app import app

    app.state.knowledge_access_service = service
    with TestClient(
        app,
        base_url=ORIGIN,
        client=("127.0.0.1", 53220),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    ) as client:
        enrolled = client.post(
            "/auth/local-owner",
            data={
                "email": OWNER.removeprefix("user:"),
                "password": "Disposable owner " + secrets.token_hex(16),  # pragma: allowlist secret
                "confirm": "yes",
            },
        )
        assert enrolled.status_code == 303, enrolled.text
        for tenant in ("knowledge-a", "knowledge-b"):
            assert client.post(
                "/api/v1/admin/tenants",
                json={"id": tenant, "display_name": tenant, "plan": "free"},
            ).status_code == 201
            assert client.put(
                f"/api/v1/admin/tenants/{tenant}/roles/{OWNER}",
                json={"role": "admin"},
            ).status_code == 204
        _select(client, "knowledge-a")
        yield client, service, registry, rights
    delattr(app.state, "knowledge_access_service")
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def _select(client, tenant):
    response = client.put("/api/v1/workspace/active-tenant", json={"tenant_id": tenant})
    assert response.status_code == 200, response.text
    client.headers["X-Lightwork-Expected-Tenant"] = tenant


def _context(client) -> str:
    response = client.get(BASE + "/requests")
    assert response.status_code == 200, response.text
    return response.json()["context"]


def _dataset(registry, rights, tenant, asset_id, *, parent_datasets=()):
    rights[(tenant, asset_id)] = {
        "allowed": True,
        "action": "export",
        "expires_at": FUTURE,
    }
    reference = registry.register_dataset(
        tenant,
        "user:source-owner",
        dataset_id=asset_id,
        version="v1",
        source_ref=f"catalog:{tenant}/{asset_id}/v1",
        content_sha256=_sha(f"content:{tenant}:{asset_id}"),
        license_id="customer-authorized",
        license_evidence_sha256=_sha(f"license:{tenant}:{asset_id}"),
        allowed_purposes=(PURPOSE,),
        usage_constraints=("tenant_only", "separate_training_permission_required"),
        data_use_action="export",
        data_use_decision_id=f"decision-{asset_id}",
        data_use_decision_sha256=_sha(f"{tenant}:decision-{asset_id}"),
        parent_datasets=parent_datasets,
    )
    return registry.approve(
        tenant,
        "user:independent-reviewer",
        reference,
        expected_revision=1,
    )


def _ref(reference):
    from dataclasses import asdict

    return asdict(reference)


def test_search_continuation_uses_current_context_and_exact_query(customer):
    client, _service, registry, rights = customer
    for asset in ("policy-a", "policy-b"):
        _dataset(registry, rights, "knowledge-a", asset)
    request = {"context": _context(client), "query": "policy", "purpose": PURPOSE, "limit": 1}
    first = client.post(BASE + "/search", json=request)
    assert first.status_code == 200, first.text
    page = first.json()
    assert page["status"] == "incomplete"
    assert page["next_cursor"]
    second = client.post(BASE + "/search", json=request | {"cursor": page["next_cursor"]})
    assert second.status_code == 200, second.text
    assert second.json()["complete"] is True
    assert second.json()["items"][0]["reference"] != page["items"][0]["reference"]
    changed_query = client.post(BASE + "/search", json=request | {
        "query": "invoices", "cursor": page["next_cursor"],
    })
    assert changed_query.status_code == 422
    _select(client, "knowledge-b")
    stale = client.post(BASE + "/search", json=request | {"cursor": page["next_cursor"]})
    assert stale.status_code == 409
    assert "Private knowledge-a" not in stale.text


def test_search_api_preserves_full_chunk_excerpt_and_partial_coverage_flags(customer):
    """Transport contract; exact source reconstruction is covered in core tests."""
    from dataclasses import replace

    client, service, registry, rights = customer
    _dataset(registry, rights, "knowledge-a", "long-policy")
    original = service.content_resolver

    def content(tenant, reference, admission):
        return replace(original(tenant, reference, admission), summary="ordinary " * 800,
                       retrieval_chunks=("ordinary " * 800, "quasardeadline: seventeen days"),
                       summary_truncated=True)

    service.content_resolver = content
    request = {"context": _context(client), "query": "quasardeadline", "purpose": PURPOSE}
    response = client.post(BASE + "/search", json=request)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["complete"] is True
    assert "quasardeadline" in result["items"][0]["summary"]
    assert result["items"][0]["summary_truncated"] is True
    assert "_retrieval_chunks" not in result["items"][0]
    service.content_resolver = lambda *args: replace(content(*args), search_coverage_complete=False)
    partial = client.post(BASE + "/search", json=request | {"query": "absent-clause"})
    assert partial.status_code == 200, partial.text
    assert partial.json()["complete"] is False
    assert "partial_source_coverage" in partial.json()["incomplete_reasons"]


def test_saved_sources_panel_loads_only_when_document_search_is_on(customer, monkeypatch):
    """Without Document search the panel would only ask its API to refuse."""
    from maverick import knowledge_sources

    client, *_ = customer
    monkeypatch.setattr(knowledge_sources, "enabled", lambda: False)
    off = client.get("/knowledge-access")
    assert off.status_code == 200, off.text
    assert "Saved Knowledge sources" in off.text and "data-knowledge-sources" not in off.text
    assert 'href="/settings/all?id=knowledge.enable"' in off.text
    monkeypatch.setattr(knowledge_sources, "enabled", lambda: True)
    on = client.get("/knowledge-access")
    assert "data-knowledge-sources" in on.text and "data-ks-form" in on.text


def test_saved_sources_panel_states_the_configured_limits(customer, monkeypatch):
    from maverick import config, knowledge_sources

    client, *_ = customer
    monkeypatch.setattr(knowledge_sources, "enabled", lambda: True)
    monkeypatch.setattr(config, "get_knowledge_sources", lambda: {
        "max_items": 200, "max_pages": 16, "max_download_mib": 8, "max_text_kib": 512,
    })
    page = client.get("/knowledge-access")
    assert page.status_code == 200, page.text
    assert ("Each refresh supports 200 documents or pages, downloads up to 8 MiB per document, "
            "and reads up to 512 KiB of source text.") in page.text


def test_saved_sources_panel_still_renders_when_its_limits_are_invalid(customer, monkeypatch):
    from maverick import config, knowledge_sources

    client, *_ = customer
    monkeypatch.setattr(knowledge_sources, "enabled", lambda: True)

    def refuse():
        raise config.KnowledgeSourcesConfigError("knowledge_sources.max_items must be a whole number from 1 to 1000")

    monkeypatch.setattr(config, "get_knowledge_sources", refuse)
    page = client.get("/knowledge-access")
    assert page.status_code == 200, page.text
    assert "data-knowledge-sources" in page.text
    assert "Each refresh supports" not in page.text


def test_page_assets_navigation_and_customer_language(customer):
    client, _service, _registry, _rights = customer
    page = client.get("/knowledge-access")
    assert page.status_code == 200, page.text
    assert "Find knowledge you can use now" in page.text
    assert "does not mean it may be used to train AI models" in page.text
    assert "does not remove what AI models already learned from it" in page.text
    assert 'id="ka-purpose"' in page.text and "<select" in page.text
    assert client.get("/static/lightwork-knowledge-library.js").status_code == 200
    main = page.text.split('<main id="content"', 1)[1].split("</main>", 1)[0]
    visible = re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>", " ", main)
    assert not re.search(
        r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|idempoten\w*|json)\b|/api/v1",
        visible,
        re.IGNORECASE,
    ), visible
    assert 'data-tenant="knowledge-a"' in page.text
    assert f'data-actor="{OWNER}"' in page.text
    assert re.search(r"style-src 'self' 'nonce-[A-Za-z0-9_-]+'", page.headers["content-security-policy"])
    assert client.get("/static/lightwork-knowledge-access.js").status_code == 200
    assert client.get("/static/lightwork-knowledge-access.css").status_code == 200
    assert client.get("/knowledge-access?unexpected=1").status_code == 404

    from maverick_dashboard import ui_visibility

    entry = ui_visibility.page_for("/knowledge-access")
    assert entry and entry["floor"] == "operate"
    assert "/knowledge-access" in {
        link["href"]
        for group in ui_visibility.nav_groups("operator")
        for link in group["links"]
    }


def test_revoke_after_cache_blocks_search_detail_and_export(customer):
    client, _service, registry, rights = customer
    source = _dataset(registry, rights, "knowledge-a", "cached-policy")
    context = _context(client)
    search = {
        "context": context,
        "query": "cached policy",
        "purpose": PURPOSE,
        "limit": 20,
    }
    first = client.post(BASE + "/search", json=search)
    assert first.status_code == 200, first.text
    assert first.json()["count"] == 1
    assert "Private knowledge-a derived summary" in first.text
    assert first.json()["items"][0]["eligibility"]["requested_action"] == "read"
    assert first.json()["items"][0]["eligibility"]["actor"] == OWNER
    assert first.json()["tenant"] == "knowledge-a"
    assert first.json()["actor"] == OWNER
    assert first.json()["actor_authorization_sha256"] == first.json()["items"][0][
        "eligibility"
    ]["actor_authorization_sha256"]

    rights[("knowledge-a", "cached-policy")]["allowed"] = False
    withheld = client.post(BASE + "/search", json=search)
    assert withheld.status_code == 200, withheld.text
    assert withheld.json()["items"] == []
    assert withheld.json()["omitted_ineligible"] == 0
    assert withheld.json()["candidates_examined"] == 0
    assert "cached-policy" not in str(withheld.json()["items"])
    for path, body in (
        ("/detail", {"context": context, "reference": _ref(source), "purpose": PURPOSE}),
        (
            "/export",
            {"context": context, "references": [_ref(source)], "purpose": PURPOSE},
        ),
    ):
        response = client.post(BASE + path, json=body)
        assert response.status_code == 409, response.text
        assert "cached-policy" not in response.text
        assert "Private knowledge-a" not in response.text
        assert "no-store" in response.headers["cache-control"]


def test_same_labels_do_not_cross_tenant_search_export_or_cache(customer):
    client, _service, registry, rights = customer
    source_a = _dataset(registry, rights, "knowledge-a", "same-label")
    source_b = _dataset(registry, rights, "knowledge-b", "same-label")
    context_a = _context(client)
    result_a = client.post(
        BASE + "/search",
        json={"context": context_a, "query": "same-label", "purpose": PURPOSE, "limit": 20},
    )
    assert result_a.status_code == 200
    assert "Private knowledge-a" in result_a.text
    assert "knowledge-b" not in result_a.text

    _select(client, "knowledge-b")
    context_b = _context(client)
    foreign = client.post(
        BASE + "/detail",
        json={"context": context_b, "reference": _ref(source_a), "purpose": PURPOSE},
    )
    assert foreign.status_code == 409
    assert "knowledge-a" not in foreign.text
    result_b = client.post(
        BASE + "/search",
        json={"context": context_b, "query": "same-label", "purpose": PURPOSE, "limit": 20},
    )
    assert "Private knowledge-b" in result_b.text
    assert "knowledge-a" not in result_b.text
    exported = client.post(
        BASE + "/export",
        json={"context": context_b, "references": [_ref(source_b)], "purpose": PURPOSE},
    )
    assert exported.status_code == 200
    assert "Private knowledge-b" in exported.text
    assert "knowledge-a" not in exported.text
    body = exported.json()
    assert body["items"][0]["eligibility"]["requested_action"] == "export"
    assert body["actor"] == OWNER
    assert body["authority_evidence"]["actor"] == OWNER
    assert body["authority_evidence"]["sources"][0]["reference"] == _ref(source_b)
    assert body["qualification"]["external_store_and_customer_qualification"] == (
        "qualification_pending"
    )


def test_correction_request_and_approved_deletion_show_lineage_honestly(customer):
    client, service, registry, rights = customer
    source = _dataset(registry, rights, "knowledge-a", "customer-source")
    derived = _dataset(
        registry,
        rights,
        "knowledge-a",
        "derived-source",
        parent_datasets=(source,),
    )
    model = registry.register_model(
        "knowledge-a",
        "user:model-owner",
        model_id="candidate-model",
        version="v1",
        source_ref="artifact:knowledge-a/candidate-model/v1",
        artifact_sha256=_sha("candidate weights"),
        license_id="internal-model-license",
        license_evidence_sha256=_sha("model license"),
        allowed_purposes=(PURPOSE,),
        usage_constraints=("tenant_only",),
        provider_model_identity="candidate-model-v1",
        immutable_provider_revision=_sha("provider revision"),
        dataset_lineage=(derived,),
        dataset_lineage_purpose=PURPOSE,
    )
    registry.approve("knowledge-a", "user:model-reviewer", model, expected_revision=1)
    context = _context(client)
    submitted = client.post(
        BASE + "/requests",
        json={
            "context": context,
            "confirm": True,
            "reference": _ref(source),
            "request_type": "deletion",
            "reason": "Customer approved deletion request.",
            "request_key": "customer-deletion-1",
            "proposed_correction": None,
        },
    )
    assert submitted.status_code == 201, submitted.text
    request = submitted.json()
    assert {item["required_action"] for item in request["derivatives"]} == {
        "invalidate_dataset",
        "retire_or_retrain_model",
    }
    assert "does not erase its influence from learned weights" in request["weight_influence_notice"]

    decided = client.post(
        BASE + "/requests/" + request["id"] + "/decision",
        json={
            "context": context,
            "confirm": True,
            "expected_revision": request["revision"],
            "decision": "approve",
            "evidence_sha256": _sha("review rationale"),
        },
    )
    assert decided.status_code == 200, decided.text
    assert decided.json()["status"] == "approved"
    assert decided.json()["raw_record_status"] == "external_source_deletion_unverified"
    assert any(
        row["workflow_state"] == "retire_or_retrain_model_required"
        for row in decided.json()["derivatives"]
    )
    assert service.search(
        "knowledge-a",
        OWNER,
        query="customer",
        purpose=PURPOSE,
    )["items"] == []


def test_finished_rights_archive_is_available_in_app_and_keeps_source_revoked(customer):
    client, _service, registry, rights = customer
    source = _dataset(registry, rights, "knowledge-a", "archive-api-source")
    context = _context(client)
    submitted = client.post(BASE + "/requests", json={
        "context": context, "confirm": True, "reference": _ref(source),
        "request_type": "exclusion", "reason": "Stop use of this exact version.",
        "request_key": "archive-api-case", "proposed_correction": None,
    })
    assert submitted.status_code == 201, submitted.text
    request = submitted.json()
    decided = client.post(BASE + f"/requests/{request['id']}/decision", json={
        "context": context, "confirm": True,
        "expected_revision": request["revision"], "decision": "approve",
        "evidence_sha256": _sha("archive-api-approval"),
    })
    assert decided.status_code == 200, decided.text
    assert decided.json()["archive_ready"] is True
    moved = client.post(BASE + f"/requests/{request['id']}/archive", json={
        "context": context, "confirm": True,
        "expected_revision": decided.json()["revision"],
    })
    assert moved.status_code == 200, moved.text
    assert moved.json()["archived_at"] is not None
    active = client.get(BASE + "/requests")
    assert active.status_code == 200 and active.json()["items"] == []
    assert active.json()["capacity"]["active_count"] == 0
    archived = client.get(BASE + "/requests?archived=true")
    assert archived.status_code == 200, archived.text
    assert [item["id"] for item in archived.json()["items"]] == [request["id"]]
    assert client.get(BASE + f"/requests/{request['id']}").json()["item"]["archived_at"] is not None
    assert client.post(BASE + "/detail", json={
        "context": context, "reference": _ref(source), "purpose": PURPOSE,
    }).status_code == 409
    _select(client, "knowledge-b")
    assert client.get(BASE + "/requests?archived=true").json()["items"] == []


def test_request_owner_can_find_older_archive_without_admin_details(customer, monkeypatch):
    from maverick_dashboard import knowledge_access_api

    client, service, registry, rights = customer
    source = _dataset(registry, rights, "knowledge-a", "owner-archive-source")
    context = _context(client)
    submitted = client.post(BASE + "/requests", json={
        "context": context, "confirm": True, "reference": _ref(source),
        "request_type": "exclusion", "reason": "My source concern.",
        "request_key": "owner-archive", "proposed_correction": None,
    })
    assert submitted.status_code == 201, submitted.text
    own = submitted.json()
    denied = service.decide_request(
        "knowledge-a", OWNER, own["id"], expected_revision=own["revision"],
        decision="deny", evidence_sha256=_sha("owner archive denial"),
    )
    service.archive_request(
        "knowledge-a", OWNER, own["id"],
        expected_revision=denied["revision"],
    )
    other = service.submit_request(
        "knowledge-a", "user:someone-else@example.test", source,
        request_type="exclusion", reason="Different employee concern.",
        request_key="other-archive",
    )
    other_denied = service.decide_request(
        "knowledge-a", OWNER, other["id"], expected_revision=other["revision"],
        decision="deny", evidence_sha256=_sha("other archive denial"),
    )
    service.archive_request(
        "knowledge-a", OWNER, other["id"],
        expected_revision=other_denied["revision"],
    )

    monkeypatch.setattr(knowledge_access_api, "has_global_permission", lambda *_args: False)
    found = client.get(BASE + f"/requests/{own['id']}")
    assert found.status_code == 200, found.text
    receipt = found.json()["item"]
    assert receipt["schema"] == "lightwork.knowledge-feedback.v1"
    assert receipt["id"] == own["id"] and receipt["archived_at"] is not None
    assert "derivatives" not in receipt and "source_reference" not in receipt
    archived = client.get(BASE + "/requests?archived=true")
    assert archived.status_code == 200, archived.text
    assert [item["id"] for item in archived.json()["items"]] == [own["id"]]
    assert archived.json()["items"][0]["archived_at"] is not None
    assert client.get(BASE + f"/requests/{other['id']}").status_code == 404


def test_shared_storage_archive_is_unavailable_in_api_without_moving_request(
    customer, monkeypatch,
):
    client, service, registry, rights = customer
    source = _dataset(registry, rights, "knowledge-a", "shared-api-archive")
    context = _context(client)
    submitted = client.post(BASE + "/requests", json={
        "context": context, "confirm": True, "reference": _ref(source),
        "request_type": "exclusion", "reason": "Review this exact version.",
        "request_key": "shared-api-archive", "proposed_correction": None,
    })
    assert submitted.status_code == 201, submitted.text
    request = submitted.json()
    denied = client.post(BASE + f"/requests/{request['id']}/decision", json={
        "context": context, "confirm": True,
        "expected_revision": request["revision"], "decision": "deny",
        "evidence_sha256": _sha("shared archive refusal"),
    })
    assert denied.status_code == 200, denied.text
    with monkeypatch.context() as shared:
        shared.setattr(service.archive_store, "_backend", lambda: SimpleNamespace(kind="postgres"))
        listing = client.get(BASE + "/requests")
        assert listing.status_code == 200, listing.text
        assert listing.json()["capacity"]["archive_available"] is False
        assert listing.json()["items"][0]["archive_ready"] is False
        refused = client.post(BASE + f"/requests/{request['id']}/archive", json={
            "context": context, "confirm": True,
            "expected_revision": denied.json()["revision"],
        })
        assert refused.status_code == 409, refused.text
        assert "unavailable on this installation" in refused.json()["detail"]
    assert service.get_request("knowledge-a", request["id"])["archived_at"] is None
    assert registry.inspect("knowledge-a", source)["state"] == "approved"


def test_full_request_list_explains_in_product_recovery_without_blocking_reads(
    customer, monkeypatch,
):
    client, _service, registry, rights = customer
    monkeypatch.setattr(knowledge_access, "_MAX_REQUESTS", 1)
    first = _dataset(registry, rights, "knowledge-a", "capacity-first")
    second = _dataset(registry, rights, "knowledge-a", "capacity-second")
    context = _context(client)
    created = client.post(BASE + "/requests", json={
        "context": context, "confirm": True, "reference": _ref(first),
        "request_type": "exclusion", "reason": "Review this exact source.",
        "request_key": "capacity-first", "proposed_correction": None,
    })
    assert created.status_code == 201, created.text
    full = client.post(BASE + "/requests", json={
        "context": context, "confirm": True, "reference": _ref(second),
        "request_type": "exclusion", "reason": "Review this other source.",
        "request_key": "capacity-second", "proposed_correction": None,
    })
    assert full.status_code == 507, full.text
    assert "archive finished requests" in full.json()["detail"]
    assert client.get(BASE + "/requests").json()["capacity"] == {
        "active_count": 1, "active_limit": 1, "archive_available": True,
    }
    assert client.post(BASE + "/detail", json={
        "context": context, "reference": _ref(second), "purpose": PURPOSE,
    }).status_code == 200


def test_admin_recovers_later_finished_request_from_legacy_overfill(customer, monkeypatch):
    client, service, registry, rights = customer
    monkeypatch.setattr(knowledge_access, "_MAX_REQUESTS", 3)
    sources = [_dataset(registry, rights, "knowledge-a", f"legacy-{i}") for i in range(3)]
    first = service.submit_request(
        "knowledge-a", OWNER, sources[0], request_type="exclusion",
        reason="Review this version.", request_key="legacy-0",
    )
    finished = service.decide_request(
        "knowledge-a", OWNER, first["id"], expected_revision=first["revision"],
        decision="deny", evidence_sha256=_sha("legacy denial"),
    )
    for index in (1, 2):
        service.submit_request(
            "knowledge-a", OWNER, sources[index], request_type="exclusion",
            reason="Review this version.", request_key=f"legacy-{index}",
        )
    monkeypatch.setattr(knowledge_access, "_MAX_REQUESTS", 2)
    assert client.get(BASE + "/requests?ready_to_archive=true").json()["items"] == []
    assert client.post(BASE + "/detail", json={
        "context": _context(client), "reference": _ref(sources[1]), "purpose": PURPOSE,
    }).status_code == 409

    cursor, candidates = "", []
    for _ in range(4):
        page = client.get(BASE + "/requests/recovery", params={"cursor": cursor, "limit": 1})
        assert page.status_code == 200, page.text
        payload = page.json()
        assert payload["can_review"] and payload["ready_to_archive"]
        assert len(payload["items"]) <= 1
        candidates.extend(payload["items"])
        cursor = payload["next_cursor"]
        if cursor is None:
            break
    assert [item["id"] for item in candidates] == [finished["id"]]
    moved = client.post(BASE + f"/requests/{finished['id']}/archive", json={
        "context": _context(client), "confirm": True,
        "expected_revision": finished["revision"],
    })
    assert moved.status_code == 200 and moved.json()["archived_at"] is not None
    assert client.post(BASE + "/detail", json={
        "context": _context(client), "reference": _ref(sources[1]), "purpose": PURPOSE,
    }).status_code == 200
    _select(client, "knowledge-b")
    assert client.get(BASE + "/requests/recovery").json()["items"] == []


def test_context_confirmation_and_malformed_inputs_fail_closed(customer):
    client, _service, registry, rights = customer
    source = _dataset(registry, rights, "knowledge-a", "input-source")
    context = _context(client)
    wrong = client.post(
        BASE + "/detail",
        json={"context": "f" * 64, "reference": _ref(source), "purpose": PURPOSE},
    )
    assert wrong.status_code == 409
    assert "input-source" not in wrong.text
    unconfirmed = client.post(
        BASE + "/requests",
        json={
            "context": context,
            "confirm": False,
            "reference": _ref(source),
            "request_type": "exclusion",
            "reason": "Review needed.",
            "request_key": "request-unconfirmed",
        },
    )
    assert unconfirmed.status_code == 422
    malformed = client.post(
        BASE + "/search",
        json={"context": context, "query": "x", "purpose": "../tenant-b", "limit": 500},
    )
    assert malformed.status_code == 422
    assert malformed.headers["cache-control"] == "private, no-store"


def test_retention_hold_and_release_are_available_through_authenticated_api(customer):
    client, _service, registry, rights = customer
    source = _dataset(registry, rights, "knowledge-a", "api-held-source")
    context = _context(client)
    submitted = client.post(
        BASE + "/requests",
        json={
            "context": context,
            "confirm": True,
            "reference": _ref(source),
            "request_type": "deletion",
            "reason": "Deletion follows the preservation review.",
            "request_key": "api-held-deletion",
            "proposed_correction": None,
        },
    )
    assert submitted.status_code == 201, submitted.text
    request = submitted.json()
    held = client.post(
        BASE + f"/requests/{request['id']}/retention-hold",
        json={
            "context": context,
            "confirm": True,
            "expected_revision": request["revision"],
            "hold_id": "matter-2026-8",
            "basis": "Preserve while the legal matter remains open.",
            "expires_at": FUTURE,
            "evidence_sha256": _sha("api hold evidence"),
        },
    )
    assert held.status_code == 200, held.text
    assert held.json()["retention_hold"]["effective_status"] == "active"
    released = client.post(
        BASE + f"/requests/{request['id']}/retention-hold/release",
        json={
            "context": context,
            "confirm": True,
            "expected_revision": held.json()["revision"],
            "reason": "The legal matter closed.",
            "evidence_sha256": _sha("api release evidence"),
        },
    )
    assert released.status_code == 200, released.text
    assert released.json()["retention_hold"]["effective_status"] == "released"
    assert released.json()["retention_hold"]["release_reason"] == (
        "The legal matter closed."
    )


def test_feature_gate_and_request_byte_boundary_fail_closed(customer, monkeypatch):
    client, _service, registry, rights = customer
    source = _dataset(registry, rights, "knowledge-a", "bounded-source")
    context = _context(client)

    oversized = client.post(
        BASE + "/detail",
        headers={"Content-Length": str(128 * 1024 + 1)},
        json={"context": context, "reference": _ref(source), "purpose": PURPOSE},
    )
    assert oversized.status_code == 413
    assert oversized.headers["cache-control"] == "private, no-store"
    assert "bounded-source" not in oversized.text

    monkeypatch.setenv("MAVERICK_KNOWLEDGE_ACCESS", "0")
    assert client.get("/knowledge-access").status_code == 404
    disabled = client.post(
        BASE + "/detail",
        json={"context": context, "reference": _ref(source), "purpose": PURPOSE},
    )
    assert disabled.status_code == 404
    assert "bounded-source" not in disabled.text


def test_purpose_picker_lists_only_this_workspaces_approved_uses(customer):
    client, _service, registry, rights = customer
    _dataset(registry, rights, "knowledge-a", "policy-handbook")
    listed = client.get(BASE + "/purposes")
    assert listed.status_code == 200, listed.text
    assert listed.json()["items"] == [{"code": PURPOSE}]
    _select(client, "knowledge-b")
    assert client.get(BASE + "/purposes").json()["items"] == []


def test_registry_failure_is_unavailable_with_retry_not_empty_inventory(customer, monkeypatch):
    client, service, _registry, _rights = customer
    original = service.available_purposes

    def unavailable(*_args):
        raise OSError("INTERNAL STORAGE LOCATION")

    monkeypatch.setattr(service, "available_purposes", unavailable)
    failure = client.get(BASE + "/purposes")
    assert failure.status_code == 503
    assert "INTERNAL STORAGE LOCATION" not in failure.text
    page = client.get("/knowledge-access")
    assert page.status_code == 200
    assert 'data-purpose-state="unavailable"' in page.text
    assert "Refresh available uses" in page.text
    monkeypatch.setattr(service, "available_purposes", original)
    recovered = client.get(BASE + "/purposes")
    assert recovered.status_code == 200 and recovered.json()["status"] == "empty"


def test_operator_feedback_does_not_grant_admin_decision_or_lineage_access(customer, monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import knowledge_access_api

    client, _service, registry, rights = customer
    source = _dataset(registry, rights, "knowledge-a", "operator-feedback")
    monkeypatch.setattr(knowledge_access_api, "has_global_permission", lambda *_args: False)
    monkeypatch.setattr(knowledge_access_api, "require_global_permission", lambda *_args: (_ for _ in ()).throw(HTTPException(403, "forbidden")))
    context = _context(client)
    response = client.post(BASE + "/requests", json={
        "context": context, "confirm": True, "reference": _ref(source), "purpose": PURPOSE,
        "request_type": "exclusion", "reason": "Please review this dated passage.",
        "request_key": "operator-feedback-request",
    })
    assert response.status_code == 201, response.text
    receipt = response.json()
    assert receipt["status"] == "submitted" and "derivatives" not in receipt
    listed = client.get(BASE + "/requests").json()
    assert listed["items"][0]["id"] == receipt["id"] and listed["can_review"] is False
    assert client.post(BASE + f"/requests/{receipt['id']}/decision", json={
        "context": context, "confirm": True, "expected_revision": 1,
        "decision": "approve", "evidence_sha256": "a" * 64,
    }).status_code == 403


FEEDBACK_OPS_BASE = "/api/v1/copilot/product-operations"


@pytest.fixture
def enabled(customer, monkeypatch):
    # Keep the real account, workspace binding, feature sources and native
    # authority; only enable this existing optional feature in the local fixture.
    original = config.load_global_config
    features = config.get_features()
    monkeypatch.setattr(config, "load_global_config", lambda: original() | {"features": original().get("features", {}) | {"copilot_operations": True}})
    monkeypatch.setattr(config, "get_features", lambda: features | {"copilot_operations": True})
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    return customer


def feedback_review(client, selection, operation="knowledge.feedback", arguments=None):
    catalog = client.post(FEEDBACK_OPS_BASE + "/catalog", json={"page": "/knowledge-access", "selection": selection})
    assert catalog.status_code == 200, catalog.text
    payload = catalog.json()
    entry = next(row for row in payload["operations"] if row["id"] == operation)
    return client.post(FEEDBACK_OPS_BASE + "/prepare", json={"page": "/knowledge-access", "selection": selection,
                       "operation": operation, "context": payload["context"], "revision": entry["revision"],
                       "arguments": arguments or {}})


def test_feedback_uses_native_exact_source_and_owned_status_without_admin_side_effect(enabled):
    client, service, registry, rights = enabled
    source = _dataset(registry, rights, "knowledge-a", "source-for-feedback")
    selected = {"kind": "knowledge_source", "reference": _ref(source), "purpose": PURPOSE}
    before = registry.inspect("knowledge-a", source)
    prepared = feedback_review(client, selected, arguments={"request_type": "correction", "reason": "The hours changed.", "correction": "Open at ten."})
    assert prepared.status_code == 200, prepared.text
    body = {"token": prepared.json()["token"], "confirmed": True}
    response = client.post(FEEDBACK_OPS_BASE + "/execute", json=body)
    assert response.status_code == 200 and response.json()["status"] == "confirmed", response.text
    result = response.json()["details"]
    assert result["status"] == "submitted" and "derivatives" not in result and "retention_hold" not in result
    again = client.post(FEEDBACK_OPS_BASE + "/execute", json=body)
    assert again.status_code == 200 and again.json()["details"]["id"] == result["id"], again.text
    assert len(service.feedback_requests("knowledge-a", OWNER)) == 1
    assert registry.inspect("knowledge-a", source)["state"] == before["state"] == "approved"
    service.submit_request("knowledge-a", "user:someone-else", source, request_type="exclusion", reason="Another private request", request_key="other")
    own = feedback_review(client, {}, operation="knowledge.my_feedback")
    assert own.status_code == 200 and own.json()["read_only"], own.text
    assert len(own.json()["details"]["items"]) == 1 and "Another private request" not in own.text


def test_revoked_source_or_workspace_switch_refuses_queued_feedback(enabled):
    client, service, registry, rights = enabled
    source = _dataset(registry, rights, "knowledge-a", "changing-source")
    selected = {"kind": "knowledge_source", "reference": _ref(source), "purpose": PURPOSE}
    prepared = feedback_review(client, selected, arguments={"request_type": "exclusion", "reason": "Review current policy", "correction": ""})
    assert prepared.status_code == 200, prepared.text
    body = {"token": prepared.json()["token"], "confirmed": True}
    rights[("knowledge-a", "changing-source")]["allowed"] = False
    assert client.post(FEEDBACK_OPS_BASE + "/execute", json=body).status_code == 409
    assert service.feedback_requests("knowledge-a", OWNER) == []
    rights[("knowledge-a", "changing-source")]["allowed"] = True
    _select(client, "knowledge-b")
    assert client.post(FEEDBACK_OPS_BASE + "/execute", json=body).status_code in {404, 409}
    assert service.feedback_requests("knowledge-b", OWNER) == []


def test_feedback_catalog_requires_exact_selection_and_correction_information(enabled):
    client, _, registry, rights = enabled
    catalog = client.post(FEEDBACK_OPS_BASE + "/catalog", json={"page": "/knowledge-access"}).json()
    feedback = next(row for row in catalog["operations"] if row["id"] == "knowledge.feedback")
    assert feedback["available"] is False
    source = _dataset(registry, rights, "knowledge-a", "correction-source")
    selected = {"kind": "knowledge_source", "reference": _ref(source), "purpose": PURPOSE}
    assert feedback_review(client, selected, arguments={"request_type": "correction", "reason": "Changed", "correction": ""}).status_code == 422
    from maverick_dashboard.product_operations_knowledge_feedback import feedback_entries
    assert [entry.id for entry in feedback_entries()] == [
        "knowledge.feedback", "knowledge.my_feedback", "knowledge.browse_requests", "knowledge.archive_request"]


def test_copilot_archives_only_reviewed_finished_request_with_current_workspace(enabled):
    client, service, registry, rights = enabled
    source = _dataset(registry, rights, "knowledge-a", "copilot-archive-source")
    context = _context(client)
    submitted = client.post(BASE + "/requests", json={
        "context": context, "confirm": True, "reference": _ref(source),
        "request_type": "exclusion", "reason": "Retire this version.",
        "request_key": "copilot-archive-case", "proposed_correction": None,
    })
    assert submitted.status_code == 201, submitted.text
    request = submitted.json()
    selected = {"kind": "knowledge_request", "id": request["id"]}
    catalog = client.post(FEEDBACK_OPS_BASE + "/catalog", json={"page": "/knowledge-access", "selection": selected})
    archive = next(row for row in catalog.json()["operations"] if row["id"] == "knowledge.archive_request")
    assert archive["available"] is False
    decided = client.post(BASE + f"/requests/{request['id']}/decision", json={
        "context": context, "confirm": True, "expected_revision": request["revision"],
        "decision": "approve", "evidence_sha256": _sha("copilot-archive-approval"),
    })
    assert decided.status_code == 200 and decided.json()["archive_ready"] is True, decided.text
    prepared = feedback_review(client, selected, operation="knowledge.archive_request")
    assert prepared.status_code == 200 and prepared.json()["read_only"] is False, prepared.text
    assert "original source" in prepared.json()["summary"]
    body = {"token": prepared.json()["token"], "confirmed": True}
    _select(client, "knowledge-b")
    assert client.post(FEEDBACK_OPS_BASE + "/execute", json=body).status_code in {404, 409}
    assert service.get_request("knowledge-a", request["id"])["archived_at"] is None
    _select(client, "knowledge-a")
    moved = client.post(FEEDBACK_OPS_BASE + "/execute", json=body)
    assert moved.status_code == 200 and moved.json()["status"] == "confirmed", moved.text
    assert moved.json()["details"]["id"] == request["id"]
    assert moved.json()["details"]["archived_at"] is not None
    repeated = client.post(FEEDBACK_OPS_BASE + "/execute", json=body)
    assert repeated.status_code == 200 and repeated.json()["status"] == "replayed", repeated.text
    assert client.get(BASE + "/requests").json()["capacity"]["active_count"] == 0
    assert [item["id"] for item in client.get(BASE + "/requests?archived=true").json()["items"]] == [request["id"]]
    assert client.post(BASE + "/detail", json={
        "context": context, "reference": _ref(source), "purpose": PURPOSE,
    }).status_code == 409


def test_copilot_archive_is_not_advertised_without_admin_authority(enabled, monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import knowledge_access_api

    client, _, registry, rights = enabled
    source = _dataset(registry, rights, "knowledge-a", "copilot-nonadmin-source")
    submitted = client.post(BASE + "/requests", json={
        "context": _context(client), "confirm": True, "reference": _ref(source),
        "request_type": "exclusion", "reason": "Review this exact source.",
        "request_key": "copilot-nonadmin-case", "proposed_correction": None,
    })
    assert submitted.status_code == 201, submitted.text
    selected = {"kind": "knowledge_request", "id": submitted.json()["id"]}
    monkeypatch.setattr(knowledge_access_api, "require_global_permission",
                        lambda *_args: (_ for _ in ()).throw(HTTPException(403, "forbidden")))
    catalog = client.post(FEEDBACK_OPS_BASE + "/catalog", json={"page": "/knowledge-access", "selection": selected})
    assert catalog.status_code == 200, catalog.text
    assert "knowledge.archive_request" not in {row["id"] for row in catalog.json()["operations"]}


def _signed_in(principal, claims):
    return SimpleNamespace(state=SimpleNamespace(principal=SimpleNamespace(principal=principal, claims=claims)))


def test_the_verified_email_comes_only_from_the_signed_in_sessions_claims():
    assert knowledge_access_api._verified_email(_signed_in("user:alice", {"verified_email": "alice@contoso.com"})) == "alice@contoso.com"
    # The workspace invitation address is not the permission address.
    assert knowledge_access_api._verified_email(_signed_in("user:alice", {"idp_email": "alice@contoso.com"})) == ""
    # An API key or a session without an asserted address has no email, so the permission filter withholds for it.
    assert knowledge_access_api._verified_email(_signed_in("user:key", {"via": "api_key"})) == ""
    assert knowledge_access_api._verified_email(SimpleNamespace(state=SimpleNamespace(principal=None))) == ""


def test_the_authority_carries_the_address_only_for_the_principal_that_asked(monkeypatch):
    monkeypatch.setattr(knowledge_access_api, "role_for_principal", lambda principal: "member")
    monkeypatch.setattr(knowledge_access_api.rbac, "permissions_for", lambda role: {"view", "operate"})
    token = knowledge_access_api._REQUEST_EMAIL.set(("user:alice", "alice@contoso.com"))
    try:
        assert knowledge_access_api._actor_authority("acme", "user:alice", "analyze", "support").verified_email == "alice@contoso.com"
        assert knowledge_access_api._actor_authority("acme", "user:bob", "analyze", "support").verified_email == ""
    finally:
        knowledge_access_api._REQUEST_EMAIL.reset(token)
    assert knowledge_access_api._actor_authority("acme", "user:alice", "analyze", "support").verified_email == ""


@pytest.mark.parametrize("email", ["Alice@Contoso.com", " alice@contoso.com", "alice@contoso.com x", "alice", "a@b@c.example"])
def test_the_authority_refuses_an_address_that_is_not_normalised(email):
    from maverick.knowledge_access import KnowledgeActorAuthority

    with pytest.raises(ValueError, match="normalized address"):
        KnowledgeActorAuthority(tenant="acme", principal="user:alice", action="analyze", purpose="support",
                                authorization_sha256="a" * 64, verified_email=email)


@pytest.mark.parametrize(("mode", "stated"), [("by_email", True), ("off", False)])
def test_saved_sources_panel_says_when_files_are_matched_to_their_sharing(customer, monkeypatch, mode, stated):
    from maverick import config, knowledge_sources

    client, *_ = customer
    monkeypatch.setattr(knowledge_sources, "enabled", lambda: True)
    monkeypatch.setattr(config, "get_knowledge_sources", lambda: {
        "max_items": 64, "max_pages": 16, "max_download_mib": 4, "max_text_kib": 256,
        "max_refresh_minutes": 5, "permission_filter": mode,
    })
    page = client.get("/knowledge-access")
    assert page.status_code == 200, page.text
    assert ("shown only to the people it is shared with" in page.text) is stated
    assert ("Files show only after a refresh made while this setting is on" in page.text) is stated
