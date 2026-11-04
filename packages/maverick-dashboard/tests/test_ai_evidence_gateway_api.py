"""HTTP and cockpit contracts for the AI Evidence-Ready Gateway."""
from __future__ import annotations

import hashlib
import re
import sys
import types

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_gateway(tmp_path, monkeypatch):
    from maverick import audit, config, world_model
    from maverick.audit import writer as audit_writer

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """[evidence_graph]
enable = true

[model_risk_assurance]
enable = true
gate_promotions = true

[evidence_gateway]
enable = true
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in (
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    yield
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()


def _install_gateway(monkeypatch, **overrides):
    import maverick

    gateway = types.ModuleType("maverick.ai_evidence_gateway")
    defaults = {
        "enabled": lambda: True,
        "summary": lambda: {
            "enabled": True,
            "certification_claim": False,
            "current_policy_count": 0,
            "interaction_receipt_count": 0,
            "current_interaction_receipt_count": 0,
            "stale_interaction_receipt_count": 0,
            "pending_regulatory_impact_count": 0,
            "accepted_regulatory_impact_count": 0,
            "dismissed_regulatory_impact_count": 0,
            "framework_sources": [],
            "readiness": {},
            "gaps": [],
        },
        "list_policies": list,
        "get_policy": lambda _policy_id: None,
        "upsert_policy": lambda _policy_id, **_kwargs: {},
        "deliver_text": lambda _generated_text, **_kwargs: {},
        "list_interaction_receipts": lambda *, limit=100: [],
        "list_interaction_receipts_page": (
            lambda *, limit=100, cursor=None: {
                "items": [],
                "next_cursor": None,
                "snapshot_total": 0,
                "count": 0,
                "missing_governed_count": 0,
            }
        ),
        "get_interaction_receipt": lambda _receipt_id: None,
        "verify_interaction_receipt": lambda _receipt: False,
        "record_regulatory_impact": lambda _alert_id, **_kwargs: {},
        "list_regulatory_impacts": lambda *, limit=100: [],
        "list_regulatory_impacts_page": (
            lambda *, limit=100, cursor=None, status=None, pending_first=True: {
                "items": [],
                "next_cursor": None,
                "snapshot_total": 0,
                "count": 0,
                "status": status,
                "pending_first": pending_first,
            }
        ),
        "get_regulatory_impact": lambda _impact_id: None,
        "review_regulatory_impact": lambda _impact_id, **_kwargs: {},
        "render_assurance_packet": lambda **_kwargs: {},
        "issue_assurance_packet": (
            lambda **_kwargs: {
                "packet": gateway.render_assurance_packet(),
                "idempotent_replay": False,
            }
        ),
        "verify_assurance_packet": lambda _packet: False,
        "seed_demo": lambda **_kwargs: {},
    }
    for name, value in (defaults | overrides).items():
        setattr(gateway, name, value)
    if (
        "list_regulatory_impacts" in overrides
        and "list_regulatory_impacts_page" not in overrides
    ):
        def _page(
            *,
            limit=100,
            cursor=None,
            status=None,
            pending_first=True,
        ):
            del cursor
            rows = gateway.list_regulatory_impacts(limit=limit)
            if status is not None:
                rows = [row for row in rows if row.get("status") == status]
            return {
                "items": rows,
                "next_cursor": None,
                "snapshot_total": len(rows),
                "count": len(rows),
                "status": status,
                "pending_first": pending_first,
            }

        gateway.list_regulatory_impacts_page = _page
    monkeypatch.setitem(sys.modules, gateway.__name__, gateway)
    monkeypatch.setattr(maverick, "ai_evidence_gateway", gateway, raising=False)
    return gateway


def test_gateway_policy_delivery_and_regulatory_api_contract(monkeypatch):
    calls = {}

    def _upsert(policy_id, **kwargs):
        calls["policy"] = {"policy_id": policy_id, **kwargs}
        return {"policy_id": policy_id, "revision": 1}

    def _deliver(generated_text, **kwargs):
        calls["delivery"] = {"generated_text": generated_text, **kwargs}
        return {
            "enabled": True,
            "delivered_text": (
                "This interaction includes AI-generated content.\n\n"
                f"{generated_text}"
            ),
            "receipt": {"receipt_id": "AER-api-1"},
            "idempotent_replay": False,
        }

    def _impact(alert_id, **kwargs):
        calls["impact"] = {"alert_id": alert_id, **kwargs}
        return {"impact_id": "ARI-api-1", "status": "pending_review"}

    impact_record = {
        "id": "AII-" + ("a" * 32),
        "impact_id": "AII-" + ("a" * 32),
        "status": "pending_review",
    }

    def _impact_page(**kwargs):
        calls["impact_page"] = kwargs
        return {
            "items": [impact_record],
            "next_cursor": "next-impact-page",
            "snapshot_total": 501,
            "count": 1,
            "status": "pending_review",
            "pending_first": True,
        }

    _install_gateway(
        monkeypatch,
        upsert_policy=_upsert,
        deliver_text=_deliver,
        record_regulatory_impact=_impact,
        list_regulatory_impacts_page=_impact_page,
        get_regulatory_impact=(
            lambda impact_id: (
                impact_record if impact_id == impact_record["id"] else None
            )
        ),
    )
    prefix = "/api/v1/security/assurance/gateway"
    digest = hashlib.sha256(b"source").hexdigest()

    invalid_policy = client.put(
        f"{prefix}/policies/customer-facing",
        json={"caller_trusted_keys": {"attacker": "key"}},
    )
    assert invalid_policy.status_code == 422

    bypass_review = client.put(
        f"{prefix}/policies/customer-facing",
        json={
            "regulatory_bindings": [{
                "impact_id": "impact-binding-1",
                "impact_sha256": digest,
                "citations_sha256": digest,
            }],
        },
    )
    assert bypass_review.status_code == 422

    policy = client.put(
        f"{prefix}/policies/customer-facing",
        json={
            "disclosure_text": "AI-generated content.",
            "require_visible_marking": True,
            "model_sha256": digest,
        },
    )
    assert policy.status_code == 200, policy.text
    assert calls["policy"]["policy_id"] == "customer-facing"
    assert calls["policy"]["actor"] == "local:dashboard"
    assert "regulatory_bindings" not in calls["policy"]

    rejected_trust_root = client.post(
        f"{prefix}/deliver",
        json={
            "generated_text": "A generated answer.",
            "conversation_id": "conversation-1",
            "idempotency_key": "delivery-1",
            "trusted_public_keys": {"attacker": "key"},
        },
    )
    assert rejected_trust_root.status_code == 422

    self_asserted_exception = client.post(
        f"{prefix}/deliver",
        json={
            "generated_text": "A generated answer.",
            "conversation_id": "conversation-1",
            "idempotency_key": "delivery-with-exception",
            "editorial_exception": {
                "decision_id": "self-asserted",
                "reviewer": "caller",
                "approved_at": "2026-07-24T12:00:00Z",
                "rationale": "Suppress the marker.",
            },
        },
    )
    assert self_asserted_exception.status_code == 422

    caller_suppressed_marking = client.post(
        f"{prefix}/deliver",
        json={
            "generated_text": "A generated answer.",
            "conversation_id": "conversation-1",
            "idempotency_key": "delivery-without-marking",
            "synthetic_content": False,
        },
    )
    assert caller_suppressed_marking.status_code == 422

    caller_suppressed_disclosure = client.post(
        f"{prefix}/deliver",
        json={
            "generated_text": "A generated answer.",
            "conversation_id": "conversation-1",
            "idempotency_key": "delivery-without-disclosure",
            "human_interaction": False,
        },
    )
    assert caller_suppressed_disclosure.status_code == 422

    delivered = client.post(
        f"{prefix}/deliver",
        json={
            "generated_text": "A generated answer.",
            "input_text": "A private prompt that must not enter the receipt.",
            "conversation_id": "conversation-1",
            "idempotency_key": "delivery-1",
            "policy_id": "customer-facing",
            "model_sha256": digest,
        },
    )
    assert delivered.status_code == 200, delivered.text
    assert "AI-generated content" in delivered.json()["delivered_text"]
    assert calls["delivery"]["actor"] == "local:dashboard"

    impact = client.post(
        f"{prefix}/regulatory-impacts",
        json={
            "alert_id": "federal-register-1",
            "alert_revision": 1,
            "content_sha256": digest,
            "citations": [{
                "source_name": "Federal Register",
                "retrieval_url": "https://www.federalregister.gov/api/v1/documents",
                "record_url": "https://www.federalregister.gov/d/example",
                "retrieved_at": "2026-07-20T12:00:00Z",
                "content_sha256": digest,
            }],
            "affected_policy_ids": ["customer-facing"],
            "control_ids": ["AI-DISCLOSURE-01"],
            "match_reasons": ["explicit domain mapping"],
        },
    )
    assert impact.status_code == 200, impact.text
    assert calls["impact"]["alert_id"] == "federal-register-1"
    assert calls["impact"]["citations"][0]["record_url"].startswith("https://")

    listed_impacts = client.get(
        f"{prefix}/regulatory-impacts"
        "?limit=1&status=pending_review&pending_first=true"
    )
    assert listed_impacts.status_code == 200, listed_impacts.text
    assert listed_impacts.json()["snapshot_total"] == 501
    assert listed_impacts.json()["regulatory_impacts"] == [impact_record]
    assert calls["impact_page"] == {
        "limit": 1,
        "cursor": None,
        "status": "pending_review",
        "pending_first": True,
    }
    fetched_impact = client.get(
        f"{prefix}/regulatory-impacts/{impact_record['id']}"
    )
    assert fetched_impact.status_code == 200
    assert fetched_impact.json() == impact_record


def test_gateway_receipt_verification_and_exact_packet_download(monkeypatch):
    receipt = {
        "id": "AER-api-1",
        "receipt_id": "AER-api-1",
        "assurance": {"status": "current", "reasons": []},
    }
    packet = {
        "schema": "lightwork.ai-evidence-assurance-packet.v1",
        "packet_id": "AEP-api-1",
        "signature": {"key_id": "server-owned", "value": "ab"},
    }
    verification = {}
    packet_issue_calls = []

    def _verify_receipt(candidate):
        verification["receipt"] = candidate
        return candidate == receipt

    def _verify_packet(candidate):
        verification["packet"] = candidate
        return candidate == packet

    def _issue_packet(**kwargs):
        packet_issue_calls.append(kwargs)
        return {
            "packet": packet,
            "idempotent_replay": len(packet_issue_calls) > 1,
        }

    _install_gateway(
        monkeypatch,
        list_interaction_receipts=lambda *, limit=100: [receipt],
        list_interaction_receipts_page=(
            lambda *, limit=100, cursor=None: {
                "items": [receipt],
                "next_cursor": "next-page-token",
                "snapshot_total": 3,
                "count": 1,
                "missing_governed_count": 0,
            }
        ),
        get_interaction_receipt=(
            lambda receipt_id: receipt if receipt_id == receipt["id"] else None
        ),
        verify_interaction_receipt=_verify_receipt,
        render_assurance_packet=lambda **_kwargs: packet,
        issue_assurance_packet=_issue_packet,
        verify_assurance_packet=_verify_packet,
    )
    prefix = "/api/v1/security/assurance/gateway"

    listed = client.get(
        f"{prefix}/receipts?limit=1&cursor=abcdefghijklmnop"
    )
    assert listed.status_code == 200
    assert listed.json() == {
        "receipts": [receipt],
        "next_cursor": "next-page-token",
        "snapshot_total": 3,
        "count": 1,
        "missing_governed_count": 0,
    }
    oversized_cursor = client.get(
        f"{prefix}/receipts?limit=1&cursor={'A' * 2049}"
    )
    assert oversized_cursor.status_code == 422

    verified = client.post(f"{prefix}/receipts/AER-api-1/verify")
    assert verified.status_code == 200
    assert verified.json() == {"receipt_id": "AER-api-1", "valid": True}
    assert verification["receipt"] == receipt

    missing_key = client.post(f"{prefix}/assurance-packet")
    assert missing_key.status_code == 422

    downloaded = client.post(
        f"{prefix}/assurance-packet",
        headers={"Idempotency-Key": "packet-download-1"},
    )
    assert downloaded.status_code == 200
    assert downloaded.json() == packet
    assert downloaded.headers["idempotent-replay"] == "false"
    assert downloaded.headers["cache-control"] == "no-store"
    assert downloaded.headers["content-disposition"] == (
        'attachment; filename="lightwork-ai-assurance-packet.json"'
    )
    replayed = client.post(
        f"{prefix}/assurance-packet",
        headers={"Idempotency-Key": "packet-download-1"},
    )
    assert replayed.content == downloaded.content
    assert replayed.headers["idempotent-replay"] == "true"
    assert packet_issue_calls == [
        {
            "profile": "combined",
            "actor": "local:dashboard",
            "idempotency_key": "packet-download-1",
        },
        {
            "profile": "combined",
            "actor": "local:dashboard",
            "idempotency_key": "packet-download-1",
        },
    ]
    assert client.get(f"{prefix}/assurance-packet").status_code == 405

    packet_check = client.post(
        f"{prefix}/assurance-packet/verify",
        json={"packet": packet},
    )
    assert packet_check.status_code == 200
    assert packet_check.json() == {"valid": True}
    assert verification["packet"] == packet

    caller_key = client.post(
        f"{prefix}/assurance-packet/verify",
        json={"packet": packet, "trusted_public_keys": {"attacker": "key"}},
    )
    assert caller_key.status_code == 422


def test_gateway_bounds_request_bodies_and_redacts_validation_inputs():
    prefix = "/api/v1/security/assurance/gateway"
    oversized = client.post(
        f"{prefix}/assurance-packet/verify",
        content=b"{}",
        headers={"content-length": str((3 * 1024 * 1024) + 1)},
    )
    assert oversized.status_code == 413

    raw_secret = "raw-prompt-that-must-not-be-echoed"
    invalid = client.post(
        f"{prefix}/deliver",
        json={
            "generated_text": {"invalid": raw_secret},
            "conversation_id": "validation-redaction",
            "idempotency_key": "turn-1",
        },
    )
    assert invalid.status_code == 422
    assert raw_secret not in invalid.text
    assert "[redacted]" in invalid.text


def test_partial_policy_update_preserves_governed_fields(monkeypatch):
    digest = hashlib.sha256(b"reviewed-impact").hexdigest()
    binding = {
        "impact_id": "AII-" + ("a" * 32),
        "impact_sha256": digest,
        "citations_sha256": digest,
    }
    captured = {}

    def _upsert(policy_id, **kwargs):
        captured.update(kwargs)
        return {"policy_id": policy_id, "revision": 5}

    _install_gateway(
        monkeypatch,
        get_policy=lambda _policy_id: {
            "policy_id": "customer-facing",
            "revision": 4,
            "regulatory_bindings": [binding],
            "settings": {
                "disclosure_text": "Prior disclosure.",
                "require_interaction_disclosure": True,
                "require_machine_readable_marking": True,
                "require_visible_marking": True,
                "supported_modalities": ["text"],
                "machine_marker": "[ai; receipt={receipt_id}]",
                "visible_marker": "AI generated.",
            },
            "model_sha256": digest,
            "context_sha256": digest,
            "metadata": {"owner_id": "model-risk"},
        },
        upsert_policy=_upsert,
    )

    response = client.put(
        "/api/v1/security/assurance/gateway/policies/customer-facing",
        json={
            "expected_revision": 4,
            "disclosure_text": "Updated AI disclosure.",
        },
    )

    assert response.status_code == 200, response.text
    assert "regulatory_bindings" not in captured
    assert captured["disclosure_text"] == "Updated AI disclosure."
    assert captured["require_visible_marking"] is True
    assert captured["model_sha256"] == digest
    assert captured["context_sha256"] == digest
    assert captured["metadata"] == {"owner_id": "model-risk"}


def test_gateway_admin_mutations_are_global_admin_only(monkeypatch):
    from maverick_dashboard import auth

    seeded = []
    _install_gateway(
        monkeypatch,
        seed_demo=lambda **kwargs: seeded.append(kwargs) or {"demo": True},
    )
    role = {"value": "operator"}
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:analyst")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: role["value"])
    monkeypatch.setattr(
        auth,
        "global_role_for_principal",
        lambda principal: role["value"],
    )
    prefix = "/api/v1/security/assurance/gateway"

    assert client.get(f"{prefix}/summary").status_code == 200
    assert client.post(f"{prefix}/demo-seed").status_code == 403
    assert client.put(
        f"{prefix}/policies/default",
        json={"disclosure_text": "AI-generated content."},
    ).status_code == 403

    role["value"] = "admin"
    seeded_response = client.post(f"{prefix}/demo-seed")
    assert seeded_response.status_code == 200
    assert seeded_response.json() == {"demo": True}
    assert seeded == [{"actor": "user:analyst"}]


def test_empty_assurance_cockpit_has_safe_synthetic_demo_path(monkeypatch):
    _install_gateway(monkeypatch)

    response = client.get("/security/assurance")

    assert response.status_code == 200, response.text
    assert "Not started" in response.text
    assert "Create and bind the first production policy" in response.text
    assert "Load sample data" in response.text
    assert "empty workspace only" in response.text
    assert 'aria-label="Setup progress"' in response.text


def test_assurance_cockpit_disabled_state_is_product_copy(monkeypatch):
    _install_gateway(monkeypatch, enabled=lambda: False)

    response = client.get("/security/assurance")

    assert response.status_code == 200, response.text
    assert "Evidence recording is off" in response.text
    assert "Ask an administrator to turn this on." in response.text
    # The cockpit is a product surface: no CLI invocations on the page.
    assert "maverick preflight" not in response.text


def test_assurance_cockpit_load_error_is_actionable_and_secret_free(monkeypatch):
    secret = "internal-store-secret-must-not-render"  # pragma: allowlist secret

    def _explode():
        raise RuntimeError(secret)

    _install_gateway(monkeypatch, summary=_explode)

    response = client.get("/security/assurance")

    assert response.status_code == 200, response.text
    assert "No readiness conclusion is available" in response.text
    assert "built-in health checks" in response.text
    assert "maverick doctor" not in response.text
    assert secret not in response.text


def test_assurance_cockpit_isolates_model_risk_panel_failure(monkeypatch):
    from maverick import model_risk_assurance

    def _explode():
        raise RuntimeError("private model-risk backend detail")

    monkeypatch.setattr(model_risk_assurance, "list_inventory", _explode)
    _install_gateway(
        monkeypatch,
        list_policies=lambda: [{
            "policy_id": "still-visible-policy",
            "settings": {"disclosure_text": "AI-generated content."},
            "model_sha256": "a" * 64,
            "context_sha256": "b" * 64,
            "regulatory_bindings": [],
            "revision": 1,
        }],
    )

    response = client.get("/security/assurance")

    assert response.status_code == 200, response.text
    assert "Model-risk assets are temporarily unavailable." in response.text
    assert "still-visible-policy" in response.text
    assert "private model-risk backend detail" not in response.text


def test_assurance_cockpit_explains_missing_tenant_without_reading_records(
    monkeypatch,
):
    class EvidenceGatewayStateError(RuntimeError):
        pass

    def _unbound():
        raise EvidenceGatewayStateError(
            "AI evidence gateway records require an explicit tenant scope"
        )

    _install_gateway(monkeypatch, summary=_unbound)

    response = client.get("/security/assurance")

    assert response.status_code == 200, response.text
    assert "Choose a workspace first to see evidence" in response.text
    assert "Nothing was read" in response.text
    assert "MAVERICK_TENANT" not in response.text


def test_assurance_cockpit_renders_gateway_evidence_without_raw_content(
    monkeypatch,
):
    digest = hashlib.sha256(b"bound-model").hexdigest()
    raw_secret = "private-prompt-must-not-render"
    _install_gateway(
        monkeypatch,
        summary=lambda: {
            "enabled": True,
            "certification_claim": False,
            "current_policy_count": 1,
            "interaction_receipt_count": 1,
            "current_interaction_receipt_count": 1,
            "stale_interaction_receipt_count": 0,
            "pending_regulatory_impact_count": 1,
            "accepted_regulatory_impact_count": 0,
            "dismissed_regulatory_impact_count": 0,
            "framework_sources": ["EU AI Act Article 50"],
            "readiness": {"status": "review_required"},
            "gaps": ["One regulatory impact awaits human review."],
        },
        list_policies=lambda: [{
            "policy_id": "customer-facing",
            "settings": {"disclosure_text": "AI-generated content."},
            "model_sha256": digest,
            "context_sha256": "",
            "regulatory_bindings": [{
                "impact_id": "AII-" + ("b" * 32),
                "impact_sha256": digest,
                "citations_sha256": digest,
            }],
            "revision": 1,
        }],
        list_interaction_receipts=lambda *, limit=100: [{
            "receipt_id": "AER-page-1",
            "assurance": {"status": "current", "reasons": []},
            "policy_id": "customer-facing",
            "model_sha256": digest,
            "issued_at": 1_753_358_400,
        }],
        list_regulatory_impacts=lambda *, limit=100: [{
            "impact_id": "ARI-page-1",
            "alert_id": "federal-register-1",
            "status": "pending_review",
            "affected_policy_ids": ["customer-facing"],
            "affected_asset_ids": ["MAA-" + ("a" * 32)],
            "control_ids": ["AI-DISCLOSURE-01"],
            "citations": [{
                "source_name": "Federal Register",
                "record_url": "https://www.federalregister.gov/d/example",
            }],
            "raw_input": raw_secret,
        }],
    )

    response = client.get("/security/assurance")

    assert response.status_code == 200, response.text
    assert "AI assurance" in response.text
    assert "Review required" in response.text
    assert "Next step" in response.text
    assert "can't be loaded once real records exist" in response.text
    assert 'id="gateway-demo-seed"' not in response.text
    assert "Governance benchmarks" in response.text
    assert "AER-page-1" in response.text
    assert re.search(r"24 Jul 2025, 12:00(:00)? UTC", response.text)
    assert "Complete:" in response.text
    assert "Incomplete:" in response.text
    assert "AI-DISCLOSURE-01" in response.text
    assert "https://www.federalregister.gov/d/example" in response.text
    assert raw_secret not in response.text


def test_real_gateway_seed_receipt_and_packet_round_trip(monkeypatch):
    from maverick import ai_evidence_gateway

    monkeypatch.setenv("MAVERICK_TENANT", "gateway-api-integration")
    assert ai_evidence_gateway.enabled() is True
    prefix = "/api/v1/security/assurance/gateway"

    seeded = client.post(f"{prefix}/demo-seed")
    assert seeded.status_code == 200, seeded.text
    seed = seeded.json()
    assert seed["synthetic"] is True
    assert seed["network_access"] is False

    receipt_id = seed["receipt_id"]
    verified_receipt = client.post(f"{prefix}/receipts/{receipt_id}/verify")
    assert verified_receipt.status_code == 200, verified_receipt.text
    assert verified_receipt.json()["valid"] is True

    packet_response = client.post(
        f"{prefix}/assurance-packet",
        headers={"Idempotency-Key": "real-round-trip-1"},
    )
    assert packet_response.status_code == 200, packet_response.text
    packet = packet_response.json()
    assert packet["stores_raw_interaction_content"] is False
    assert "Synthetic evidence-ready request." not in packet_response.text
    assert "Synthetic evidence-ready response." not in packet_response.text

    verified_packet = client.post(
        f"{prefix}/assurance-packet/verify",
        json={"packet": packet},
    )
    assert verified_packet.status_code == 200, verified_packet.text
    assert verified_packet.json() == {"valid": True}
