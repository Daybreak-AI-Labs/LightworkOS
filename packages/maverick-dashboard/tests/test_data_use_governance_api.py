"""End-to-end HTTP contracts for provider-neutral Data Use Governance."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/data-use"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture(autouse=True)
def isolated_data_use(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer

    path = tmp_path / "config.toml"
    path.write_text(
        "[data_use_governance]\n"
        "enable = true\n"
        "[data_use_governance.compiler]\n"
        "enable = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in (
        "MAVERICK_DASHBOARD_ADMINS",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    yield path
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()


def _ok(response, expected: int = 200) -> dict:
    assert response.status_code == expected, response.text
    return response.json()


def _cas(key: str, revision: int = 0) -> dict:
    return {"expected_revision": revision, "idempotency_key": key}


def _catalog() -> None:
    _ok(
        client.put(
            f"{API}/assets/customers",
            json={
                **_cas("asset-customers"),
                "asset_type": "table",
                "catalog_binding_sha256": _digest("catalog:customers"),
            },
        )
    )
    for field_id, data_type, nullable in (
        ("email", "string", False),
        ("region", "string", False),
    ):
        _ok(
            client.put(
                f"{API}/assets/customers/fields/{field_id}",
                json={
                    **_cas(f"field-{field_id}"),
                    "data_type": data_type,
                    "nullable": nullable,
                    "catalog_binding_sha256": _digest(f"catalog:{field_id}"),
                },
            )
        )


def _contexts() -> None:
    now = time.time()
    values = {
        "business_purpose": ["analytics"],
        "regulatory": ["gdpr"],
        "consent": ["granted"],
        "observed_classification": ["personal"],
    }
    for number, (kind, context_values) in enumerate(values.items(), start=1):
        _ok(
            client.put(
                f"{API}/assets/customers/contexts/{kind}",
                json={
                    **_cas(f"context-{kind}"),
                    "values": context_values,
                    "source_system": f"authority-{kind}",
                    "source_revision": number,
                    "source_authority_sha256": _digest(f"source:{kind}"),
                    "evidence_sha256": _digest(f"evidence:{kind}"),
                    "observed_at": now - 60,
                    "fresh_until": now + 3_600,
                },
            )
        )


def _label() -> None:
    now = time.time()
    _ok(
        client.post(
            f"{API}/labels/personal-data/versions",
            json={
                **_cas("label-v1"),
                "version": 1,
                "taxonomy_id": "enterprise-taxonomy",
                "sensitivity": 80,
                "definition_sha256": _digest("personal definition"),
                "reviewed_at": now - 30,
                "expected_current_version": 0,
            },
        ),
        201,
    )
    _ok(
        client.put(
            f"{API}/labels/personal-data/assignments",
            json={
                **_cas("label-assign"),
                "asset_id": "customers",
                "field_id": "email",
                "label_version": 1,
                "assignment_evidence_sha256": _digest("assignment evidence"),
            },
        )
    )


def _policy_document() -> dict:
    return {
        "scope": {
            "asset_ids": ["customers"],
            "field_ids": ["email"],
            "project_ids": [],
            "actions": ["read"],
        },
        "conditions": {
            "business_purpose_any": ["analytics"],
            "regulatory_any": ["gdpr"],
            "consent_any": ["granted"],
            "observed_classification_any": ["personal"],
            "label_any": ["personal-data"],
        },
        "controls": [
            {
                "control_id": "mask-email",
                "effect": "mask",
                "field_ids": ["email"],
                "mask_method": "hash_sha256",
            }
        ],
    }


def test_data_use_authority_and_compiler_are_independently_default_off(
    isolated_data_use: Path,
) -> None:
    from maverick import config

    isolated_data_use.write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert client.get(f"{API}/status").status_code == 403

    isolated_data_use.write_text(
        "[data_use_governance]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert _ok(client.get(f"{API}/status"))["compiler_enabled"] is False
    assert client.post(
        f"{API}/decisions/decision-1/compile", json={}
    ).status_code == 403


def test_full_authorize_compile_and_read_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick_dashboard import data_use_governance_api as api_module

    actor = ["author-a"]
    monkeypatch.setattr(
        api_module,
        "_actor_binding",
        lambda _request: (actor[0], _digest(f"authority:{actor[0]}")),
    )
    _catalog()
    _contexts()
    _label()
    draft = _ok(
        client.post(
            f"{API}/policies/mask-personal/versions",
            json={
                **_cas("policy-draft"),
                "version": 1,
                "document": _policy_document(),
                "expected_current_version": 0,
            },
        ),
        201,
    )
    assert draft["state"] == "draft"

    actor[0] = "reviewer-b"
    active = _ok(
        client.post(
            f"{API}/policies/mask-personal/activate",
            json={
                **_cas("policy-activate", draft["revision"]),
                "version": 1,
                "reviewed_at": time.time() - 1,
            },
        )
    )
    assert active["state"] == "active"

    actor[0] = "requester-c"
    request_record = _ok(
        client.post(
            f"{API}/requests/use-email",
            json={
                "project_id": "analytics-project",
                "asset_id": "customers",
                "field_ids": ["email"],
                "action": "read",
                "purpose_codes": ["analytics"],
                "request_evidence_sha256": _digest("approved project evidence"),
                "idempotency_key": "request-create",
            },
        ),
        201,
    )
    assert request_record["status"] == "pending"

    actor[0] = "authorizer-d"
    decision = _ok(
        client.post(
            f"{API}/requests/use-email/authorize",
            json={
                "expected_request_revision": request_record["revision"],
                "idempotency_key": "request-authorize",
            },
        )
    )
    assert decision["outcome"] == "mask"
    assert decision["controls"][0]["mask_method"] == "hash_sha256"

    compiled = _ok(
        client.post(
            f"{API}/decisions/{decision['decision_id']}/compile",
            json={"expected_decision_sha256": decision["decision_sha256"]},
        )
    )
    assert compiled["provider_writes_possible"] is False
    assert compiled["desired_state"][0]["operation"] == "mask"
    assert compiled["rollback_state"][0]["operation"] == "deny"

    listed = _ok(client.get(f"{API}/records/decision"))
    assert listed["truncated"] is False
    assert [item["decision_id"] for item in listed["items"]] == [
        decision["decision_id"]
    ]
    fetched = _ok(
        client.get(f"{API}/records/decision/{decision['decision_id']}")
    )
    assert fetched["decision_sha256"] == decision["decision_sha256"]
    status = _ok(client.get(f"{API}/status"))
    assert status["provider_writes_possible"] is False
    assert status["native_adapter_attached"] is False


def test_server_actors_enforce_four_eyes_and_client_cannot_supply_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick_dashboard import data_use_governance_api as api_module

    monkeypatch.setattr(
        api_module,
        "_actor_binding",
        lambda _request: ("same-actor", _digest("same authority")),
    )
    _catalog()
    draft = _ok(
        client.post(
            f"{API}/policies/policy-a/versions",
            json={
                **_cas("policy-a-draft"),
                "version": 1,
                "document": _policy_document(),
                "expected_current_version": 0,
            },
        ),
        201,
    )
    response = client.post(
        f"{API}/policies/policy-a/activate",
        json={
            **_cas("policy-a-activate", draft["revision"]),
            "version": 1,
            "reviewed_at": time.time() - 1,
        },
    )
    assert response.status_code == 422
    assert "author and reviewer must differ" in response.json()["detail"]

    forged = client.post(
        f"{API}/requests/forged",
        json={
            "project_id": "project",
            "asset_id": "customers",
            "field_ids": ["email"],
            "action": "read",
            "purpose_codes": ["analytics"],
            "request_evidence_sha256": _digest("evidence"),
            "idempotency_key": "forged",
            "requester_id": "attacker-selected",
        },
    )
    assert forged.status_code == 422


def test_cross_tenant_records_and_idempotency_are_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _catalog()
    assert len(_ok(client.get(f"{API}/records/asset"))["items"]) == 1

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    assert _ok(client.get(f"{API}/records/asset"))["items"] == []
    _catalog()
    assert len(_ok(client.get(f"{API}/records/asset"))["items"]) == 1

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    assert len(_ok(client.get(f"{API}/records/field"))["items"]) == 2


def test_closed_policy_boundary_rejects_raw_sql_and_unknown_fields() -> None:
    _catalog()
    unsafe = _policy_document()
    unsafe["controls"] = [
        {
            "control_id": "bypass",
            "effect": "row_filter",
            "field_ids": [],
            "row_filter": {"op": "raw_sql", "value": "1=1; DROP TABLE x"},
        }
    ]
    response = client.post(
        f"{API}/policies/unsafe/versions",
        json={
            **_cas("unsafe-policy"),
            "version": 1,
            "document": unsafe,
            "expected_current_version": 0,
        },
    )
    assert response.status_code == 422

    unknown = client.put(
        f"{API}/assets/other",
        json={
            **_cas("asset-other"),
            "asset_type": "table",
            "catalog_binding_sha256": _digest("other"),
            "tenant_id": "tenant-b",
        },
    )
    assert unknown.status_code == 422
