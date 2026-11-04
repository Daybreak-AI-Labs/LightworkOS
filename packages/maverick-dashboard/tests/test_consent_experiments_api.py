from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick.consent_experiments import ConsentExperimentAuthority
from maverick_dashboard import consent_experiments_api

NOW = 1_800_000_000.0
API = "/api/v1/consent/experiments"
ENABLED = {
    "consent_preferences": {
        "enable": True,
        "experiments": {"enable": True},
    }
}


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> float:
        return self.now


class FakeKeyAuthority:
    def key_for(self, tenant_id: str, capability: str) -> bytes:
        return hmac.new(
            b"dashboard-consent-experiments".ljust(32, b"!"),
            f"{capability}:{tenant_id}".encode(),
            hashlib.sha256,
        ).digest()


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    holder: dict[str, object] = {"config": ENABLED}
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    for name in (
        "MAVERICK_DASHBOARD_ADMINS",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(
        consent_experiments_api,
        "_config",
        lambda: holder["config"],
    )
    clock = Clock()
    authority = ConsentExperimentAuthority(
        tmp_path / "consent-experiments.sqlite3",
        key_authority=FakeKeyAuthority(),
        config_loader=lambda: holder["config"],
        clock=clock,
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(
            sub=request.headers.get("X-Test-Subject", "experiment-owner")
        )
        return await call_next(request)

    app.state.consent_experiment_authority_factory = (
        lambda **_kwargs: authority
    )
    app.include_router(consent_experiments_api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    return client, authority, clock, holder


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _variant(
    variant_id: str,
    allocation_bps: int,
    *,
    control: bool = False,
) -> dict[str, object]:
    return {
        "variant_id": variant_id,
        "allocation_bps": allocation_bps,
        "content_ref": f"bundle:{variant_id}",
        "content_sha256": _digest(f"content:{variant_id}"),
        "accessibility_evidence_sha256": _digest(f"a11y:{variant_id}"),
        "equal_choice_evidence_sha256": _digest(f"parity:{variant_id}"),
        "is_control": control,
        "is_holdout": False,
    }


def _definition(
    *,
    experiment_id: str = "banner-copy-v1",
    idempotency_key: str = "create-banner-copy-v1",
    retention_days: int = 30,
) -> dict[str, object]:
    return {
        "experiment_id": experiment_id,
        "metric_id": "preference-completion",
        "variants": [
            _variant("control", 5_000, control=True),
            _variant("treatment", 5_000),
        ],
        "starts_at": NOW - 100.0,
        "ends_at": NOW + 1_000.0,
        "traffic_bps": 10_000,
        "max_exposures": 10_000,
        "min_sample_per_variant": 20,
        "alpha": 0.05,
        "max_analysis_looks": 5,
        "minimum_effect": 0.0,
        "dedupe_retention_days": retention_days,
        "audience": {"country_codes": ["US"], "channels": ["web"]},
        "idempotency_key": idempotency_key,
    }


def _ok(response, expected: int = 200) -> dict:
    assert response.status_code == expected, response.text
    return response.json()


def _create(client: TestClient, **overrides) -> dict:
    body = {**_definition(), **overrides}
    return _ok(client.post(API, json=body), 201)


def _activate(client: TestClient) -> None:
    _create(client)
    _ok(
        client.post(
            f"{API}/banner-copy-v1/approve",
            json={"expected_revision": 0, "idempotency_key": "approve-banner-001"},
            headers={"X-Test-Subject": "privacy-reviewer"},
        )
    )
    _ok(
        client.post(
            f"{API}/banner-copy-v1/activate",
            json={"expected_revision": 1, "idempotency_key": "activate-banner-001"},
        )
    )


def _context(**overrides) -> dict[str, object]:
    return {
        "country_code": "US",
        "channel": "web",
        "privacy_signals": [],
        "required_purpose": False,
        "accessibility_supported": True,
        "equal_choice_prominence": True,
        **overrides,
    }


def test_status_is_explicit_and_capability_is_independently_default_off(
    environment,
) -> None:
    client, _authority, _clock, holder = environment
    status = _ok(client.get(f"{API}/status"))
    assert status["enabled"] is True
    assert status["live_estate_acceptance_verified"] is False
    assert status["causal_certification_provided"] is False
    assert status["raw_identity_persisted"] is False
    assert status["limits"]["max_analysis_looks"] == 20

    holder["config"] = {"consent_preferences": {"enable": True}}
    assert _ok(client.get(f"{API}/status"))["enabled"] is False
    response = client.post(API, json=_definition())
    assert response.status_code == 403
    assert "experiments are disabled" in response.json()["detail"]


def test_default_authority_uses_a_separate_stable_private_root_key(
    environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _authority, _clock, _holder = environment
    delattr(client.app.state, "consent_experiment_authority_factory")
    monkeypatch.delenv("MAVERICK_CONSENT_EXPERIMENT_KEY", raising=False)
    created = _create(client)
    assert created["state"] == "draft"
    assert _ok(client.get(f"{API}/banner-copy-v1"))["definition_sha256"] == created[
        "definition_sha256"
    ]

    home = Path(os.environ["MAVERICK_HOME"])
    key_path = home / "keys" / "consent-experiments.key"
    database = next(home.rglob("consent-experiments.sqlite3"))
    key = key_path.read_bytes()
    assert len(key) == 32
    assert database.parent != key_path.parent
    assert key not in database.read_bytes()


def test_create_approve_activate_enforces_stable_identity_and_four_eyes(
    environment,
) -> None:
    client, _authority, _clock, _holder = environment
    draft = _create(client)
    assert draft["state"] == "draft"
    assert draft["revision"] == 0
    self_approval = client.post(
        f"{API}/banner-copy-v1/approve",
        json={"expected_revision": 0, "idempotency_key": "self-approve-denied-001"},
    )
    assert self_approval.status_code == 403
    approved = _ok(
        client.post(
            f"{API}/banner-copy-v1/approve",
            json={"expected_revision": 0, "idempotency_key": "approve-banner-001"},
            headers={"X-Test-Subject": "privacy-reviewer"},
        )
    )
    assert approved["state"] == "approved"
    active = _ok(
        client.post(
            f"{API}/banner-copy-v1/activate",
            json={"expected_revision": 1, "idempotency_key": "activate-banner-001"},
        )
    )
    assert active["state"] == "active"
    assert _ok(client.get(f"{API}/banner-copy-v1"))["revision"] == 2

    export = _ok(client.get(f"{API}/banner-copy-v1/audit-export"))
    lifecycle = [
        event
        for event in export["audit"]
        if event["action"]
        in {"experiment.created", "experiment.approved", "experiment.activated"}
    ]
    assert len(lifecycle) == 3
    assert lifecycle[0]["actor_token"] != lifecycle[1]["actor_token"]
    assert lifecycle[0]["actor_token"] == lifecycle[2]["actor_token"]
    assert "local-operator" not in str(export)
    assert "experiment-owner" not in str(export)
    assert "privacy-reviewer" not in str(export)


def test_strict_boundary_rejects_tenant_actor_executable_and_unknown_fields(
    environment,
) -> None:
    client, _authority, _clock, _holder = environment
    forged = {
        **_definition(),
        "tenant_id": "tenant-b",
        "created_by": "attacker",
        "executable_content": "<script>alert(1)</script>",
    }
    assert client.post(API, json=forged).status_code == 422
    string_number = {**_definition(), "traffic_bps": "10000"}
    assert client.post(API, json=string_number).status_code == 422
    malformed = _definition()
    malformed["variants"] = [
        {**_variant("control", 5_000, control=True), "javascript": "alert(1)"},
        _variant("treatment", 5_000),
    ]
    assert client.post(API, json=malformed).status_code == 422


def test_assignment_exposure_outcome_and_analysis_are_privacy_bounded(
    environment,
) -> None:
    client, authority, _clock, _holder = environment
    _activate(client)
    subject = "sensitive-person@example.test"
    assignment_body = {"subject_identity": subject, "context": _context()}
    assignment = _ok(
        client.post(f"{API}/banner-copy-v1/assign", json=assignment_body)
    )
    assert assignment["eligible"] is True
    assert subject not in str(assignment)

    exposure = _ok(
        client.post(
            f"{API}/banner-copy-v1/exposures",
            json={
                **assignment_body,
                "idempotency_key": "exposure-sensitive-001",
            },
        ),
        201,
    )
    assert exposure["recorded"] is True
    assert subject not in str(exposure)
    outcome = _ok(
        client.post(
            f"{API}/banner-copy-v1/outcomes",
            json={
                "subject_identity": subject,
                "success": True,
                "idempotency_key": "outcome-sensitive-001",
            },
        ),
        201,
    )
    assert outcome["recorded"] is True

    analysis = _ok(
        client.post(
            f"{API}/banner-copy-v1/analysis",
            json={"idempotency_key": "analysis-banner-001"},
        )
    )
    assert analysis["winner_variant_id"] is None
    assert analysis["causal_claim_authorized"] is False
    assert analysis["limitations"]
    export = _ok(client.get(f"{API}/banner-copy-v1/audit-export"))
    assert export["raw_identity_retained"] is False
    assert export["raw_event_payload_retained"] is False
    assert subject not in str(export)
    assert subject.encode() not in authority.path.read_bytes()


def test_legal_signal_precedence_records_no_exposure(environment) -> None:
    client, _authority, _clock, _holder = environment
    _activate(client)
    body = {
        "subject_identity": "gpc-subject",
        "context": _context(privacy_signals=["gpc"]),
        "idempotency_key": "exposure-gpc-001",
    }
    result = _ok(
        client.post(f"{API}/banner-copy-v1/exposures", json=body),
        201,
    )
    assert result["recorded"] is False
    assert result["assignment"]["reason"] == "legal_signal_precedence"
    assert result["assignment"]["is_control"] is True
    export = _ok(client.get(f"{API}/banner-copy-v1/audit-export"))
    assert sum(item["exposures"] for item in export["aggregates"]) == 0


def test_outcome_requires_exposure_and_lifecycle_supports_pause_resume_rollback(
    environment,
) -> None:
    client, _authority, _clock, _holder = environment
    _activate(client)
    missing = client.post(
        f"{API}/banner-copy-v1/outcomes",
        json={
            "subject_identity": "not-exposed",
            "success": True,
            "idempotency_key": "missing-outcome-001",
        },
    )
    assert missing.status_code == 409
    paused = _ok(
        client.post(
            f"{API}/banner-copy-v1/pause",
            json={"expected_revision": 2, "idempotency_key": "pause-banner-001"},
        )
    )
    assert paused["state"] == "paused"
    resumed = _ok(
        client.post(
            f"{API}/banner-copy-v1/resume",
            json={"expected_revision": 3, "idempotency_key": "resume-banner-001"},
        )
    )
    assert resumed["state"] == "active"
    rolled_back = _ok(
        client.post(
            f"{API}/banner-copy-v1/rollback",
            json={"expected_revision": 4, "idempotency_key": "rollback-banner-001"},
        )
    )
    assert rolled_back["state"] == "rolled_back"
    assert rolled_back["rollback_variant_id"] == "control"
    fallback = _ok(
        client.post(
            f"{API}/banner-copy-v1/assign",
            json={"subject_identity": "after-rollback", "context": _context()},
        )
    )
    assert fallback["eligible"] is False
    assert fallback["reason"] == "rolled_back"


def test_unicode_tenant_isolation_and_no_body_tenant_selector(
    environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _authority, _clock, _holder = environment
    _create(client)
    monkeypatch.setenv("MAVERICK_TENANT", "Café Customer 北")
    assert client.get(f"{API}/banner-copy-v1").status_code == 404
    tenant_b = _create(
        client,
        idempotency_key="create-unicode-tenant-001",
    )
    assert tenant_b["state"] == "draft"
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    assert _ok(client.get(f"{API}/banner-copy-v1"))["state"] == "draft"


def test_expired_dedupe_retention_purge_is_explicit_and_idempotent(
    environment,
) -> None:
    client, _authority, clock, _holder = environment
    _create(client, dedupe_retention_days=1)
    _ok(
        client.post(
            f"{API}/banner-copy-v1/approve",
            json={"expected_revision": 0, "idempotency_key": "approve-retention-001"},
            headers={"X-Test-Subject": "privacy-reviewer"},
        )
    )
    _ok(
        client.post(
            f"{API}/banner-copy-v1/activate",
            json={"expected_revision": 1, "idempotency_key": "activate-retention-001"},
        )
    )
    _ok(
        client.post(
            f"{API}/banner-copy-v1/exposures",
            json={
                "subject_identity": "expiring-subject",
                "context": _context(),
                "idempotency_key": "exposure-retention-001",
            },
        ),
        201,
    )
    clock.now = NOW + 90_000
    body = {"idempotency_key": "purge-retention-001"}
    first = _ok(client.post(f"{API}/retention/purge", json=body))
    replay = _ok(client.post(f"{API}/retention/purge", json=body))
    assert first == replay
    assert first["records_purged"] == 1
    assert _ok(client.get(f"{API}/banner-copy-v1/audit-export"))[
        "pseudonymous_dedupe_record_count"
    ] == 0


def test_experiment_list_is_read_only_tenant_scoped_and_needs_operate(
    environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastapi import HTTPException

    client, _authority, _clock, _holder = environment
    _create(client)
    listed = _ok(client.get(API))
    assert [item["definition"]["experiment_id"] for item in listed["items"]] == ["banner-copy-v1"]
    assert listed["items"][0]["state"] == "draft" and listed["truncated"] is False
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    assert _ok(client.get(API))["items"] == []
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")

    asked: list[str] = []

    def deny(_request, permission):
        asked.append(permission)
        raise HTTPException(status_code=403, detail="insufficient role for this action")

    monkeypatch.setattr(consent_experiments_api, "require_permission", deny)
    assert client.get(API).status_code == 403
    assert client.get(
        f"{API}/variant-content?property_id=site&rule_group_id=rules&rule_group_version=1"
    ).status_code == 403
    assert asked == ["operate", "operate"]


def test_variant_layout_fingerprints_match_what_the_public_endpoint_verifies() -> None:
    from maverick_dashboard import consent_public_api

    messages = {"t": "Your privacy", "b": "Choose élève", "a": "Accept", "r": "Reject", "s": "Save"}
    bundle = {
        "rule_group": {"payload": {"rules": [{
            "rule_id": "global",
            "locales": ["fr-FR"],
            "template": {"id": "banner", "version": 2},
            "translation_catalog_id": "copy",
            "translation_versions": {"fr-FR": 3},
        }]}},
        "resources": [
            {"resource_kind": "template", "resource_id": "banner", "locale": "", "version": 2,
             "payload": {"title_key": "t", "body_key": "b",
                         "actions": {"accept_all": "a", "reject_all": "r", "save_preferences": "s"}}},
            {"resource_kind": "translation", "resource_id": "copy", "locale": "fr-FR", "version": 3,
             "payload": {"messages": messages}},
        ],
    }
    items = consent_experiments_api._variant_contents(bundle)
    assert [item["layout"] for item in items] == ["stacked", "inline", "compact"]
    contract = SimpleNamespace(public_configuration={
        "rule": {"locale": "fr-FR"},
        "configuration": {"template": {"title": "Your privacy", "body": messages["b"],
                                       "actions": {"accept_all": "Accept", "reject_all": "Reject",
                                                   "save_preferences": "Save", "close": "x"}}},
    })
    for item in items:
        expected = consent_public_api._sha256(
            consent_public_api._published_experiment_render(contract, layout=item["layout"])
        )
        assert item["content_sha256"] == expected
        assert item["content_ref"] == "public-layout:" + item["layout"]
