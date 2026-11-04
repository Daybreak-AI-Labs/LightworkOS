"""Acceptance and adversarial tests for operational AI policy management."""
from __future__ import annotations

import copy
import json

import pytest
from maverick import ai_policy_management as apm
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _service(clock: Clock | None = None) -> apm.AIPolicyManagement:
    return apm.AIPolicyManagement(
        policies=GovernedRecordStore(
            "test_ai_operational_policies", "AOP", "test_ai_operational_policy"
        ),
        exceptions=GovernedRecordStore(
            "test_ai_policy_exceptions", "APX", "test_ai_policy_exception"
        ),
        evaluations=GovernedRecordStore(
            "test_ai_policy_evaluations", "APE", "test_ai_policy_evaluation"
        ),
        clock=clock or Clock(),
    )


def _statement(
    statement_id: str,
    effect: str,
    *,
    risk_tiers: list[str] | None = None,
    jurisdictions: list[str] | None = None,
    controls: list[str] | None = None,
) -> dict[str, object]:
    return {
        "statement_id": statement_id,
        "text": f"Apply the {effect} policy for {statement_id}.",
        "effect": effect,
        "applicability": {
            "risk_tiers": risk_tiers or [],
            "jurisdictions": jurisdictions or [],
        },
        "required_control_ids": controls or [],
    }


def _context(asset_id: str = "asset-1") -> dict[str, object]:
    return {
        "asset_id": asset_id,
        "risk_tier": "high",
        "jurisdictions": ["us", "eu"],
        "data_classes": ["personal"],
        "deployment_types": ["production"],
        "asset_types": ["agent"],
        "tags": ["external", "customer-facing"],
        "use_case_tags": ["support"],
    }


def _create_and_activate(
    service: apm.AIPolicyManagement,
    policy_id: str,
    statements: list[dict[str, object]],
) -> dict[str, object]:
    draft = service.create_policy(
        policy_id,
        title=f"{policy_id} policy",
        statements=statements,
        actor="user:author",
    )
    return service.activate_policy(
        policy_id,
        1,
        expected_revision=draft["revision"],
        actor="user:activator",
    )


def test_feature_gate_is_explicit_and_default_off(tmp_path):
    from maverick import config

    assert apm.enabled() is False
    with pytest.raises(apm.AIPolicyManagementConfigError, match="disabled"):
        apm.configured_policy_management()

    (tmp_path / "config.toml").write_text(
        "[ai_policy_management]\nenable = true\n", encoding="utf-8"
    )
    config.reset_config_cache()

    assert apm.enabled() is True
    assert isinstance(apm.configured_policy_management(), apm.AIPolicyManagement)


def test_operations_require_explicit_tenant_authority():
    service = _service()
    with pytest.raises(apm.AIPolicyManagementStateError, match="explicit tenant"):
        service.list_policies()
    with pytest.raises(apm.AIPolicyManagementStateError, match="explicit tenant"):
        service.preview(_context())


def test_policy_records_are_tenant_isolated_and_semantic_ids_can_repeat():
    service = _service()
    with tenant_scope(tenant="acme"):
        acme = service.create_policy(
            "runtime-policy",
            title="Acme runtime policy",
            statements=[_statement("review", "review")],
            actor="user:author",
        )
        assert service.get_policy("runtime-policy") == acme

    with tenant_scope(tenant="globex"):
        assert service.get_policy("runtime-policy") is None
        assert service.list_policies() == []
        globex = service.create_policy(
            "runtime-policy",
            title="Globex runtime policy",
            statements=[_statement("allow", "allow")],
            actor="user:author",
        )
        assert globex["versions"][0]["title"] == "Globex runtime policy"

    with tenant_scope(tenant="acme"):
        assert service.get_policy("runtime-policy")["versions"][0]["title"] == (
            "Acme runtime policy"
        )


def test_versions_are_immutable_and_activation_requires_human_cas():
    service = _service()
    with tenant_scope(tenant="acme"):
        first = service.create_policy(
            "data-use",
            title="Data use v1",
            statements=[_statement("personal-data", "review")],
            actor="agent:policy-drafter",
        )
        original = copy.deepcopy(first["versions"][0])
        with pytest.raises(ValueError, match="authenticated user"):
            service.activate_policy(
                "data-use",
                1,
                expected_revision=first["revision"],
                actor="agent:policy-drafter",
            )
        with pytest.raises(RecordConflict, match="expected revision 0"):
            service.activate_policy(
                "data-use", 1, expected_revision=0, actor="user:approver"
            )
        active = service.activate_policy(
            "data-use",
            1,
            expected_revision=first["revision"],
            actor="user:approver",
        )
        with pytest.raises(RecordConflict, match="expected revision"):
            service.add_policy_version(
                "data-use",
                title="Data use v2",
                statements=[_statement("personal-data", "restrict")],
                expected_revision=first["revision"],
                actor="user:author",
            )
        second = service.add_policy_version(
            "data-use",
            title="Data use v2",
            statements=[_statement("personal-data", "restrict")],
            expected_revision=active["revision"],
            actor="user:author",
        )

    assert second["versions"][0] == original
    assert second["versions"][1]["version"] == 2
    assert second["versions"][0]["digest"] != second["versions"][1]["digest"]
    assert second["active_version"] == 1


def test_deterministic_strictest_wins_and_all_conditions_are_supported():
    service = _service()
    with tenant_scope(tenant="acme"):
        _create_and_activate(
            service,
            "z-allow",
            [_statement("general", "allow", controls=["log-control"])],
        )
        _create_and_activate(
            service,
            "b-review",
            [_statement("eu-review", "review", jurisdictions=["eu"])],
        )
        _create_and_activate(
            service,
            "a-restrict",
            [_statement("high-risk", "restrict", risk_tiers=["high"])],
        )
        policy = service.create_policy(
            "m-prohibit",
            title="Production agents",
            statements=[{
                "statement_id": "external-agent",
                "text": "Prohibit external high-risk support agents.",
                "effect": "prohibit",
                "applicability": {
                    "risk_tiers": ["high"],
                    "jurisdictions": ["us"],
                    "data_classes": ["personal"],
                    "deployment_types": ["production"],
                    "asset_types": ["agent"],
                    "tags": ["external"],
                    "use_case_tags": ["support"],
                },
                "required_control_ids": ["kill-switch"],
            }],
            actor="user:author",
        )
        service.activate_policy(
            "m-prohibit",
            1,
            expected_revision=policy["revision"],
            actor="user:activator",
        )
        first = service.preview(_context())
        shuffled = _context()
        shuffled["jurisdictions"] = ["eu", "us"]
        shuffled["tags"] = ["customer-facing", "external"]
        second = service.preview(shuffled)

    assert first == second
    assert first["final_effect"] == "prohibit"
    assert [item["policy_id"] for item in first["matched_statements"]] == [
        "a-restrict",
        "b-review",
        "m-prohibit",
        "z-allow",
    ]
    assert first["required_control_ids"] == ["kill-switch", "log-control"]
    assert first["defaulted_to_review"] is False


def test_no_matching_policy_fails_safe_to_review():
    service = _service()
    with tenant_scope(tenant="acme"):
        _create_and_activate(
            service,
            "eu-only",
            [_statement("eu", "allow", jurisdictions=["eu"])],
        )
        context = _context()
        context["jurisdictions"] = ["ca"]
        decision = service.preview(context)

    assert decision["matched_statements"] == []
    assert decision["final_effect"] == "review"
    assert decision["defaulted_to_review"] is True


def test_exception_requires_four_eyes_and_only_approved_unexpired_state_authorizes():
    clock = Clock()
    service = _service(clock)
    with tenant_scope(tenant="acme"):
        _create_and_activate(
            service,
            "blocked-use",
            [_statement("deny", "prohibit", controls=["baseline-control"])],
        )
        pending = service.request_exception(
            "launch-waiver",
            policy_id="blocked-use",
            policy_version=1,
            scope={"asset_ids": ["asset-1"], "statement_ids": ["deny"]},
            reason="A bounded launch window is required for migration.",
            compensating_control_ids=["human-review", "traffic-cap"],
            expires_at=clock.value + 300,
            requester="user:requester",
        )
        assert pending["authorizes"] is False
        assert service.preview(_context())["final_effect"] == "prohibit"
        with pytest.raises(ValueError, match="own request"):
            service.approve_exception(
                "launch-waiver",
                expected_revision=pending["revision"],
                approver="user:requester",
            )
        approved = service.approve_exception(
            "launch-waiver",
            expected_revision=pending["revision"],
            approver="user:independent-approver",
        )
        allowed = service.preview(_context())
        other_asset = service.preview(_context("asset-2"))
        clock.value += 301
        expired = service.get_exception("launch-waiver")
        denied_after_expiry = service.preview(_context())
        closed = service.close_exception(
            "launch-waiver",
            expected_revision=approved["revision"],
            actor="user:risk-owner",
            reason="Migration window ended and the waiver is retired.",
        )

    assert approved["status"] == "approved"
    assert approved["authorizes"] is True
    assert allowed["final_effect"] == "allow"
    applied = allowed["matched_statements"][0]
    assert applied["effect"] == "prohibit"
    assert applied["effective_effect"] == "allow"
    assert applied["exception"]["exception_key"] == "launch-waiver"
    assert allowed["required_control_ids"] == [
        "baseline-control",
        "human-review",
        "traffic-cap",
    ]
    assert other_asset["final_effect"] == "prohibit"
    assert expired["status"] == "expired"
    assert expired["authorizes"] is False
    assert denied_after_expiry["final_effect"] == "prohibit"
    assert closed["status"] == "closed"
    assert closed["authorizes"] is False


def test_expired_pending_exception_cannot_be_approved():
    clock = Clock()
    service = _service(clock)
    with tenant_scope(tenant="acme"):
        _create_and_activate(
            service,
            "blocked-use",
            [_statement("deny", "prohibit")],
        )
        pending = service.request_exception(
            "expired-before-review",
            policy_id="blocked-use",
            policy_version=1,
            scope={"asset_ids": ["asset-1"]},
            reason="Short-lived request for an emergency migration.",
            compensating_control_ids=["manual-monitor"],
            expires_at=clock.value + 10,
            requester="user:requester",
        )
        clock.value += 11
        with pytest.raises(ValueError, match="expired exception"):
            service.approve_exception(
                "expired-before-review",
                expected_revision=pending["revision"],
                approver="user:approver",
            )
        assert service.get_exception("expired-before-review")["status"] == "expired"


def test_policy_activation_makes_evaluation_and_attestation_stale_until_revalidated():
    service = _service()
    with tenant_scope(tenant="acme"):
        active = _create_and_activate(
            service,
            "runtime",
            [_statement("runtime-rule", "review")],
        )
        evaluation = service.evaluate(
            "asset-1-runtime",
            _context(),
            expected_revision=0,
            actor="policy-engine",
        )
        attested = service.attest_evaluation(
            "asset-1-runtime",
            expected_revision=evaluation["revision"],
            actor="user:risk-owner",
        )
        second = service.add_policy_version(
            "runtime",
            title="Runtime v2",
            statements=[_statement("runtime-rule", "restrict")],
            expected_revision=active["revision"],
            actor="user:author",
        )
        service.activate_policy(
            "runtime",
            2,
            expected_revision=second["revision"],
            actor="user:activator",
        )
        stale = service.get_evaluation("asset-1-runtime")
        with pytest.raises(apm.AIPolicyManagementStateError, match="revalidation"):
            service.attest_evaluation(
                "asset-1-runtime",
                expected_revision=attested["revision"],
                actor="user:risk-owner",
            )
        refreshed = service.evaluate(
            "asset-1-runtime",
            _context(),
            expected_revision=attested["revision"],
            actor="policy-engine",
        )
        reattested = service.attest_evaluation(
            "asset-1-runtime",
            expected_revision=refreshed["revision"],
            actor="user:risk-owner",
        )

    assert stale["revalidation_required"] is True
    assert stale["attestation"]["status"] == "stale"
    assert stale["authority_digest"] != stale["current_authority_digest"]
    assert refreshed["revalidation_required"] is False
    assert refreshed["decision"]["final_effect"] == "restrict"
    assert refreshed["attestation"]["status"] == "missing"
    assert reattested["attestation"]["status"] == "current"


def test_exception_expiry_also_requires_evaluation_revalidation():
    clock = Clock()
    service = _service(clock)
    with tenant_scope(tenant="acme"):
        _create_and_activate(
            service,
            "blocked-use",
            [_statement("deny", "prohibit")],
        )
        pending = service.request_exception(
            "temporary",
            policy_id="blocked-use",
            policy_version=1,
            scope={"asset_ids": ["asset-1"]},
            reason="Temporary controlled exception.",
            compensating_control_ids=["manual-monitor"],
            expires_at=clock.value + 100,
            requester="user:requester",
        )
        service.approve_exception(
            "temporary",
            expected_revision=pending["revision"],
            approver="user:approver",
        )
        evaluation = service.evaluate(
            "temporary-eval",
            _context(),
            expected_revision=0,
            actor="policy-engine",
        )
        assert evaluation["decision"]["final_effect"] == "allow"
        clock.value += 101
        stale = service.get_evaluation("temporary-eval")

    assert stale["revalidation_required"] is True
    assert stale["current_decision_digest"] != stale["decision_digest"]


def test_malformed_stored_policy_fails_closed_before_decision():
    service = _service()
    with tenant_scope(tenant="acme"):
        policy = _create_and_activate(
            service,
            "runtime",
            [_statement("runtime-rule", "restrict")],
        )
        _, tenant_ref = apm._active_tenant()
        record_id = apm._policy_record_id(tenant_ref, "runtime")

        def corrupt(row):
            row["versions"][0]["statements"][0]["effect"] = "permit"

        service._policies.update(
            record_id,
            corrupt,
            expected_revision=policy["revision"],
            action="test_corrupt_policy",
            actor="test",
        )
        with pytest.raises(apm.AIPolicyManagementStateError, match="malformed"):
            service.preview(_context())
        with pytest.raises(apm.AIPolicyManagementStateError, match="malformed"):
            service.get_policy("runtime")


def test_safe_projections_exclude_internal_ids_tenant_bindings_and_evidence_refs():
    service = _service()
    with tenant_scope(tenant="acme"):
        policy = _create_and_activate(
            service,
            "runtime",
            [_statement("runtime-rule", "review")],
        )
        evaluation = service.evaluate(
            "runtime-eval",
            _context(),
            expected_revision=0,
            actor="policy-engine",
        )

    serialized = json.dumps({"policy": policy, "evaluation": evaluation})
    assert "tenant_ref" not in serialized
    assert '"id":' not in serialized
    assert "evidence_ref" not in serialized
    assert "raw_evidence" not in serialized
    assert policy["active_digest"]
    assert evaluation["authority_digest"]
    assert evaluation["decision_digest"]


def test_policy_inputs_are_bounded_and_reject_unknown_or_secret_fields():
    service = _service()
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match="unknown fields"):
            service.create_policy(
                "bad",
                title="Bad policy",
                statements=[{
                    **_statement("rule", "review"),
                    "raw_evidence_ref": "opaque-123",
                }],
                actor="user:author",
            )
        with pytest.raises(ValueError, match="secret material"):
            service.create_policy(
                "secret",
                title="Bad sk-abcdefghijklmnopqrstuvwxyz123456 policy",
                statements=[_statement("rule", "review")],
                actor="user:author",
            )
