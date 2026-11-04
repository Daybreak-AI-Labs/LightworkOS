"""Focused contracts for the transient local AI runtime guardrail core."""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
from maverick import ai_dynamic_risk
from maverick import ai_runtime_guardrails as guardrails
from maverick.paths import tenant_scope

NOW = 1_800_000_000.0
ASSET = "MAA-0123456789abcdef0123456789abcdef"
ASSET_DIGEST = hashlib.sha256(b"asset-v7").hexdigest()
SECRET = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"
EMAIL = "alice.sensitive@example.com"


class AllowShield:
    def scan_input(self, _text):
        return SimpleNamespace(allowed=True)

    def scan_output(self, _text, known_prompt=None):
        return SimpleNamespace(allowed=True)

    def scan_tool_call(self, _name, _arguments):
        return SimpleNamespace(allowed=True)


class TrackingShield(AllowShield):
    def __init__(self, *, blocked_stage: str | None = None) -> None:
        self.blocked_stage = blocked_stage
        self.calls: list[tuple[object, ...]] = []

    def scan_input(self, text):
        self.calls.append(("prompt", text))
        return SimpleNamespace(allowed=self.blocked_stage != "prompt")

    def scan_output(self, text, known_prompt=None):
        self.calls.append(("output", text, known_prompt))
        return SimpleNamespace(allowed=self.blocked_stage != "output")

    def scan_tool_call(self, name, arguments):
        self.calls.append(("action", name, arguments))
        return SimpleNamespace(allowed=self.blocked_stage != "action")


class PolicyManager:
    def __init__(self, effect: str, *, statement: bool = True) -> None:
        self.effect = effect
        self.statement = statement
        self.contexts: list[dict[str, object]] = []

    def preview(self, context):
        self.contexts.append(dict(context))
        statements = []
        if self.statement:
            statements = [{
                "policy_id": "runtime-policy",
                "statement_id": f"{self.effect}-rule",
                "statement_text": "Confidential policy prose is digest-only.",
            }]
        return {
            "final_effect": self.effect,
            "matched_statements": statements,
            "required_control_ids": ["human-approval", "runtime-log"],
            "defaulted_to_review": not statements,
            "authority": [{"digest": hashlib.sha256(b"policy").hexdigest()}],
        }


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    from maverick import config

    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _configure(tmp_path, *, policy: bool = False) -> None:
    body = "[ai_runtime_guardrails]\nenable = true\n"
    if policy:
        body += "\n[ai_policy_management]\nenable = true\n"
    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    from maverick import config

    config.reset_config_cache()


def _asset() -> guardrails.RuntimeAssetBinding:
    return guardrails.RuntimeAssetBinding(ASSET, 7, ASSET_DIGEST)


def _request(
    content: str = "summarize the quarterly report",
    *,
    stage: str = "prompt",
    **changes,
) -> guardrails.RuntimeGuardrailInput:
    values = {"stage": stage, "content": content, "asset": _asset()}
    values.update(changes)
    return guardrails.RuntimeGuardrailInput(**values)


def _service(shield=None, policy=None) -> guardrails.RuntimeGuardrails:
    return guardrails.RuntimeGuardrails(
        shield=shield or AllowShield(),
        policy_manager=policy,
        clock=lambda: NOW,
    )


def test_feature_gate_is_explicit_default_off_and_safe(_isolate):
    assert guardrails.enabled() is False
    with tenant_scope(tenant="acme"):
        with pytest.raises(
            guardrails.RuntimeGuardrailsConfigError,
            match="disabled",
        ):
            _service().evaluate(_request(SECRET))

    _configure(_isolate)
    assert guardrails.enabled() is True
    guardrails.require_enabled()


def test_operations_require_an_explicit_tenant(_isolate):
    _configure(_isolate)
    with pytest.raises(
        guardrails.RuntimeGuardrailsTenantError,
        match="explicit tenant",
    ):
        _service().evaluate(_request())


def test_allow_receipt_is_closed_exactly_bound_and_has_no_content(_isolate):
    _configure(_isolate)
    raw = "ordinary low-risk request"
    with tenant_scope(tenant="acme"):
        result = _service().evaluate(_request(raw))

    assert result.decision == "allow"
    assert result.redacted_content is None
    assert set(result.receipt) == {
        "stage",
        "decision",
        "categories",
        "rule_ids",
        "control_ids",
        "input_sha256",
        "output_sha256",
        "policy_sha256",
        "evaluated_at",
        "asset_binding",
    }
    assert result.receipt["input_sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    assert result.receipt["output_sha256"] == result.receipt["input_sha256"]
    assert result.receipt["asset_binding"] == {
        "tenant_ref": "TEN-" + hashlib.sha256(b"acme").hexdigest()[:24],
        "asset_id": ASSET,
        "asset_revision": 7,
        "asset_version_digest": ASSET_DIGEST,
    }
    assert raw not in json.dumps(result.receipt)


def test_secret_and_pii_are_composed_into_one_redacted_release(_isolate):
    _configure(_isolate)
    raw = f"Email {EMAIL}; token {SECRET}"
    with tenant_scope(tenant="acme"):
        result = _service().evaluate(_request(raw, stage="output"))

    assert result.decision == "redact"
    assert result.redacted_content is not None
    assert SECRET not in result.redacted_content
    assert EMAIL not in result.redacted_content
    assert "[REDACTED:openai_api_key]" in result.redacted_content
    assert "[REDACTED:email]" in result.redacted_content
    assert result.receipt["categories"] == ["privacy", "security"]
    assert result.receipt["rule_ids"] == [
        "pii/email",
        "secret/openai_api_key",
    ]
    assert result.receipt["output_sha256"] == hashlib.sha256(
        result.redacted_content.encode()
    ).hexdigest()


@pytest.mark.parametrize("stage", ["prompt", "output", "action"])
def test_shield_uses_the_stage_specific_surface_and_blocks(_isolate, stage):
    _configure(_isolate)
    shield = TrackingShield(blocked_stage=stage)
    changes = {}
    if stage == "output":
        changes["known_prompt"] = "system prompt"
    if stage == "action":
        changes.update(action_name="shell", action_arguments={"cmd": "whoami"})
    with tenant_scope(tenant="acme"):
        result = _service(shield=shield).evaluate(
            _request("transient body", stage=stage, **changes)
        )

    assert result.decision == "block"
    assert result.redacted_content is None
    assert result.receipt["rule_ids"] == [f"shield/{stage}/blocked"]
    assert result.receipt["output_sha256"] == hashlib.sha256(b"").hexdigest()
    assert shield.calls[0][0] == stage
    if stage == "output":
        assert shield.calls[0][2] == "system prompt"
    if stage == "action":
        assert shield.calls[0][1] == "shell"
        assert shield.calls[0][2]["arguments"] == {"cmd": "whoami"}


def test_action_digest_and_redaction_cover_name_content_and_arguments(_isolate):
    _configure(_isolate)
    request = _request(
        "send these values",
        stage="action",
        action_name="notify",
        action_arguments={"recipient": EMAIL, "token": SECRET},
    )
    with tenant_scope(tenant="acme"):
        result = _service().evaluate(request)

    assert result.decision == "redact"
    assert result.redacted_content is not None
    assert SECRET not in result.redacted_content
    assert EMAIL not in result.redacted_content
    assert '"action_name":"notify"' in result.redacted_content


@pytest.mark.parametrize(
    ("effect", "expected"),
    [("allow", "allow"), ("review", "review"), ("restrict", "restrict"), ("prohibit", "block")],
)
def test_policy_preview_maps_all_effects_and_binds_context(
    _isolate,
    effect,
    expected,
):
    _configure(_isolate, policy=True)
    policy = PolicyManager(effect)
    context = guardrails.RuntimePolicyContext(
        risk_tier="high",
        jurisdictions=("eu",),
        data_classes=("personal",),
        deployment_types=("production",),
        asset_types=("agent",),
        tags=("external",),
        use_case_tags=("support",),
    )
    with tenant_scope(tenant="acme"):
        result = _service(policy=policy).evaluate(
            _request(policy_context=context)
        )

    assert result.decision == expected
    assert result.receipt["rule_ids"] == [
        f"policy/runtime-policy/{effect}-rule"
    ]
    assert result.receipt["control_ids"] == ["human-approval", "runtime-log"]
    assert policy.contexts[0]["asset_id"] == ASSET
    assert policy.contexts[0]["risk_tier"] == "high"
    assert "Confidential policy prose" not in json.dumps(result.receipt)


def test_policy_default_review_and_strictest_wins_over_redaction(_isolate):
    _configure(_isolate, policy=True)
    policy = PolicyManager("review", statement=False)
    with tenant_scope(tenant="acme"):
        result = _service(policy=policy).evaluate(_request(EMAIL))

    assert result.decision == "review"
    assert result.redacted_content is None
    assert result.receipt["categories"] == ["policy", "privacy"]
    assert result.receipt["rule_ids"] == ["pii/email", "policy/default-review"]
    assert result.receipt["output_sha256"] == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("failure", ["factory", "preview"])
def test_enabled_policy_management_failure_fails_closed_without_error_leak(
    _isolate,
    failure,
):
    _configure(_isolate, policy=True)
    marker = "raw-sensitive-policy-error"

    class BrokenPolicy:
        def preview(self, _context):
            raise RuntimeError(marker)

    def broken_factory():
        if failure == "factory":
            raise RuntimeError(marker)
        return BrokenPolicy()

    service = guardrails.RuntimeGuardrails(
        shield_factory=AllowShield,
        policy_factory=broken_factory,
        clock=lambda: NOW,
    )
    with tenant_scope(tenant="acme"):
        result = service.evaluate(_request())

    assert result.decision == "block"
    assert result.receipt["rule_ids"] == ["policy-management/error"]
    assert marker not in json.dumps(result.receipt)


def test_disabled_policy_management_is_not_contacted(_isolate):
    _configure(_isolate, policy=False)

    def should_not_run():
        raise AssertionError("disabled policy authority was contacted")

    service = guardrails.RuntimeGuardrails(
        shield_factory=AllowShield,
        policy_factory=should_not_run,
        clock=lambda: NOW,
    )
    with tenant_scope(tenant="acme"):
        assert service.evaluate(_request()).decision == "allow"


def test_real_policy_management_preview_is_composed_through_its_stable_api(
    _isolate,
    monkeypatch,
):
    _configure(_isolate, policy=True)
    from maverick import ai_policy_management as apm
    from maverick import audit
    from maverick.governed_records import GovernedRecordStore

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    manager = apm.AIPolicyManagement(
        policies=GovernedRecordStore("runtime_test_policies", "AOP", "runtime_test"),
        exceptions=GovernedRecordStore("runtime_test_exceptions", "APX", "runtime_test"),
        evaluations=GovernedRecordStore("runtime_test_evaluations", "APE", "runtime_test"),
        clock=lambda: NOW,
    )
    with tenant_scope(tenant="acme"):
        draft = manager.create_policy(
            "runtime-restriction",
            title="Runtime restriction",
            statements=[{
                "statement_id": "high-risk-runtime",
                "text": "Restrict high-risk runtime processing.",
                "effect": "restrict",
                "applicability": {"risk_tiers": ["high"]},
                "required_control_ids": ["human-approval"],
            }],
            actor="user:author",
        )
        manager.activate_policy(
            "runtime-restriction",
            1,
            expected_revision=draft["revision"],
            actor="user:approver",
        )
        result = _service(policy=manager).evaluate(
            _request(policy_context=guardrails.RuntimePolicyContext(risk_tier="high"))
        )

    assert result.decision == "restrict"
    assert result.receipt["rule_ids"] == [
        "policy/runtime-restriction/high-risk-runtime"
    ]
    assert result.receipt["control_ids"] == ["human-approval"]


def test_default_shield_constructor_is_pinned_to_the_offline_backend():
    shield = guardrails._local_shield()
    assert shield.backend == shield.BACKEND_BUILTIN


def test_detector_and_shield_errors_fail_closed_with_safe_rules(_isolate, monkeypatch):
    _configure(_isolate)
    from maverick.safety import pii_detector, secret_detector

    marker = "sensitive detector exception"

    def fail(_text):
        raise RuntimeError(marker)

    monkeypatch.setattr(secret_detector, "redact", fail)
    monkeypatch.setattr(pii_detector, "redact", fail)

    class BrokenShield:
        def scan_input(self, _text):
            raise RuntimeError(marker)

    with tenant_scope(tenant="acme"):
        result = _service(shield=BrokenShield()).evaluate(_request())

    assert result.decision == "block"
    assert result.receipt["rule_ids"] == [
        "pii-detector/error",
        "secret-detector/error",
        "shield/prompt/error",
    ]
    assert marker not in json.dumps(result.receipt)


def test_oversize_redactor_output_fails_closed_instead_of_being_released(
    _isolate,
    monkeypatch,
):
    _configure(_isolate)
    from maverick.safety import secret_detector

    match = SimpleNamespace(name="openai_api_key")
    monkeypatch.setattr(
        secret_detector,
        "redact",
        lambda _text: ("x" * (guardrails.MAX_BODY_BYTES + 1), [match]),
    )
    with tenant_scope(tenant="acme"):
        result = _service().evaluate(_request("small body"))

    assert result.decision == "block"
    assert result.redacted_content is None
    assert "redacted-body/oversize" in result.receipt["rule_ids"]


def test_tenant_binding_changes_without_exposing_tenant_name(_isolate):
    _configure(_isolate)
    service = _service()
    with tenant_scope(tenant="acme-private-name"):
        acme = service.evaluate(_request()).receipt
    with tenant_scope(tenant="globex-private-name"):
        globex = service.evaluate(_request()).receipt

    assert acme["asset_binding"]["tenant_ref"] != globex["asset_binding"]["tenant_ref"]
    serialized = json.dumps([acme, globex])
    assert "acme-private-name" not in serialized
    assert "globex-private-name" not in serialized


def test_body_bounds_asset_binding_and_context_mismatch_are_safe(_isolate):
    _configure(_isolate)
    service = _service()
    with tenant_scope(tenant="acme"):
        with pytest.raises(guardrails.RuntimeGuardrailsInputError, match="byte limit"):
            service.evaluate(_request("x" * (guardrails.MAX_BODY_BYTES + 1)))
        with pytest.raises(guardrails.RuntimeGuardrailsInputError, match="exact asset"):
            service.evaluate(
                _request(policy_context={"asset_id": "MAA-" + "a" * 32})
            )
        with pytest.raises(guardrails.RuntimeGuardrailsInputError, match="asset_id"):
            service.evaluate(
                guardrails.RuntimeGuardrailInput(
                    stage="prompt",
                    content="safe",
                    asset=guardrails.RuntimeAssetBinding(
                        "asset-1", 1, ASSET_DIGEST
                    ),
                )
            )
        with pytest.raises(guardrails.RuntimeGuardrailsInputError, match="action_name"):
            service.evaluate(_request("safe", stage="action"))


def test_deterministic_order_digests_and_no_service_payload_retention(_isolate):
    _configure(_isolate)
    raw = f"{EMAIL} {SECRET}"
    service = _service()
    with tenant_scope(tenant="acme"):
        first = service.evaluate(_request(raw))
        second = service.evaluate(_request(raw))

    assert first == second
    assert first.receipt["categories"] == sorted(first.receipt["categories"])
    assert first.receipt["rule_ids"] == sorted(first.receipt["rule_ids"])
    assert raw not in repr(service.__dict__)
    assert raw not in json.dumps(first.receipt)
    assert SECRET not in repr(first)
    assert EMAIL not in repr(first)


def test_evaluation_performs_no_record_or_payload_writes(_isolate):
    _configure(_isolate)
    before = sorted(path.relative_to(_isolate) for path in _isolate.rglob("*"))
    with tenant_scope(tenant="acme"):
        result = _service().evaluate(_request(f"{EMAIL} {SECRET}"))
    after = sorted(path.relative_to(_isolate) for path in _isolate.rglob("*"))

    assert result.decision == "redact"
    assert after == before


def test_dynamic_risk_adapter_is_schema_exact_digest_closed_and_no_leak(_isolate):
    _configure(_isolate)
    raw = f"Contact {EMAIL}"
    with tenant_scope(tenant="acme"):
        result = _service().evaluate(_request(raw))
    normalized = guardrails.dynamic_risk_receipt(result, validity_seconds=600)

    assert set(normalized) == {
        "schema",
        "asset_id",
        "receipt_id",
        "signal_code",
        "severity",
        "confidence",
        "observed_at",
        "expires_at",
        "category",
        "receipt_sha256",
    }
    assert normalized["schema"] == ai_dynamic_risk.RUNTIME_RECEIPT_SCHEMA
    assert normalized["category"] == "privacy"
    assert normalized["severity"] == 35.0
    assert normalized["expires_at"] == NOW + 600
    signal = ai_dynamic_risk.signal_from_runtime_receipt(normalized)
    assert signal.asset_id == ASSET
    assert signal.category == "privacy"
    assert raw not in json.dumps(normalized)


def test_dynamic_risk_adapter_rejects_mutated_or_unbounded_result(_isolate):
    _configure(_isolate)
    with tenant_scope(tenant="acme"):
        result = _service().evaluate(_request())
    result.receipt["raw_content"] = "must never be admitted"
    with pytest.raises(guardrails.RuntimeGuardrailsInputError, match="malformed"):
        guardrails.dynamic_risk_receipt(result)
    with pytest.raises(guardrails.RuntimeGuardrailsInputError, match="validity"):
        guardrails.dynamic_risk_receipt(result, validity_seconds=59)

    with tenant_scope(tenant="acme"):
        nested = _service().evaluate(_request())
    nested.receipt["asset_binding"]["raw_content"] = "must never be admitted"
    with pytest.raises(guardrails.RuntimeGuardrailsInputError, match="binding"):
        guardrails.dynamic_risk_receipt(nested)
