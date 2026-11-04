"""Focused contracts for tenant-governed, digest-only AI explanations."""
from __future__ import annotations

import hashlib
import json

import pytest
from maverick import ai_explainability as explain
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict

NOW = 1_800_000_000.0
ASSET = "MAA-0123456789abcdef0123456789abcdef"
OTHER_ASSET = "MAA-fedcba9876543210fedcba9876543210"


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _canonical_sha(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ManualClock:
    def __init__(self, value: float = NOW) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class AssetRegistry:
    def __init__(self) -> None:
        self.revision = 1
        self.digest = _hex("asset-v1")

    def __call__(self, asset_id: str):
        if asset_id not in {ASSET, OTHER_ASSET}:
            return None
        return {
            "asset_id": asset_id,
            "revision": self.revision,
            "version_digest": self.digest,
        }

    def change_version(self) -> None:
        self.revision += 1
        self.digest = _hex(f"asset-v{self.revision}")


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(
        "[ai_explainability]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _store(label: str) -> GovernedRecordStore:
    return GovernedRecordStore(
        f"test_ai_explanations_{label}",
        "AIX",
        "test_ai_explanation",
    )


def _service(label: str = "main"):
    store = _store(label)
    registry = AssetRegistry()
    clock = ManualClock()
    service = explain.ExplainabilityService(
        records=store,
        asset_lookup=registry,
        clock=clock,
    )
    return service, registry, clock, store


def _actor(principal: str = "user:explanation-owner@example.test"):
    return explain.ExplanationActor("human", principal)


def _system_actor():
    return explain.ExplanationActor("system", "system:explanation-normalizer")


def _contributions():
    return [
        {"factor_code": "income_ratio", "direction": "negative", "magnitude": 0.8},
        {"factor_code": "account_age", "direction": "positive", "magnitude": 0.5},
        {"factor_code": "prior_default", "direction": "negative", "magnitude": 0.6},
    ]


def _counterfactuals():
    return [
        {
            "change_code": "reduce_utilization",
            "outcome_code": "eligible",
            "distance": 0.2,
            "feasible": True,
        },
        {
            "change_code": "extend_history",
            "outcome_code": "eligible",
            "distance": 0.1,
            "feasible": False,
        },
    ]


def _receipt(
    method: str = "shap",
    *,
    receipt_id: str = "receipt-001",
    asset_id: str = ASSET,
    asset_revision: int = 1,
    asset_version_digest: str | None = None,
    contributions=None,
    counterfactuals=None,
    observed_at: float = NOW,
):
    if contributions is None:
        contributions = [] if method == "counterfactual" else _contributions()
    if counterfactuals is None:
        counterfactuals = _counterfactuals()
    payload = {
        "schema": explain.METHOD_RECEIPT_SCHEMAS[method],
        "method": method,
        "asset_id": asset_id,
        "asset_revision": asset_revision,
        "asset_version_digest": asset_version_digest or _hex("asset-v1"),
        "receipt_id": receipt_id,
        "observed_at": observed_at,
        "input_sha256": _hex("input-row-with-values-not-persisted"),
        "output_sha256": _hex("model-output-not-persisted"),
        "explainer_sha256": _hex(f"explainer:{method}"),
        "source_sha256": _hex("closed-normalizer-source"),
        "contributions": contributions,
        "counterfactuals": counterfactuals,
    }
    return {**payload, "receipt_sha256": _canonical_sha(payload)}


def _rehash(receipt):
    payload = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return {**payload, "receipt_sha256": _canonical_sha(payload)}


def test_feature_gate_is_explicit_default_off_and_tenant_is_required(_isolate):
    from maverick import config

    (_isolate / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert explain.enabled() is False
    service, *_ = _service("disabled")
    with tenant_scope(tenant="acme"):
        with pytest.raises(explain.ExplainabilityConfigError, match="disabled"):
            service.ingest_receipt(_receipt(), actor=_system_actor())

    (_isolate / "config.toml").write_text(
        "[ai_explainability]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert explain.enabled() is True
    with pytest.raises(explain.ExplainabilityStateError, match="explicit tenant"):
        service.ingest_receipt(_receipt(), actor=_system_actor())


@pytest.mark.parametrize(
    ("method", "adapter"),
    [
        ("native_additive", explain.explanation_from_native_additive_receipt),
        ("shap", explain.explanation_from_shap_receipt),
        ("lime", explain.explanation_from_lime_receipt),
        ("captum", explain.explanation_from_captum_receipt),
        ("alibi", explain.explanation_from_alibi_receipt),
        ("counterfactual", explain.explanation_from_counterfactual_receipt),
    ],
)
def test_all_provider_adapters_accept_only_their_closed_normalized_schema(
    method, adapter
):
    receipt = _receipt(method)
    normalized = adapter(receipt)
    generic = explain.explanation_from_receipt(receipt)
    assert normalized == generic
    assert normalized.method == method
    assert normalized.asset_revision == 1
    assert normalized.asset_version_digest == _hex("asset-v1")
    assert normalized.receipt_sha256 == receipt["receipt_sha256"]

    wrong = dict(receipt)
    wrong["method"] = "lime" if method != "lime" else "shap"
    with pytest.raises(ValueError, match="method|digest"):
        adapter(wrong)


def test_receipt_boundary_rejects_provider_payloads_raw_values_and_tampering():
    receipt = _receipt()
    with_raw_provider = {**receipt, "provider_payload": {"prompt": "secret"}}
    with pytest.raises(ValueError, match="unexpected"):
        explain.explanation_from_shap_receipt(with_raw_provider)

    raw_factor = dict(receipt)
    raw_factor["contributions"] = [
        {
            "factor_code": "income_ratio",
            "direction": "negative",
            "magnitude": 0.8,
            "raw_value": "123-45-6789",
        }
    ]
    raw_factor = _rehash(raw_factor)
    with pytest.raises(ValueError, match="closed normalized shape"):
        explain.explanation_from_shap_receipt(raw_factor)

    tampered = dict(receipt)
    tampered["output_sha256"] = _hex("different-output")
    with pytest.raises(ValueError, match="digest"):
        explain.explanation_from_shap_receipt(tampered)


@pytest.mark.parametrize(
    "receipt, message",
    [
        (
            lambda: _receipt(
                contributions=[
                    {
                        "factor_code": f"factor_{index}",
                        "direction": "positive",
                        "magnitude": 0.1,
                    }
                    for index in range(65)
                ]
            ),
            "cannot exceed 64",
        ),
        (
            lambda: _receipt(
                "counterfactual",
                counterfactuals=[
                    {
                        "change_code": f"change_{index}",
                        "outcome_code": "approved",
                        "distance": 0.2,
                        "feasible": True,
                    }
                    for index in range(17)
                ],
            ),
            "cannot exceed 16",
        ),
        (
            lambda: _receipt(
                contributions=[
                    {
                        "factor_code": "income_ratio",
                        "direction": "negative",
                        "magnitude": 1.1,
                    }
                ]
            ),
            "magnitude",
        ),
    ],
)
def test_contribution_and_counterfactual_bounds_are_enforced(receipt, message):
    with pytest.raises(ValueError, match=message):
        explain.explanation_from_receipt(receipt())


def test_ingest_is_exact_asset_bound_idempotent_and_public_projection_is_safe():
    service, _, _, store = _service("ingest")
    receipt = _receipt(receipt_id="sensitive-provider-receipt-id")
    with tenant_scope(tenant="acme"):
        first = service.ingest_receipt(receipt, actor=_system_actor())
        replay = service.ingest_receipt(receipt, actor=_actor())
        assert replay == first
        assert first["asset_revision"] == 1
        assert first["asset_version_digest"] == _hex("asset-v1")
        assert first["binding_current"] is True
        assert first["status"] == "pending_review"
        assert first["recorded_by_kind"] == "system"
        assert first["adverse_reasons"] == [
            "adverse.income_ratio",
            "adverse.prior_default",
        ]
        assert first["reason_codes"][0] == "explain.income_ratio.negative"
        assert first["counterfactual_projection"][0]["code"] == (
            "counterfactual.reduce_utilization.to.eligible"
        )
        assert "not a legal adverse-action notice" in first["disclaimer"]

        public_json = json.dumps(first)
        stored_json = json.dumps(store.list())
        for forbidden in (
            "sensitive-provider-receipt-id",
            "input-row-with-values-not-persisted",
            "model-output-not-persisted",
            "provider_payload",
            "raw_value",
        ):
            assert forbidden not in public_json
            assert forbidden not in stored_json
        assert "explanation-normalizer" not in public_json
        assert "tenant_ref" not in public_json


def test_idempotency_identity_conflicts_when_normalized_payload_changes():
    service, *_ = _service("idempotency")
    with tenant_scope(tenant="acme"):
        service.ingest_receipt(_receipt(), actor=_system_actor())
        changed = _receipt(
            contributions=[
                {
                    "factor_code": "income_ratio",
                    "direction": "negative",
                    "magnitude": 0.9,
                }
            ]
        )
        with pytest.raises(explain.ExplainabilityIdempotencyConflict, match="identity"):
            service.ingest_receipt(changed, actor=_system_actor())


def test_receipt_must_match_the_exact_current_model_risk_binding():
    service, _, _, _ = _service("binding")
    with tenant_scope(tenant="acme"):
        with pytest.raises(explain.ExplainabilityAssetError, match="current"):
            service.ingest_receipt(
                _receipt(asset_revision=2),
                actor=_system_actor(),
            )
        with pytest.raises(explain.ExplainabilityAssetError, match="current"):
            service.ingest_receipt(
                _receipt(asset_version_digest=_hex("other-artifact")),
                actor=_system_actor(),
            )
        with pytest.raises(explain.ExplainabilityAssetError, match="does not exist"):
            service.ingest_receipt(
                _receipt(asset_id="MAA-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                actor=_system_actor(),
            )


def test_governed_records_are_tenant_isolated_even_for_the_same_receipt_identity():
    service, *_ = _service("tenants")
    with tenant_scope(tenant="acme"):
        acme = service.ingest_receipt(_receipt(), actor=_system_actor())
        assert len(service.list_explanations()) == 1
    with tenant_scope(tenant="globex"):
        assert service.get_explanation(acme["explanation_id"]) is None
        globex = service.ingest_receipt(
            _receipt(
                contributions=[
                    {
                        "factor_code": "different_factor",
                        "direction": "positive",
                        "magnitude": 0.4,
                    }
                ]
            ),
            actor=_system_actor(),
        )
        assert globex["explanation_id"] != acme["explanation_id"]
        assert globex["reason_codes"] == ["explain.different_factor.positive"]
    with tenant_scope(tenant="acme"):
        assert service.get_explanation(acme["explanation_id"])["reason_codes"][0] == (
            "explain.income_ratio.negative"
        )


def test_review_is_human_cas_governed_and_requires_four_eyes():
    service, *_ = _service("review")
    owner = _actor("user:owner@example.test")
    reviewer = _actor("user:reviewer@example.test")
    with tenant_scope(tenant="acme"):
        admitted = service.ingest_receipt(_receipt(), actor=owner)
        with pytest.raises(explain.ExplainabilityStateError, match="different principal"):
            service.review_explanation(
                admitted["explanation_id"],
                expected_revision=admitted["revision"],
                outcome="accepted",
                evidence_sha256=_hex("review-evidence"),
                actor=owner,
            )
        with pytest.raises(ValueError, match="human"):
            service.review_explanation(
                admitted["explanation_id"],
                expected_revision=admitted["revision"],
                outcome="accepted",
                evidence_sha256=_hex("review-evidence"),
                actor=_system_actor(),
            )
        with pytest.raises(RecordConflict):
            service.review_explanation(
                admitted["explanation_id"],
                expected_revision=admitted["revision"] + 1,
                outcome="accepted",
                evidence_sha256=_hex("review-evidence"),
                actor=reviewer,
            )
        reviewed = service.review_explanation(
            admitted["explanation_id"],
            expected_revision=admitted["revision"],
            outcome="needs_remediation",
            evidence_sha256=_hex("review-evidence"),
            actor=reviewer,
        )
        assert reviewed["status"] == "reviewed"
        assert reviewed["review"]["outcome"] == "needs_remediation"
        assert reviewed["review"]["evidence_sha256"] == _hex("review-evidence")
        assert "reviewer@example.test" not in json.dumps(reviewed)
        with pytest.raises(explain.ExplainabilityStateError, match="already"):
            service.review_explanation(
                admitted["explanation_id"],
                expected_revision=reviewed["revision"],
                outcome="accepted",
                evidence_sha256=_hex("second-review"),
                actor=_actor("user:second-reviewer@example.test"),
            )


def test_model_artifact_change_marks_explanation_stale_and_blocks_review():
    service, registry, _, _ = _service("stale")
    with tenant_scope(tenant="acme"):
        admitted = service.ingest_receipt(_receipt(), actor=_system_actor())
        registry.change_version()
        stale = service.get_explanation(admitted["explanation_id"])
        assert stale["binding_current"] is False
        assert stale["stale_reasons"] == [
            "asset_revision_changed",
            "asset_version_digest_changed",
        ]
        assert stale["current_asset_revision"] == 2
        with pytest.raises(explain.ExplainabilityStateError, match="stale"):
            service.review_explanation(
                admitted["explanation_id"],
                expected_revision=admitted["revision"],
                outcome="accepted",
                evidence_sha256=_hex("review-evidence"),
                actor=_actor(),
            )


def test_malformed_or_tampered_governed_state_fails_closed():
    service, _, _, store = _service("tamper")
    with tenant_scope(tenant="acme"):
        admitted = service.ingest_receipt(_receipt(), actor=_system_actor())

        def corrupt(row):
            row["contributions"][0]["magnitude"] = 0.99

        store.update(
            admitted["explanation_id"],
            corrupt,
            expected_revision=admitted["revision"],
            action="test_corrupt_explanation",
            actor="user:test",
        )
        with pytest.raises(explain.ExplainabilityStateError, match="malformed"):
            service.get_explanation(admitted["explanation_id"])

    other_service, _, _, other_store = _service("malformed")
    with tenant_scope(tenant="acme"):
        second = other_service.ingest_receipt(_receipt(), actor=_system_actor())

        def inject_provider_payload(row):
            row["provider_payload"] = {"raw_output": "secret"}

        other_store.update(
            second["explanation_id"],
            inject_provider_payload,
            expected_revision=second["revision"],
            action="test_inject_provider_payload",
            actor="user:test",
        )
        with pytest.raises(explain.ExplainabilityStateError, match="shape"):
            other_service.get_explanation(second["explanation_id"])
