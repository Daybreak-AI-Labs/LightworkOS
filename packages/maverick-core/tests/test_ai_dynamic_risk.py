"""Focused contracts for tenant-governed dynamic AI risk scoring."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest
from maverick import ai_dynamic_risk as risk
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

    def advance(self, seconds: float) -> None:
        self.value += seconds


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
        "[ai_dynamic_risk]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _stores(label: str):
    return (
        GovernedRecordStore(
            f"test_dynamic_risk_signals_{label}",
            "DRS",
            "test_dynamic_risk_signal",
        ),
        GovernedRecordStore(
            f"test_dynamic_risk_snapshots_{label}",
            "DRP",
            "test_dynamic_risk_snapshot",
        ),
    )


def _service(label: str = "main"):
    signals, snapshots = _stores(label)
    clock = ManualClock()
    registry = AssetRegistry()
    service = risk.DynamicRiskService(
        signals=signals,
        snapshots=snapshots,
        asset_lookup=registry,
        clock=clock,
    )
    return service, clock, registry, signals, snapshots


def _actor(kind: str = "human") -> risk.RiskActor:
    if kind == "human":
        return risk.RiskActor("human", "user:risk-owner@example.test")
    return risk.RiskActor("system", "system:production-monitor")


def _context(**overrides: str) -> risk.RiskContext:
    values = {
        "asset_criticality": "low",
        "eu_risk_tier": "minimal",
        "sensitive_data": "none",
        "external_exposure": "internal",
    }
    values.update(overrides)
    return risk.RiskContext(**values)


def _signal(
    *,
    category: str = "safety",
    severity: float = 60.0,
    confidence: float = 0.5,
    source_type: str = "telemetry",
    source_id: str = "window-001",
    source_digest: str | None = None,
    signal_code: str = "threshold_exceeded",
    idempotency_key: str = "signal-001",
    observed_at: float = NOW,
    expires_at: float = NOW + 3600,
    asset_id: str = ASSET,
) -> risk.RiskSignal:
    return risk.RiskSignal(
        asset_id=asset_id,
        category=category,
        severity=severity,
        confidence=confidence,
        observed_at=observed_at,
        expires_at=expires_at,
        source_type=source_type,
        source_id=source_id,
        source_digest=source_digest or _hex(source_id),
        signal_code=signal_code,
        idempotency_key=idempotency_key,
    )


def _normalized_receipt(schema: str, *, category: str, receipt_id: str):
    payload = {
        "schema": schema,
        "asset_id": ASSET,
        "receipt_id": receipt_id,
        "signal_code": "normalized_threshold",
        "severity": 80.0,
        "confidence": 0.75,
        "observed_at": NOW,
        "expires_at": NOW + 3600,
        "category": category,
    }
    return {**payload, "receipt_sha256": _canonical_sha(payload)}


def test_feature_gate_is_explicit_default_off_and_fail_closed(_isolate):
    from maverick import config

    (_isolate / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert risk.enabled() is False
    service, *_ = _service("disabled")
    with tenant_scope(tenant="acme"):
        with pytest.raises(risk.DynamicRiskConfigError, match="disabled"):
            service.ingest_signal(_signal(), actor=_actor())

    (_isolate / "config.toml").write_text(
        "[ai_dynamic_risk]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert risk.enabled() is True


def test_signal_ingest_is_exact_asset_bound_idempotent_and_safe():
    service, _, registry, _, _ = _service("idempotency")
    with tenant_scope(tenant="acme"):
        first = service.ingest_signal(_signal(), actor=_actor())
        replay = service.ingest_signal(_signal(), actor=_actor("system"))
        assert replay == first
        assert first["asset_revision"] == registry.revision
        assert first["asset_version_digest"] == registry.digest
        assert first["source_digest"] == _hex("window-001")
        assert first["status"] == "active"
        serialized = json.dumps(first)
        assert "prompt" not in serialized
        assert "output" not in serialized
        assert "signal-001" not in serialized

        with pytest.raises(risk.DynamicRiskIdempotencyConflict, match="idempotency"):
            service.ingest_signal(
                replace(_signal(), severity=61.0),
                actor=_actor(),
            )

        with pytest.raises(risk.DynamicRiskAssetError, match="does not exist"):
            service.ingest_signal(
                replace(_signal(), asset_id="MAA-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                actor=_actor(),
            )


def test_actor_and_signal_bounds_are_enforced():
    service, *_ = _service("bounds")
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match="user:"):
            service.ingest_signal(
                _signal(),
                actor=risk.RiskActor("human", "system:not-a-human"),
            )
        with pytest.raises(ValueError, match="severity"):
            service.ingest_signal(
                replace(_signal(), severity=101.0),
                actor=_actor(),
            )
        with pytest.raises(ValueError, match="validity"):
            service.ingest_signal(
                replace(_signal(), expires_at=NOW + 10),
                actor=_actor(),
            )
        with pytest.raises(ValueError, match="SHA-256"):
            service.ingest_signal(
                replace(_signal(), source_digest="not-a-digest"),
                actor=_actor(),
            )


def test_governed_store_is_tenant_isolated():
    service, *_ = _service("tenants")
    with tenant_scope(tenant="acme"):
        acme = service.ingest_signal(_signal(), actor=_actor())
        assert len(service.list_signals(ASSET)) == 1
    with tenant_scope(tenant="globex"):
        assert service.list_signals(ASSET) == []
        globex = service.ingest_signal(
            replace(_signal(), severity=90.0),
            actor=_actor(),
        )
        assert globex["signal_id"] == acme["signal_id"]
        assert globex["severity"] == 90.0
    with tenant_scope(tenant="acme"):
        assert service.get_signal(acme["signal_id"])["severity"] == 60.0


def test_normalized_receipt_adapters_are_digest_closed_and_reject_raw_fields():
    drift = _normalized_receipt(
        risk.DRIFT_RECEIPT_SCHEMA,
        category="drift",
        receipt_id="drift-001",
    )
    policy = _normalized_receipt(
        risk.POLICY_RECEIPT_SCHEMA,
        category="policy",
        receipt_id="policy-001",
    )
    runtime = _normalized_receipt(
        risk.RUNTIME_RECEIPT_SCHEMA,
        category="privacy",
        receipt_id="runtime-001",
    )
    assert risk.signal_from_drift_receipt(drift).category == "drift"
    assert risk.signal_from_policy_receipt(policy).source_type == "policy_receipt"
    assert risk.signal_from_runtime_receipt(runtime).category == "privacy"

    tampered = dict(drift)
    tampered["severity"] = 81.0
    with pytest.raises(ValueError, match="digest"):
        risk.signal_from_drift_receipt(tampered)
    raw = {**drift, "raw_provider_json": {"prompt": "secret"}}
    with pytest.raises(ValueError, match="unexpected"):
        risk.signal_from_drift_receipt(raw)
    wrong_category = _normalized_receipt(
        risk.DRIFT_RECEIPT_SCHEMA,
        category="safety",
        receipt_id="drift-002",
    )
    with pytest.raises(ValueError, match="must be drift"):
        risk.signal_from_drift_receipt(wrong_category)


def test_deterministic_formula_lists_every_contribution_and_strictest_floor():
    service, _, _, _, _ = _service("formula")
    with tenant_scope(tenant="acme"):
        first = service.ingest_signal(
            _signal(
                category="quality",
                severity=80.0,
                confidence=0.5,
                source_id="quality-window",
                idempotency_key="quality-signal",
            ),
            actor=_actor("system"),
        )
        second = service.ingest_signal(
            _signal(
                category="safety",
                severity=20.0,
                confidence=1.0,
                source_id="safety-window",
                idempotency_key="safety-signal",
            ),
            actor=_actor("system"),
        )
        report = service.score_asset(
            ASSET,
            context=_context(
                asset_criticality="medium",
                eu_risk_tier="limited",
                sensitive_data="personal",
                external_exposure="partner",
            ),
            expected_revision=0,
            actor=_actor(),
        )

        assert report["formula_version"] == risk.FORMULA_VERSION
        assert report["signal_score"] == 52.0
        assert report["context_floor"] == 40.0
        assert report["score"] == 52.0
        assert report["risk_tier"] == "high"
        assert {row["signal_id"] for row in report["contributions"]} == {
            first["signal_id"],
            second["signal_id"],
        }
        quality = next(
            row for row in report["contributions"] if row["category"] == "quality"
        )
        assert quality["category_weight"] == risk.CATEGORY_WEIGHTS["quality"]
        assert quality["points"] == 32.0
        assert quality["freshness"] == "fresh"
        assert report["change"]["direction"] == "initial"

        replay = service.score_asset(
            ASSET,
            context=_context(
                asset_criticality="medium",
                eu_risk_tier="limited",
                sensitive_data="personal",
                external_exposure="partner",
            ),
            expected_revision=report["snapshot_revision"],
            actor=_actor(),
        )
        assert replay["score"] == report["score"]
        assert replay["contributions"] == report["contributions"]
        assert replay["change"]["direction"] == "unchanged"
        assert replay["trend"]["direction"] == "unchanged"


def test_context_floor_is_strictest_wins_and_context_is_closed():
    service, *_ = _service("floors")
    with tenant_scope(tenant="acme"):
        report = service.score_asset(
            ASSET,
            context=_context(
                asset_criticality="critical",
                eu_risk_tier="high",
                sensitive_data="special_category",
                external_exposure="public",
            ),
            expected_revision=0,
            actor=_actor(),
        )
        assert report["signal_score"] == 0.0
        assert report["context_floor"] == 80.0
        assert report["score"] == 80.0
        assert report["risk_tier"] == "critical"

        with pytest.raises(ValueError, match="eu_risk_tier"):
            service.score_asset(
                OTHER_ASSET,
                context=_context(eu_risk_tier="unknown"),
                expected_revision=0,
                actor=_actor(),
            )


def test_expired_signal_is_removed_with_attributable_change():
    service, clock, _, _, _ = _service("expiry")
    with tenant_scope(tenant="acme"):
        signal = service.ingest_signal(
            _signal(
                severity=80.0,
                confidence=1.0,
                expires_at=NOW + 60,
            ),
            actor=_actor("system"),
        )
        first = service.score_asset(
            ASSET,
            context=_context(),
            expected_revision=0,
            actor=_actor("system"),
        )
        assert first["score"] == 80.0
        clock.advance(61)
        stale = service.current_score(ASSET)
        assert stale["snapshot_fresh"] is False
        assert stale["stale_reasons"] == ["signal_expired_since_evaluation"]
        second = service.score_asset(
            ASSET,
            context=_context(),
            expected_revision=first["snapshot_revision"],
            actor=_actor("system"),
        )
        assert second["score"] == 0.0
        assert second["active_signal_count"] == 0
        assert second["excluded_signals"] == [{
            "signal_id": signal["signal_id"],
            "category": "safety",
            "reason": "expired",
            "age_seconds": 61.0,
            "expires_in_seconds": -1.0,
            "freshness": "expired",
        }]
        assert second["change"]["direction"] == "improved"
        assert second["change"]["removed_signals"] == [{
            "signal_id": signal["signal_id"],
            "reason": "expired",
        }]


def test_asset_version_change_makes_old_signal_stale_not_silently_active():
    service, _, registry, _, _ = _service("asset-change")
    with tenant_scope(tenant="acme"):
        signal = service.ingest_signal(_signal(), actor=_actor())
        registry.change_version()
        report = service.score_asset(
            ASSET,
            context=_context(),
            expected_revision=0,
            actor=_actor(),
        )
        assert report["score"] == 0.0
        assert report["active_signal_count"] == 0
        excluded = report["excluded_signals"][0]
        assert excluded["signal_id"] == signal["signal_id"]
        assert excluded["reason"] == "asset_version_changed"
        assert excluded["freshness"] == "stale_binding"


def test_resolution_is_cas_governed_and_removes_signal_from_score():
    service, _, _, _, _ = _service("resolution")
    with tenant_scope(tenant="acme"):
        signal = service.ingest_signal(_signal(), actor=_actor())
        before = service.score_asset(
            ASSET,
            context=_context(),
            expected_revision=0,
            actor=_actor(),
        )
        with pytest.raises(RecordConflict):
            service.resolve_signal(
                signal["signal_id"],
                expected_revision=signal["revision"] + 1,
                resolution_code="mitigation_verified",
                resolution_evidence_digest=_hex("resolution"),
                actor=_actor(),
            )
        resolved = service.resolve_signal(
            signal["signal_id"],
            expected_revision=signal["revision"],
            resolution_code="mitigation_verified",
            resolution_evidence_digest=_hex("resolution"),
            actor=_actor(),
        )
        assert resolved["status"] == "resolved"
        assert resolved["resolution"]["evidence_digest"] == _hex("resolution")
        stale = service.current_score(ASSET)
        assert stale["snapshot_fresh"] is False
        assert stale["stale_reasons"] == ["signal_state_changed_since_evaluation"]
        report = service.score_asset(
            ASSET,
            context=_context(),
            expected_revision=before["snapshot_revision"],
            actor=_actor(),
        )
        assert report["contributions"] == []
        assert report["excluded_signals"][0]["reason"] == "resolved"


def test_supersession_is_cas_governed_and_strictly_bound_to_replacement():
    service, clock, _, _, _ = _service("supersession")
    with tenant_scope(tenant="acme"):
        old = service.ingest_signal(_signal(), actor=_actor("system"))
        clock.advance(10)
        replacement = service.ingest_signal(
            _signal(
                severity=20.0,
                observed_at=NOW + 10,
                expires_at=NOW + 3610,
                source_id="window-002",
                idempotency_key="signal-002",
            ),
            actor=_actor("system"),
        )
        with pytest.raises(RecordConflict):
            service.supersede_signal(
                old["signal_id"],
                superseding_signal_id=replacement["signal_id"],
                expected_revision=old["revision"] + 1,
                actor=_actor("system"),
            )
        superseded = service.supersede_signal(
            old["signal_id"],
            superseding_signal_id=replacement["signal_id"],
            expected_revision=old["revision"],
            actor=_actor("system"),
        )
        assert superseded["status"] == "superseded"
        assert (
            superseded["supersession"]["superseding_payload_sha256"]
            == replacement["payload_sha256"]
        )
        report = service.score_asset(
            ASSET,
            context=_context(),
            expected_revision=0,
            actor=_actor("system"),
        )
        assert [row["signal_id"] for row in report["contributions"]] == [
            replacement["signal_id"]
        ]
        assert report["excluded_signals"][0]["reason"] == "superseded"


def test_snapshot_change_and_trend_history_are_bounded():
    service, clock, _, _, _ = _service("history")
    with tenant_scope(tenant="acme"):
        current_revision = 0
        report = None
        for index in range(70):
            report = service.score_asset(
                ASSET,
                context=_context(
                    external_exposure=("internal" if index % 2 == 0 else "partner")
                ),
                expected_revision=current_revision,
                actor=_actor("system"),
            )
            current_revision = report["snapshot_revision"]
            clock.advance(1)
        assert report is not None
        assert len(report["history"]) == 64
        assert len(report["trend"]["points"]) == 64
        assert report["trend"]["bounded_to"] == 64
        assert report["change"]["context_floor_change"] in {-30.0, 30.0}


def test_malformed_governed_snapshot_fails_closed():
    service, _, _, _, snapshots = _service("malformed")
    with tenant_scope(tenant="acme"):
        report = service.score_asset(
            ASSET,
            context=_context(),
            expected_revision=0,
            actor=_actor(),
        )

        def corrupt(row):
            row["current"]["score"] = 999.0

        snapshots.update(
            report["snapshot_id"],
            corrupt,
            expected_revision=report["snapshot_revision"],
            action="test_corrupt_snapshot",
            actor="user:test",
        )
        with pytest.raises(risk.DynamicRiskStateError, match="malformed"):
            service.current_score(ASSET)
