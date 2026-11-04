from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from maverick import ai_governance_loop as loop
from maverick_dashboard import ai_governance_loop_composition as composition

TENANT = "tenant-loop"
OTHER_TENANT = "tenant-other"
ASSET = "MAA-0123456789abcdef0123456789abcdef"
NOW = 1_800_000_000.0


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def config(**overrides: object) -> dict[str, object]:
    section = {
        "enable": True,
        "poll_seconds": 30,
        "batch_size": 5,
        "lease_seconds": 60,
        "max_attempts": 4,
        "retry_base_seconds": 2,
        "max_lag_seconds": 300,
        **overrides,
    }
    return {
        "ai_inventory": {"enable": True},
        "ai_dynamic_risk": {"enable": True},
        "ai_policy_management": {"enable": True},
        "ai_runtime_guardrails": {"enable": True},
        "ai_governance_loop": section,
    }


def pin(name: str, *, tenant: str = TENANT) -> loop.AuthorityPin:
    return loop.AuthorityPin(
        tenant_id=tenant,
        asset_id=ASSET,
        record_id=f"{name}-record",
        revision=1,
        sha256=digest(f"{tenant}:{ASSET}:{name}"),
    )


def snapshot(*, policy: str = "restrict", enforcement: str = "not_applicable"):
    return loop.AuthoritySnapshot(
        tenant_id=TENANT,
        asset_id=ASSET,
        inventory=pin("inventory"),
        declaration=pin("declaration"),
        risk=pin("risk"),
        policy=pin("policy"),
        enforcement=pin("enforcement"),
        evidence=pin("evidence"),
        declaration_approved=True,
        risk_current=True,
        policy_current=True,
        policy_decision=policy,
        enforcement_decision=enforcement,
        evidence_complete=True,
        limitations=(),
        captured_at=NOW,
    )


class Reader:
    def __init__(self) -> None:
        self.reads: list[tuple[str, str]] = []

    def read_snapshot(self, *, tenant_id: str, asset_id: str):
        self.reads.append((tenant_id, asset_id))
        return snapshot()


def trigger(*, tenant: str = TENANT) -> loop.GovernanceTrigger:
    return loop.GovernanceTrigger(
        tenant_id=tenant,
        asset_id=ASSET,
        code="policy_changed",
        source_revision=1,
        source_sha256=digest(f"trigger:{tenant}"),
        occurred_at=NOW,
    )


def test_settings_are_exact_default_off_dependency_complete_and_bounded() -> None:
    assert composition.governance_loop_settings({}) is None
    disabled = config(enable=False)
    assert composition.governance_loop_settings(disabled) is None
    exact = composition.governance_loop_settings(config())
    assert exact is not None
    assert exact.batch_size == 5
    assert exact.max_attempts == 4

    for dependency in (
        "ai_inventory",
        "ai_dynamic_risk",
        "ai_policy_management",
        "ai_runtime_guardrails",
    ):
        malformed = config()
        malformed[dependency] = {"enable": False}
        with pytest.raises(composition.AIGovernanceLoopCompositionError, match=dependency):
            composition.governance_loop_settings(malformed)

    with pytest.raises(composition.AIGovernanceLoopCompositionError, match="unsupported"):
        composition.governance_loop_settings(config(raw_telemetry=True))
    with pytest.raises(composition.AIGovernanceLoopCompositionError, match="boolean"):
        composition.governance_loop_settings(config(enable=1))
    for key, value in (
        ("poll_seconds", 4),
        ("batch_size", 501),
        ("lease_seconds", 3_601),
        ("max_attempts", 21),
        ("retry_base_seconds", 0),
        ("max_lag_seconds", 0),
    ):
        with pytest.raises(composition.AIGovernanceLoopCompositionError, match="bound"):
            composition.governance_loop_settings(config(**{key: value}))


def test_builder_requires_injected_reader_and_bypasses_only_verified_gate(
    tmp_path: Path,
) -> None:
    with pytest.raises(composition.AIGovernanceLoopCompositionError, match="disabled"):
        composition.build_ai_governance_loop_runtime(
            tenant_id=TENANT,
            principal_ref="operator-one",
            authority_reader_factory=lambda **_kwargs: Reader(),
            config=config(enable=False),
            store_path=tmp_path / "disabled.sqlite3",
            clock=lambda: NOW,
        )
    assert not (tmp_path / "disabled.sqlite3").exists()

    with pytest.raises(composition.AIGovernanceLoopCompositionError, match="factory"):
        composition.build_ai_governance_loop_runtime(
            tenant_id=TENANT,
            principal_ref="operator-one",
            authority_reader_factory=None,  # type: ignore[arg-type]
            config=config(),
            store_path=tmp_path / "missing-reader.sqlite3",
            clock=lambda: NOW,
        )
    assert not (tmp_path / "missing-reader.sqlite3").exists()

    calls: list[dict[str, object]] = []
    reader = Reader()

    def factory(**kwargs):
        calls.append(kwargs)
        return reader

    runtime = composition.build_ai_governance_loop_runtime(
        tenant_id=TENANT,
        principal_ref="operator-one",
        authority_reader_factory=factory,
        config=config(),
        store_path=tmp_path / "runtime.sqlite3",
        clock=lambda: NOW,
    )
    assert runtime.status()["authority_reader_injected"] is True
    assert calls == [
        {
            "tenant_id": TENANT,
            "principal_ref": "operator-one",
            "request": None,
        }
    ]


def test_server_trigger_batch_human_control_and_audit_projection_are_closed(
    tmp_path: Path,
) -> None:
    projected: list[dict[str, object]] = []

    def sink(*, tenant_id, source_id, events):
        projected.append(
            {
                "tenant_id": tenant_id,
                "source_id": source_id,
                "events": events,
            }
        )

    reader = Reader()
    runtime = composition.build_ai_governance_loop_runtime(
        tenant_id=TENANT,
        principal_ref="human-reviewer",
        authority_reader_factory=lambda **_kwargs: reader,
        config=config(),
        store_path=tmp_path / "runtime.sqlite3",
        projection_sink=sink,
        clock=lambda: NOW,
    )
    queued = runtime.ingest_server_trigger(trigger(), operation_id="source-event-1")
    assert queued["state"] == "queued"
    result = runtime.run_batch(worker_id="worker-one", limit=5)
    assert result.processed == 1
    assert result.failed == 0
    assert reader.reads == [(TENANT, ASSET), (TENANT, ASSET)]
    current = runtime.get_case(ASSET)
    assert current["state"] == "escalated"

    authorized = runtime.authorize_control(
        ASSET,
        decision="restrict",
        reason_sha256=digest("approved-by-counsel"),
        expected_revision=current["revision"],
        operation_id="human-control-1",
    )
    assert authorized["state"] == "control_pending"
    assert authorized["control_authorization_sha256"] != digest("approved-by-counsel")
    assert projected
    assert all(item["tenant_id"] == TENANT for item in projected)
    assert all(item["source_id"] == "ai_governance" for item in projected)
    events = projected[-1]["events"]
    assert events
    assert all(type(event) is loop.UnifiedAuditProjectionEvent for event in events)
    assert "approved-by-counsel" not in repr(projected)

    with pytest.raises(loop.AIGovernanceLoopValidationError, match="closed"):
        runtime.ingest_server_trigger(  # type: ignore[arg-type]
            {"raw_telemetry": "secret"},
            operation_id="poisoned-trigger",
        )
    with pytest.raises(loop.AIGovernanceLoopValidationError, match="tenant"):
        runtime.ingest_server_trigger(
            trigger(tenant=OTHER_TENANT),
            operation_id="cross-tenant-trigger",
        )


def test_principal_is_bound_into_authorization_and_idempotency(tmp_path: Path) -> None:
    reader = Reader()

    def build(principal: str, name: str):
        runtime = composition.build_ai_governance_loop_runtime(
            tenant_id=TENANT,
            principal_ref=principal,
            authority_reader_factory=lambda **_kwargs: reader,
            config=config(),
            store_path=tmp_path / name,
            clock=lambda: NOW,
        )
        runtime.ingest_server_trigger(trigger(), operation_id="source-event")
        runtime.run_batch(worker_id=f"worker-{principal}", limit=1)
        current = runtime.get_case(ASSET)
        return runtime.authorize_control(
            ASSET,
            decision="restrict",
            reason_sha256=digest("same-reason"),
            expected_revision=current["revision"],
            operation_id="same-operation",
        )

    first = build("reviewer-one", "one.sqlite3")
    second = build("reviewer-two", "two.sqlite3")
    assert first["control_authorization_sha256"] != second["control_authorization_sha256"]
    assert first["last_operation_sha256"] != second["last_operation_sha256"]


def test_install_is_lazy_and_server_factories_fail_closed_without_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    composition.install_ai_governance_loop_composition(app)
    composition.install_ai_governance_loop_composition(app)
    assert app.state.ai_governance_loop_composition_installed is True
    assert callable(app.state.ai_governance_loop_runtime_factory)
    assert callable(app.state.ai_governance_loop_worker_factory)
    assert callable(app.state.ai_governance_loop_trigger_callback_factory)
    from maverick_dashboard.ai_governance_native_sources import factory as native_factory

    # The native retained authorities are the default reader, but nothing is
    # built until the loop is turned on.
    assert app.state.ai_governance_loop_authority_reader_factory is native_factory
    with pytest.raises(composition.AIGovernanceLoopCompositionError, match="disabled"):
        app.state.ai_governance_loop_runtime_factory(
            TENANT,
            "operator-one",
            SimpleNamespace(app=app),
        )
    # Turned on but with the authority reader removed, it still fails closed.
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: config())
    app.state.ai_governance_loop_authority_reader_factory = None
    with pytest.raises(composition.AIGovernanceLoopCompositionError, match="factory"):
        app.state.ai_governance_loop_runtime_factory(
            TENANT,
            "operator-one",
            SimpleNamespace(app=app),
        )

    app.state.ai_governance_loop_authority_reader_factory = lambda **_kwargs: Reader()
    callback = app.state.ai_governance_loop_trigger_callback_factory("inventory-authority")
    assert callable(callback)
