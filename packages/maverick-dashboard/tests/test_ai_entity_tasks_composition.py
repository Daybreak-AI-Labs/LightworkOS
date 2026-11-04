from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from maverick import ai_entity_tasks as tasks
from maverick_dashboard import ai_entity_tasks_composition as composition

NOW = 2_100_000_000.0
TENANT = "tenant-a"
ASSET_ID = "MAA-0123456789abcdef0123456789abcdef"


class Clock:
    def __init__(self, value: float = NOW) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _config(
    *,
    enabled: bool = True,
    inventory_enabled: bool = True,
    max_tasks: int = 100_000,
    retention_seconds: int = 3_600,
    authority_max_age_seconds: int = 10_000,
) -> dict[str, object]:
    return {
        "ai_inventory": {"enable": inventory_enabled},
        "ai_entity_tasks": {
            "enable": enabled,
            "max_tasks": max_tasks,
            "retention_seconds": retention_seconds,
            "authority_max_age_seconds": authority_max_age_seconds,
        },
    }


def _asset(
    *,
    revision: int = 7,
    status: str = "present",
    updated_at: float = NOW - 5,
    version_seed: str = "version-a",
) -> dict[str, object]:
    return {
        "asset_id": ASSET_ID,
        "revision": revision,
        "asset_type": "model",
        "connector": "bedrock",
        "source": "aws_bedrock",
        "source_id": "arn:aws:bedrock:us-east-1:123:model/support",
        "version_digest": hashlib.sha256(version_seed.encode()).hexdigest(),
        "observation_revision": 3,
        "observation_snapshot_sha256": hashlib.sha256(
            f"snapshot:{version_seed}".encode()
        ).hexdigest(),
        "updated_at": updated_at,
        "status": status,
    }


def _request(
    app: FastAPI,
    *,
    subject: str = "user:operator",
) -> Request:
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/api/v1/ai-entity-tasks",
            "raw_path": b"/api/v1/ai-entity-tasks",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("127.0.0.1", 443),
            "app": app,
        }
    )
    request.state.principal = SimpleNamespace(principal=subject)
    return request


def _install_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    config: dict[str, object] | None = None,
    assets: list[dict[str, object]] | None = None,
) -> tuple[FastAPI, Request, Clock]:
    selected_config = config or _config()
    selected_assets = assets if assets is not None else [_asset()]
    clock = Clock()
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: selected_config,
    )
    monkeypatch.setattr(
        composition.inventory,
        "list_discovered_assets",
        lambda: [dict(row) for row in selected_assets],
    )
    monkeypatch.setattr(composition.inventory, "enabled", lambda: True)
    monkeypatch.setattr(
        composition,
        "data_dir",
        lambda *parts, tenant: tmp_path / tenant / Path(*parts),
    )
    app = FastAPI()
    app.state.ai_entity_tasks_clock = clock
    composition.install_ai_entity_tasks_composition(app)
    return app, _request(app), clock


def test_settings_are_default_off_closed_and_exactly_bounded() -> None:
    assert composition.ai_entity_tasks_settings({}) is None
    assert composition.ai_entity_tasks_settings(
        {"ai_entity_tasks": {"enable": False}}
    ) is None

    selected = composition.ai_entity_tasks_settings(_config())
    assert selected == composition.AIEntityTasksCompositionSettings(
        max_tasks=100_000,
        retention_seconds=3_600,
        authority_max_age_seconds=10_000,
    )

    with pytest.raises(composition.AIEntityTasksCompositionError, match="require"):
        composition.ai_entity_tasks_settings(_config(inventory_enabled=False))
    with pytest.raises(composition.AIEntityTasksCompositionError, match="unknown"):
        invalid = _config()
        invalid["ai_entity_tasks"]["unsafe"] = True  # type: ignore[index]
        composition.ai_entity_tasks_settings(invalid)
    with pytest.raises(composition.AIEntityTasksCompositionError, match="max_tasks"):
        composition.ai_entity_tasks_settings(_config(max_tasks=True))
    with pytest.raises(composition.AIEntityTasksCompositionError, match="max_age"):
        composition.ai_entity_tasks_settings(
            _config(authority_max_age_seconds=31_536_001)
        )


def test_install_is_lazy_idempotent_and_wires_every_api_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    calls = {"config": 0, "inventory": 0, "path": 0}

    def no_config(_tenant: str):
        calls["config"] += 1
        raise AssertionError("installation loaded tenant configuration")

    def no_inventory():
        calls["inventory"] += 1
        raise AssertionError("installation read inventory")

    def no_path(*_args, **_kwargs):
        calls["path"] += 1
        raise AssertionError("installation resolved storage")

    monkeypatch.setattr(composition, "_load_tenant_config", no_config)
    monkeypatch.setattr(composition.inventory, "list_discovered_assets", no_inventory)
    monkeypatch.setattr(composition, "data_dir", no_path)
    composition.install_ai_entity_tasks_composition(app)
    seams = (
        "ai_entity_tasks_store_factory",
        "ai_entity_tasks_enabled_probe",
        "ai_entity_tasks_readiness_probe",
        "ai_entity_tasks_principal_resolver_factory",
        "ai_entity_tasks_maintenance_authorizer_factory",
        "ai_entity_tasks_entity_authority_resolver_factory",
        "ai_entity_tasks_store_path_factory",
    )
    first = {name: getattr(app.state, name) for name in seams}
    assert all(callable(value) for value in first.values())
    composition.install_ai_entity_tasks_composition(app)
    assert {name: getattr(app.state, name) for name in seams} == first
    assert calls == {"config": 0, "inventory": 0, "path": 0}


def test_readiness_is_default_off_and_never_opens_inventory_or_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = {"value": _config()}
    app = FastAPI()
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: selected["value"],
    )
    monkeypatch.setattr(composition.inventory, "enabled", lambda: True)
    monkeypatch.setattr(
        composition.inventory,
        "list_discovered_assets",
        lambda: (_ for _ in ()).throw(AssertionError("readiness read inventory")),
    )
    monkeypatch.setattr(
        composition,
        "data_dir",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("readiness opened storage")
        ),
    )
    app.state.ai_entity_tasks_clock = lambda: NOW
    composition.install_ai_entity_tasks_composition(app)
    assert app.state.ai_entity_tasks_enabled_probe(TENANT) is True
    assert app.state.ai_entity_tasks_readiness_probe(TENANT) is True

    selected["value"] = _config(enabled=False)
    assert app.state.ai_entity_tasks_enabled_probe(TENANT) is False
    assert app.state.ai_entity_tasks_readiness_probe(TENANT) is False


def test_inventory_authority_opens_tenant_store_with_exact_limits_and_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, request, clock = _install_environment(
        monkeypatch,
        tmp_path,
        config=_config(max_tasks=1),
    )
    monkeypatch.setattr(composition, "has_global_permission", lambda *_args: True)
    principal = composition._principal_ref_from_request(request, TENANT)
    settings = composition.settings_for_tenant(TENANT)
    resolver = app.state.ai_entity_tasks_entity_authority_resolver_factory(
        tenant_id=TENANT,
        settings=settings,
        request=request,
    )
    authority = resolver(TENANT, ASSET_ID, 7)
    assert authority.tenant_id == TENANT
    assert authority.entity_id == ASSET_ID
    assert authority.entity_revision == 7
    assert authority.entity_type == "model"
    assert authority.issuer_ref.startswith("ai-inventory:")
    assert len(authority.issuer_ref.removeprefix("ai-inventory:")) == 64
    assert authority.issued_at == NOW - 5
    assert authority.valid_until == NOW - 5 + 10_000

    store = app.state.ai_entity_tasks_store_factory(
        tenant_id=TENANT,
        principal_ref=principal,
        request=request,
    )
    assert store.path == tmp_path / TENANT / "ai_entity_tasks" / "ai-entity-tasks.sqlite3"
    created = store.create_task(
        TENANT,
        entity_id=ASSET_ID,
        entity_revision=7,
        kind="review",
        title="Review the inventory asset",
        idempotency_key="create-first",
    )
    assert created.entity_authority_sha256 == authority.authority_sha256
    with pytest.raises(tasks.AIEntityTaskConflict, match="quota"):
        store.create_task(
            TENANT,
            entity_id=ASSET_ID,
            entity_revision=7,
            kind="remediation",
            title="Second task exceeds the configured cap",
            idempotency_key="create-second",
        )
    closed = store.update_task(
        TENANT,
        created.task_id,
        expected_revision=1,
        changes={"status": "resolved"},
        idempotency_key="close-first",
    )
    clock.value += 3_601
    assert store.retention_due(TENANT) == (closed,)
    assert store.purge_expired(TENANT) == 1
    assert store.verify_integrity(TENANT)["tombstone_count"] == 1


def test_inventory_resolver_rejects_missing_stale_revision_and_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = [_asset()]
    app, request, _clock = _install_environment(
        monkeypatch,
        tmp_path,
        config=_config(authority_max_age_seconds=60),
        assets=assets,
    )
    settings = composition.settings_for_tenant(TENANT)
    resolver = app.state.ai_entity_tasks_entity_authority_resolver_factory(
        tenant_id=TENANT,
        settings=settings,
        request=request,
    )
    with pytest.raises(tasks.AIEntityTaskConflict, match="revision"):
        resolver(TENANT, ASSET_ID, 8)

    assets[0] = _asset(status="missing")
    with pytest.raises(tasks.AIEntityTaskConflict, match="revoked"):
        resolver(TENANT, ASSET_ID, 7)

    assets[0] = _asset(updated_at=NOW - 61)
    with pytest.raises(tasks.AIEntityTaskConflict, match="stale"):
        resolver(TENANT, ASSET_ID, 7)

    assets[0] = _asset()
    app.state.ai_entity_tasks_entity_revocation_probe = lambda **_kwargs: True
    with pytest.raises(tasks.AIEntityTaskConflict, match="revoked"):
        resolver(TENANT, ASSET_ID, 7)

    app.state.ai_entity_tasks_entity_revocation_probe = lambda **_kwargs: "yes"
    with pytest.raises(
        composition.AIEntityTasksCompositionError,
        match="revocation authority",
    ):
        resolver(TENANT, ASSET_ID, 7)


def test_core_double_resolution_detects_inventory_digest_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, request, _clock = _install_environment(monkeypatch, tmp_path)
    versions = iter(("version-a", "version-b"))
    monkeypatch.setattr(
        composition.inventory,
        "list_discovered_assets",
        lambda: [_asset(version_seed=next(versions))],
    )
    principal = composition._principal_ref_from_request(request, TENANT)
    store = app.state.ai_entity_tasks_store_factory(
        tenant_id=TENANT,
        principal_ref=principal,
        request=request,
    )
    with pytest.raises(tasks.AIEntityTaskConflict, match="authority changed"):
        store.create_task(
            TENANT,
            entity_id=ASSET_ID,
            entity_revision=7,
            kind="review",
            title="Reject a drifting inventory projection",
            idempotency_key="drift-create",
        )


def test_principal_is_re_resolved_from_app_request_and_tenants_are_isolated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, request, _clock = _install_environment(monkeypatch, tmp_path)
    principal = composition._principal_ref_from_request(request, TENANT)
    with pytest.raises(tasks.AIEntityTaskPermissionDenied):
        app.state.ai_entity_tasks_store_factory(
            tenant_id=TENANT,
            principal_ref="ai-task-principal-attacker",
            request=request,
        )

    store = app.state.ai_entity_tasks_store_factory(
        tenant_id=TENANT,
        principal_ref=principal,
        request=request,
    )
    request.state.principal = SimpleNamespace(principal="user:changed")
    with pytest.raises(tasks.AIEntityTaskPermissionDenied):
        store.create_task(
            TENANT,
            entity_id=ASSET_ID,
            entity_revision=7,
            kind="review",
            title="Identity drift is not admitted",
            idempotency_key="identity-drift",
        )

    request_b = _request(app, subject="user:tenant-b")
    principal_b = composition._principal_ref_from_request(request_b, "tenant-b")
    store_b = app.state.ai_entity_tasks_store_factory(
        tenant_id="tenant-b",
        principal_ref=principal_b,
        request=request_b,
    )
    assert store.path != store_b.path
    assert TENANT in store.path.parts
    assert "tenant-b" in store_b.path.parts


def test_explicit_deployment_factories_and_probes_are_composed_not_overwritten(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    sentinel = object()
    calls: list[tuple[str, str]] = []

    def store_factory(**_kwargs):
        return sentinel

    app.state.ai_entity_tasks_store_factory = store_factory
    app.state.ai_entity_tasks_enabled_probe = lambda tenant: (
        calls.append(("enabled", tenant)) or True
    )
    app.state.ai_entity_tasks_readiness_probe = lambda tenant: (
        calls.append(("ready", tenant)) or True
    )
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: _config())
    monkeypatch.setattr(composition.inventory, "enabled", lambda: True)
    app.state.ai_entity_tasks_clock = lambda: NOW
    composition.install_ai_entity_tasks_composition(app)

    assert app.state.ai_entity_tasks_store_factory is store_factory
    assert app.state.ai_entity_tasks_enabled_probe(TENANT) is True
    assert app.state.ai_entity_tasks_readiness_probe(TENANT) is True
    assert calls == [
        ("enabled", TENANT),
        ("enabled", TENANT),
        ("ready", TENANT),
    ]
