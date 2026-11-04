from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import get_ident
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import config as config_module
from maverick import third_party_collaboration as collaboration
from maverick.paths import tenant_scope
from maverick_dashboard import third_party_collaboration_composition as composition

KEY = b"deployment-owned-routing-key-32-bytes-minimum"
NEXT_KEY = b"next-deployment-routing-key-also-32-bytes"


@dataclass(frozen=True)
class Tenant:
    id: str
    active: bool


class FakeStore:
    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.calls: list[tuple[Any, ...]] = []

    def contract_for_token(self, tenant_id: str, token: str) -> dict[str, str]:
        self.calls.append(("contract", tenant_id, token))
        return {"tenant_id": tenant_id}

    def verify_integrity(self, tenant_id: str) -> dict[str, str]:
        self.calls.append(("integrity", tenant_id))
        return {"tenant_id": tenant_id}


def _request(path: str) -> Request:
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": [],
            "client": ("198.51.100.10", 43123),
            "server": ("127.0.0.1", 80),
        }
    )


@pytest.fixture()
def allow_policy(monkeypatch: pytest.MonkeyPatch):
    policy = collaboration.ThirdPartyCollaborationPolicy()
    loaded: list[str] = []

    def load(tenant_id: str):
        loaded.append(tenant_id)
        return policy

    monkeypatch.setattr(composition, "_load_tenant_policy", load)
    return policy, loaded


def test_attach_is_lazy_and_refs_are_opaque_stable_and_tenant_scoped(
    allow_policy,
) -> None:
    _policy, loaded = allow_policy
    tenants = [Tenant("tenant-a", True), Tenant("tenant-b", True)]
    builds: list[str] = []

    def build(*, tenant_id: str, **_kwargs: Any) -> FakeStore:
        builds.append(tenant_id)
        return FakeStore(tenant_id)

    app = FastAPI()
    composition.attach_third_party_collaboration_composition(
        app,
        routing_key_resolver=lambda: KEY,
        tenant_registry_resolver=lambda: tenants,
        store_builder=build,
    )

    assert builds == []
    portal_a = app.state.third_party_collaboration_portal_ref_for_tenant("tenant-a")
    repeated_a = app.state.third_party_collaboration_portal_ref_for_tenant("tenant-a")
    portal_b = app.state.third_party_collaboration_portal_ref_for_tenant("tenant-b")
    assert portal_a == repeated_a
    assert portal_a != portal_b
    assert portal_a.startswith("tpcp_")
    assert "tenant" not in portal_a
    assert len(portal_a) == 48
    with tenant_scope(tenant="tenant-a"):
        assert app.state.third_party_collaboration_current_portal_ref() == portal_a
    assert builds == []

    material_a = app.state.third_party_collaboration_portal_resolver(
        portal_a,
        _request(f"/api/v1/external/third-party-collaboration/{portal_a}/contract"),
    )
    material_b = app.state.third_party_collaboration_portal_resolver(
        portal_b,
        _request(f"/api/v1/external/third-party-collaboration/{portal_b}/contract"),
    )
    assert material_a.tenant_id == "tenant-a"
    assert material_b.tenant_id == "tenant-b"
    assert builds == []
    repeated_material_a = app.state.third_party_collaboration_portal_resolver(
        portal_a,
        _request(f"/api/v1/external/third-party-collaboration/{portal_a}/contract"),
    )
    assert repeated_material_a.store is material_a.store

    assert material_a.store.contract_for_token("tenant-a", "token") == {"tenant_id": "tenant-a"}
    assert repeated_material_a.store.contract_for_token("tenant-a", "other") == {
        "tenant_id": "tenant-a"
    }
    assert builds == ["tenant-a"]
    with pytest.raises(collaboration.ThirdPartyCollaborationPermissionDenied):
        material_a.store.contract_for_token("tenant-b", "token")
    assert set(loaded) == {"tenant-a", "tenant-b"}


def test_cached_external_store_rebuilds_when_policy_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = [collaboration.ThirdPartyCollaborationPolicy(max_artifacts=20)]
    builds: list[collaboration.ThirdPartyCollaborationPolicy] = []

    def load_policy(_tenant_id: str):
        return current[0]

    def build(*, tenant_id: str, policy, **_kwargs: Any) -> FakeStore:
        builds.append(policy)
        return FakeStore(tenant_id)

    monkeypatch.setattr(composition, "_load_tenant_policy", load_policy)
    app = FastAPI()
    composition.attach_third_party_collaboration_composition(
        app,
        routing_key_resolver=lambda: KEY,
        tenant_registry_resolver=lambda: [Tenant("tenant-a", True)],
        store_builder=build,
    )
    portal = composition.derive_third_party_collaboration_portal_ref("tenant-a", KEY)
    material = app.state.third_party_collaboration_portal_resolver(
        portal,
        _request(f"/api/v1/external/third-party-collaboration/{portal}/contract"),
    )
    material.store.contract_for_token("tenant-a", "one")
    current[0] = collaboration.ThirdPartyCollaborationPolicy(max_artifacts=1)
    material.store.contract_for_token("tenant-a", "two")

    assert [policy.max_artifacts for policy in builds] == [20, 1]


def test_missing_or_short_routing_key_fails_closed_without_store(
    monkeypatch: pytest.MonkeyPatch,
    allow_policy,
) -> None:
    monkeypatch.delenv(composition.ROUTING_KEY_ENV, raising=False)
    builds: list[str] = []
    app = FastAPI()
    composition.attach_third_party_collaboration_composition(
        app,
        tenant_registry_resolver=lambda: [Tenant("tenant-a", True)],
        store_builder=lambda **kwargs: builds.append(kwargs["tenant_id"]),
    )

    with pytest.raises(composition.ThirdPartyCollaborationCompositionError):
        app.state.third_party_collaboration_portal_ref_for_tenant("tenant-a")
    opaque = composition.derive_third_party_collaboration_portal_ref("tenant-a", KEY)
    with pytest.raises(composition.ThirdPartyCollaborationCompositionError):
        app.state.third_party_collaboration_portal_resolver(
            opaque,
            _request(f"/api/v1/external/third-party-collaboration/{opaque}/contract"),
        )
    with pytest.raises(composition.ThirdPartyCollaborationCompositionError):
        composition.derive_third_party_collaboration_portal_ref(
            "tenant-a",
            b"too-short",
        )
    assert builds == []


def test_suspended_tenant_ref_is_not_resolvable(allow_policy) -> None:
    opaque = composition.derive_third_party_collaboration_portal_ref("tenant-a", KEY)
    app = FastAPI()
    composition.attach_third_party_collaboration_composition(
        app,
        routing_key_resolver=lambda: KEY,
        tenant_registry_resolver=lambda: [Tenant("tenant-a", False)],
    )

    with pytest.raises(composition.ThirdPartyCollaborationCompositionError):
        app.state.third_party_collaboration_portal_ref_for_tenant("tenant-a")
    with pytest.raises(composition.ThirdPartyCollaborationCompositionError):
        app.state.third_party_collaboration_portal_resolver(
            opaque,
            _request(f"/api/v1/external/third-party-collaboration/{opaque}/contract"),
        )


def test_routing_keyring_supports_explicit_grace_and_retirement(allow_policy) -> None:
    keyring = [
        composition.ThirdPartyCollaborationRoutingKeyring(
            revision="key-v1",
            current=KEY,
        )
    ]
    app = FastAPI()
    composition.attach_third_party_collaboration_composition(
        app,
        routing_key_resolver=lambda: keyring[0],
        tenant_registry_resolver=lambda: [Tenant("tenant-a", True)],
        routing_clock=lambda: 100.0,
    )
    old_ref = composition.derive_third_party_collaboration_portal_ref("tenant-a", KEY)
    new_ref = composition.derive_third_party_collaboration_portal_ref(
        "tenant-a",
        NEXT_KEY,
    )
    request = _request(f"/api/v1/external/third-party-collaboration/{old_ref}/contract")
    assert app.state.third_party_collaboration_portal_resolver(old_ref, request).tenant_id == (
        "tenant-a"
    )

    keyring[0] = composition.ThirdPartyCollaborationRoutingKeyring(
        revision="key-v2-grace",
        current=NEXT_KEY,
        previous=(KEY,),
    )
    assert app.state.third_party_collaboration_portal_resolver(old_ref, request).tenant_id == (
        "tenant-a"
    )
    assert app.state.third_party_collaboration_portal_resolver(new_ref, request).tenant_id == (
        "tenant-a"
    )

    keyring[0] = composition.ThirdPartyCollaborationRoutingKeyring(
        revision="key-v3-retired",
        current=NEXT_KEY,
    )
    with pytest.raises(composition.ThirdPartyCollaborationCompositionError):
        app.state.third_party_collaboration_portal_resolver(old_ref, request)
    assert app.state.third_party_collaboration_portal_resolver(new_ref, request).tenant_id == (
        "tenant-a"
    )


def test_routing_index_scans_roster_once_per_bound_cache_window(allow_policy) -> None:
    tenants = [Tenant(f"tenant-{index}", True) for index in range(10_000)]
    registry_calls = [0]

    def registry():
        registry_calls[0] += 1
        return tenants

    app = FastAPI()
    composition.attach_third_party_collaboration_composition(
        app,
        routing_key_resolver=lambda: KEY,
        tenant_registry_resolver=registry,
        routing_clock=lambda: 100.0,
        routing_cache_seconds=10.0,
    )
    valid = composition.derive_third_party_collaboration_portal_ref("tenant-9999", KEY)
    request = _request(f"/api/v1/external/third-party-collaboration/{valid}/contract")
    assert app.state.third_party_collaboration_portal_resolver(valid, request).tenant_id == (
        "tenant-9999"
    )
    for index in range(100):
        invalid = composition.derive_third_party_collaboration_portal_ref(
            f"not-active-{index}",
            KEY,
        )
        with pytest.raises(composition.ThirdPartyCollaborationCompositionError):
            app.state.third_party_collaboration_portal_resolver(
                invalid,
                _request(f"/api/v1/external/third-party-collaboration/{invalid}/contract"),
            )
    assert registry_calls == [1]


def test_cold_routing_index_build_runs_off_the_event_loop() -> None:
    registry_threads: list[int] = []
    route_threads: list[int] = []

    def registry():
        registry_threads.append(get_ident())
        return [Tenant("tenant-a", True)]

    app = FastAPI()
    composition.attach_third_party_collaboration_composition(
        app,
        routing_key_resolver=lambda: KEY,
        tenant_registry_resolver=registry,
    )
    portal = composition.derive_third_party_collaboration_portal_ref("tenant-a", KEY)

    @app.get("/api/v1/external/third-party-collaboration/{portal_ref}/contract")
    async def limited(portal_ref: str, request: Request) -> dict[str, str]:
        route_threads.append(get_ident())
        request.app.state.third_party_collaboration_rate_limit("a" * 64, "contract")
        return {"portal_ref": portal_ref}

    response = TestClient(app, base_url="http://127.0.0.1").get(f"/api/v1/external/third-party-collaboration/{portal}/contract")
    assert response.status_code == 200
    assert len(registry_threads) == len(route_threads) == 1
    assert registry_threads[0] != route_threads[0]


def test_tenant_policy_uses_exact_gate_and_core_loader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = {
        "third_party_management": {
            "enable": True,
            "lifecycle": {"enable": True, "portal": {"enable": True}},
        }
    }
    enabled_calls: list[object] = []
    policy_calls: list[object] = []
    expected = collaboration.ThirdPartyCollaborationPolicy()
    monkeypatch.setattr(config_module, "load_config", lambda: config)
    monkeypatch.setattr(
        config_module,
        "config_source_errors",
        lambda *, include_tenant: [] if include_tenant else ["wrong floor"],
    )
    monkeypatch.setattr(
        collaboration,
        "enabled",
        lambda value: enabled_calls.append(value) is None,
    )
    monkeypatch.setattr(
        collaboration,
        "load_policy",
        lambda value: policy_calls.append(value) or expected,
    )

    assert composition._load_tenant_policy("tenant-a") is expected
    assert enabled_calls == [config]
    assert policy_calls == [config]

    monkeypatch.setattr(collaboration, "enabled", lambda _value: False)
    with pytest.raises(composition.ThirdPartyCollaborationCompositionError):
        composition._load_tenant_policy("tenant-a")


def test_store_paths_and_lazy_factories_remain_tenant_isolated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    allow_policy,
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    captures: list[SimpleNamespace] = []

    class CapturingStore:
        def __init__(self, path: Path, **kwargs: Any) -> None:
            kwargs["config_gate"]()
            self.path = Path(path)
            self.lifecycle_path = Path(kwargs["lifecycle_path"])
            self.principal = kwargs["principal_resolver"]()
            self.policy = kwargs["policy"]
            captures.append(
                SimpleNamespace(
                    path=self.path,
                    lifecycle_path=self.lifecycle_path,
                    principal=self.principal,
                )
            )

    monkeypatch.setattr(collaboration, "ThirdPartyCollaborationStore", CapturingStore)

    def registry():
        return [Tenant("tenant-a", True), Tenant("tenant-b", True)]

    first = composition.build_third_party_collaboration_store(
        tenant_id="tenant-a",
        principal_resolver=lambda: "principal-a",
        registry_resolver=registry,
    )
    second = composition.build_third_party_collaboration_store(
        tenant_id="tenant-b",
        principal_resolver=lambda: "principal-b",
        registry_resolver=registry,
    )

    assert first.path != second.path
    assert first.lifecycle_path != second.lifecycle_path
    assert "tenant-a" in str(first.path)
    assert "tenant-b" in str(second.path)
    assert [capture.principal for capture in captures] == ["principal-a", "principal-b"]


def _limited_app(
    policy: composition.ThirdPartyCollaborationRateLimitPolicy,
    *,
    clock=lambda: 100.0,
    trusted_client_address_resolver=None,
    tenant_ids: tuple[str, ...] = ("rate-limit-tenant",),
) -> tuple[TestClient, FastAPI, str]:
    app = FastAPI()
    composition.attach_third_party_collaboration_composition(
        app,
        routing_key_resolver=lambda: KEY,
        tenant_registry_resolver=lambda: [Tenant(tenant_id, True) for tenant_id in tenant_ids],
        trusted_client_address_resolver=trusted_client_address_resolver,
        rate_limit_policy=policy,
        rate_limit_clock=clock,
    )
    portal_ref = composition.derive_third_party_collaboration_portal_ref(
        "rate-limit-tenant",
        KEY,
    )

    @app.get("/api/v1/external/third-party-collaboration/{portal_ref}/contract")
    def limited(portal_ref: str, request: Request) -> dict[str, str]:
        credential = request.headers.get("X-Test-Credential", "0" * 64)
        request.app.state.third_party_collaboration_rate_limit(credential, "contract")
        return {"portal_ref": portal_ref}

    return TestClient(app, base_url="http://127.0.0.1"), app, portal_ref


def test_random_credentials_and_spoofed_xff_cannot_bypass_source_limit() -> None:
    client, _app, portal = _limited_app(
        composition.ThirdPartyCollaborationRateLimitPolicy(
            global_portal_action_limit=100,
            source_portal_action_limit=2,
            credential_portal_action_limit=100,
            max_buckets=32,
        )
    )

    for index in range(2):
        response = client.get(
            f"/api/v1/external/third-party-collaboration/{portal}/contract",
            headers={
                "X-Test-Credential": f"{index:064x}",
                "X-Forwarded-For": f"203.0.113.{index + 1}",
            },
        )
        assert response.status_code == 200
    rejected = client.get(
        f"/api/v1/external/third-party-collaboration/{portal}/contract",
        headers={
            "X-Test-Credential": f"{2:064x}",
            "X-Forwarded-For": "203.0.113.99",
        },
    )
    assert rejected.status_code == 429
    assert rejected.headers["retry-after"] == "60"


def test_global_portal_action_limit_spans_trusted_sources_and_credentials() -> None:
    client, _app, portal = _limited_app(
        composition.ThirdPartyCollaborationRateLimitPolicy(
            global_portal_action_limit=2,
            source_portal_action_limit=100,
            credential_portal_action_limit=100,
            max_buckets=32,
        ),
        trusted_client_address_resolver=lambda request: request.headers["X-Trusted-Peer"],
    )

    for index in range(2):
        assert (
            client.get(
                f"/api/v1/external/third-party-collaboration/{portal}/contract",
                headers={
                    "X-Test-Credential": f"{index:064x}",
                    "X-Trusted-Peer": f"198.51.100.{index + 1}",
                },
            ).status_code
            == 200
        )
    rejected = client.get(
        f"/api/v1/external/third-party-collaboration/{portal}/contract",
        headers={
            "X-Test-Credential": f"{2:064x}",
            "X-Trusted-Peer": "198.51.100.3",
        },
    )
    assert rejected.status_code == 429


def test_random_portal_refs_do_not_allocate_portal_or_credential_buckets() -> None:
    client, app, _portal = _limited_app(
        composition.ThirdPartyCollaborationRateLimitPolicy(
            deployment_action_limit=100,
            source_action_limit=2,
            global_portal_action_limit=100,
            source_portal_action_limit=100,
            credential_portal_action_limit=100,
            max_buckets=8,
        )
    )
    for index in range(2):
        unknown = composition.derive_third_party_collaboration_portal_ref(
            f"unknown-{index}",
            KEY,
        )
        response = client.get(
            f"/api/v1/external/third-party-collaboration/{unknown}/contract",
            headers={"X-Test-Credential": f"{index:064x}"},
        )
        assert response.status_code == 200
    limiter = app.state.third_party_collaboration_rate_limit
    assert limiter.bucket_count == 2

    third_unknown = composition.derive_third_party_collaboration_portal_ref(
        "unknown-2",
        KEY,
    )
    rejected = client.get(
        f"/api/v1/external/third-party-collaboration/{third_unknown}/contract",
        headers={"X-Test-Credential": f"{2:064x}"},
    )
    assert rejected.status_code == 429
    assert limiter.bucket_count == 2


def test_limiter_bucket_state_is_bounded_and_expired_state_is_cleaned() -> None:
    now = [100.0]
    client, app, _portal = _limited_app(
        composition.ThirdPartyCollaborationRateLimitPolicy(
            window_seconds=1,
            global_portal_action_limit=100,
            source_portal_action_limit=100,
            credential_portal_action_limit=100,
            max_buckets=8,
        ),
        clock=lambda: now[0],
        tenant_ids=("tenant-0", "tenant-1", "tenant-2"),
    )
    refs = [
        composition.derive_third_party_collaboration_portal_ref(f"tenant-{index}", KEY)
        for index in range(3)
    ]
    assert (
        client.get(
            f"/api/v1/external/third-party-collaboration/{refs[0]}/contract",
            headers={"X-Test-Credential": f"{1:064x}"},
        ).status_code
        == 200
    )
    assert (
        client.get(
            f"/api/v1/external/third-party-collaboration/{refs[1]}/contract",
            headers={"X-Test-Credential": f"{2:064x}"},
        ).status_code
        == 200
    )
    rejected = client.get(
        f"/api/v1/external/third-party-collaboration/{refs[2]}/contract",
        headers={"X-Test-Credential": f"{3:064x}"},
    )
    limiter = app.state.third_party_collaboration_rate_limit
    assert rejected.status_code == 429
    assert limiter.bucket_count <= 8

    now[0] += 2
    admitted = client.get(
        f"/api/v1/external/third-party-collaboration/{refs[2]}/contract",
        headers={"X-Test-Credential": f"{3:064x}"},
    )
    assert admitted.status_code == 200
    assert limiter.bucket_count <= 8


def test_evidence_uploads_have_their_own_rate_limited_action() -> None:
    app = FastAPI()
    composition.attach_third_party_collaboration_composition(
        app,
        routing_key_resolver=lambda: KEY,
        tenant_registry_resolver=lambda: [Tenant("rate-limit-tenant", True)],
        rate_limit_policy=composition.ThirdPartyCollaborationRateLimitPolicy(
            global_portal_action_limit=100,
            source_portal_action_limit=100,
            credential_portal_action_limit=2,
            max_buckets=32,
        ),
        rate_limit_clock=lambda: 100.0,
    )
    portal = composition.derive_third_party_collaboration_portal_ref("rate-limit-tenant", KEY)

    @app.post("/api/v1/external/third-party-collaboration/{portal_ref}/evidence")
    def evidence(portal_ref: str, request: Request) -> dict[str, str]:
        action = request.headers.get("X-Test-Action", "evidence")
        request.app.state.third_party_collaboration_rate_limit("0" * 64, action)
        return {"portal_ref": portal_ref}

    client = TestClient(app, base_url="http://127.0.0.1")
    path = f"/api/v1/external/third-party-collaboration/{portal}/evidence"
    assert client.post(path, headers={"X-Test-Action": "contract"}).status_code == 429
    assert [client.post(path).status_code for _ in range(3)] == [200, 200, 429]


def test_lazy_store_forwards_evidence_measurement_only_for_its_own_tenant(allow_policy) -> None:
    measured: list[tuple[str, dict[str, Any]]] = []

    class MeasuringStore(FakeStore):
        def measure_evidence(self, tenant_id: str, token: str, **kwargs: Any) -> dict[str, str]:
            measured.append((tenant_id, kwargs))
            return {"tenant_id": tenant_id}

    app = FastAPI()
    composition.attach_third_party_collaboration_composition(
        app,
        routing_key_resolver=lambda: KEY,
        tenant_registry_resolver=lambda: [Tenant("tenant-a", True), Tenant("tenant-b", True)],
        store_builder=lambda *, tenant_id, **_kwargs: MeasuringStore(tenant_id),
    )
    portal_a = app.state.third_party_collaboration_portal_ref_for_tenant("tenant-a")
    material = app.state.third_party_collaboration_portal_resolver(
        portal_a,
        _request(f"/api/v1/external/third-party-collaboration/{portal_a}/evidence"),
    )
    assert material.store.measure_evidence("tenant-a", "token", content=b"x") == {
        "tenant_id": "tenant-a"
    }
    with pytest.raises(collaboration.ThirdPartyCollaborationPermissionDenied):
        material.store.measure_evidence("tenant-b", "token", content=b"x")
    assert measured == [("tenant-a", {"content": b"x"})]
