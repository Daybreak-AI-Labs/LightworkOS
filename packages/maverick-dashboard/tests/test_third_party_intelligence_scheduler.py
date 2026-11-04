"""Scheduler boundaries for tenant-scoped third-party provider feeds."""

from __future__ import annotations

import math
import threading
from types import SimpleNamespace

import pytest
from maverick_dashboard import third_party_intelligence_scheduler as scheduler


class ProviderFactory:
    def create(self, provider, provenance_uri):
        raise AssertionError((provider, provenance_uri))


def enabled_config(*, poll_seconds: object = 300) -> dict[str, object]:
    return {
        "third_party_management": {
            "enable": True,
            "intelligence": {
                "enable": True,
                "providers": {
                    "enable": True,
                    "scheduler": {
                        "enable": True,
                        "poll_seconds": poll_seconds,
                    },
                },
            },
        }
    }


def dependencies(**overrides):
    values = {
        "intelligence_store_for": lambda tenant: ("intelligence", tenant),
        "runtime_store_for": lambda tenant: ("runtime", tenant),
        "provider_factory": ProviderFactory(),
        "credential_resolver": lambda tenant, env, provider, source: (
            tenant,
            env,
            provider,
            source,
        ),
    }
    values.update(overrides)
    return scheduler.ThirdPartyFeedSchedulerDependencies(**values)


def test_scheduler_gate_is_exact_and_poll_interval_is_bounded() -> None:
    assert scheduler.scheduler_enabled({}) is False
    config = enabled_config()
    assert scheduler.scheduler_enabled(config) is True
    config["third_party_management"]["intelligence"]["providers"]["scheduler"]["enable"] = 1
    assert scheduler.scheduler_enabled(config) is False
    for invalid in (True, "60", 59, 86_401, math.inf, math.nan):
        with pytest.raises(ValueError, match="poll_seconds"):
            scheduler._poll_seconds(enabled_config(poll_seconds=invalid))
    assert scheduler._poll_seconds(enabled_config(poll_seconds=60)) == 60
    assert scheduler._poll_seconds(enabled_config(poll_seconds=86_400)) == 86_400
    unknown = enabled_config()
    unknown["third_party_management"]["intelligence"]["providers"]["scheduler"]["url"] = (
        "https://attacker.example"
    )
    with pytest.raises(ValueError, match="unsupported"):
        scheduler._poll_seconds(unknown)


def test_dependencies_require_injected_factories_and_closed_provider_factory() -> None:
    with pytest.raises(TypeError, match="dependency"):
        dependencies(runtime_store_for=None)
    with pytest.raises(TypeError, match="provider factory"):
        dependencies(provider_factory=object())


def test_tenant_cycle_uses_only_active_tenant_context(monkeypatch) -> None:
    from maverick import config, paths
    from maverick import third_party_intelligence_runtime as runtime

    tenant = "tenant-feed-a"
    intelligence_store = object()
    runtime_store = object()
    seen: list[tuple[str, object]] = []

    monkeypatch.setattr(paths, "current_tenant_id_strict", lambda: tenant)
    monkeypatch.setattr(config, "config_source_errors", lambda **_kwargs: [])
    monkeypatch.setattr(config, "load_config", enabled_config)

    def intelligence_for(value):
        assert value == tenant
        seen.append(("intelligence", value))
        return intelligence_store

    def runtime_for(value):
        assert value == tenant
        seen.append(("runtime", value))
        return runtime_store

    def enqueue(store, authority, **kwargs):
        assert (store, authority) == (runtime_store, intelligence_store)
        assert kwargs == {
            "tenant_id": tenant,
            "actor_ref": "feed-scheduler",
            "limit": 7,
        }
        return (object(), object())

    def run(store, authority, factory, resolver, **kwargs):
        assert (store, authority, factory) == (
            runtime_store,
            intelligence_store,
            provider_factory,
        )
        assert resolver is credential_resolver
        assert kwargs == {
            "tenant_id": tenant,
            "worker_id": "feed-scheduler",
            "limit": 3,
        }
        return SimpleNamespace(
            claimed=2,
            completed=1,
            retry_pending=1,
            dead_lettered=0,
            revoked=0,
        )

    provider_factory = ProviderFactory()

    def credential_resolver(*_args):
        return None

    monkeypatch.setattr(runtime, "enqueue_due_monitors", enqueue)
    monkeypatch.setattr(runtime, "run_feed_batch", run)
    result = scheduler.tenant_cycle(
        dependencies(
            intelligence_store_for=intelligence_for,
            runtime_store_for=runtime_for,
            provider_factory=provider_factory,
            credential_resolver=credential_resolver,
        ),
        actor_ref="feed-scheduler",
        enqueue_limit=7,
        worker_limit=3,
    )
    assert result == {
        "tenant_id": tenant,
        "skipped": False,
        "queued": 2,
        "claimed": 2,
        "completed": 1,
        "retry_pending": 1,
        "dead_lettered": 0,
        "revoked": 0,
    }
    assert seen == [("intelligence", tenant), ("runtime", tenant)]

    monkeypatch.setattr(paths, "current_tenant_id_strict", lambda: None)
    with pytest.raises(RuntimeError, match="active tenant"):
        scheduler.tenant_cycle(dependencies(), actor_ref="feed-scheduler")


def test_tenant_opt_out_does_not_construct_provider_stores(monkeypatch) -> None:
    from maverick import config, paths

    touched: list[str] = []
    monkeypatch.setattr(paths, "current_tenant_id_strict", lambda: "tenant-disabled")
    monkeypatch.setattr(config, "config_source_errors", lambda **_kwargs: [])
    monkeypatch.setattr(config, "load_config", dict)
    result = scheduler.tenant_cycle(
        dependencies(
            intelligence_store_for=lambda _tenant: touched.append("intelligence"),
            runtime_store_for=lambda _tenant: touched.append("runtime"),
        ),
        actor_ref="feed-scheduler",
    )
    assert result["skipped"] is True
    assert result["claimed"] == 0
    assert touched == []


def test_scheduler_cycle_delegates_to_active_tenant_runner(monkeypatch) -> None:
    from maverick import config
    from maverick_dashboard import automation_queue

    calls: list[object] = []
    deps = dependencies()
    monkeypatch.setattr(config, "config_source_errors", lambda **_kwargs: [])
    monkeypatch.setattr(config, "load_global_config", enabled_config)
    monkeypatch.setattr(
        scheduler,
        "tenant_cycle",
        lambda value, *, actor_ref: calls.append((value, actor_ref)),
    )

    def active_tenants(label, callback):
        calls.append(label)
        callback()
        return True

    monkeypatch.setattr(automation_queue, "_run_for_active_tenants", active_tenants)
    assert scheduler.scheduler_cycle(deps, actor_ref="scheduler-actor") is True
    assert calls == [
        "Third-party intelligence feed collection",
        (deps, "scheduler-actor"),
    ]

    monkeypatch.setattr(config, "config_source_errors", lambda **_kwargs: ["bad"])
    calls.clear()
    assert scheduler.scheduler_cycle(deps, actor_ref="scheduler-actor") is False
    assert calls == []


def test_scheduler_start_and_stop_are_default_off_and_bounded(monkeypatch) -> None:
    from maverick import config

    deps = dependencies()
    worker = scheduler.ThirdPartyFeedScheduler(deps)
    monkeypatch.setattr(config, "config_source_errors", lambda **_kwargs: [])
    monkeypatch.setattr(config, "load_global_config", dict)
    assert worker.start() is False
    assert worker.stop() is False

    started = threading.Event()

    def loop(stop, _actor, _poll_seconds):
        started.set()
        stop.wait(5)

    monkeypatch.setattr(config, "load_global_config", enabled_config)
    monkeypatch.setattr(worker, "_loop", loop)
    assert worker.start() is True
    assert started.wait(1)
    assert worker.start() is False
    assert worker.stop(timeout=1) is True
