"""Configurable dispatch pools + backpressure: webhook in-flight cap, and
gRPC / federation worker + concurrency settings resolved from env/config."""
from __future__ import annotations

# ---- webhook dispatch: configurable workers + bounded queue ---------------


def test_webhook_pool_size_from_env(monkeypatch):
    from maverick import webhooks
    monkeypatch.setenv("MAVERICK_WEBHOOK_WORKERS", "9")
    assert webhooks._pool_size() == 9
    monkeypatch.delenv("MAVERICK_WEBHOOK_WORKERS")
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"webhooks": {"workers": 3}})
    assert webhooks._pool_size() == 3


def test_webhook_inflight_cap_drops_on_overflow(monkeypatch):
    from maverick import webhooks
    monkeypatch.setenv("MAVERICK_WEBHOOK_MAX_INFLIGHT", "2")
    webhooks._executor = None  # rebuild pool + semaphore with the new cap

    import threading
    release = threading.Event()
    started = threading.Semaphore(0)

    def _block(*_a):
        started.release()
        release.wait(5)

    monkeypatch.setattr(webhooks, "_post", _block)
    n = webhooks.fire(
        "goal_finished", {"goal_id": 1},
        urls=["https://a.example", "https://b.example", "https://c.example"],
        secret=None,
    )
    # cap=2 -> only two dispatches admitted, the third dropped.
    assert n == 2
    release.set()
    webhooks._get_executor().shutdown(wait=True)
    webhooks._executor = None


# ---- gRPC server settings -------------------------------------------------


def test_grpc_worker_setting_env_and_config(monkeypatch):
    from maverick.grpc_api import server
    monkeypatch.setenv("MAVERICK_GRPC_MAX_WORKERS", "16")
    assert server._grpc_int_setting("MAVERICK_GRPC_MAX_WORKERS", "max_workers", 8) == 16
    monkeypatch.delenv("MAVERICK_GRPC_MAX_WORKERS")
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"grpc": {"max_workers": 12}})
    assert server._grpc_int_setting("MAVERICK_GRPC_MAX_WORKERS", "max_workers", 8) == 12


def test_grpc_concurrent_can_default_to_worker_count(monkeypatch):
    from maverick.grpc_api import server
    monkeypatch.delenv("MAVERICK_GRPC_MAX_CONCURRENT", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    assert server._grpc_int_setting(
        "MAVERICK_GRPC_MAX_CONCURRENT", "max_concurrent_rpcs", 8) == 8


def test_grpc_setting_bad_value_falls_back(monkeypatch):
    from maverick.grpc_api import server
    monkeypatch.setenv("MAVERICK_GRPC_MAX_WORKERS", "not-an-int")
    assert server._grpc_int_setting("MAVERICK_GRPC_MAX_WORKERS", "max_workers", 8) == 8


# ---- federation server settings -------------------------------------------


def test_federation_worker_setting(monkeypatch):
    from maverick import federation
    monkeypatch.setenv("MAVERICK_FEDERATION_MAX_WORKERS", "5")
    assert federation._fed_int_setting(
        "MAVERICK_FEDERATION_MAX_WORKERS", "max_workers", 8) == 5
    monkeypatch.delenv("MAVERICK_FEDERATION_MAX_WORKERS")
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"federation": {"max_workers": 7}})
    assert federation._fed_int_setting(
        "MAVERICK_FEDERATION_MAX_WORKERS", "max_workers", 8) == 7
