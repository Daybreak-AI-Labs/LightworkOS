"""Authenticated queue dispatcher security and compatibility tests."""

from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import ModuleType, SimpleNamespace

import maverick.queue_dispatcher as qd
import maverick.runner as runner
import pytest
from maverick.capability import Capability
from maverick.paths import current_tenant_id, tenant_scope


@pytest.fixture(autouse=True)
def _isolated_queue_config(monkeypatch, tmp_path):
    import maverick.job_queue as jq

    # Do not let a developer's real config alter local-envelope expectations.
    monkeypatch.setattr(qd, "_queue_signing_key", lambda: None)
    monkeypatch.setattr(qd, "_configured_envelope_ttl_seconds", lambda: 900)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_QUEUE_NAMESPACE", "pytest-fleet")
    monkeypatch.delenv("MAVERICK_ALLOW_INSECURE_QUEUE_REDIS", raising=False)
    for name in (
        "MAVERICK_QUEUE_REDIS_DSN",
        "MAVERICK_QUEUE_REDIS_CA_CERTS",
        "MAVERICK_QUEUE_REDIS_CERTFILE",
        "MAVERICK_QUEUE_REDIS_KEYFILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(jq, "DEFAULT_DB", None)


class _SharedClaimBackend:
    """Fresh worker handles over one tenant-aware atomic backing store."""

    def __init__(self):
        self.claims = set()
        self.lock = threading.Lock()
        self.handles_opened = 0
        self.handles_closed = 0

    def open_world(self):
        backend = self
        with self.lock:
            self.handles_opened += 1

        class Handle:
            def mark_message_processed(self, channel, external_id, goal_id=None):
                key = (current_tenant_id(), channel, external_id)
                with backend.lock:
                    if key in backend.claims:
                        return False
                    backend.claims.add(key)
                    return True

            def close(self):
                with backend.lock:
                    backend.handles_closed += 1

        return Handle()


def _install_shared_claim_store(monkeypatch):
    import maverick.world_model as world_model
    import maverick.world_model_backends as backends

    backend = _SharedClaimBackend()
    monkeypatch.setattr(backends, "is_postgres_configured", lambda: True)
    monkeypatch.setattr(world_model, "open_world", backend.open_world)
    return backend


def _local_envelope(goal_id: int = 9, **kwargs):
    jobs = []
    qd.QueueDispatcher(lambda _name, payload: jobs.append(payload)).submit(
        goal_id, **kwargs
    )
    assert len(jobs) == 1
    return jobs[0]


def _network_envelope(monkeypatch, tenant: str, goal_id: int = 9, **kwargs):
    import maverick.world_model_backends as backends

    monkeypatch.setattr(qd, "_queue_signing_key", lambda: "k" * 32)
    monkeypatch.setattr(backends, "is_postgres_configured", lambda: True)
    jobs = []
    with tenant_scope(tenant=tenant):
        qd.QueueDispatcher(
            lambda _name, payload: jobs.append(payload), transport="network"
        ).submit(goal_id, **kwargs)
    assert len(jobs) == 1
    return jobs[0]


def test_submit_authenticates_complete_envelope_and_returns_none():
    jobs = []
    disp = qd.QueueDispatcher(
        enqueue=lambda name, payload: jobs.append((name, payload))
    )
    out = disp.submit(
        42,
        max_dollars=2.0,
        max_wall_seconds=30,
        channel="api",
        user_id="u1",
        concurrency_principal="principal:u1",
    )

    assert out == qd.QUEUED_STATUS
    assert len(jobs) == 1
    name, payload = jobs[0]
    assert name == qd.JOB_NAME
    assert frozenset(payload) == qd._ENVELOPE_FIELDS
    assert payload["version"] == qd.ENVELOPE_VERSION
    assert payload["job_name"] == qd.JOB_NAME
    assert payload["auth_mode"] == qd._AUTH_LOCAL
    assert payload["goal_id"] == 42
    assert payload["conversation_id"] is None
    assert payload["max_dollars"] == 2.0
    assert payload["max_wall_seconds"] == 30
    assert payload["channel"] == "api"
    assert payload["user_id"] == "u1"
    assert payload["concurrency_principal"] == "principal:u1"
    assert payload["allowed_suites"] is None
    assert payload["max_depth"] == runner.DEFAULT_MAX_DEPTH
    assert payload["message_id"] != payload["nonce"]
    assert payload["expires_at"] > payload["issued_at"]
    assert qd._verify_envelope(payload) == payload


def test_payload_is_json_safe():
    payload = _local_envelope(7)
    json.dumps(payload, allow_nan=False)


@pytest.mark.parametrize(
    ("grant", "wire_value", "worker_value"),
    [
        (None, None, None),
        (frozenset(), [], frozenset()),
        (
            frozenset({"legal", "finance"}),
            ["finance", "legal"],
            frozenset({"finance", "legal"}),
        ),
    ],
)
def test_allowed_suites_tri_state_is_signed_and_restored_exactly(
    monkeypatch, grant, wire_value, worker_value
):
    seen = {}
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda **kwargs: seen.update(kwargs) or "done",
    )

    payload = _local_envelope(allowed_suites=grant)

    assert payload["allowed_suites"] == wire_value
    assert qd.run_queued_goal(payload) == "done"
    if worker_value is None:
        assert seen["allowed_suites"] is None
    else:
        assert seen["allowed_suites"] == worker_value
        assert isinstance(seen["allowed_suites"], frozenset)


def test_unknown_allowed_suite_is_rejected_before_enqueue():
    jobs = []
    dispatcher = qd.QueueDispatcher(
        lambda _name, payload: jobs.append(payload)
    )

    with pytest.raises(qd.QueueSecurityError, match="unknown suite"):
        dispatcher.submit(9, allowed_suites=frozenset({"finance", "root"}))

    assert jobs == []


def test_submit_serializes_explicit_capability():
    cap = Capability(
        principal="user:limited",
        allow_tools=frozenset({"safe_tool"}),
        deny_tools=frozenset({"shell"}),
        max_risk="low",
        expires_at=123.0,
        allow_paths=frozenset({"/tmp/safe/*"}),
        allow_hosts=frozenset({"example.com"}),
    )

    payload = _local_envelope(7, capability=cap)

    capability = dict(payload["capability"])
    signature = capability.pop("sig")
    assert capability == {
        "principal": "user:limited",
        "allow_tools": ["safe_tool"],
        "deny_tools": ["shell"],
        "max_risk": "low",
        "expires_at": 123.0,
        "allow_paths": ["/tmp/safe/*"],
        "allow_hosts": ["example.com"],
    }
    assert qd._HEX_SIG_RE.fullmatch(signature)


def test_run_queued_goal_restores_explicit_capability(monkeypatch):
    seen = {}

    def fake_run(*, goal_id, **kwargs):
        seen["goal_id"] = goal_id
        seen.update(kwargs)
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_thread", fake_run)
    cap = Capability(
        principal="user:limited",
        allow_tools=frozenset({"safe_tool"}),
        deny_tools=frozenset({"shell"}),
        max_risk="low",
        expires_at=123.0,
        allow_paths=frozenset({"/tmp/safe/*"}),
        allow_hosts=frozenset({"example.com"}),
    )

    out = qd.run_queued_goal(_local_envelope(capability=cap))

    assert out == "done"
    assert seen["goal_id"] == 9
    assert seen["capability"] == cap


def test_run_queued_goal_attenuates_capability_by_worker_policy(monkeypatch):
    seen = {}

    def fake_run(*, goal_id, **kwargs):
        seen.update(kwargs)
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_thread", fake_run)
    monkeypatch.setenv("MAVERICK_ENFORCE_CAPABILITIES", "1")
    monkeypatch.setattr(
        "maverick.safety.tool_acl.resolve_lists",
        lambda **_kwargs: (set(), {"shell"}),
    )
    monkeypatch.setattr(
        "maverick.safety.tool_acl.resolve_max_risk", lambda **_kwargs: "low"
    )
    cap = Capability(
        principal="user:alice",
        allow_tools=frozenset({"shell", "safe_tool"}),
        max_risk="high",
    )

    out = qd.run_queued_goal(
        _local_envelope(user_id="alice", capability=cap)
    )

    assert out == "done"
    narrowed = seen["capability"]
    assert narrowed.permits("shell") is False
    assert "shell" in narrowed.deny_tools
    assert narrowed.max_risk == "low"


def test_worker_policy_cannot_be_disabled_by_omitting_capability(monkeypatch):
    seen = {}

    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda **kwargs: seen.update(kwargs) or "done",
    )
    monkeypatch.setenv("MAVERICK_ENFORCE_CAPABILITIES", "1")
    monkeypatch.setattr(
        "maverick.safety.tool_acl.resolve_lists",
        lambda **_kwargs: (set(), {"shell"}),
    )
    monkeypatch.setattr(
        "maverick.safety.tool_acl.resolve_max_risk", lambda **_kwargs: "low"
    )

    assert qd.run_queued_goal(_local_envelope(capability=None)) == "done"

    worker_capability = seen["capability"]
    assert worker_capability is not None
    assert worker_capability.permits("shell") is False
    assert worker_capability.max_risk == "low"


def test_run_queued_goal_executes_authenticated_local_envelope(monkeypatch):
    seen = {}

    def fake_run(*, goal_id, **kwargs):
        seen["goal_id"] = goal_id
        seen.update(kwargs)
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_thread", fake_run)
    out = qd.run_queued_goal(
        _local_envelope(max_dollars=1.5, channel="q")
    )

    assert out == "done"
    assert seen["goal_id"] == 9
    assert seen["max_dollars"] == 1.5
    assert seen["channel"] == "q"


def test_worker_clamps_signed_producer_limits_to_local_policy(monkeypatch):
    import maverick.config as cfg

    seen = {}
    monkeypatch.setattr(
        cfg,
        "load_config",
        lambda: {
            "queue": {
                "worker_max_dollars": 0.5,
                "worker_max_wall_seconds": 20,
                "worker_max_depth": 2,
            }
        },
    )
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda **kwargs: seen.update(kwargs) or "done",
    )

    assert qd.run_queued_goal(
        _local_envelope(max_dollars=50, max_wall_seconds=500, max_depth=20)
    ) == "done"
    assert seen["max_dollars"] == 0.5
    assert seen["max_wall_seconds"] == 20
    assert seen["max_depth"] == 2


@pytest.mark.parametrize("requested", [None, 0.0, 100_000.0])
def test_worker_preserves_absent_or_explicit_task_limits(monkeypatch, requested):
    seen = {}
    monkeypatch.setattr(runner, "run_goal_in_thread", lambda **kw: seen.update(kw) or "done")
    assert qd.run_queued_goal(_local_envelope(
        max_dollars=requested, max_wall_seconds=requested,
    )) == "done"
    assert seen["max_dollars"] == requested
    assert seen["max_wall_seconds"] == requested


@pytest.mark.parametrize("requested", [None, 0.0, 100_000.0])
@pytest.mark.parametrize("source", ["budget", "queue", "environment"])
def test_worker_enforces_explicit_caps_before_dispatch(monkeypatch, source, requested):
    from maverick import config

    if source == "environment":
        monkeypatch.setenv("MAVERICK_QUEUE_WORKER_MAX_DOLLARS", "2")
        monkeypatch.setenv("MAVERICK_QUEUE_WORKER_MAX_WALL_SECONDS", "20")
    else:
        prefix = "worker_" if source == "queue" else ""
        monkeypatch.setattr(config, "load_config", lambda: {source: {
            f"{prefix}max_dollars": 2.0, f"{prefix}max_wall_seconds": 20.0,
        }})
    seen = {}
    monkeypatch.setattr(runner, "run_goal_in_thread", lambda **kw: seen.update(kw) or "done")
    assert qd.run_queued_goal(_local_envelope(
        max_dollars=requested, max_wall_seconds=requested,
    )) == "done"
    assert seen["max_dollars"] == (0.0 if requested == 0 else 2.0)
    assert seen["max_wall_seconds"] == (0.0 if requested == 0 else 20.0)


@pytest.mark.parametrize("raw", [True, -1, float("nan"), float("inf"), "invalid"])
@pytest.mark.parametrize("field", ["worker_max_dollars", "worker_max_wall_seconds"])
def test_worker_invalid_limits_are_rejected_before_consuming_envelope(monkeypatch, raw, field):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda: {"queue": {field: raw}})
    monkeypatch.setattr(
        "maverick.job_queue.JobQueue.claim_dispatch_envelope",
        lambda *_a, **_kw: pytest.fail("invalid worker policy consumed the envelope"),
    )
    with pytest.raises(qd.QueueSecurityError, match=f"{field} is invalid"):
        qd.run_queued_goal(_local_envelope())


def test_explicit_zero_worker_limits_survive_disabled_task_defaults(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda: {
        "budget": {"task_limits_enabled": False, "max_dollars": 100},
        "queue": {"worker_max_dollars": 0, "worker_max_wall_seconds": 0},
    })
    seen = {}
    monkeypatch.setattr(runner, "run_goal_in_thread", lambda **kw: seen.update(kw) or "done")
    assert qd.run_queued_goal(_local_envelope(max_dollars=100, max_wall_seconds=100)) == "done"
    assert seen["max_dollars"] == 0
    assert seen["max_wall_seconds"] == 0


def test_malformed_signed_capability_is_rejected_before_claim(monkeypatch):
    cap = Capability(principal="user:limited", allow_tools=frozenset({"read_file"}))
    payload = _local_envelope(capability=cap)
    payload["capability"]["allow_tools"] = "read_file"
    payload["capability"]["sig"] = qd._capability_sig(
        payload["capability"], qd._LOCAL_SIGNING_KEY
    )
    payload = qd._sign_envelope(payload, qd._LOCAL_SIGNING_KEY)
    monkeypatch.setattr(
        "maverick.job_queue.JobQueue.claim_dispatch_envelope",
        lambda *_args, **_kwargs: pytest.fail("malformed capability was claimed"),
    )

    with pytest.raises(qd.QueueSecurityError, match="allow_tools"):
        qd.run_queued_goal(payload)


def test_local_envelope_is_claimed_once_in_tenant_job_store(monkeypatch):
    calls = 0

    def fake_run(**_kwargs):
        nonlocal calls
        calls += 1
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_thread", fake_run)
    payload = _local_envelope()

    assert qd.run_queued_goal(payload) == "done"
    with pytest.raises(qd.QueueReplayError, match="already consumed"):
        qd.run_queued_goal(payload)
    assert calls == 1


def test_shared_root_local_envelope_cannot_drift_into_tenant(monkeypatch):
    import maverick.paths as paths

    monkeypatch.setattr(paths, "current_tenant_id", lambda: None)
    payload = _local_envelope()
    assert payload["tenant"] == ""
    monkeypatch.setattr(paths, "current_tenant_id", lambda: "other-tenant")
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda **_kwargs: pytest.fail("root envelope crossed into tenant"),
    )

    with pytest.raises(qd.QueueSecurityError, match="cannot run inside"):
        qd.run_queued_goal(payload)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("version", 1),
        ("job_name", "maverick.other"),
        ("auth_mode", "shared-hmac"),
        ("message_id", "A" * 24),
        ("nonce", "B" * 24),
        ("issued_at", 1),
        ("expires_at", 9_999_999_999),
        ("tenant", "attacker"),
        ("goal_id", 999),
        ("conversation_id", 999),
        ("max_dollars", 999_999.0),
        ("max_wall_seconds", 999_999.0),
        ("max_depth", 64),
        ("channel", "attacker-channel"),
        ("user_id", "attacker-user"),
        ("capability", {"principal": "admin"}),
        ("concurrency_principal", "attacker-principal"),
        ("allowed_suites", ["finance"]),
        ("sig", "0" * 64),
        # A forged non-ASCII signature is the same refusal, not a TypeError.
        ("sig", "é" * 64),
    ],
)
def test_every_dispatch_field_is_authenticated_before_execution(
    monkeypatch, field, replacement
):
    payload = _local_envelope(
        max_dollars=1.0,
        max_wall_seconds=10,
        channel="api",
        user_id="alice",
        concurrency_principal="user:alice",
    )
    payload[field] = replacement
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda **_kwargs: pytest.fail("tampered envelope reached dispatch"),
    )

    with pytest.raises(qd.QueueSecurityError, match="signature|auth mode|requires"):
        qd.run_queued_goal(payload)


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("v1", "unsupported.*version"),
        ("missing", "fields.*version 2"),
        ("wrong-type", "null or a bounded list"),
        ("duplicates", "not canonical"),
        ("unknown", "unknown suite"),
    ],
)
def test_signed_legacy_or_malformed_suite_grant_is_rejected_before_claim(
    monkeypatch, mutation, error
):
    payload = _local_envelope(allowed_suites=frozenset({"finance"}))
    if mutation == "v1":
        payload["version"] = 1
    elif mutation == "missing":
        payload.pop("allowed_suites")
    elif mutation == "wrong-type":
        payload["allowed_suites"] = "finance"
    elif mutation == "duplicates":
        payload["allowed_suites"] = ["finance", "finance"]
    else:
        payload["allowed_suites"] = ["root"]
    payload = qd._sign_envelope(payload, qd._LOCAL_SIGNING_KEY)
    monkeypatch.setattr(
        "maverick.job_queue.JobQueue.claim_dispatch_envelope",
        lambda *_args, **_kwargs: pytest.fail("invalid envelope was claimed"),
    )
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda **_kwargs: pytest.fail("invalid envelope reached execution"),
    )

    with pytest.raises(qd.QueueSecurityError, match=error):
        qd.run_queued_goal(payload)


def test_unsigned_legacy_payload_is_rejected_before_execution(monkeypatch):
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda **_kwargs: pytest.fail("unsigned envelope reached dispatch"),
    )
    with pytest.raises(qd.QueueSecurityError, match="auth mode"):
        qd.run_queued_goal({"goal_id": 9, "max_dollars": 1.0})


@pytest.mark.parametrize("error_type", [RecursionError, OverflowError])
def test_envelope_serialization_failures_are_security_errors(
    monkeypatch, error_type
):
    def fail_json(*_args, **_kwargs):
        raise error_type("hostile nesting")

    monkeypatch.setattr(
        qd,
        "json",
        SimpleNamespace(dumps=fail_json, loads=json.loads),
    )

    with pytest.raises(qd.QueueSecurityError, match="canonical JSON"):
        qd._canonical_body({})
    with pytest.raises(qd.QueueSecurityError, match="valid JSON"):
        qd._snapshot_payload({})


def test_envelope_snapshot_parse_overflow_is_security_error(monkeypatch):
    def fail_json(*_args, **_kwargs):
        raise OverflowError("hostile nesting")

    monkeypatch.setattr(
        qd,
        "json",
        SimpleNamespace(dumps=json.dumps, loads=fail_json),
    )

    with pytest.raises(qd.QueueSecurityError, match="valid JSON"):
        qd._snapshot_payload({})


def test_expired_but_correctly_signed_envelope_is_rejected(monkeypatch):
    payload = _local_envelope()
    payload["issued_at"] = 1
    payload["expires_at"] = 2
    payload = qd._sign_envelope(payload, qd._LOCAL_SIGNING_KEY)
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda **_kwargs: pytest.fail("expired envelope reached dispatch"),
    )

    with pytest.raises(qd.QueueSecurityError, match="expired"):
        qd.run_queued_goal(payload)


def test_network_transport_requires_strong_shared_key(monkeypatch):
    with pytest.raises(qd.QueueSecurityError, match="requires"):
        qd.QueueDispatcher(lambda _name, _payload: None, transport="network")

    monkeypatch.setattr(qd, "_queue_signing_key", lambda: "too-short")
    with pytest.raises(qd.QueueSecurityError, match="at least 32"):
        qd.QueueDispatcher(lambda _name, _payload: None, transport="network")


def test_network_producer_rejects_unshared_claim_store(monkeypatch):
    import maverick.world_model_backends as backends

    monkeypatch.setattr(qd, "_queue_signing_key", lambda: "k" * 32)
    monkeypatch.setattr(backends, "is_postgres_configured", lambda: False)

    with pytest.raises(qd.QueueSecurityError, match="shared Postgres"):
        qd.QueueDispatcher(lambda _name, _payload: None, transport="network")


def test_network_transport_requires_explicit_tenant(monkeypatch):
    import maverick.paths as paths
    import maverick.world_model_backends as backends

    monkeypatch.setattr(qd, "_queue_signing_key", lambda: "k" * 32)
    monkeypatch.setattr(backends, "is_postgres_configured", lambda: True)
    monkeypatch.setattr(paths, "current_tenant_id", lambda: None)
    dispatcher = qd.QueueDispatcher(
        lambda _name, _payload: None, transport="network"
    )

    with pytest.raises(qd.QueueSecurityError, match="explicit tenant"):
        dispatcher.submit(9)


def test_network_claim_survives_fresh_shared_worker_handle(monkeypatch):
    backend = _install_shared_claim_store(monkeypatch)
    payload = _network_envelope(
        monkeypatch,
        "tenant-a",
        channel="api",
        user_id="alice",
        concurrency_principal="user:alice",
    )
    seen = []

    def fake_run(*, goal_id, **kwargs):
        seen.append(
            {
                "goal_id": goal_id,
                "tenant": current_tenant_id(),
                **kwargs,
            }
        )
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_thread", fake_run)

    assert qd.run_queued_goal(payload) == "done"
    assert seen[0]["tenant"] == "tenant-a"
    with pytest.raises(qd.QueueReplayError, match="already consumed"):
        qd.run_queued_goal(payload)
    assert len(seen) == 1
    # open_world returned a new handle for the simulated restarted/peer worker,
    # while both handles coordinated through one shared atomic store.
    assert backend.handles_opened == 2
    assert backend.handles_closed == 2


def test_worker_rechecks_tenant_suspension_before_claim(monkeypatch):
    backend = _install_shared_claim_store(monkeypatch)
    from maverick.tenant import registry

    registry.create_tenant("tenant-suspended")
    payload = _network_envelope(monkeypatch, "tenant-suspended")
    registry.suspend_tenant("tenant-suspended")
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda **_kwargs: pytest.fail("suspended queued work was dispatched"),
    )

    with pytest.raises(qd.QueueSecurityError, match="unavailable or inactive"):
        qd.run_queued_goal(payload)
    assert backend.claims == set()


def test_worker_rejects_corrupt_tenant_registry_before_claim(monkeypatch, tmp_path):
    backend = _install_shared_claim_store(monkeypatch)
    payload = _network_envelope(monkeypatch, "tenant-corrupt")
    (tmp_path / "tenant_registry.json").write_text(
        '{"tenants":[{"id":"tenant-corrupt","status":"suspnded"}]}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda **_kwargs: pytest.fail("corrupt-policy queued work was dispatched"),
    )

    with pytest.raises(qd.QueueSecurityError, match="unavailable or inactive"):
        qd.run_queued_goal(payload)
    assert backend.claims == set()


def test_post_claim_failure_burns_network_envelope(monkeypatch):
    _install_shared_claim_store(monkeypatch)
    payload = _network_envelope(monkeypatch, "tenant-crash")
    calls = 0

    def crash_after_claim(**_kwargs):
        nonlocal calls
        calls += 1
        raise RuntimeError("worker crashed after durable claim")

    monkeypatch.setattr(runner, "run_goal_in_thread", crash_after_claim)

    with pytest.raises(RuntimeError, match="crashed"):
        qd.run_queued_goal(payload)
    with pytest.raises(qd.QueueReplayError, match="fresh signed job"):
        qd.run_queued_goal(payload)
    assert calls == 1


def test_concurrent_network_workers_only_dispatch_once(monkeypatch):
    _install_shared_claim_store(monkeypatch)
    payload = _network_envelope(monkeypatch, "tenant-concurrent")
    calls = 0
    call_lock = threading.Lock()

    def fake_run(**_kwargs):
        nonlocal calls
        with call_lock:
            calls += 1
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_thread", fake_run)
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(qd.run_queued_goal, payload) for _ in range(8)]

    results = []
    replays = 0
    for future in futures:
        try:
            results.append(future.result())
        except qd.QueueReplayError:
            replays += 1

    assert results == ["done"]
    assert replays == 7
    assert calls == 1


def test_network_claim_store_must_be_shared_postgres(monkeypatch):
    import maverick.world_model_backends as backends

    payload = _network_envelope(monkeypatch, "tenant-no-store")
    monkeypatch.setattr(backends, "is_postgres_configured", lambda: False)
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda **_kwargs: pytest.fail("dispatch ran without shared claim store"),
    )

    with pytest.raises(qd.QueueSecurityError, match="shared Postgres"):
        qd.run_queued_goal(payload)


def test_unavailable_network_claim_store_fails_closed(monkeypatch):
    import maverick.world_model as world_model
    import maverick.world_model_backends as backends

    payload = _network_envelope(monkeypatch, "tenant-store-down")
    monkeypatch.setattr(backends, "is_postgres_configured", lambda: True)
    monkeypatch.setattr(
        world_model,
        "open_world",
        lambda: (_ for _ in ()).throw(ConnectionError("postgres down")),
    )
    monkeypatch.setattr(
        runner,
        "run_goal_in_thread",
        lambda **_kwargs: pytest.fail("dispatch ran while claim store was down"),
    )

    with pytest.raises(qd.QueueSecurityError, match="store is unavailable"):
        qd.run_queued_goal(payload)


def test_network_replay_claims_are_tenant_isolated(monkeypatch):
    backend = _install_shared_claim_store(monkeypatch)
    first = _network_envelope(monkeypatch, "tenant-one")
    second = dict(first)
    second["tenant"] = "tenant-two"
    second = qd._sign_envelope(second, "k" * 32)
    seen_tenants = []

    def fake_run(**_kwargs):
        seen_tenants.append(current_tenant_id())
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_thread", fake_run)

    assert qd.run_queued_goal(first) == "done"
    assert qd.run_queued_goal(second) == "done"
    assert seen_tenants == ["tenant-one", "tenant-two"]
    assert {claim[0] for claim in backend.claims} == {"tenant-one", "tenant-two"}
    with pytest.raises(qd.QueueReplayError):
        qd.run_queued_goal(first)
    with pytest.raises(qd.QueueReplayError):
        qd.run_queued_goal(second)


def test_known_network_broker_cannot_silently_use_local_mode():
    def broker(_name, _payload):
        return None

    broker._maverick_network_broker = True
    with pytest.raises(qd.QueueSecurityError, match="transport='network'"):
        qd.QueueDispatcher(broker)


@pytest.mark.parametrize("host", ["localhost", "127.0.0.42", "::1", "[::1]"])
def test_plaintext_redis_is_allowed_only_on_loopback(host):
    qd._validate_redis_transport(
        SimpleNamespace(host=host, unix_socket_path=None, ssl=False)
    )


@pytest.mark.parametrize(
    "host", ["10.0.0.5", "redis.internal", "127.0.0.1.attacker.example"]
)
def test_nonloopback_plaintext_redis_is_rejected(host):
    with pytest.raises(qd.QueueSecurityError, match="verified TLS"):
        qd._validate_redis_transport(
            SimpleNamespace(host=host, unix_socket_path=None, ssl=False)
        )


def test_nonloopback_redis_requires_certificate_verification():
    qd._validate_redis_transport(
        SimpleNamespace(
            host="redis.internal",
            unix_socket_path=None,
            ssl=True,
            ssl_cert_reqs="required",
            ssl_check_hostname=True,
        )
    )
    with pytest.raises(qd.QueueSecurityError, match="verified TLS"):
        qd._validate_redis_transport(
            SimpleNamespace(
                host="redis.internal",
                unix_socket_path=None,
                ssl=True,
                ssl_cert_reqs="none",
                ssl_check_hostname=True,
            )
        )


def test_redis_unix_socket_is_local_transport():
    qd._validate_redis_transport(
        SimpleNamespace(
            host="redis.internal",
            unix_socket_path="/run/redis/redis.sock",
            ssl=False,
        )
    )


def test_insecure_nonloopback_redis_requires_narrow_explicit_opt_out(monkeypatch):
    settings = SimpleNamespace(host="10.0.0.5", unix_socket_path=None, ssl=False)
    monkeypatch.setenv("MAVERICK_ALLOW_INSECURE_QUEUE_REDIS", "1")

    qd._validate_redis_transport(settings)


@pytest.mark.parametrize("cert_reqs", ["optional", "CERT_OPTIONAL", 1, 0, None])
def test_nonloopback_redis_rejects_incomplete_certificate_validation(cert_reqs):
    with pytest.raises(qd.QueueSecurityError, match="verified TLS"):
        qd._validate_redis_transport(
            SimpleNamespace(
                host="redis.internal",
                unix_socket_path=None,
                ssl=True,
                ssl_cert_reqs=cert_reqs,
                ssl_check_hostname=True,
            )
        )


def test_nonloopback_redis_requires_hostname_validation():
    with pytest.raises(qd.QueueSecurityError, match="verified TLS"):
        qd._validate_redis_transport(
            SimpleNamespace(
                host="redis.internal",
                unix_socket_path=None,
                ssl=True,
                ssl_cert_reqs="required",
                ssl_check_hostname=False,
            )
        )


def test_arq_codec_round_trips_json_and_inerts_exceptions():
    record = {
        "f": qd.JOB_NAME,
        "a": (_local_envelope(),),
        "k": {},
        "t": 1,
        "et": 123,
    }
    decoded = qd._arq_safe_deserialize(qd._arq_safe_serialize(record))
    assert decoded["f"] == qd.JOB_NAME
    assert decoded["a"][0]["goal_id"] == 9

    failed = qd._arq_safe_deserialize(
        qd._arq_safe_serialize({"s": False, "r": RuntimeError("boom")})
    )
    assert failed == {"s": False, "r": "RuntimeError: boom"}


def test_arq_codec_rejects_pickle_duplicate_keys_and_deep_json():
    with pytest.raises(qd.QueueSecurityError, match="safe JSON codec"):
        qd._arq_safe_deserialize(b"\x80\x04pickle")

    duplicate = qd._ARQ_CODEC_PREFIX + b'{"f":"one","f":"two"}'
    with pytest.raises(qd.QueueSecurityError, match="repeats JSON key"):
        qd._arq_safe_deserialize(duplicate)

    deep = qd._ARQ_CODEC_PREFIX + (b"[" * 33) + b"0" + (b"]" * 33)
    with pytest.raises(qd.QueueSecurityError, match="nesting limit"):
        qd._arq_safe_deserialize(deep)


class _FakeRedisSettings:
    def __init__(self):
        self.host = "localhost"
        self.unix_socket_path = None
        self.ssl = False
        self.ssl_cert_reqs = "required"
        self.ssl_check_hostname = False
        self.ssl_ca_certs = None
        self.ssl_certfile = None
        self.ssl_keyfile = None

    @classmethod
    def from_dsn(cls, dsn):
        from urllib.parse import urlsplit

        parsed = urlsplit(dsn)
        settings = cls()
        settings.host = parsed.hostname or "localhost"
        settings.unix_socket_path = parsed.path if parsed.scheme == "unix" else None
        settings.ssl = parsed.scheme == "rediss"
        return settings


def test_shared_arq_settings_builder_forces_verified_rediss(monkeypatch):
    monkeypatch.setattr(qd, "_queue_redis_config", dict)
    monkeypatch.setenv(
        "MAVERICK_QUEUE_REDIS_DSN",
        "rediss://user:top-secret@redis.internal:6380/4",  # pragma: allowlist secret
    )
    settings = qd._configured_arq_redis_settings(_FakeRedisSettings)
    assert settings.host == "redis.internal"
    assert settings.ssl is True
    assert settings.ssl_cert_reqs == "required"
    assert settings.ssl_check_hostname is True


def test_arq_queue_names_are_explicit_and_fleet_isolated(monkeypatch):
    monkeypatch.setattr(qd, "_queue_redis_config", dict)
    monkeypatch.setenv("MAVERICK_QUEUE_NAMESPACE", "fleet-a")
    first = qd._configured_arq_queue_name()
    monkeypatch.setenv("MAVERICK_QUEUE_NAMESPACE", "fleet-b")
    second = qd._configured_arq_queue_name()
    assert first == "maverick:queue:fleet-a"
    assert second == "maverick:queue:fleet-b"
    assert first != second

    monkeypatch.delenv("MAVERICK_QUEUE_NAMESPACE")
    with pytest.raises(qd.QueueSecurityError, match="QUEUE_NAMESPACE"):
        qd._configured_arq_queue_name()


def test_packaged_arq_worker_has_matching_async_named_function(monkeypatch):
    captured = {}

    def func(coroutine, **kwargs):
        assert inspect.iscoroutinefunction(coroutine)
        captured["function"] = SimpleNamespace(coroutine=coroutine, **kwargs)
        return captured["function"]

    arq_module = ModuleType("arq")
    connections_module = ModuleType("arq.connections")
    connections_module.RedisSettings = _FakeRedisSettings
    worker_module = ModuleType("arq.worker")
    worker_module.func = func
    monkeypatch.setitem(sys.modules, "arq", arq_module)
    monkeypatch.setitem(sys.modules, "arq.connections", connections_module)
    monkeypatch.setitem(sys.modules, "arq.worker", worker_module)
    monkeypatch.setattr(qd, "_queue_redis_config", dict)
    monkeypatch.delenv("MAVERICK_QUEUE_REDIS_DSN", raising=False)
    sys.modules.pop("maverick.arq_worker", None)
    try:
        packaged = importlib.import_module("maverick.arq_worker")
        assert packaged.WorkerSettings.functions[0].name == qd.JOB_NAME
        assert packaged.WorkerSettings.functions[0].max_tries == 1
        assert packaged.WorkerSettings.job_serializer is qd._arq_safe_serialize
        assert packaged.WorkerSettings.job_deserializer is qd._arq_safe_deserialize
        assert packaged.WorkerSettings.queue_name == "maverick:queue:pytest-fleet"
        assert packaged.WorkerSettings.on_startup is packaged._preflight
        monkeypatch.setattr(packaged, "run_queued_goal", lambda payload: "done")
        result = asyncio.run(
            packaged.WorkerSettings.functions[0].coroutine({}, {"goal_id": 1})
        )
        assert result == "done"
        with pytest.raises(qd.QueueSecurityError, match="SIGNING_KEY"):
            asyncio.run(packaged.WorkerSettings.on_startup({}))
    finally:
        sys.modules.pop("maverick.arq_worker", None)


def test_packaged_arq_worker_job_timeout_follows_the_wall_ceiling(monkeypatch):
    """ARQ's 300 s default would cancel a long goal's job while its thread
    kept running; the deadline must cover the worker wall ceiling."""
    captured = {}

    def func(coroutine, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(coroutine=coroutine, **kwargs)

    connections_module = ModuleType("arq.connections")
    connections_module.RedisSettings = _FakeRedisSettings
    worker_module = ModuleType("arq.worker")
    worker_module.func = func
    monkeypatch.setitem(sys.modules, "arq", ModuleType("arq"))
    monkeypatch.setitem(sys.modules, "arq.connections", connections_module)
    monkeypatch.setitem(sys.modules, "arq.worker", worker_module)
    monkeypatch.setattr(qd, "_queue_redis_config", dict)
    monkeypatch.delenv("MAVERICK_QUEUE_REDIS_DSN", raising=False)
    monkeypatch.setenv("MAVERICK_QUEUE_WORKER_MAX_WALL_SECONDS", "7200")
    sys.modules.pop("maverick.arq_worker", None)
    try:
        packaged = importlib.import_module("maverick.arq_worker")
        assert captured["timeout"] > 7200
        assert packaged.WorkerSettings.job_timeout == captured["timeout"]
    finally:
        sys.modules.pop("maverick.arq_worker", None)


def test_real_arq_worker_constructs_with_safe_named_function(monkeypatch):
    arq_worker = pytest.importorskip("arq.worker")
    monkeypatch.setattr(qd, "_queue_redis_config", dict)
    monkeypatch.setenv("MAVERICK_QUEUE_NAMESPACE", "real-arq-test")
    sys.modules.pop("maverick.arq_worker", None)
    try:
        packaged = importlib.import_module("maverick.arq_worker")
        worker = arq_worker.create_worker(
            packaged.WorkerSettings,
            handle_signals=False,
        )
        assert qd.JOB_NAME in worker.functions
        assert worker.job_serializer is qd._arq_safe_serialize
        assert worker.job_deserializer is qd._arq_safe_deserialize
        assert worker.queue_name == "maverick:queue:real-arq-test"
    finally:
        sys.modules.pop("maverick.arq_worker", None)


def test_arq_producer_explicitly_installs_safe_codec(monkeypatch):
    captured = {}

    class Pool:
        async def enqueue_job(self, name, payload, **kwargs):
            captured["job"] = (name, payload, kwargs)
            return object()

        async def close(self):
            captured["closed"] = True

    async def create_pool(settings, **kwargs):
        captured["settings"] = settings
        captured["codec"] = kwargs
        return Pool()

    arq_module = ModuleType("arq")
    arq_module.create_pool = create_pool
    connections_module = ModuleType("arq.connections")
    connections_module.RedisSettings = type("RedisSettings", (), {})
    monkeypatch.setitem(sys.modules, "arq", arq_module)
    monkeypatch.setitem(sys.modules, "arq.connections", connections_module)

    settings = SimpleNamespace(
        host="localhost", unix_socket_path=None, ssl=False
    )
    enqueue = qd.arq_enqueue(settings)

    async def call_from_active_event_loop():
        enqueue(
            qd.JOB_NAME,
            {
                "message_id": "m",
                "nonce": "n",
                "expires_at": int(time.time()) + 60,
            },
        )

    asyncio.run(call_from_active_event_loop())

    assert captured["codec"] == {
        "job_serializer": qd._arq_safe_serialize,
        "job_deserializer": qd._arq_safe_deserialize,
        "default_queue_name": "maverick:queue:pytest-fleet",
    }
    assert captured["job"][2]["_job_id"].startswith("maverick-")
    assert 1 <= captured["job"][2]["_expires"] <= 60
    assert captured["closed"] is True


def test_queue_dispatcher_plugs_into_runner_seam():
    jobs = []
    original = runner.get_dispatcher()
    try:
        runner.set_dispatcher(qd.QueueDispatcher(lambda _name, payload: jobs.append(payload)))
        assert runner.run_goal_in_background(3, user_id="z") == qd.QUEUED_STATUS
        assert jobs and jobs[0]["goal_id"] == 3
        assert jobs[0]["sig"]
    finally:
        runner.set_dispatcher(original)


def test_install_from_config_noop_without_backend(monkeypatch):
    import maverick.config as cfg

    monkeypatch.setattr(cfg, "load_config", dict)
    original = runner.get_dispatcher()
    try:
        assert qd.install_from_config() is False
        assert runner.get_dispatcher() is original
    finally:
        runner.set_dispatcher(original)


def test_insecure_network_config_pins_fail_closed_dispatcher(monkeypatch):
    import maverick.config as cfg

    monkeypatch.setattr(cfg, "load_config", lambda: {"queue": {"backend": "arq"}})
    original = runner.get_dispatcher()
    try:
        with pytest.raises(qd.QueueSecurityError, match="requires"):
            qd.install_from_config()
        with pytest.raises(qd.QueueSecurityError, match="unavailable or insecure"):
            runner.get_dispatcher().submit(9)
    finally:
        runner.set_dispatcher(original)


def test_unknown_nonempty_queue_backend_pins_fail_closed_dispatcher(monkeypatch):
    import maverick.config as cfg

    monkeypatch.setattr(cfg, "load_config", lambda: {"queue": {"backend": "rq"}})
    original = runner.get_dispatcher()
    try:
        with pytest.raises(qd.QueueSecurityError, match="unsupported queue backend"):
            qd.install_from_config()
        with pytest.raises(qd.QueueSecurityError, match="unsupported queue backend"):
            runner.get_dispatcher().submit(9)
    finally:
        runner.set_dispatcher(original)


def test_channel_server_does_not_overwrite_failed_queue_with_grpc(monkeypatch):
    import maverick.server as server_mod

    calls = []
    original = runner.get_dispatcher()

    def broken_queue():
        runner.set_dispatcher(qd._FailClosedQueueDispatcher("bad queue"))
        calls.append("queue")
        raise qd.QueueSecurityError("bad queue")

    monkeypatch.setattr(qd, "install_from_config", broken_queue)
    monkeypatch.setattr(
        "maverick.grpc_dispatcher.install_from_config",
        lambda: calls.append("grpc") or True,
    )
    try:
        server_mod._install_goal_dispatcher()
        assert calls == ["queue"]
        with pytest.raises(qd.QueueSecurityError, match="bad queue"):
            runner.get_dispatcher().submit(1)
    finally:
        runner.set_dispatcher(original)
