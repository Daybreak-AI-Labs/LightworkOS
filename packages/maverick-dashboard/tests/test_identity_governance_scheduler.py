from __future__ import annotations

import copy
import hashlib
import json
import threading
from collections.abc import Mapping
from contextlib import contextmanager

import pytest
from maverick.privacy_ops import RecordConflict
from maverick_dashboard import identity_governance_scheduler as scheduler


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _pid(prefix: str, value: str) -> str:
    return f"{prefix}_{_sha(value)[:32]}"


class Clock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class FakeCASStore:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.records: dict[str, dict] = {}
        self.lock = threading.RLock()

    def authoritative_time(self) -> float:
        return self.clock()

    def get(self, record_id: str):
        with self.lock:
            value = self.records.get(record_id)
            return copy.deepcopy(value) if value is not None else None

    def create(self, record, *, action, actor, max_records=None):
        del action, actor, max_records
        with self.lock:
            record_id = record["id"]
            if record_id in self.records:
                raise RecordConflict("already exists")
            value = copy.deepcopy(record)
            value["revision"] = 1
            value["created_at"] = self.clock()
            value["updated_at"] = self.clock()
            self.records[record_id] = value
            return copy.deepcopy(value)

    def update(
        self,
        record_id,
        mutate,
        *,
        expected_revision,
        action,
        actor,
    ):
        del action, actor
        with self.lock:
            current = self.records.get(record_id)
            if current is None:
                return None
            if current["revision"] != expected_revision:
                raise RecordConflict("stale")
            value = copy.deepcopy(current)
            mutate(value)
            value["revision"] += 1
            value["updated_at"] = self.clock()
            self.records[record_id] = value
            return copy.deepcopy(value)


@contextmanager
def _tenant(value: str):
    from maverick.paths import reset_tenant, set_tenant

    token = set_tenant(value)
    try:
        yield
    finally:
        reset_tenant(token)


def _section(
    *providers: str,
    interval_seconds: int = 60,
    retry_base_seconds: int = 10,
    retry_max_seconds: int = 30,
    max_attempts_per_slot: int = 2,
    history_limit: int = 3,
    max_snapshot_items: int = 100,
    max_delta_digests: int = 10,
    poll_seconds: float = 5.0,
) -> dict:
    value: dict = {
        "enable": True,
        "scheduler": {
            "enable": True,
            "poll_seconds": poll_seconds,
            "providers": {},
        },
    }
    for provider in providers:
        value[provider] = {
            "enable": True,
            "tenant_id": f"raw-{provider}-tenant@example.invalid",
            "base_url": f"https://raw-{provider}.example.invalid",
            "credential_secret_ref": f"RAW_{provider.upper()}_TOKEN",
        }
        value["scheduler"]["providers"][provider] = {
            "enable": True,
            "interval_seconds": interval_seconds,
            "retry_base_seconds": retry_base_seconds,
            "retry_max_seconds": retry_max_seconds,
            "max_attempts_per_slot": max_attempts_per_slot,
            "lease_seconds": 60,
            "history_limit": history_limit,
            "max_snapshot_items": max_snapshot_items,
            "max_delta_digests": max_delta_digests,
        }
    return value


def _snapshot(
    provider: str,
    version: str = "one",
    *,
    identity_count: int = 1,
    extra_identity_field: tuple[str, object] | None = None,
) -> dict:
    identities = []
    for index in range(identity_count):
        identity = {
            "observation_id": _pid("idn", f"{provider}:{version}:{index}"),
            "identity_kind": "application",
            "enabled": True,
            "assignment_required": None,
            "source_sha256": _sha(f"identity:{provider}:{version}:{index}"),
        }
        if extra_identity_field is not None:
            identity[extra_identity_field[0]] = extra_identity_field[1]
        identities.append(identity)
    grants = [
        {
            "observation_id": _pid("grt", f"grant:{provider}:{version}"),
            "subject_id": _pid("sub", f"subject:{provider}:{version}"),
            "resource_id": _pid("res", f"resource:{provider}:{version}"),
            "grant_kind": "application_role",
            "subject_kind": "service_principal",
            "permission_id": _pid("prm", f"permission:{provider}:{version}"),
            "source_sha256": _sha(f"grant-source:{provider}:{version}"),
        }
    ]
    classifications = [
        {
            "observation_id": _pid("cls", f"classification:{provider}:{version}"),
            "asset_id": _pid("ast", f"asset:{provider}:{version}"),
            "entity_type": "DataSet",
            "classification_codes": ["Confidential"],
            "label_codes": ["Internal"],
            "source_sha256": _sha(f"classification-source:{provider}:{version}"),
        }
    ]
    return {
        "schema": "lightwork.identity_governance.snapshot.v1",
        "provider": provider,
        "tenant_sha256": _sha(f"provider-tenant:{provider}"),
        "configuration_sha256": _sha(f"provider-config:{provider}"),
        "observed_at": "2026-08-28T12:00:00Z",
        "source_sha256": _sha(f"source:{provider}:{version}"),
        "identities": identities,
        "grants": grants,
        "data_classifications": classifications,
        "coverage": "bounded_read_only_snapshot",
        "live_acceptance_verified": False,
        "complete_inventory_claimed": False,
    }


def _schedule(section: Mapping, provider: str = "entra"):
    return {item.provider: item for item in scheduler.configured_schedules(section)}[provider]


def _only_record(store: FakeCASStore) -> dict:
    assert len(store.records) == 1
    return next(iter(store.records.values()))


def test_schedules_are_strict_bounded_and_opt_in() -> None:
    assert scheduler.configured_schedules({}) == ()
    assert scheduler.configured_schedules({"enable": True}) == ()

    disabled = _section("entra")
    disabled["entra"]["enable"] = False
    with pytest.raises(scheduler.IdentityGovernanceScheduleError, match="explicitly"):
        scheduler.configured_schedules(disabled)

    too_fast = _section("entra")
    too_fast["scheduler"]["providers"]["entra"]["interval_seconds"] = 59
    with pytest.raises(scheduler.IdentityGovernanceScheduleError, match="between 60"):
        scheduler.configured_schedules(too_fast)

    unbounded = _section("entra")
    unbounded["scheduler"]["providers"]["entra"]["max_snapshot_items"] = 10_001
    with pytest.raises(scheduler.IdentityGovernanceScheduleError, match="10000"):
        scheduler.configured_schedules(unbounded)

    invalid_poll = _section("entra")
    invalid_poll["scheduler"]["poll_seconds"] = float("inf")
    with pytest.raises(scheduler.IdentityGovernanceScheduleError, match="between 5"):
        scheduler.configured_schedules(invalid_poll)


def test_schedule_allows_control_metadata_but_never_passes_it_to_collector() -> None:
    clock = Clock()
    store = FakeCASStore(clock)
    captured = []

    def collect(section, provider):
        captured.append((section, provider))
        return _snapshot(provider)

    section = _section("entra")
    section["controls"] = {
        "enable": True,
        "change_coupling": {
            "enable": True,
            "dynamic_risk": True,
            "alerts": False,
        },
    }
    engine = scheduler.IdentityGovernanceScheduler(
        store=store,
        collector=collect,
        clock=clock,
    )
    with _tenant("tenant-alpha"):
        result = engine.run_provider(
            section,
            _schedule(section),
            actor="system:test",
        )

    assert result["collected"] is True
    assert len(captured) == 1
    assert "scheduler" not in captured[0][0]
    assert "controls" not in captured[0][0]


def test_control_tenant_binding_requires_explicit_tenant() -> None:
    with pytest.raises(scheduler.IdentityGovernanceScheduleError, match="explicit tenant"):
        scheduler.tenant_binding_sha256(require_explicit=True)
    with _tenant("tenant-alpha"):
        strict = scheduler.tenant_binding_sha256(require_explicit=True)
        compatible = scheduler.tenant_binding_sha256()
    assert strict == compatible
    assert len(strict) == 64


def test_disabled_status_does_not_resolve_tenant_clock_or_store() -> None:
    class DisabledStore:
        def authoritative_time(self):
            raise AssertionError("disabled status must not resolve a clock")

        def get(self, _record_id):
            raise AssertionError("disabled status must not read state")

    engine = scheduler.IdentityGovernanceScheduler(store=DisabledStore())
    status = engine.status({})
    assert status["enabled"] is False
    assert status["tenant_sha256"] is None
    assert status["providers"] == []
    assert status["risk_generated"] is False


def test_duplicate_slots_and_unchanged_snapshots_do_not_repeat_callback() -> None:
    clock = Clock()
    store = FakeCASStore(clock)
    calls: list[Mapping] = []
    collections = 0

    def collect(_section, provider):
        nonlocal collections
        collections += 1
        return _snapshot(provider)

    engine = scheduler.IdentityGovernanceScheduler(
        store=store,
        collector=collect,
        clock=clock,
        change_callback=calls.append,
    )
    section = _section("entra")
    schedule = _schedule(section)
    with _tenant("tenant-alpha"):
        first = engine.run_provider(section, schedule, actor="system:test")
        duplicate = engine.run_provider(section, schedule, actor="system:test")
        clock.advance(61)
        unchanged = engine.run_provider(section, schedule, actor="system:test")

    assert first["collected"] is True
    assert first["changed"] is True
    assert duplicate["reason"] == "duplicate_slot"
    assert unchanged["collected"] is True
    assert unchanged["changed"] is False
    assert collections == 2
    assert len(calls) == 1
    assert calls[0]["delta"]["change_kind"] == "baseline"
    assert calls[0]["risk_generated"] is False
    record = _only_record(store)
    assert len(record["history"]) == 2
    assert record["last_delta"]["changed"] is False
    assert record["source_state"] == "incomplete"
    assert record["source_complete"] is False


def test_changes_emit_exact_counts_and_only_bounded_digests() -> None:
    clock = Clock()
    store = FakeCASStore(clock)
    version = "one"
    callbacks: list[Mapping] = []

    def collect(_section, provider):
        count = 1 if version == "one" else 3
        return _snapshot(provider, version, identity_count=count)

    engine = scheduler.IdentityGovernanceScheduler(
        store=store,
        collector=collect,
        clock=clock,
        change_callback=callbacks.append,
    )
    section = _section("entra", max_delta_digests=1)
    schedule = _schedule(section)
    with _tenant("tenant-alpha"):
        engine.run_provider(section, schedule, actor="system:test")
        version = "two"
        clock.advance(61)
        result = engine.run_provider(section, schedule, actor="system:test")

    assert result["changed"] is True
    assert len(callbacks) == 2
    delta = callbacks[-1]["delta"]
    identities = delta["categories"]["identities"]
    assert identities["added_count"] == 3
    assert identities["removed_count"] == 1
    assert len(identities["added_sha256"]) == 1
    assert identities["digests_truncated"] is True
    assert delta["risk_generated"] is False
    assert callbacks[-1]["source_complete"] is False
    assert callbacks[-1]["live_acceptance_verified"] is False
    assert not any(
        key in json.dumps(callbacks[-1]).lower()
        for key in ("email", "token", "subject_id", "observation_id")
    )


def test_failure_backoff_exhaustion_and_recovery_hide_exception_text() -> None:
    clock = Clock()
    store = FakeCASStore(clock)
    attempts = 0

    def collect(_section, provider):
        nonlocal attempts
        attempts += 1
        if attempts <= 2:
            raise RuntimeError("Bearer sk-live-secret for person@example.invalid")
        return _snapshot(provider, "recovered")

    engine = scheduler.IdentityGovernanceScheduler(
        store=store,
        collector=collect,
        clock=clock,
    )
    section = _section("entra", max_attempts_per_slot=2)
    schedule = _schedule(section)
    with _tenant("tenant-alpha"):
        first = engine.run_provider(section, schedule, actor="system:test")
        clock.advance(5)
        waiting = engine.run_provider(section, schedule, actor="system:test")
        clock.advance(5)
        exhausted = engine.run_provider(section, schedule, actor="system:test")
        clock.advance(11)
        recovered = engine.run_provider(section, schedule, actor="system:test")

    assert first["reason"] == "collection_failed"
    assert waiting["reason"] == "backoff"
    assert exhausted["reason"] == "collection_failed"
    assert recovered["collected"] is True
    assert recovered["health"] == "healthy"
    assert attempts == 3
    record = _only_record(store)
    assert record["consecutive_failures"] == 0
    assert record["last_error_type"] is None
    persisted = json.dumps(store.records, sort_keys=True)
    assert "sk-live-secret" not in persisted
    assert "person@example.invalid" not in persisted
    assert "Bearer" not in persisted


def test_tenants_and_providers_have_separate_state_without_raw_tenant_names() -> None:
    clock = Clock()
    store = FakeCASStore(clock)
    engine = scheduler.IdentityGovernanceScheduler(
        store=store,
        collector=lambda _section, provider: _snapshot(provider),
        clock=clock,
    )
    section = _section("entra", "okta")
    schedules = {item.provider: item for item in scheduler.configured_schedules(section)}
    with _tenant("tenant-alpha@example.invalid"):
        engine.run_provider(section, schedules["entra"], actor="system:test")
        engine.run_provider(section, schedules["okta"], actor="system:test")
    with _tenant("tenant-beta@example.invalid"):
        engine.run_provider(section, schedules["entra"], actor="system:test")

    assert len(store.records) == 3
    assert len({row["tenant_sha256"] for row in store.records.values()}) == 2
    assert {row["provider"] for row in store.records.values()} == {"entra", "okta"}
    persisted = json.dumps(store.records, sort_keys=True)
    assert "tenant-alpha" not in persisted
    assert "tenant-beta" not in persisted
    assert "RAW_ENTRA_TOKEN" not in persisted
    assert "RAW_OKTA_TOKEN" not in persisted


@pytest.mark.parametrize(
    ("max_items", "snapshot_factory", "forbidden"),
    [
        (2, lambda: _snapshot("entra", identity_count=2), None),
        (
            100,
            lambda: _snapshot(
                "entra",
                extra_identity_field=("email", "person@example.invalid"),
            ),
            "person@example.invalid",
        ),
    ],
)
def test_item_limits_and_unexpected_fields_fail_closed(
    max_items, snapshot_factory, forbidden
) -> None:
    clock = Clock()
    store = FakeCASStore(clock)
    engine = scheduler.IdentityGovernanceScheduler(
        store=store,
        collector=lambda _section, _provider: snapshot_factory(),
        clock=clock,
    )
    section = _section("entra", max_snapshot_items=max_items)
    schedule = _schedule(section)
    with _tenant("tenant-alpha"):
        result = engine.run_provider(section, schedule, actor="system:test")

    assert result["reason"] == "collection_failed"
    record = _only_record(store)
    assert record["source_state"] == "unavailable"
    assert record["current"] is None
    if forbidden is not None:
        assert forbidden not in json.dumps(store.records, sort_keys=True)


def test_single_process_overlap_is_prevented_across_engine_instances() -> None:
    clock = Clock()
    store = FakeCASStore(clock)
    entered = threading.Event()
    release = threading.Event()
    results: list[dict] = []
    collections = 0

    def collect(_section, provider):
        nonlocal collections
        collections += 1
        entered.set()
        assert release.wait(5)
        return _snapshot(provider)

    section = _section("entra")
    schedule = _schedule(section)
    first = scheduler.IdentityGovernanceScheduler(
        store=store,
        collector=collect,
        clock=clock,
    )
    second = scheduler.IdentityGovernanceScheduler(
        store=store,
        collector=collect,
        clock=clock,
    )

    def worker() -> None:
        with _tenant("tenant-alpha"):
            results.append(first.run_provider(section, schedule, actor="system:first"))

    thread = threading.Thread(target=worker)
    thread.start()
    assert entered.wait(5)
    with _tenant("tenant-alpha"):
        overlap = second.run_provider(section, schedule, actor="system:second")
    release.set()
    thread.join(5)

    assert not thread.is_alive()
    assert overlap["reason"] == "overlap"
    assert results[0]["collected"] is True
    assert collections == 1


def test_callback_failure_is_retried_without_recollection_and_recovers() -> None:
    clock = Clock()
    store = FakeCASStore(clock)
    callback_attempts = 0
    collections = 0
    seen: list[Mapping] = []

    def collect(_section, provider):
        nonlocal collections
        collections += 1
        return _snapshot(provider)

    def callback(payload):
        nonlocal callback_attempts
        callback_attempts += 1
        seen.append(payload)
        if callback_attempts == 1:
            raise RuntimeError("callback secret must not persist")

    engine = scheduler.IdentityGovernanceScheduler(
        store=store,
        collector=collect,
        clock=clock,
        change_callback=callback,
    )
    section = _section("entra")
    schedule = _schedule(section)
    with _tenant("tenant-alpha"):
        first = engine.run_provider(section, schedule, actor="system:test")
        clock.advance(5)
        waiting = engine.run_provider(section, schedule, actor="system:test")
        clock.advance(5)
        retried = engine.run_provider(section, schedule, actor="system:test")

    assert first["callback_status"] == "failed"
    assert first["health"] == "degraded"
    assert waiting["reason"] == "duplicate_slot"
    assert waiting["callback_status"] == "backoff"
    assert retried["reason"] == "duplicate_slot"
    assert retried["callback_status"] == "delivered"
    assert callback_attempts == 2
    assert collections == 1
    assert seen[0]["change_sha256"] == seen[1]["change_sha256"]
    record = _only_record(store)
    assert record["pending_changes"] == []
    assert record["callback_health"] == "healthy"
    assert record["health"] == "healthy"
    assert "callback secret" not in json.dumps(store.records, sort_keys=True)


def test_history_is_bounded_and_omits_per_item_digest_lists() -> None:
    clock = Clock()
    store = FakeCASStore(clock)
    version = 0

    def collect(_section, provider):
        return _snapshot(provider, str(version))

    engine = scheduler.IdentityGovernanceScheduler(
        store=store,
        collector=collect,
        clock=clock,
    )
    section = _section("entra", history_limit=2)
    schedule = _schedule(section)
    with _tenant("tenant-alpha"):
        for index in range(4):
            version = index
            engine.run_provider(section, schedule, actor="system:test")
            clock.advance(61)

    record = _only_record(store)
    assert len(record["history"]) == 2
    assert all("item_digests" not in row["snapshot"] for row in record["history"])
    assert "item_digests" in record["current"]


def test_status_is_read_only_sanitized_and_tenant_scoped() -> None:
    clock = Clock()
    store = FakeCASStore(clock)
    engine = scheduler.IdentityGovernanceScheduler(
        store=store,
        collector=lambda _section, provider: _snapshot(provider),
        clock=clock,
    )
    section = _section("entra")
    schedule = _schedule(section)
    with _tenant("tenant-alpha@example.invalid"):
        before = engine.status(section)
        engine.run_provider(section, schedule, actor="system:test")
        revisions = {key: row["revision"] for key, row in store.records.items()}
        after = engine.status(section)
    with _tenant("tenant-beta@example.invalid"):
        other_tenant = engine.status(section)

    assert before["providers"][0]["health"] == "never_run"
    provider = after["providers"][0]
    assert provider["health"] == "healthy"
    assert provider["source_state"] == "incomplete"
    assert provider["source_complete"] is False
    assert provider["counts"] == {
        "data_classifications": 1,
        "grants": 1,
        "identities": 1,
        "total": 3,
    }
    assert provider["risk_generated"] is False
    assert after["tenant_sha256"] != other_tenant["tenant_sha256"]
    assert other_tenant["providers"][0]["health"] == "never_run"
    assert {key: row["revision"] for key, row in store.records.items()} == revisions
    serialized = json.dumps(after, sort_keys=True)
    assert "tenant-alpha@example.invalid" not in serialized
    assert "observation_id" not in serialized
    assert "subject_id" not in serialized


def test_default_collector_uses_runtime_seam_without_scheduler_keys(monkeypatch) -> None:
    from maverick_dashboard import identity_governance_runtime

    clock = Clock()
    store = FakeCASStore(clock)
    received: list[Mapping] = []

    def collect(section, provider):
        received.append(section)
        return _snapshot(provider)

    monkeypatch.setattr(identity_governance_runtime, "collect_connector", collect)
    engine = scheduler.IdentityGovernanceScheduler(store=store, clock=clock)
    section = _section("entra")
    with _tenant("tenant-alpha"):
        result = engine.run_provider(
            section,
            _schedule(section),
            actor="system:test",
        )

    assert result["collected"] is True
    assert len(received) == 1
    assert "scheduler" not in received[0]
    assert received[0]["entra"]["enable"] is True


def test_supervisor_start_is_singleton_and_shutdown_is_bounded() -> None:
    section = _section("entra")
    entered = threading.Event()

    def cycle(_actor):
        entered.set()

    try:
        assert scheduler.start_identity_governance_scheduler(
            section=section,
            cycle_runner=cycle,
        )
        assert entered.wait(5)
        assert not scheduler.start_identity_governance_scheduler(
            section=section,
            cycle_runner=cycle,
        )
        assert scheduler.stop_identity_governance_scheduler(timeout=1)
        assert not scheduler.stop_identity_governance_scheduler(timeout=1)
    finally:
        scheduler.stop_identity_governance_scheduler(timeout=1)


def test_supervisor_can_start_before_tenant_provider_schedules_are_enabled() -> None:
    """The global opt-in keeps polling so later tenant schedules are discovered."""

    entered = threading.Event()

    def cycle(_actor):
        entered.set()

    try:
        assert scheduler.start_identity_governance_scheduler(
            section=_section(),
            cycle_runner=cycle,
        )
        assert entered.wait(5)
        assert scheduler.stop_identity_governance_scheduler(timeout=1)
    finally:
        scheduler.stop_identity_governance_scheduler(timeout=1)
