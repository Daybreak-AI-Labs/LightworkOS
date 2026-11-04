"""A failed file-lock acquisition must not strand earlier store locks."""
from __future__ import annotations

import importlib
import threading
from contextlib import contextmanager

import pytest

# Store entry points, including the already-correct Settings implementation.
STORES = [
    ("maverick.agent_trust", "_managed_locked", "_MANAGED_LOCK", False, True),
    ("maverick.external_agents", "_sidecar_locked", None, False, True),
    ("maverick.tenant.registry", "_locked", "_REGISTRY_LOCK", False, True),
    ("maverick.suite_grants", "_locked", "_GRANTS_LOCK", True, True),
    ("maverick.voice_unlock", "VoiceGate", "_lock", False, False),
    ("maverick_dashboard.event_triggers_store", "_locked", "_LOCK", False, False),
    ("maverick_dashboard.invites", "_locked", "_INVITES_LOCK", True, False),
    ("maverick_dashboard.rbac", "_locked", "_RBAC_LOCK", True, True),
    ("maverick_dashboard.scim", "_locked_users", "_USERS_LOCK", False, True),
    ("maverick_dashboard.scim", "_locked_groups", "_GROUPS_LOCK", False, True),
    ("maverick_dashboard.triggers_store", "_locked", "_TRIGGERS_LOCK", False, False),
    ("maverick_dashboard.ui_visibility", "_locked", "_VIS_LOCK", True, False),
    ("maverick_dashboard.workspace_tenants", "_locked", "_LOCK", True, True),
    ("maverick_dashboard.settings_store", "_locked", "_SETTINGS_LOCK", False, True),
]


class InterruptedAcquisition(BaseException):
    """Cancellation must unwind locks just as an ordinary I/O error does."""


@pytest.fixture
def isolated_home(monkeypatch, tmp_path):
    from maverick import client, config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    configuration = tmp_path / "config.toml"
    configuration.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(configuration))
    config.reset_config_cache()
    client.reset_client_cache()
    yield tmp_path
    config.reset_config_cache()
    client.reset_client_cache()


@pytest.mark.parametrize("store", STORES, ids=[f"{row[0]}.{row[1]}" for row in STORES])
@pytest.mark.parametrize("error_type", [PermissionError, InterruptedAcquisition])
def test_failed_acquisition_unwinds_and_next_attempt_can_enter(monkeypatch, isolated_home, store, error_type):
    from maverick import authority_effects, file_lock

    module_name, name, lock_name, takes_path, fenced = store
    if module_name.startswith("maverick_dashboard."):
        pytest.importorskip("maverick_dashboard")
    module = importlib.import_module(module_name)
    target = isolated_home / "state.json"
    owner = module
    if name == "VoiceGate":
        owner = module.VoiceGate(lambda _audio: [1.0], store_path=target)
        acquire = owner._locked
    elif name in {"OutboundQueue", "PushRegistry"}:
        owner = getattr(module, name)(path=target)
        acquire = owner._locked
    else:
        acquire = getattr(module, name)
    lock = threading.Lock() if lock_name else None
    if lock is not None:
        monkeypatch.setattr(owner, lock_name, lock)
    active_fences = set()

    @contextmanager
    def authority_fence():
        token = object()
        active_fences.add(token)
        try:
            yield
        finally:
            active_fences.discard(token)

    attempts = []

    @contextmanager
    def file_guard(path, **kwargs):
        assert bool(active_fences) is fenced
        assert lock is None or lock.locked()
        attempts.append((path, kwargs))
        if len(attempts) == 1:
            raise error_type("file lock unavailable")
        yield

    monkeypatch.setattr(authority_effects, "authority_effect_fence", authority_fence)
    monkeypatch.setattr(file_lock, "cross_process_lock", file_guard)
    if hasattr(module, "cross_process_lock"):
        monkeypatch.setattr(module, "cross_process_lock", file_guard)
    arguments = (target,) if takes_path else ()
    try:
        # Keep the exception alive, as an HTTP error/logger may do. Cleanup
        # must be deterministic, not depend on traceback garbage collection.
        with pytest.raises(error_type, match="file lock unavailable") as caught:
            with acquire(*arguments):
                pytest.fail("the failed acquisition admitted a mutation")
        assert caught.value is not None
        assert lock is None or not lock.locked(), "store lock remained held"
        assert not active_fences, "global authority fence remained held"
        with acquire(*arguments):
            assert lock is None or lock.locked()
            assert bool(active_fences) is fenced
        assert len(attempts) == 2
        assert lock is None or not lock.locked()
        assert not active_fences
    finally:
        # A failing baseline must not hang later tests on its private lock.
        if lock is not None and lock.locked():
            lock.release()


def test_workspace_selection_recovers_after_real_lock_file_obstruction(monkeypatch, isolated_home):
    workspace_tenants = pytest.importorskip("maverick_dashboard.workspace_tenants")
    lock = threading.Lock()
    monkeypatch.setattr(workspace_tenants, "_LOCK", lock)
    target = workspace_tenants.store_path()
    obstruction = target.with_name(target.name + ".lock")
    obstruction.mkdir()
    try:
        with pytest.raises(OSError) as caught:
            workspace_tenants.set_selection("user:alice", "tenant-a")
        assert caught.value is not None
        assert not target.exists(), "failed acquisition must not write state"
        assert not lock.locked(), "workspace selection lock remained held"
        obstruction.rmdir()
        workspace_tenants.set_selection("user:alice", "tenant-a")
        assert workspace_tenants.get_selection_binding("user:alice") == ("tenant-a", 1)
        workspace_tenants.set_selection("user:alice", None)
        assert workspace_tenants.get_selection_binding("user:alice") == (None, 2)
    finally:
        if lock.locked():
            lock.release()
