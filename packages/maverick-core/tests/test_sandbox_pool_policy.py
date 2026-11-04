"""Synthetic daemon tests of explicit transfer and the actual runner lifecycle."""
from __future__ import annotations

import gc
import hashlib
import subprocess
import threading
import weakref
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest
import pytest as _workspace_guard_pytest
from maverick.sandbox import build_sandbox, pool
from maverick.sandbox.container_cleanup import ContainerCleanup
from maverick.sandbox.docker import DockerBackend
from maverick.sandbox.podman import PodmanBackend


def _digest(image):
    return image if image.startswith("sha256:") else "sha256:" + hashlib.sha256(image.encode()).hexdigest()


@pytest.fixture
def daemon(monkeypatch):
    """Every daemon response is synthetic; unexpected subprocesses fail."""
    calls = []

    def run(args, **_kwargs):
        calls.append(list(args))
        assert args[0] in {"docker", "podman"}
        if args[1] == "version":
            return subprocess.CompletedProcess(args, 0, "version", "")
        if args[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(args, 0, _digest(args[-1]), "")
        if args[1] == "run":
            return subprocess.CompletedProcess(args, 0, "ok", "")
        raise AssertionError(args)

    monkeypatch.setattr(subprocess, "run", run)
    pool.reset_shared_pool()
    yield calls
    pool.reset_shared_pool()


def _config(monkeypatch, **options):
    from maverick import config
    full = {"backend": "docker", "cross_run_pool": True, **options}
    monkeypatch.setattr(config, "load_config", lambda: {"sandbox": full})
    monkeypatch.setattr(config, "get_sandbox", lambda: {"backend": full["backend"], "timeout": 60})


@pytest.mark.parametrize("backend,engine", [(DockerBackend, "docker"), (PodmanBackend, "podman")])
def test_handoff_retires_old_handle_and_reconstructs_every_lease(tmp_path, daemon, backend, engine):
    original = backend(workdir=tmp_path / "old", image="reviewed:tag")
    transfers = pool.SandboxPool()
    assert transfers.park(original)
    snapshot = transfers._entries[0].policy
    with pytest.raises(FrozenInstanceError):
        snapshot.allow_network = True
    fresh = transfers.acquire(engine, "reviewed:tag", workdir=tmp_path / "new", timeout=42)
    assert type(fresh) is backend and fresh is not original
    assert fresh.image == _digest("reviewed:tag")
    assert fresh.timeout == 42 and fresh.workdir == tmp_path / "new"
    original.workdir = tmp_path / "somewhere-else"
    with pytest.raises(RuntimeError, match="lease was transferred"):
        original.exec("old reference")
    assert fresh.exec("new lease").stdout == "ok"
    run = next(call for call in daemon if call[1] == "run")
    assert str((tmp_path / "old").resolve()) not in " ".join(run)
    assert str((tmp_path / "new").resolve()) in " ".join(run)
    assert _digest("reviewed:tag") in run
    assert transfers.park(fresh)
    third = transfers.acquire(engine, "reviewed:tag", workdir=tmp_path / "third", timeout=5)
    assert third is not fresh and third is not original


@pytest.mark.parametrize("change", [
    {"allow_network": True}, {"allow_root": True}, {"pids_limit": 128},
    {"memory": "1g"}, {"cpus": "0.5"}, {"runtime": "runsc"},
])
def test_each_security_flag_mismatch_preserves_entry_for_matching_policy(tmp_path, daemon, change):
    transfers = pool.SandboxPool()
    original = DockerBackend(workdir=tmp_path)
    assert transfers.park(original)
    assert transfers.acquire("docker", original.image, workdir=tmp_path, timeout=60, **change) is None
    assert len(transfers) == 1
    assert transfers.acquire("docker", original.image, workdir=tmp_path, timeout=60) is not None


@pytest.mark.parametrize("engine,backend", [("docker", DockerBackend), ("podman", PodmanBackend)])
def test_requested_flags_are_rebuilt_not_copied_from_old_handle(tmp_path, daemon, engine, backend):
    options = dict(allow_network=True, allow_root=True, pids_limit=73, memory="2g", cpus="0.25")
    if engine == "docker":
        options["runtime"] = "runsc"
    original = backend(workdir=tmp_path / "old", **options)
    transfers = pool.SandboxPool()
    assert transfers.park(original)
    fresh = transfers.acquire(engine, original.image, workdir=tmp_path / "new", timeout=80, **options)
    assert all(getattr(fresh, key) == value for key, value in options.items())
    assert fresh.exec("flags").ok
    run = next(call for call in daemon if call[1] == "run")
    assert "--network" not in run and "--user" not in run
    assert run[run.index("--pids-limit") + 1] == "73"
    assert run[run.index("--memory") + 1] == "2g"
    assert run[run.index("--cpus") + 1] == "0.25"
    if engine == "docker":
        assert run[run.index("--runtime") + 1] == "runsc"


def test_old_protected_mount_rejected_and_new_protected_mount_built_fresh(tmp_path, daemon, monkeypatch):
    old = tmp_path / "old"
    (old / "protected").mkdir(parents=True)
    original = DockerBackend(workdir=old, read_only_paths=("protected",))
    assert not pool.shared_pool().park(original)
    clean = DockerBackend(workdir=tmp_path / "clean")
    assert pool.shared_pool().park(clean)
    new = tmp_path / "new"
    (new / "protected").mkdir(parents=True)
    _config(monkeypatch, read_only_paths=["protected"])
    fresh = build_sandbox(workdir=new)
    assert fresh.read_only_paths == ("protected",)
    assert fresh._read_only_mounts[0][0] == (new / "protected").resolve()
    assert len(pool.shared_pool()) == 1  # protected config never acquires a policy


@pytest.mark.parametrize("state", ["credential", "mount_cache", "warm", "pending_cleanup", "legacy", "invalid_flag"])
def test_unknown_or_unsafe_instance_state_cannot_be_parked(tmp_path, daemon, state):
    original = DockerBackend(workdir=tmp_path)
    if state == "credential":
        original.access_token = "synthetic-secret"
    elif state == "mount_cache":
        original._read_only_mounts = ((tmp_path, "/workspace/old"),)
    elif state == "warm":
        original._warm_name = "maverick-warm-existing"
    elif state == "pending_cleanup":
        original.pending_cleanup["maverick-owned"] = ContainerCleanup("docker", "maverick-owned", False, 1, "failed")
    elif state == "legacy":
        del original._pool_lease
    else:
        original.allow_network = "false"
    before = len(daemon)
    assert pool.SandboxPool().park(original) is False
    assert len(daemon) == before


def test_subclasses_and_unknown_backends_are_excluded(tmp_path, daemon):
    class CredentialBackend(DockerBackend):
        access_token = "synthetic-secret"
    assert not pool.SandboxPool().park(CredentialBackend(workdir=tmp_path))
    assert not pool.SandboxPool().park(object())


def test_pool_retains_no_backend_or_source_workspace_reference(tmp_path, daemon):
    transfers = pool.SandboxPool()
    original = DockerBackend(workdir=tmp_path)
    reference = weakref.ref(original)
    assert transfers.park(original)
    del original
    gc.collect()
    assert reference() is None
    assert not hasattr(transfers._entries[0], "sandbox")


@pytest.mark.parametrize("response", ["", "python:tag", "sha256:abc", "secret-error"])
def test_unavailable_or_malformed_digest_never_falls_back_to_tag(tmp_path, daemon, monkeypatch, response):
    original = DockerBackend(workdir=tmp_path)
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: subprocess.CompletedProcess(args, 0, response, ""))
    assert pool._image_digest("docker", original.image) is None
    assert not pool.SandboxPool().park(original)


def test_digest_lookup_failure_and_moved_image_refuse_acquire(tmp_path, daemon, monkeypatch):
    transfers = pool.SandboxPool()
    original = DockerBackend(workdir=tmp_path)
    assert transfers.park(original)
    monkeypatch.setattr(pool, "_image_digest", lambda *a: None)
    assert transfers.acquire("docker", original.image, workdir=tmp_path, timeout=60) is None
    monkeypatch.setattr(pool, "_image_digest", lambda *a: "sha256:" + "f" * 64)
    assert transfers.acquire("docker", original.image, workdir=tmp_path, timeout=60) is None
    assert len(transfers) == 1


def test_client_environment_and_effective_user_changes_invalidate_policy(tmp_path, daemon, monkeypatch):
    transfers = pool.SandboxPool()
    original = DockerBackend(workdir=tmp_path)
    assert transfers.park(original)
    with monkeypatch.context() as changed:
        changed.setenv("DOCKER_CONTEXT", "different-daemon")
        assert transfers.acquire("docker", original.image, workdir=tmp_path, timeout=60) is None
    with monkeypatch.context() as changed:
        changed.setattr(pool, "container_user_args", lambda _: ["--user", "different-user"])
        assert transfers.acquire("docker", original.image, workdir=tmp_path, timeout=60) is None
    assert transfers.acquire("docker", original.image, workdir=tmp_path, timeout=60) is not None


def test_nonzero_and_unavailable_image_probe_never_retire_handle(tmp_path, daemon, monkeypatch):
    original = DockerBackend(workdir=tmp_path)
    with monkeypatch.context() as changed:
        changed.setattr(subprocess, "run", lambda args, **kw: subprocess.CompletedProcess(
            args, 1, _digest(original.image), "synthetic credential must not be logged"))
        assert not pool.SandboxPool().park(original)

    def unavailable(*args, **kwargs):
        raise OSError("synthetic credential must not be logged")

    with monkeypatch.context() as changed:
        changed.setattr(subprocess, "run", unavailable)
        assert not pool.SandboxPool().park(original)
    assert original.exec("still owns lease").ok


def test_execution_started_during_park_probe_prevents_retirement(tmp_path, daemon, monkeypatch):
    original = DockerBackend(workdir=tmp_path)
    inspecting, finish_probe = threading.Event(), threading.Event()

    def inspect_image(engine, image):
        inspecting.set()
        assert finish_probe.wait(5)
        return _digest(image)

    monkeypatch.setattr(pool, "_image_digest", inspect_image)
    with ThreadPoolExecutor(max_workers=1) as executor:
        parking = executor.submit(pool.SandboxPool().park, original)
        assert inspecting.wait(5)
        with original._pool_lease.operation():
            finish_probe.set()
            assert parking.result(timeout=5) is False
    assert original.exec("still owns lease").ok


def test_active_execution_and_cleanup_cannot_transfer_ownership(tmp_path, daemon, monkeypatch):
    original = DockerBackend(workdir=tmp_path)
    entered, release = threading.Event(), threading.Event()
    real_run = subprocess.run

    def blocked_run(args, **kw):
        if args[1] == "run":
            entered.set()
            assert release.wait(5)
        return real_run(args, **kw)

    monkeypatch.setattr(subprocess, "run", blocked_run)
    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(original.exec, "long operation")
        assert entered.wait(5)
        assert not pool.SandboxPool().park(original)
        release.set()
        assert running.result(timeout=5).ok
    with original._pool_lease.operation(cleanup=True):
        assert not pool.SandboxPool().park(original)
    assert pool.SandboxPool().park(original)


def test_policy_change_during_digest_probe_aborts_transfer(tmp_path, daemon, monkeypatch):
    original = DockerBackend(workdir=tmp_path)

    def change_policy(engine, image):
        original.allow_network = True
        return _digest(image)

    monkeypatch.setattr(pool, "_image_digest", change_policy)
    assert not pool.SandboxPool().park(original)
    assert original.exec("still owned").ok


def test_concurrent_parking_and_acquisition_never_duplicate_a_lease(tmp_path, daemon):
    original = DockerBackend(workdir=tmp_path)
    transfers = pool.SandboxPool()
    barrier = threading.Barrier(8)

    def park(_):
        barrier.wait(timeout=5)
        return transfers.park(original)

    with ThreadPoolExecutor(max_workers=8) as executor:
        assert list(executor.map(park, range(8))).count(True) == 1
    assert len(transfers) == 1
    barrier = threading.Barrier(8)

    def acquire(index):
        barrier.wait(timeout=5)
        return transfers.acquire("docker", original.image, workdir=tmp_path / str(index), timeout=60)

    with ThreadPoolExecutor(max_workers=8) as executor:
        acquired = [result for result in executor.map(acquire, range(8)) if result is not None]
    assert len(acquired) == 1 and acquired[0] is not original
    assert len(transfers) == 0


def test_fresh_constructor_failure_consumes_policy_and_falls_back(tmp_path, daemon, monkeypatch):
    original = DockerBackend(workdir=tmp_path)
    transfers = pool.SandboxPool()
    assert transfers.park(original)

    def unavailable(self):
        raise RuntimeError("synthetic daemon error")

    monkeypatch.setattr(DockerBackend, "_verify_docker", unavailable)
    assert transfers.acquire("docker", original.image, workdir=tmp_path, timeout=60) is None
    assert len(transfers) == 0


def test_actual_runner_keeps_fresh_lifecycle_and_does_not_claim_pool_savings(tmp_path, daemon, monkeypatch):
    from maverick import budget, llm, orchestrator, runner, trace_pin, world_model
    _config(monkeypatch)
    built = []
    closed = []
    original_close = DockerBackend.close

    def close(sandbox):
        closed.append(sandbox)
        original_close(sandbox)

    database = tmp_path / "world.db"
    seeded = world_model.WorldModel(database)
    goals = [seeded.create_goal(f"Synthetic goal {index}", owner="user:alice",
                               execution_principal="user:alice") for index in range(2)]
    seeded.close()

    def execute(_llm, world, _budget, goal_id, **kwargs):
        sandbox = kwargs["sandbox"]
        built.append(sandbox)
        assert sandbox.exec("synthetic task").ok
        world.set_goal_status(goal_id, "done")

    monkeypatch.chdir(tmp_path)
    # Exercise the real transactional authority/lineage read before setup.
    monkeypatch.setattr(world_model, "open_world", lambda: world_model.WorldModel(database))
    monkeypatch.setattr(world_model, "close_world_if_owned", lambda world: world.close())
    monkeypatch.setattr(llm, "LLM", object)
    monkeypatch.setattr(budget, "budget_from_config", lambda **kw: budget.Budget())
    monkeypatch.setattr(orchestrator, "run_goal_sync", execute)
    monkeypatch.setattr(trace_pin, "pin_trace", lambda *a: None)
    monkeypatch.setattr(DockerBackend, "close", close)
    monkeypatch.setattr(pool, "park_at_run_end", lambda sandbox: pytest.fail("unqualified parking enabled"))
    assert runner.run_goal_in_thread(goals[0], user_id="alice") == "done"
    assert runner.run_goal_in_thread(goals[1], user_id="alice") == "done"
    assert built[0] is not built[1]
    assert [id(sandbox) for sandbox in closed] == [id(sandbox) for sandbox in built]
    assert len(pool.shared_pool()) == 0
    assert [call[1] for call in daemon].count("version") == 2
    assert [call[1] for call in daemon].count("run") == 2
    assert not any(call[1] == "image" for call in daemon)


@pytest.mark.parametrize("reported", ["sha256:" + "a" * 64, "b" * 64])
def test_both_engine_image_id_forms_pin_the_image(monkeypatch, reported):
    monkeypatch.setattr(pool.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=0, stdout=reported + "\n"))
    assert pool._image_digest("podman", "python:3.12") == reported


# Container argv tests use a workspace separate from the operator's state.
@_workspace_guard_pytest.fixture(autouse=True)
def _separate_container_test_home(tmp_path, monkeypatch, _isolate_dynamic_maverick_home):
    operator_home = tmp_path.parent / (tmp_path.name + "-operator")
    monkeypatch.setenv("HOME", str(operator_home))
    monkeypatch.setenv("USERPROFILE", str(operator_home))
    monkeypatch.setenv("MAVERICK_HOME", str(operator_home / ".maverick"))
