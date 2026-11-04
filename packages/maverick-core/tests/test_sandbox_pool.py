"""Sandbox feature 6: Firecracker warm reuse + cross-run pooling.

Offline: docker daemon calls and the E2B REST API are stubbed; the pool's
TTL clock is injected.
"""
from __future__ import annotations

import hashlib
import sys
import types

import pytest
from maverick.sandbox import build_sandbox, pool
from maverick.sandbox.docker import DockerBackend
from maverick.sandbox.firecracker import FirecrackerBackend
from maverick.sandbox.local import LocalBackend
from maverick.sandbox.podman import PodmanBackend


@pytest.fixture(autouse=True)
def _isolated_pool(monkeypatch):
    pool.reset_shared_pool()
    # No daemon calls: return a stable synthetic content identity.
    monkeypatch.setattr(pool, "_image_digest",
                        lambda engine, image: _digest(image))
    yield
    pool.reset_shared_pool()


@pytest.fixture
def docker_ok(monkeypatch):
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)
    monkeypatch.setattr(PodmanBackend, "_verify_podman", lambda self: None)


def _backend(tmp_path, **kw):
    return DockerBackend(workdir=tmp_path / "run1", **kw)


def _digest(image):
    return image if image.startswith("sha256:") else "sha256:" + hashlib.sha256(image.encode()).hexdigest()


# ------------------------------------------------------------- the pool ----

def test_park_acquire_round_trip_scrubs_workdir_and_timeout(tmp_path, docker_ok):
    p = pool.SandboxPool(clock=lambda: 0.0)
    sb = _backend(tmp_path, timeout=60.0)
    assert p.park(sb) is True
    assert len(p) == 1
    out = p.acquire("docker", sb.image, workdir=tmp_path / "run2", timeout=90.0)
    assert type(out) is DockerBackend and out is not sb
    assert sb.workdir == tmp_path / "run1"  # old reference is never redirected
    with pytest.raises(RuntimeError, match="lease was transferred"):
        sb.exec("must not execute")
    assert out.workdir == tmp_path / "run2"
    assert out.workdir.is_dir()          # workspace re-pointed + created
    assert out.timeout == 90.0           # per-run timeout reapplied
    assert len(p) == 0                   # handed out, not shared


def test_acquire_misses_on_any_config_mismatch(tmp_path, docker_ok):
    p = pool.SandboxPool(clock=lambda: 0.0)
    p.park(_backend(tmp_path))
    assert p.acquire("docker", "other:image", workdir=tmp_path, timeout=60) is None
    assert p.acquire("docker", "python:3.12-slim", workdir=tmp_path, timeout=60,
                     allow_network=True) is None
    assert p.acquire("podman", "python:3.12-slim", workdir=tmp_path,
                     timeout=60) is None
    # The parked entry is still there for the matching config.
    assert p.acquire("docker", "python:3.12-slim", workdir=tmp_path,
                     timeout=60) is not None


def test_ttl_eviction_via_injected_clock(tmp_path, docker_ok):
    now = {"t": 0.0}
    p = pool.SandboxPool(ttl=600.0, clock=lambda: now["t"])
    p.park(_backend(tmp_path))
    now["t"] = 599.0
    assert len(p) == 1
    now["t"] = 600.0
    assert p.acquire("docker", "python:3.12-slim", workdir=tmp_path,
                     timeout=60) is None
    assert len(p) == 0


def test_pool_is_bounded_to_two_evicting_oldest(tmp_path, docker_ok):
    p = pool.SandboxPool(clock=lambda: 0.0)
    backends = [DockerBackend(workdir=tmp_path, image=f"img{i}:latest")
                for i in range(3)]
    for b in backends:
        assert p.park(b)
    assert len(p) == pool.POOL_MAX == 2
    assert p.acquire("docker", "img0:latest", workdir=tmp_path, timeout=60) is None
    assert p.acquire("docker", "img1:latest", workdir=tmp_path,
                     timeout=60).image == _digest("img1:latest")
    assert p.acquire("docker", "img2:latest", workdir=tmp_path,
                     timeout=60).image == _digest("img2:latest")


def test_ineligible_backends_fail_to_fresh(tmp_path):
    p = pool.SandboxPool(clock=lambda: 0.0)
    assert p.park(LocalBackend(workdir=tmp_path)) is False
    fc = FirecrackerBackend(workdir=tmp_path, provider="e2b", api_key="k")
    assert p.park(fc) is False           # warm VM state can't be scrubbed
    assert len(p) == 0


def test_unhealthy_sandbox_is_not_parked(tmp_path, monkeypatch):
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)
    sb = _backend(tmp_path)

    monkeypatch.setattr(pool, "_image_digest", lambda *a: None)
    p = pool.SandboxPool(clock=lambda: 0.0)
    assert p.park(sb) is False
    assert len(p) == 0


# ------------------------------------------------------ build_sandbox wiring

def _wire_config(monkeypatch, sandbox_cfg):
    import maverick.config as config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"sandbox": sandbox_cfg})
    monkeypatch.setattr(config, "get_sandbox", lambda: {
        "backend": sandbox_cfg.get("backend", "local"),
        "workdir": sandbox_cfg.get("workdir", "~/maverick-workspace"),
        "timeout": sandbox_cfg.get("timeout", 60),
    })
    monkeypatch.delenv("MAVERICK_LANGUAGE", raising=False)


def test_knob_off_is_zero_behavior_change(tmp_path, docker_ok, monkeypatch):
    _wire_config(monkeypatch, {"backend": "docker"})
    parked = _backend(tmp_path)
    pool.shared_pool().park(parked)
    built = build_sandbox(workdir=tmp_path / "next")
    assert isinstance(built, DockerBackend)
    assert built is not parked           # fresh construction, pool ignored
    assert len(pool.shared_pool()) == 1  # pool untouched


def test_knob_on_hands_parked_sandbox_to_next_run(tmp_path, docker_ok, monkeypatch):
    _wire_config(monkeypatch, {"backend": "docker", "cross_run_pool": True})
    parked = _backend(tmp_path)
    assert pool.shared_pool().park(parked)
    built = build_sandbox(workdir=tmp_path / "next")
    assert built is not parked and built.image == _digest(parked.image)
    assert built.workdir == tmp_path / "next"
    # Pool now empty -> a second build constructs fresh.
    again = build_sandbox(workdir=tmp_path / "next2")
    assert again is not parked


def test_warm_docker_backend_is_not_pool_eligible(tmp_path, docker_ok):
    p = pool.SandboxPool(clock=lambda: 0.0)
    sb = _backend(tmp_path, reuse_container=True)
    sb._warm_name = "maverick-warm-existing"

    assert p.park(sb) is False
    assert len(p) == 0


def test_reuse_container_config_bypasses_cross_run_pool(
    tmp_path, docker_ok, monkeypatch
):
    _wire_config(monkeypatch, {
        "backend": "docker",
        "cross_run_pool": True,
        "reuse_container": True,
    })
    parked = _backend(tmp_path)
    assert pool.shared_pool().park(parked)

    built = build_sandbox(workdir=tmp_path / "next")

    assert built is not parked
    assert isinstance(built, DockerBackend)
    assert built.reuse_container is True
    assert len(pool.shared_pool()) == 1


def test_knob_on_empty_pool_builds_fresh(tmp_path, docker_ok, monkeypatch):
    _wire_config(monkeypatch, {"backend": "docker", "cross_run_pool": True})
    built = build_sandbox(workdir=tmp_path / "next")
    assert isinstance(built, DockerBackend)


def test_park_at_run_end_respects_knob(tmp_path, docker_ok, monkeypatch):
    _wire_config(monkeypatch, {"backend": "docker"})
    assert pool.park_at_run_end(_backend(tmp_path)) is False
    assert len(pool.shared_pool()) == 0
    _wire_config(monkeypatch, {"backend": "docker", "cross_run_pool": True})
    assert pool.park_at_run_end(_backend(tmp_path)) is True
    assert len(pool.shared_pool()) == 1


# ------------------------------------------------- firecracker warm (e2b) ---

class _FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def _fake_httpx(state):
    class Client:
        def __init__(self, timeout=None):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def post(self, url, headers=None, json=None):
            assert headers["Authorization"].startswith("Bearer ")
            if url.endswith("/sandboxes"):
                state["creates"] += 1
                return _FakeResponse(200, {"id": f"sb-{state['creates']}"})
            sb_id = url.split("/sandboxes/")[1].split("/")[0]
            state["processes"].append((sb_id, json["cmd"]))
            if sb_id in state["fail_once"]:
                state["fail_once"].discard(sb_id)
                return _FakeResponse(502, {})
            return _FakeResponse(200, {"exitCode": 0,
                                       "stdout": f"ran:{json['cmd']}",
                                       "stderr": ""})

        def delete(self, url, headers=None):
            state["deletes"].append(url.rsplit("/", 1)[1])
            return _FakeResponse(200, {})

    mod = types.ModuleType("httpx")
    mod.Client = Client
    return mod


@pytest.fixture
def e2b(monkeypatch):
    state = {"creates": 0, "processes": [], "deletes": [], "fail_once": set()}
    monkeypatch.setitem(sys.modules, "httpx", _fake_httpx(state))
    return state


def _fc(tmp_path, **kw):
    return FirecrackerBackend(workdir=tmp_path, provider="e2b", api_key="k", **kw)


def test_e2b_default_remains_one_shot_per_exec(tmp_path, e2b):
    fc = _fc(tmp_path)
    assert fc.exec("echo 1").ok and fc.exec("echo 2").ok
    assert e2b["creates"] == 2
    assert e2b["deletes"] == ["sb-1", "sb-2"]


def test_e2b_warm_reuses_microvm_until_close(tmp_path, e2b):
    fc = _fc(tmp_path, warm=True)
    r1 = fc.exec("echo 1")
    r2 = fc.exec("echo 2")
    assert r1.stdout == "ran:echo 1" and r2.stdout == "ran:echo 2"
    assert e2b["creates"] == 1                      # one boot, two execs
    assert [p[0] for p in e2b["processes"]] == ["sb-1", "sb-1"]
    assert e2b["deletes"] == []                     # alive between execs
    fc.close()
    assert e2b["deletes"] == ["sb-1"]
    fc.close()                                      # idempotent
    assert e2b["deletes"] == ["sb-1"]


def test_e2b_warm_recreates_expired_sandbox_once(tmp_path, e2b):
    fc = _fc(tmp_path, warm=True)
    assert fc.exec("echo 1").ok
    e2b["fail_once"].add("sb-1")                    # server expired our VM
    out = fc.exec("echo 2")
    assert out.ok and out.stdout == "ran:echo 2"
    assert e2b["creates"] == 2
    assert fc._warm_id == "sb-2"


def test_e2b_warm_create_failure_surfaces(tmp_path, e2b, monkeypatch):
    fc = _fc(tmp_path, warm=True)

    real_client = sys.modules["httpx"].Client

    class FailingCreate(real_client):
        def post(self, url, headers=None, json=None):
            if url.endswith("/sandboxes"):
                return _FakeResponse(503, {})
            return super().post(url, headers=headers, json=json)

    monkeypatch.setattr(sys.modules["httpx"], "Client", FailingCreate)
    out = fc.exec("echo 1")
    assert out.exit_code == 126 and "create failed" in out.stderr


def test_local_provider_warm_is_honestly_ignored(tmp_path, monkeypatch):
    from maverick.sandbox.local import ExecResult
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    calls = []

    def fake_firectl(self, cmd):
        calls.append(cmd)
        return ExecResult(stdout="", stderr="", exit_code=0)

    monkeypatch.setattr(FirecrackerBackend, "_firectl", fake_firectl)
    fc = FirecrackerBackend(workdir=tmp_path, provider="local", warm=True)
    fc.exec("echo 1")
    fc.exec("echo 2")
    assert calls == ["echo 1", "echo 2"]  # one-shot boot per exec, no reuse
    assert fc._warm_id is None
    fc.close()                            # no-op without a warm VM


def test_acquire_does_not_hold_lock_across_digest(tmp_path, docker_ok, monkeypatch):
    # The image-digest subprocess (up to 10s) must run OUTSIDE the pool lock, or
    # one acquire() stalls every other acquire()/park()/len() behind it.
    import threading

    p = pool.SandboxPool(clock=lambda: 0.0)
    sb = _backend(tmp_path, timeout=60.0)
    p.park(sb)  # an entry exists, so acquire proceeds into the digest

    in_digest = threading.Event()
    release = threading.Event()

    def slow_digest(engine, image):
        in_digest.set()
        release.wait(timeout=5)
        return _digest(image)

    monkeypatch.setattr(pool, "_image_digest", slow_digest)

    t = threading.Thread(
        target=lambda: p.acquire("docker", sb.image,
                                 workdir=tmp_path / "run2", timeout=90.0))
    t.start()
    assert in_digest.wait(timeout=2)  # acquire reached the (blocked) digest

    # While acquire is stuck in the digest, another pool op must NOT block.
    other_done = threading.Event()
    threading.Thread(target=lambda: (len(p), other_done.set())).start()
    assert other_done.wait(timeout=2), "pool lock held across the digest subprocess"

    release.set()
    t.join(timeout=5)
