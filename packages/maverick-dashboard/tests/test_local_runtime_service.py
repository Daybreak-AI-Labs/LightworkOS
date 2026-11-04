"""The reviewed local model server start: what a failed start leaves behind and
when the port probe reads as "another service"."""
from __future__ import annotations

import os
import queue
import socket
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick.local_runtime import Launcher, load_local_runtime
from maverick_dashboard import local_runtime_service as svc


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(svc, "_path", lambda: tmp_path / "local-runtime" / "operations.json")
    monkeypatch.setattr(svc, "_managed", None)
    monkeypatch.setattr(svc, "authority", lambda request, write=False: ("admin", None, "c" * 64))
    monkeypatch.setattr(svc, "state", lambda request: {"revision": "r1", "settings_revision": "s1", "can_start": True})
    monkeypatch.setattr("maverick_dashboard.system_checks_api._record", lambda *a, **k: None)


def _stage(monkeypatch, port):
    """A reviewed start for ``port`` whose native plan is still current."""
    cfg = load_local_runtime({"enabled": True, "engine": "llamacpp", "model": "/models/m.gguf",
                              "port": port})
    argv, env = Launcher(cfg).plan()
    argv[0] = "/usr/bin/llama-server"
    plan = {"cfg": cfg, "argv": argv, "env": env, "binary": "0" * 64,
            "resource": {"label": "m", "bytes": 1, "path": "/models/m.gguf", "identity": "x"},
            "endpoint": f"http://127.0.0.1:{port}"}
    monkeypatch.setattr(svc, "_plan", lambda: plan)
    return {"id": uuid.uuid4().hex, "action": "start", "actor": "admin", "tenant": None,
            "context": "c" * 64, "revision": "r1", "summary": ""}


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _fake_process():
    """What ``OwnedProcess`` hands back once the program is running."""
    out, err = queue.Queue(), queue.Queue()
    out.put(None)
    err.put(None)
    return SimpleNamespace(proc=SimpleNamespace(pid=4242, poll=lambda: None),
                           stdout=out, stderr=err, close=lambda: None)


def _time_wait_port():
    """A port whose only holder is a connection the server closed first."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    client = socket.create_connection(("127.0.0.1", port))
    served, _ = listener.accept()
    served.close()
    client.close()
    listener.close()
    return port


def test_a_spawn_failure_before_any_process_leaves_no_active_record(monkeypatch):
    review = _stage(monkeypatch, _free_port())

    def cannot_spawn(*_args, **_kwargs):
        raise OSError(2, "No such file or directory")

    monkeypatch.setattr(svc, "OwnedProcess", cannot_spawn)
    receipt = svc.apply(None, review)
    assert receipt["state"] == "refused"
    saved = svc._load()
    assert saved["active"] is None
    assert svc._managed is None
    # Nothing is left to block the next Start.
    assert svc._runtime(saved["active"])[0] == "stopped"


def test_a_live_listener_still_blocks_the_start(monkeypatch):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        review = _stage(monkeypatch, listener.getsockname()[1])
        monkeypatch.setattr(svc, "OwnedProcess", lambda *a, **k: pytest.fail("spawned"))
        with pytest.raises(HTTPException) as exc:
            svc.apply(None, review)
    assert exc.value.status_code == 409
    assert "Another service is using this local AI address" in exc.value.detail
    assert svc._load()["active"] is None


@pytest.mark.skipif(os.name == "nt", reason="TIME_WAIT never blocks a plain bind on Windows")
def test_a_port_left_in_time_wait_by_a_stop_does_not_read_as_another_service(monkeypatch):
    port = _time_wait_port()
    with socket.socket() as plain, pytest.raises(OSError):
        plain.bind(("127.0.0.1", port))  # the situation under test exists here
    review = _stage(monkeypatch, port)
    monkeypatch.setattr(svc, "OwnedProcess", lambda *a, **k: _fake_process())
    receipt = svc.apply(None, review)
    assert receipt["state"] == "started"
    assert svc._load()["active"]["pid"] == 4242
