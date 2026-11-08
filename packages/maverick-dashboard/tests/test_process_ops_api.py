"""Start / stop / restart Lightwork's services from Settings > Maintenance.

Real supervised child processes (a small stand-in program replaces the
``maverick`` command so the test does not start a real server), one instance
per kind, global-admin only (a workspace administrator is refused), confirmed
stops, activity-record rows, and cleanup on dashboard shutdown."""
from __future__ import annotations

import sys
import time

import pytest
from fastapi.testclient import TestClient

from test_support.starlette_state import patch_state

ORIGIN = {"Origin": "http://127.0.0.1"}
BASE = "/api/v1/admin/services"
_REAL_COMMAND = __import__("maverick_dashboard.service_supervisor", fromlist=["command"]).command  # before any stand-in
_CHILD = ("import sys, time\n"
          "print('service ready', flush=True)\n"
          "print('token sk-ant-api03-' + 'x' * 40, flush=True)\n"
          "time.sleep(60)\n")


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import service_supervisor
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_CLIENT_ID"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    monkeypatch.setattr(service_supervisor, "command", lambda kind: [sys.executable, "-c", _CHILD])
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    service_supervisor.stop_all(timeout=5.0)
    config.reset_config_cache()
    audit_writer._defaults.clear()


def _as(monkeypatch, role: str, who: str = "user:someone"):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _audit_verbs(monkeypatch):
    from maverick.audit import writer
    seen: list[dict] = []
    real = writer.audit_event

    def spy(kind, **payload):
        seen.append(payload)
        return real(kind, **payload)
    monkeypatch.setattr(writer, "audit_event", spy)
    import maverick.audit as audit_pkg
    monkeypatch.setattr(audit_pkg, "audit_event", spy)
    return seen


def _row(client, kind):
    return next(r for r in client.get(BASE).json()["services"] if r["kind"] == kind)


def _eventually(check, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.05)
    return False


def test_the_real_command_is_a_fixed_argument_list():
    import os

    from maverick_dashboard import service_supervisor
    assert set(service_supervisor.KINDS) == {"worker", "channels", "tools", "profiling", "ebpf_monitor",
                                             "model_proxy"}
    assert service_supervisor.command("ebpf_monitor") == [sys.executable, "-m", "maverick.ebpf_monitor", "run",
                                                          "--pid", str(os.getpid())]
    assert service_supervisor.command("model_proxy") == [sys.executable, "-m", "maverick.model_proxy"]
    assert service_supervisor.command("worker")[-1] == "worker"
    assert service_supervisor.command("channels")[-1] == "serve"
    tools = service_supervisor.command("tools")
    assert tools[0] == sys.executable and tools[1:3] == ["-m", "maverick.cli"]
    assert tools[3:] == ["mcp", "--http", "--host", "127.0.0.1", "--port", "8771"]


@pytest.mark.parametrize("who", ["operator", "workspace admin"])
def test_only_an_installation_administrator_controls_services(client, monkeypatch, who):
    from maverick_dashboard import auth
    _as(monkeypatch, "operator" if who == "operator" else "viewer")
    if who == "workspace admin":
        monkeypatch.setattr(auth, "role_for_principal", lambda principal: "admin")
    assert client.get(BASE).status_code == 403
    for action in ("start", "stop", "restart"):
        assert client.post(f"{BASE}/{action}", json={"service": "worker", "confirm": True}).status_code == 403
    assert _row_raw_not_running()


def _row_raw_not_running():
    from maverick_dashboard import service_supervisor
    return not any(r["running"] for r in service_supervisor.status())


def test_start_stop_restart_one_instance_with_confirmation_and_records(client, monkeypatch):
    seen = _audit_verbs(monkeypatch)
    assert TestClient(client.app, base_url="http://127.0.0.1").post(f"{BASE}/start", json={"service": "worker"}).status_code == 403
    assert client.post(f"{BASE}/start", json={"service": "nope"}).status_code == 422
    started = client.post(f"{BASE}/start", json={"service": "worker"})
    assert started.status_code == 200 and started.json()["service"]["running"] is True
    assert client.post(f"{BASE}/start", json={"service": "worker"}).status_code == 409  # one per kind
    assert _eventually(lambda: any("service ready" in line for line in _row(client, "worker")["log"]))
    log = _row(client, "worker")["log"]
    assert not any("sk-ant-api03-" + "x" * 40 in line for line in log)  # secrets masked
    assert client.post(f"{BASE}/stop", json={"service": "worker"}).status_code == 409  # needs confirming
    assert _row(client, "worker")["running"] is True
    restarted = client.post(f"{BASE}/restart", json={"service": "worker", "confirm": True})
    assert restarted.status_code == 200 and restarted.json()["service"]["running"] is True
    stopped = client.post(f"{BASE}/stop", json={"service": "worker", "confirm": True})
    assert stopped.status_code == 200 and stopped.json()["service"]["running"] is False
    assert _row(client, "worker")["last_error"] == ""  # a requested stop is not an error
    assert client.post(f"{BASE}/stop", json={"service": "worker", "confirm": True}).status_code == 409
    verbs = [p.get("verb") for p in seen]
    assert verbs.count("service_start") == 2 and "service_restart" in verbs and "service_stop" in verbs


def test_an_unexpected_exit_is_reported_plainly(client, monkeypatch):
    from maverick_dashboard import service_supervisor
    monkeypatch.setattr(service_supervisor, "command",
                        lambda kind: [sys.executable, "-c", "import sys; print('bad setting'); sys.exit(3)"])
    client.post(f"{BASE}/start", json={"service": "channels"})
    assert _eventually(lambda: not _row(client, "channels")["running"] and _row(client, "channels")["last_error"])
    error = _row(client, "channels")["last_error"]
    assert error.startswith("Stopped unexpectedly (exit code 3).") and "bad setting" in error


def test_held_chat_reply_statuses_are_cleared_once_the_chat_service_has_ended(client, monkeypatch, tmp_path):
    # A chat service ended without a chance to remove its statuses (every stop
    # on Windows) leaves them behind; once it has ended the dashboard removes
    # the ones it saved, so they never stand in for a chat service that is
    # gone. A chat service started some other way keeps its own.
    import re

    from maverick.file_lock import ensure_private_directory
    from maverick_channels import hold_status
    from maverick_dashboard import service_supervisor
    child = ("import os, sys, time\n"
             "open(sys.argv[1], 'w').write(os.environ.get(sys.argv[2], ''))\n"
             "time.sleep(60)\n")
    monkeypatch.setattr(service_supervisor, "command", lambda kind: [
        sys.executable, "-c", child, str(tmp_path / f"owner-{kind}"), hold_status.OWNER_ENV])
    assert service_supervisor.HOLDS_OWNER_ENV == hold_status.OWNER_ENV
    holds = hold_status._directory()
    ensure_private_directory(holds)
    for kind in ("worker", "channels"):
        client.post(f"{BASE}/start", json={"service": kind})
    assert _eventually(lambda: all((tmp_path / f"owner-{kind}").exists() for kind in ("worker", "channels")))
    assert (tmp_path / "owner-worker").read_text() == ""
    owner = (tmp_path / "owner-channels").read_text()
    assert re.fullmatch(r"[0-9a-f]{16}", owner)
    mine = [holds / f"irc-{owner}-4242-0123456789abcdef.enc", holds / f"signal-{owner}-4242-fedcba9876543210.enc"]
    elsewhere = holds / "signal-4243-00112233445566ff.enc"
    for path in (*mine, elsewhere):
        path.write_bytes(b"x")
    worker = service_supervisor._SERVICES["worker"].process
    assert client.post(f"{BASE}/stop", json={"service": "worker", "confirm": True}).status_code == 200
    assert _eventually(lambda: worker.proc.poll() is not None and service_supervisor._SERVICES["worker"].process is None)
    assert all(path.exists() for path in mine)  # only the chat service's end clears them
    assert client.post(f"{BASE}/stop", json={"service": "channels", "confirm": True}).status_code == 200
    assert _eventually(lambda: not any(path.exists() for path in mine))
    assert elsewhere.exists()


def test_dashboard_shutdown_stops_every_owned_service(client):
    from maverick_dashboard import service_supervisor
    client.post(f"{BASE}/start", json={"service": "tools"})
    process = service_supervisor._SERVICES["tools"].process
    service_supervisor.stop_all(timeout=0, wait=False)  # the shutdown signal never blocks
    service_supervisor.stop_all(timeout=5.0)
    assert _eventually(lambda: process.proc.poll() is not None)
    assert _eventually(lambda: not _row(client, "tools")["running"])


def test_shutdown_supervisor_knows_about_the_services():
    from maverick_dashboard import _lifecycle

    class Recorder:
        def __init__(self):
            self.names = []

        def register(self, name, stop, alive):
            self.names.append(name)

        def register_final_resource(self, name, stop, alive):
            self.names.append(name)
    recorder = Recorder()

    class App:
        class state:
            pass
    _lifecycle.register_main_components(App, recorder)
    assert "services" in recorder.names


# ---- restarting this dashboard -------------------------------------------------

@pytest.mark.parametrize("environ, marker, kind, restarts", [
    ({"MAVERICK_DESKTOP_CONTROL": "stdin-v1", "INVOCATION_ID": "x"}, False, "desktop", False),
    ({"KUBERNETES_SERVICE_HOST": "10.0.0.1"}, False, "kubernetes", True),
    ({"INVOCATION_ID": "abc"}, False, "systemd", None),
    ({}, True, "container", None),
    ({}, False, "none", False),
])
def test_what_would_start_the_dashboard_again(environ, marker, kind, restarts):
    from maverick_dashboard.dashboard_restart import supervision
    info = supervision(environ, exists=lambda path: marker and path == "/.dockerenv")
    assert info["kind"] == kind and info["restarts"] is restarts and info["note"]


@pytest.fixture
def restartable(monkeypatch):
    from types import SimpleNamespace

    from maverick_dashboard import dashboard_restart
    from maverick_dashboard.app import app
    server = SimpleNamespace(should_exit=False)
    patch_state(monkeypatch, app.state, "dashboard_server", server, raising=False)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    dashboard_restart._reset_for_tests()
    yield server
    dashboard_restart._reset_for_tests()


def test_an_unsupervised_dashboard_says_plainly_it_cannot_restart_itself(client, monkeypatch):
    from maverick_dashboard.app import app
    for name in ("KUBERNETES_SERVICE_HOST", "INVOCATION_ID", "MAVERICK_DESKTOP_CONTROL"):
        monkeypatch.delenv(name, raising=False)
    patch_state(monkeypatch, app.state, "dashboard_server", None, raising=False)
    from maverick_dashboard import dashboard_restart
    monkeypatch.setattr(dashboard_restart.os.path, "exists", lambda path: False)
    row = client.get(BASE).json()["dashboard"]
    assert row["can_restart"] is False and "started by hand" in row["note"]
    refused = client.post(f"{BASE}/dashboard/restart", json={"confirm": True})
    assert refused.status_code == 409 and "started by hand" in refused.json()["detail"]
    monkeypatch.setenv("INVOCATION_ID", "abc")  # supervised, but launched without Lightwork's start command
    assert "can't restart itself" in client.get(BASE).json()["dashboard"]["note"]


def test_a_supervised_dashboard_restarts_gracefully_with_confirmation_and_a_record(client, monkeypatch, restartable):
    from maverick_dashboard import auth, dashboard_restart
    row = client.get(BASE).json()["dashboard"]
    assert row["can_restart"] is True and row["supervisor"] == "kubernetes"
    assert client.post(f"{BASE}/dashboard/restart", json={}).status_code == 409
    seen = _audit_verbs(monkeypatch)
    done = client.post(f"{BASE}/dashboard/restart", json={"confirm": True})
    assert done.status_code == 200 and done.json()["restarting"] is True
    assert _eventually(lambda: restartable.should_exit is True)
    assert dashboard_restart.requested() is True
    assert any(p.get("verb") == "dashboard_restart" and p.get("supervisor") == "kubernetes" for p in seen)
    _as(monkeypatch, "viewer", "user:wanda")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "admin")  # a workspace admin
    assert client.post(f"{BASE}/dashboard/restart", json={"confirm": True}).status_code == 403


@pytest.fixture
def logging_state():
    """The command configures process-wide logging; put it back for later tests."""
    import logging

    from maverick import logging_config
    configured = logging_config._configured
    root = logging.getLogger()
    saved = (root.level, root.handlers[:], root.filters[:])
    handler_filters = {id(h): h.filters[:] for h in root.handlers}
    loggers = {name: (lg.level, lg.propagate, lg.disabled, lg.handlers[:], lg.filters[:])
               for name, lg in logging.Logger.manager.loggerDict.items() if isinstance(lg, logging.Logger)}
    yield
    # The command's logging set-up runs once per process; a later command in
    # the same test process must configure it afresh, as it would alone.
    logging_config._configured = configured
    root.setLevel(saved[0])
    root.handlers[:] = saved[1]
    root.filters[:] = saved[2]
    for handler in root.handlers:
        handler.filters[:] = handler_filters.get(id(handler), handler.filters)
    for name, lg in logging.Logger.manager.loggerDict.items():
        if isinstance(lg, logging.Logger) and name in loggers:
            level, propagate, disabled, handlers, filters = loggers[name]
            lg.setLevel(level)
            lg.propagate, lg.disabled = propagate, disabled
            lg.handlers[:], lg.filters[:] = handlers, filters


def test_launchers_exit_with_the_restart_code_after_a_requested_restart(monkeypatch, logging_state):
    import uvicorn
    from click.testing import CliRunner
    from maverick.cli import main
    from maverick_dashboard import _server, dashboard_restart
    from maverick_dashboard.app import app

    def serve_then(restart):
        def run(self, sockets=None):
            self.started = True
            if restart:
                dashboard_restart.request(app, delay=0)
        return run
    for name in ("MAVERICK_DESKTOP_CONTROL", "WEB_CONCURRENCY", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    try:
        monkeypatch.setattr(uvicorn.Server, "run", serve_then(False))
        assert CliRunner().invoke(main, ["dashboard"]).exit_code == 0
        monkeypatch.setattr(uvicorn.Server, "run", serve_then(True))
        result = CliRunner().invoke(main, ["dashboard"])
        assert result.exit_code == dashboard_restart.RESTART_EXIT_CODE == 75, result.output
        monkeypatch.setattr(_server.DashboardServer, "run", serve_then(True))
        with pytest.raises(SystemExit) as exited:
            _server.run_dashboard_server(app, host="127.0.0.1", port=0)
        assert exited.value.code == 75
    finally:
        dashboard_restart._reset_for_tests()
        app.state.dashboard_server = None



# ---- programs a setting turns on share the same registry ------------------------

def test_setting_driven_programs_follow_their_setting_from_maintenance(client, monkeypatch):
    for name in ("MAVERICK_PROFILING",):
        monkeypatch.delenv(name, raising=False)
    rows = {r["kind"]: r for r in client.get(BASE).json()["services"]}
    assert rows["profiling"]["setting_driven"] is True and rows["profiling"]["wanted"] is False
    assert rows["profiling"]["settings_href"].startswith("/settings/all#group-")
    assert rows["worker"]["setting_driven"] is False and rows["worker"]["wanted"] is None
    refused = client.post(f"{BASE}/start", json={"service": "profiling"})
    assert refused.status_code == 409 and "turned off in All settings" in refused.json()["detail"]
    monkeypatch.setenv("MAVERICK_PROFILING", "1")
    seen = _audit_verbs(monkeypatch)
    assert client.post(f"{BASE}/start", json={"service": "profiling"}).json()["service"]["running"] is True
    assert client.post(f"{BASE}/start", json={"service": "profiling"}).status_code == 409  # one per kind
    assert client.post(f"{BASE}/stop", json={"service": "profiling"}).status_code == 409  # confirm first
    monkeypatch.setenv("MAVERICK_PROFILING", "0")
    assert client.post(f"{BASE}/restart", json={"service": "profiling", "confirm": True}).status_code == 409
    stopped = client.post(f"{BASE}/stop", json={"service": "profiling", "confirm": True})
    assert stopped.json()["service"]["running"] is False  # stopping is always allowed
    assert [p.get("verb") for p in seen if p.get("service") == "profiling"] == [
        "service_start", "service_start", "service_restart", "service_stop"]


def test_settings_start_and_the_dashboard_shutdown_use_the_one_registry(client, monkeypatch):
    from maverick_dashboard import background_programs, service_supervisor
    monkeypatch.setenv("MAVERICK_PROFILING", "1")
    assert background_programs.start_enabled() == ["profiling"]
    assert background_programs.start("profiling")["running"] is True  # already running: left alone
    client.post(f"{BASE}/start", json={"service": "worker"})
    assert service_supervisor.alive(["profiling"]) and service_supervisor.alive(["worker"])
    service_supervisor.stop_all(timeout=5.0)  # the single shutdown component
    assert _eventually(lambda: not service_supervisor.alive())


def test_frozen_builds_refuse_program_modules_plainly(monkeypatch):
    from maverick_dashboard import service_supervisor
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    with pytest.raises(service_supervisor.ServiceError, match="no separate Python"):
        service_supervisor.command("model_proxy")
    assert service_supervisor.command("worker") == [sys.executable, "worker"]


def test_a_frozen_refusal_reaches_the_page_and_the_settings_start(client, monkeypatch):
    from maverick_dashboard import background_programs, service_supervisor
    monkeypatch.setattr(service_supervisor, "command", _REAL_COMMAND)  # the fixture's stand-in, undone
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setenv("MAVERICK_PROFILING", "1")
    refused = client.post(f"{BASE}/start", json={"service": "profiling"})
    assert refused.status_code == 409 and "no separate Python" in refused.json()["detail"]
    quiet = background_programs.start("profiling")  # the settings start records it instead
    assert quiet["running"] is False and "no separate Python" in quiet["last_error"]


_PROXY_CONFIGS = {
    "anthropic": '[model_proxy]\nenable = true\nupstream = "https://api.anthropic.com"\n',
    "unknown": '[model_proxy]\nenable = true\nupstream = "https://models.internal.example"\n',
    "unset": "[model_proxy]\nenable = true\n",
    "off": '[model_proxy]\nenable = false\nupstream = "https://api.anthropic.com"\n',
}
_KEYS = {"ANTHROPIC_API_KEY": "sk-ant-test", "OPENAI_API_KEY": "sk-test",  # pragma: allowlist secret
         "AZURE_OPENAI_AD_TOKEN": "ad-token", "MAVERICK_PROXY_KEY": "proxy-held"}  # pragma: allowlist secret
_KEPT = {
    # Only the AI service the proxy forwards to loses its key; others are kept.
    "anthropic": {"OPENAI_API_KEY", "AZURE_OPENAI_AD_TOKEN"},
    # An upstream that can't be matched to an AI service: every key is removed.
    "unknown": set(),
    "unset": set(),
    "off": set(_KEYS),
}


@pytest.mark.parametrize("mode", list(_PROXY_CONFIGS))
def test_services_get_the_ai_service_keys_only_while_the_model_proxy_is_off(client, monkeypatch, tmp_path, mode):
    """With the model proxy on, only the proxy holds the key of the AI service it
    forwards to: every other program reaches that service through it."""
    from maverick import config, owned_process
    from maverick_dashboard import service_supervisor
    (tmp_path / "config.toml").write_text(_PROXY_CONFIGS[mode], encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.delenv("MAVERICK_PROXY_UPSTREAM", raising=False)
    for name, value in _KEYS.items():
        monkeypatch.setenv(name, value)
    seen: dict[str, dict] = {}

    class Recorder:
        def __init__(self, argv, env=None):
            seen[argv[-1]] = dict(env or {})
    monkeypatch.setattr(owned_process, "OwnedProcess", Recorder)
    monkeypatch.setattr(service_supervisor, "command", lambda kind: ["prog", kind])
    for kind in ("worker", "channels", "tools", "profiling", "model_proxy"):
        service_supervisor._spawn(kind)
    for kind in ("worker", "channels", "tools", "profiling"):
        assert {name for name in _KEYS if name in seen[kind]} == _KEPT[mode], kind
    assert seen["model_proxy"]["MAVERICK_PROXY_KEY"] == "proxy-held"
