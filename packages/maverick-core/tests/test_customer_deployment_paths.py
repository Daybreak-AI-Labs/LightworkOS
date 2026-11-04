"""Offline setup/recipe contracts; no cloud, Docker, systemd or SSH is invoked."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest
from maverick import config, sandbox
from maverick.sandbox.ssh import SSHBackend

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[3]
BASH = shutil.which("bash") if os.name != "nt" else "C:/Program Files/Git/bin/bash.exe"


@pytest.mark.parametrize("port", [None, "9900"])
def test_demo_compose_publishes_only_on_loopback(port):
    docker = shutil.which("docker")
    if docker is None or subprocess.run([docker, "compose", "version"], capture_output=True).returncode:
        pytest.skip("Docker Compose is unavailable")
    env = {**os.environ, "MAVERICK_DASHBOARD_TOKEN": "synthetic-test-token"}
    env.pop("MAVERICK_DEMO_PORT", None)
    if port:
        env["MAVERICK_DEMO_PORT"] = port
    result = subprocess.run(
        [docker, "compose", "-f", str(ROOT / "deploy/demo/docker-compose.yml"),
         "config", "--format", "json"],
        env=env, capture_output=True, text=True, check=True, timeout=30,
    )
    published = json.loads(result.stdout)["services"]["maverick-demo"]["ports"][0]
    assert published["host_ip"] == "127.0.0.1"
    assert str(published["published"]) == (port or "8765")
    assert published["target"] == 8765


def load(relative):
    spec = importlib.util.spec_from_file_location("deployment_fixture", ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(os.name == "nt", reason="VPS renderer uses POSIX descriptor protections")
def test_vps_renderer_rejects_fifo_and_symlinked_config(tmp_path):
    renderer = load("deploy/vps/render_service.py")
    state = tmp_path / ".maverick"
    state.mkdir()
    config_file = state / "config.toml"
    os.mkfifo(config_file)
    with pytest.raises(ValueError, match="regular file"):
        renderer._read_user_config(tmp_path)
    config_file.unlink()
    outside = tmp_path / "outside.toml"
    outside.write_text('[sandbox]\nworkdir = "/tmp"\n')
    config_file.symlink_to(outside)
    with pytest.raises(OSError):
        renderer._read_user_config(tmp_path)


@pytest.mark.skipif(not BASH or not Path(BASH).is_file(), reason="existing Bash runtime unavailable")
@pytest.mark.parametrize("mode", ["ready", "missing", "render-failed"])
def test_vps_service_uses_system_python_and_preserves_unit_on_failure(tmp_path, mode):
    # Execute the actual install_service function with filesystem/systemctl
    # commands intercepted into a disposable tree; never touch the host unit.
    source = (ROOT / "deploy/vps/install.sh").read_text(encoding="utf-8")
    function = source[source.index("install_service() {"):source.index("\nmain() {")]
    function = function.replace("/usr/bin/python3 -I", "root_python -I")
    fixture = r'''
set -euo pipefail
cd "$1"
TARGET_USER=fixture
TARGET_HOME="$PWD/service home"
mkdir -p "$PWD/venvs/maverick-agent/bin"
if [[ "$2" != missing ]]; then
  printf '#!/bin/sh\nexit 0\n' > "$PWD/venvs/maverick-agent/bin/python"
  chmod +x "$PWD/venvs/maverick-agent/bin/python"
fi
printf 'original unit\n' > published-unit
MODE="$2"
log() { :; }
run_as_user() {
  if [[ "$1" == pipx ]]; then printf '%s\n' "$PWD/venvs"; return 0; fi
  [[ "$1" == "$PWD/venvs/maverick-agent/bin/python" ]] || return 91
  [[ "$2" == /opt/maverick/deploy/vps/render_service.py ]] || return 92
  printf '%s\n' "$1" > interpreter-used
  [[ "$MODE" != render-failed ]] || return 93
  printf 'untrusted unit that must never be published\n'
}
root_python() {
  [[ "$1" == -I && "$2" == /opt/maverick/deploy/vps/render_service.py ]] || return 94
  printf 'system interpreter\n' > root-interpreter-used
  printf 'rendered unit\n'
}
mktemp() { command mktemp "$PWD/render.XXXXXX"; }
mv() { command mv -f -- "$3" "$PWD/published-unit"; }
systemctl() { printf '%s\n' "$*" >> systemctl-calls; }
'''
    script = tmp_path / "fixture.sh"
    script.write_text(fixture + "\n" + function + "\ninstall_service\n", encoding="utf-8")
    env = {key: value for key, value in os.environ.items() if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATHEXT", "COMSPEC"}}
    result = subprocess.run([BASH, "--noprofile", "--norc", str(script), str(tmp_path), mode],
                            env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == (0 if mode == "ready" else 1), result.stderr
    assert (tmp_path / "published-unit").read_text() == ("rendered unit\n" if mode == "ready" else "original unit\n")
    assert (tmp_path / "systemctl-calls").exists() == (mode == "ready")
    assert (tmp_path / "interpreter-used").exists() == (mode != "missing")
    assert (tmp_path / "root-interpreter-used").exists() == (mode == "ready")


@pytest.mark.parametrize("override,configured,expected", [
    ("/requested/task-b", "/configured/task-a", "/requested/task-b"),
    (PurePosixPath("/requested/space name"), "/configured/task-a", "/requested/space name"),
    (None, "/configured/task-a", "/configured/task-a"),
    (None, None, "~/maverick-workspace"),
])
def test_ssh_uses_explicit_posix_workspace_in_actual_command(monkeypatch, override, configured, expected):
    calls = []
    monkeypatch.setattr(SSHBackend, "_verify_ssh", lambda self: None)
    monkeypatch.delenv("MAVERICK_DEPLOYMENT_ISOLATION", raising=False)

    def transport(args, **_kwargs):
        calls.append(args)
        return SimpleNamespace(stdout="fixture", stderr="", returncode=0)

    monkeypatch.setattr("maverick.sandbox.ssh.subprocess.run", transport)
    settings = {"backend": "ssh", "host": "fixture.invalid"}
    if configured is not None:
        settings["workdir"] = configured
    backend = sandbox.build_sandbox(workdir=override, backend="ssh", sandbox_config=settings)
    assert isinstance(backend.workdir, PurePosixPath)
    assert str(backend.workdir) == expected
    assert backend.exec("pwd").exit_code == 0
    assert backend._quote_workdir() in shlex.split(calls[0][-1])[-1]


@pytest.mark.skipif(os.name == "nt", reason="VPS renderer uses POSIX descriptor protections")
@pytest.mark.parametrize("workspace", ["Documents/Maverick", "custom workspace/with%sign"])
def test_vps_renderer_provisions_saved_workspace_and_quotes_both_unit_paths(tmp_path, workspace):
    renderer = load("deploy/vps/render_service.py")
    home = tmp_path / "service-home"
    state = home / ".maverick"
    state.mkdir(parents=True)
    selected = home / workspace
    (state / "config.toml").write_text('[sandbox]\nworkdir=' + json.dumps(str(selected)) + '\n', encoding="utf-8")
    template = (ROOT / "deploy/vps/maverick.service").read_text(encoding="utf-8")
    rendered = renderer.render_service(template, user="fixture", home=home)
    assert selected.is_dir()
    assert f"WorkingDirectory={renderer._unit_value(selected)}" in rendered
    assert f"ReadWritePaths={renderer._unit_value(state)} {renderer._unit_value(selected)}" in rendered
    assert "@WORKDIR@" not in rendered
    assert not list(selected.iterdir())


@pytest.mark.skipif(os.name == "nt", reason="VPS renderer uses POSIX descriptor protections")
def test_vps_workspace_failure_precedes_any_completed_unit(tmp_path, monkeypatch):
    renderer = load("deploy/vps/render_service.py")
    state = tmp_path / ".maverick"
    state.mkdir()
    (state / "config.toml").write_text('[sandbox]\nworkdir=' + json.dumps(str(tmp_path / "workspace")) + '\n', encoding="utf-8")

    def denied(**_kwargs):
        raise PermissionError("read-only workspace")

    monkeypatch.setattr(renderer.tempfile, "TemporaryFile", denied)
    with pytest.raises(PermissionError):
        renderer.render_service("WorkingDirectory=@WORKDIR@", user="fixture", home=tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="VPS renderer uses POSIX descriptor protections")
@pytest.mark.parametrize("remote", ["~/remote-only", "/remote/customer/workspace"])
def test_vps_ssh_workspace_stays_remote_despite_local_collision(tmp_path, monkeypatch, remote):
    renderer = load("deploy/vps/render_service.py")
    home = tmp_path / "service-home"
    state = home / ".maverick"
    state.mkdir(parents=True)
    collision = home / "remote-only"
    collision.write_text("unrelated local file", encoding="utf-8")
    config_path = state / "config.toml"
    config_path.write_text('[sandbox]\nbackend="ssh"\nhost="customer@remote"\nworkdir=' + json.dumps(remote) + '\n', encoding="utf-8")
    before = config_path.read_bytes()
    template = (ROOT / "deploy/vps/maverick.service").read_text(encoding="utf-8")
    original_mkdir = Path.mkdir

    def local_mkdir(path, *args, **kwargs):
        assert path.resolve().is_relative_to(tmp_path.resolve()), "remote path must not be provisioned locally"
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", local_mkdir)
    rendered = renderer.render_service(template, user="fixture", home=home)
    local_workspace = state / "service-workspace"
    assert local_workspace.is_dir()
    assert not list(local_workspace.iterdir())
    assert f"WorkingDirectory={renderer._unit_value(local_workspace)}" in rendered
    assert f"ReadWritePaths={renderer._unit_value(state)} {renderer._unit_value(local_workspace)}" in rendered
    assert remote not in rendered
    assert collision.read_text(encoding="utf-8") == "unrelated local file"
    assert config_path.read_bytes() == before


def test_container_default_matches_state_mount_and_explicit_config_wins(monkeypatch):
    dockerfile = (ROOT / "deploy/docker/Dockerfile").read_text(encoding="utf-8")
    assert "ENV MAVERICK_WORKDIR=/home/maverick/.maverick/workspace" in dockerfile
    monkeypatch.setenv("MAVERICK_WORKDIR", "/home/maverick/.maverick/workspace")
    monkeypatch.setattr(config, "load_config", dict)
    assert config.get_sandbox()["workdir"] == "/home/maverick/.maverick/workspace"
    monkeypatch.setattr(config, "load_config", lambda: {"sandbox": {"workdir": "/selected/mounted-workspace"}})
    assert config.get_sandbox()["workdir"] == "/selected/mounted-workspace"
    compose = (ROOT / "deploy/docker/docker-compose.yml").read_text(encoding="utf-8")
    assert "MAVERICK_WORKDIR: /workspace" in compose and ":/workspace" in compose
    fly = tomllib.loads((ROOT / "deploy/reference-architectures/flyio/fly.toml").read_text(encoding="utf-8"))
    assert fly["env"]["MAVERICK_WORKDIR"].startswith(fly["mounts"][0]["destination"] + "/")


@pytest.mark.parametrize("payload,length,expected", [
    (b'{"title":42}', None, 400), (b'{"title":[]}', None, 400),
    (b'{"title":null}', None, 400), (b'{"title":{}}', None, 400),
    (b'{"title":true}', None, 400), (b'[]', None, 400),
    (b'{"title":"\xff"}', None, 400), (b'{bad', None, 400),
    (b'{"title":"fixture"}', "invalid", 400), (b'{}', "-1", 413),
    (b'{}', "65537", 413), (b'{}', "0", 413), (b'{}', "3", 400),
])
def test_relay_invalid_request_has_structured_error_and_never_forwards(monkeypatch, payload, length, expected):
    relay = load("deploy/relay/relay.py")
    monkeypatch.setattr(relay, "CALLER_TOKEN", "synthetic")
    calls = []
    monkeypatch.setattr(relay, "forward", lambda body: calls.append(body))
    handler = object.__new__(relay.Handler)
    handler.path = "/relay"
    handler.headers = {"Authorization": "Bearer synthetic", "Content-Length": str(len(payload)) if length is None else length}
    handler.rfile = io.BytesIO(payload)
    responses = []
    handler._send = lambda code, body: responses.append((code, json.loads(body)))
    handler.do_POST()
    assert responses[0][0] == expected
    assert isinstance(responses[0][1]["error"], str)
    assert not calls


def test_relay_valid_string_title_still_forwards(monkeypatch):
    relay = load("deploy/relay/relay.py")
    monkeypatch.setattr(relay, "CALLER_TOKEN", "synthetic")
    calls = []
    monkeypatch.setattr(relay, "forward", lambda body: (calls.append(body) or (202, b'{}')))
    handler = object.__new__(relay.Handler)
    body = b'{"title":"  fixture  "}'
    handler.path = "/relay"
    handler.headers = {"Authorization": "Bearer synthetic", "Content-Length": str(len(body))}
    handler.rfile = io.BytesIO(body)
    responses = []
    handler._send = lambda code, response: responses.append(code)
    handler.do_POST()
    assert responses == [202]
    assert calls == [{"title": "fixture"}]


@pytest.mark.skipif(not BASH or not Path(BASH).is_file(), reason="existing Bash runtime unavailable")
@pytest.mark.parametrize("mode", ["never", "hung", "ready"])
def test_demo_launcher_has_bounded_honest_readiness(tmp_path, mode):
    script = tmp_path / "run-demo.sh"
    script.write_bytes((ROOT / "deploy/demo/run-demo.sh").read_bytes())
    (tmp_path / "demo.env").write_text("# synthetic fixture\n", encoding="utf-8")
    fixture = '''docker() { return 0; }
curl() {
  calls=$((${calls:-0} + 1))
  [[ "$*" == *"--connect-timeout 1"* && "$*" == *"--max-time "* ]] || exit 91
  if [[ "$FIXTURE_MODE" == ready && "$calls" -ge 3 ]]; then return 0; fi
  if [[ "$FIXTURE_MODE" == hung ]]; then SECONDS=$((SECONDS + 3)); fi
  return 28
}
sleep() { SECONDS=$((SECONDS + 1)); }
export -f docker curl sleep
bash "$1"
'''
    env = {key: value for key, value in os.environ.items() if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATHEXT", "COMSPEC"}}
    env.update(MAVERICK_DASHBOARD_TOKEN="synthetic", FIXTURE_MODE=mode)
    result = subprocess.run([BASH, "--noprofile", "--norc", "-c", fixture, "--", str(script)], env=env, text=True, capture_output=True, timeout=10)
    assert result.returncode == (0 if mode == "ready" else 1), result.stderr
    assert ("Lightwork demo is live:" in result.stdout) == (mode == "ready")
    if mode != "ready":
        assert "did not become ready within 60 seconds" in result.stderr


def test_reference_recipes_provision_the_dashboard_credentials_they_require():
    recipes = ROOT / "deploy/reference-architectures"
    for document in [recipes / "flyio/fly.toml", recipes / "railway/README.md"]:
        text = document.read_text(encoding="utf-8")
        assert "ANTHROPIC_API_KEY" in text and "MAVERICK_DASHBOARD_TOKEN" in text
    task = json.loads((recipes / "ecs/task-definition.json").read_text(encoding="utf-8"))
    readme = (recipes / "ecs/README.md").read_text(encoding="utf-8")
    for secret in task["containerDefinitions"][0]["secrets"]:
        name = secret["valueFrom"].split(":parameter")[-1]
        assert name in readme


@pytest.mark.skipif(not BASH or not Path(BASH).is_file(), reason="existing Bash runtime unavailable")
def test_container_entrypoint_provisions_workspace_and_preserves_files_across_processes(tmp_path):
    def shell_path(value):
        text = value.as_posix()
        return "/" + text[0].lower() + text[2:] if os.name == "nt" else text

    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    stub = binary_dir / "maverick"
    stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$MAVERICK_WORKDIR/arguments"\nif [ "$1" = start ]; then printf retained > "$MAVERICK_WORKDIR/result"; fi\n', encoding="utf-8")
    stub.chmod(0o700)
    workspace = tmp_path / "mounted-state/workspace"
    env = {key: value for key, value in os.environ.items() if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATHEXT", "COMSPEC"}}
    env["MAVERICK_WORKDIR"] = shell_path(workspace)
    command = [BASH, "--noprofile", "--norc", "-c", 'export PATH="$1:$PATH"; shift; exec sh "$@"', "--", shell_path(binary_dir), shell_path(ROOT / "deploy/docker/entrypoint.sh")]
    for args in [["start", "synthetic"], ["--help"]]:
        result = subprocess.run([*command, *args], env=env, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
    assert (workspace / "result").read_text(encoding="utf-8") == "retained"
    assert (workspace / "arguments").read_text(encoding="utf-8").splitlines() == ["start synthetic", "--help"]
