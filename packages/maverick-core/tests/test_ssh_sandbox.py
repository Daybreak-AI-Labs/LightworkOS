"""Tests for the SSH sandbox backend (pure monkeypatch, no real ssh)."""
from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest
from maverick.sandbox import build_sandbox
from maverick.sandbox import ssh as ssh_module
from maverick.sandbox.ssh import SSHBackend, _marking_255

_MARK = "lightwork-ssh-exit-255-fixed"

_LOCAL_WORKSPACE_TOOLS = {
    "read_file", "write_file", "list_dir", "repo_map", "str_replace_editor",
    "ast_edit", "dep_graph", "cross_repo_deps", "semantic_code_search",
    "apply_patch", "preview_diff",
    "read_pdf", "view_image", "view_video", "sql_query", "sql_query_read",
    "pandas_query", "git_advanced", "file_watcher", "spreadsheet", "spreadsheet_read",
    "a11y", "model3d_inspect", "image_content_classifier", "openapi_runner", "ocr",
    "container_build", "ffmpeg", "pandoc", "office_convert", "wasm_run", "imagemagick",
    "audio_understanding", "image_edit", "embedded_device", "transcribe_audio", "speak",
    "workspace_snapshot", "html_to_app", "notebook_exec", "latex", "diagram",
}


@pytest.fixture(autouse=True)
def _fixed_marker(monkeypatch):
    """Each call draws a fresh marker; pin it so commands can be compared."""
    monkeypatch.setattr(ssh_module, "_new_marker", lambda: _MARK)


def _patch_ssh_ok(monkeypatch, run_recorder=None):
    """Make shutil.which find ssh and the verify probe succeed."""
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/ssh")

    def _fake_run(args, **kwargs):
        if run_recorder is not None:
            run_recorder.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)


def test_verify_ssh_probe_runs_on_construction(monkeypatch):
    calls = []
    _patch_ssh_ok(monkeypatch, calls)

    SSHBackend(host="me@example.com", ssh_args=["-i", "key"])

    probe = calls[0][0]
    assert probe[0] == "ssh"
    assert "BatchMode=yes" in probe
    assert "ConnectTimeout=10" in probe
    # Host-key policy pinned on the probe (default accept-new).
    assert "StrictHostKeyChecking=accept-new" in probe
    assert probe[-2:] == ["me@example.com", "true"]
    # ssh_args are threaded into the probe before host.
    assert "-i" in probe and "key" in probe


def test_verify_ssh_missing_binary_raises(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="ssh binary not found"):
        SSHBackend(host="me@example.com")


def test_verify_ssh_failed_probe_raises(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/ssh")

    def _fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 255, stdout=b"", stderr=b"perm denied")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    with pytest.raises(RuntimeError, match="ssh to me@example.com failed: perm denied"):
        SSHBackend(host="me@example.com")


@pytest.mark.parametrize("code,stderr,expected", [
    (0, b"", None),
    (255, b"Connection reset by peer", "could not check GNU timeout: the ssh connection failed: Connection reset by peer"),
    (127, b"sh: timeout: not found", "does not accept --signal=KILL: sh: timeout: not found"),
    (255, b"odd timeout\nlightwork-ssh-exit-255-fixed\n", r"does not accept --signal=KILL: odd timeout\. Install"),
])
def test_timeout_probe_runs_the_form_exec_uses_and_reports_why(monkeypatch, code, stderr, expected):
    """The probe is what exec runs (``timeout --signal=KILL <n>s``), so a remote
    whose timeout lacks ``--version`` is accepted; a failed probe keeps the
    remote stderr and tells a dropped connection from a missing timeout."""
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/ssh")
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args[-1])
        if args[-1] == "true":
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        if args[-1] == _marking_255("timeout --signal=KILL 1.000000s true", _MARK):
            return subprocess.CompletedProcess(args, code, stdout=b"", stderr=stderr)
        return subprocess.CompletedProcess(args, 125, stdout=b"", stderr=b"unrecognized option")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    if expected is None:
        assert SSHBackend(host="me@example.com").host == "me@example.com"
    else:
        with pytest.raises(RuntimeError, match=expected):
            SSHBackend(host="me@example.com")
    assert calls == ["true", _marking_255("timeout --signal=KILL 1.000000s true", _MARK)]


def test_exec_builds_mkdir_cd_and_quotes_command(monkeypatch):
    calls = []
    _patch_ssh_ok(monkeypatch)
    backend = SSHBackend(host="me@example.com", workdir="/home/me/ws", ssh_args=["-p", "2222"])

    def _exec_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="hi", stderr="warn")

    monkeypatch.setattr(subprocess, "run", _exec_run)

    result = backend.exec("echo $HOME")

    args, kwargs = calls[0]
    assert args[0] == "ssh"
    # ssh hardening opts precede ssh_args, which precede the host.
    assert "BatchMode=yes" in args
    assert "StrictHostKeyChecking=accept-new" in args
    p_idx = args.index("-p")
    assert args[p_idx:p_idx + 2] == ["-p", "2222"]  # ssh_args threaded before host
    host = args[-2]
    remote = args[-1]
    assert host == "me@example.com"
    quoted = shlex.quote("/home/me/ws")
    # cmd runs as a single quoted arg inside sh -c so it can't escape the cd.
    inner = shlex.quote("echo $HOME")
    command = f"mkdir -p {quoted} && cd {quoted} && sh -c {inner}"
    assert remote == _marking_255(f"timeout --signal=KILL 60.000000s sh -c {shlex.quote(command)}", _MARK)
    # Output is drained through bounded pipes (sandbox.local.run_capped).
    assert isinstance(kwargs["stdout"], int) and isinstance(kwargs["stderr"], int)
    assert kwargs["text"] is True
    assert result.stdout == "hi"
    assert result.stderr == "warn"
    assert result.exit_code == 0


def test_exec_cmd_injection_stays_single_arg(monkeypatch):
    """A cmd that tries to break out of the cd guard with a leading `;` must
    stay a single quoted argument to `sh -c`, not splice into the remote
    shell as a second statement that runs outside the workspace."""
    calls = []
    _patch_ssh_ok(monkeypatch)
    backend = SSHBackend(host="me@example.com", workdir="/home/me/ws")

    def _exec_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _exec_run)

    evil = "; rm -rf /"
    backend.exec(evil)

    remote = calls[0][0][-1]
    quoted = shlex.quote("/home/me/ws")
    # The whole evil string is one quoted arg to `sh -c` -- it never appears
    # as a bare `; rm -rf /` spliced after the cd.
    command = f"mkdir -p {quoted} && cd {quoted} && sh -c {shlex.quote(evil)}"
    assert remote == _marking_255(f"timeout --signal=KILL 60.000000s sh -c {shlex.quote(command)}", _MARK)


def test_exec_uses_default_timeout_then_override(monkeypatch):
    seen = []
    _patch_ssh_ok(monkeypatch)
    backend = SSHBackend(host="me@example.com", timeout=42.0)

    def _exec_run(args, **kwargs):
        seen.append(kwargs.get("timeout"))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _exec_run)

    backend.exec("ls")
    backend.exec("ls", timeout=7)

    assert seen == [42.0, 7]


def test_exec_timeout_returns_124(monkeypatch):
    _patch_ssh_ok(monkeypatch)
    backend = SSHBackend(host="me@example.com", timeout=3.0)

    def _exec_run(args, **kwargs):
        raise subprocess.TimeoutExpired(args, kwargs.get("timeout", 0), output=b"partial")

    monkeypatch.setattr(subprocess, "run", _exec_run)

    result = backend.exec("sleep 99")

    assert result.exit_code == 124
    assert result.stderr == "TIMEOUT after 3.0s"
    assert result.stdout == "partial"

    # On Windows subprocess fills the partial output as str in text mode.
    def _exec_run_text(args, **kwargs):
        raise subprocess.TimeoutExpired(args, kwargs.get("timeout", 0), output="partial")

    monkeypatch.setattr(subprocess, "run", _exec_run_text)
    result = backend.exec("sleep 99")
    assert (result.exit_code, result.stdout) == (124, "partial")


def test_factory_selects_ssh_backend(monkeypatch):
    calls = []
    _patch_ssh_ok(monkeypatch, calls)

    from maverick import config as config_mod

    monkeypatch.setattr(config_mod, "get_sandbox", lambda: {"backend": "ssh", "timeout": 99})
    monkeypatch.setattr(config_mod, "load_config", lambda: {
        "sandbox": {
            "backend": "ssh",
            "host": "me@example.com",
            "workdir": "/remote/ws",
            "ssh_args": ["-i", "key"],
        }
    })

    backend = build_sandbox()

    assert isinstance(backend, SSHBackend)
    assert backend.host == "me@example.com"
    assert backend.workdir == PurePosixPath("/remote/ws")
    assert backend.timeout == 99.0
    assert backend.ssh_args == ["-i", "key"]


def test_factory_ssh_without_host_raises(monkeypatch):
    from maverick import config as config_mod

    monkeypatch.setattr(config_mod, "get_sandbox", lambda: {"backend": "ssh"})
    monkeypatch.setattr(config_mod, "load_config", lambda: {"sandbox": {"backend": "ssh"}})

    with pytest.raises(ValueError, match="backend=ssh requires"):
        build_sandbox()


def test_remote_workspace_omits_local_path_tools_for_ssh_subclasses(monkeypatch, tmp_path):
    from maverick.tools import base_registry

    class CustomSSHBackend(SSHBackend):
        pass

    monkeypatch.setattr(SSHBackend, "_verify_ssh", lambda self: None)
    remote = CustomSSHBackend(host="example.com", workdir=tmp_path)
    names = {tool.name for tool in base_registry(SimpleNamespace(), remote).all()}
    assert not _LOCAL_WORKSPACE_TOOLS & names
    assert "shell" in names


def test_backend_can_declare_a_remote_workspace_without_using_ssh(tmp_path):
    from maverick.tools import base_registry

    sandbox = SimpleNamespace(workdir=tmp_path, workdir_is_local=False)
    names = {tool.name for tool in base_registry(SimpleNamespace(), sandbox).all()}
    assert not _LOCAL_WORKSPACE_TOOLS & names
    assert "shell" in names


def test_legacy_local_workspace_keeps_standard_tools(tmp_path):
    from maverick.tools import base_registry

    sandbox = SimpleNamespace(workdir=tmp_path)
    names = [tool.name for tool in base_registry(SimpleNamespace(), sandbox).all()]
    assert set(names) >= _LOCAL_WORKSPACE_TOOLS
    # Registration order affects limited provider catalogs as well as schemas.
    assert names[:10] == [
        "read_file", "write_file", "list_dir", "shell", "ask_user",
        "list_attachments", "read_tool_result", "read_attachment", "repo_map",
        "str_replace_editor",
    ]


@pytest.mark.parametrize("invalid", [None, 0, "yes"])
def test_invalid_workspace_declaration_does_not_enable_local_access(invalid):
    from maverick.sandbox.sdk import workdir_is_local

    assert not workdir_is_local(SimpleNamespace(workdir_is_local=invalid))


@pytest.mark.parametrize("stderr,expected", [
    ("ssh: connect to host h port 22: Connection refused\n",
     "The ssh connection failed (exit 255): ssh: connect to host h port 22: Connection refused"),
    ("oops\nlightwork-ssh-exit-255-fixed\n", "oops\n"),
    # A background child may keep writing after the marker.
    ("oops\nlightwork-ssh-exit-255-fixed\nlate\n", "oops\nlate\n"),
    # Another call's marker (or a guess) does not count.
    ("lightwork-ssh-exit-255-other\n",
     "The ssh connection failed (exit 255): lightwork-ssh-exit-255-other"),
])
def test_exec_tells_a_failed_connection_from_a_remote_exit_255(monkeypatch, stderr, expected):
    """ssh exits 255 for its own failures and passes a remote 255 through; the
    remote wrapper marks the latter, so only an unmarked 255 is reported as a
    connection failure."""
    _patch_ssh_ok(monkeypatch)
    backend = SSHBackend(host="me@example.com")
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: subprocess.CompletedProcess(
        args, 255, stdout="", stderr=stderr))
    result = backend.exec("exit 255")
    assert (result.exit_code, result.stderr) == (255, expected)


def test_the_destination_always_follows_an_end_of_options_mark(monkeypatch):
    calls = []
    _patch_ssh_ok(monkeypatch, calls)
    backend = SSHBackend(host="me@example.com", ssh_args=["-p2222"])
    monkeypatch.setattr(ssh_module, "run_capped",
                        lambda args, **kw: calls.append((args, kw)) or SimpleNamespace(
                            returncode=0, stdout="", stderr=""))
    backend.exec("true")
    for args, _ in calls:
        assert args[args.index("me@example.com") - 1] == "--", args


@pytest.mark.parametrize("host", ["-oProxyCommand=touch /tmp/x", "me@ex ample.com", "me@example.com\n",
                                  "me@example.com\t-v", ""])
def test_a_destination_ssh_could_read_as_an_option_is_refused(monkeypatch, host):
    calls = []
    _patch_ssh_ok(monkeypatch, calls)
    with pytest.raises(ValueError, match="SSH destination"):
        SSHBackend(host=host)
    assert calls == []


def test_a_workspace_host_cannot_run_a_command_on_this_computer(tmp_path, monkeypatch):
    """End to end with the real ssh client: the organisation lets workspaces
    choose their remote computer, and a workspace names an ssh option."""
    if not shutil.which("ssh"):
        pytest.skip("needs the ssh client")
    from maverick import config

    ran = tmp_path / "ran"
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.delenv("MAVERICK_DEPLOYMENT_ISOLATION", raising=False)
    (tmp_path / "config.toml").write_text(
        '[sandbox]\nbackend = "ssh"\nhost = "me@example.invalid"\nworkspace_infrastructure = true\n'
        'workspace_hosts = ["*"]\n', encoding="utf-8")
    tenant = tmp_path / "tenants" / "acme" / "config.toml"
    tenant.parent.mkdir(parents=True)
    tenant.write_text(f'[sandbox]\nhost = "-oProxyCommand=touch {ran}"\n', encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    with pytest.raises((ValueError, RuntimeError)):
        build_sandbox()
    assert not ran.exists()
