"""Unit checks and opt-in real Linux-container containment acceptance.

Unit tests below do not establish container isolation. Real tests require an
already running local Linux engine and explicitly selected locally present
image, and never pull an image or invoke a model provider.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import asdict

import pytest
from maverick.budget import Budget, BudgetExceeded
from maverick.sandbox.research import (
    ResearchContainerError,
    ResearchContainerRunner,
    ResearchLimits,
    _capture,
    _digest,
    _host_environment,
    _input_digest,
    _inputs,
    _local_endpoint,
)


@pytest.mark.parametrize("name", ["../escape.py", "/absolute.py", "a/../x.py", "a/./x.py", "a\\x.py",
                                  "a:ads.py", "CON.py", "x./main.py", "a,,b.py"])
def test_research_snapshot_refuses_path_aliases(name):
    with pytest.raises(ValueError):
        _inputs({name: b"pass"}, name)


def test_research_snapshot_requires_bytes_and_unique_paths():
    with pytest.raises(ValueError):
        _inputs({"main.py": "print(1)"}, "main.py")
    with pytest.raises(ValueError):
        _inputs({"main.py": b"pass", "MAIN.py": b"pass"}, "main.py")
    with pytest.raises(ValueError):
        _inputs({"main.py": b"x" * (8 * 1024 * 1024 + 1)}, "main.py")


def test_input_digest_binds_names_and_bytes_independent_of_mapping_order():
    assert _input_digest({"a.py": b"A", "b.py": b"B"}) == _input_digest({"b.py": b"B", "a.py": b"A"})
    assert _input_digest({"a.py": b"A"}) != _input_digest({"a.py": b"B"})
    assert _input_digest({"a.py": b"A"}) != _input_digest({"b.py": b"A"})


@pytest.mark.parametrize("extra", [
    {"a/x.py": b"x", "A/y.py": b"y"},
    {"data": b"x", "data/x.py": b"pass"},
    {"data/x.py": b"pass", "data": b"x"},
])
def test_snapshot_directory_alias_and_file_parent_conflicts_fail_before_materialization(extra):
    with pytest.raises(ValueError, match="alias|parent"):
        _inputs({"main.py": b"pass", **extra}, "main.py")


def test_snapshot_preflights_implied_directory_count():
    files = {f"f{i}/" + "a/" * 42 + "main.py": b"pass" for i in range(100)}
    with pytest.raises(ValueError, match="entry limit"):
        _inputs(files, next(iter(files)))


def test_setup_control_calls_are_capped_by_remaining_budget(monkeypatch):
    budget = Budget(max_wall_seconds=60)
    monkeypatch.setattr(budget, "remaining_wall", lambda: 0.5)
    assert ResearchContainerRunner._control_time(budget) == 0.5
    monkeypatch.setattr(budget, "remaining_wall", lambda: 40)
    assert ResearchContainerRunner._control_time(budget) == 15


@pytest.mark.parametrize("field,value", [("pids", 0), ("cpus", 0), ("cpus", float("nan")),
                                        ("output_bytes", 2**40), ("timeout_seconds", True)])
def test_research_limits_cannot_be_disabled(field, value):
    with pytest.raises(ValueError):
        ResearchLimits(**{field: value})


def test_controller_environment_drops_remote_engine_and_secret_overrides(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://untrusted.invalid:2375")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-only")
    monkeypatch.setenv("UNEXPECTED_NAME", "synthetic-only")
    result = _host_environment()
    assert "DOCKER_HOST" not in result
    assert "OPENAI_API_KEY" not in result
    assert "UNEXPECTED_NAME" not in result


@pytest.mark.parametrize("endpoint,allowed", [
    ("npipe:////./pipe/dockerDesktopLinuxEngine", True),
    ("unix:///var/run/docker.sock", True),
    ("npipe:////remote-host/pipe/docker_engine", False),
    ("tcp://127.0.0.1:2375", False),
    ("ssh://remote-host", False),
])
def test_research_engine_endpoint_must_be_local(endpoint, allowed):
    assert _local_endpoint(endpoint) is allowed


def test_research_profile_pins_nonroot_independently_of_host_uid(tmp_path, monkeypatch):
    # Command construction only; no claim of runtime containment.
    runner = object.__new__(ResearchContainerRunner)
    runner.limits = ResearchLimits()
    runner.image_id = "sha256:" + "1" * 64
    monkeypatch.setenv("MAVERICK_SANDBOX_ALLOW_ROOT", "1")
    argv = runner._create_args("owned-name", tmp_path, "main.py")
    assert argv[argv.index("--user") + 1] == "65532:65532"
    assert "--pull=never" in argv and "--network=none" in argv
    assert "--read-only" in argv and "--cap-drop=ALL" in argv
    assert "--entrypoint" in argv and "-i" in argv
    assert argv[argv.index("--shm-size") + 1] == str(runner.limits.scratch_bytes)
    assert not hasattr(runner, "exec_authenticated_tests")


@pytest.mark.parametrize("metadata", [None, [], [{}], [None], [{"HostConfig": {}, "Config": {}}]])
def test_malformed_inspection_returns_stable_refusal(tmp_path, monkeypatch, metadata):
    runner = object.__new__(ResearchContainerRunner)
    monkeypatch.setattr(runner, "_json", lambda *args, **kwargs: metadata)
    with pytest.raises(ResearchContainerError, match="metadata"):
        runner._verify_created("owned-name", tmp_path, "main.py")


@pytest.mark.parametrize("stage,metadata", [
    ("context", value) for value in (None, [], [{}], [None], [{"Endpoints": []}])
] + [
    ("image", value) for value in (None, [], [None], [{"Os": "linux", "Config": None}],
                                  [{"Os": "linux", "Id": []}], [{"Os": "linux"}])
])
def test_malformed_constructor_metadata_returns_stable_refusal(monkeypatch, stage, metadata):
    from maverick.sandbox import research

    monkeypatch.setattr(research.shutil, "which", lambda name: "docker")
    monkeypatch.setattr(ResearchContainerRunner, "_control", lambda *args, **kwargs:
                        research._Capture(0, b"linux", b"", "completed"))
    context = [{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}]
    image = [{"Os": "linux", "Id": "sha256:" + "1" * 64, "Config": {}}]
    monkeypatch.setattr(ResearchContainerRunner, "_json", lambda self, args, **kwargs:
                        metadata if args[0] == stage else context if args[0] == "context" else image)
    runner = ResearchContainerRunner("reviewed-image")
    with pytest.raises(ResearchContainerError, match="metadata"):
        runner._initialize(budget=Budget(max_wall_seconds=30))


def test_docker_readiness_subprocesses_are_lazy_and_wall_capped(monkeypatch):
    from maverick.sandbox import research

    calls = []

    def capture(args, env, *, timeout, limit):
        calls.append((args, timeout))
        command = args[-2:]
        if command == ["context", "show"]:
            output = b"default"
        elif "context" in args and "inspect" in args:
            output = json.dumps([{"Endpoints": {"docker": {
                "Host": "unix:///var/run/docker.sock"}}}]).encode()
        elif "info" in args:
            output = b"linux"
        else:
            output = json.dumps([{"Os": "linux", "Id": "sha256:" + "1" * 64,
                                  "Config": {}}]).encode()
        return research._Capture(0, output, b"", "completed")

    monkeypatch.setattr(research.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(research, "_capture", capture)
    runner = ResearchContainerRunner("reviewed-image")
    assert calls == []
    budget = Budget(max_wall_seconds=30)
    monkeypatch.setattr(budget, "remaining_wall", lambda: 0.25)
    runner._initialize(budget=budget)
    assert len(calls) == 4
    assert all(timeout == 0.25 for _, timeout in calls)
    assert runner.image_id == "sha256:" + "1" * 64


def test_exhausted_setup_budget_starts_no_docker_subprocess(monkeypatch):
    from maverick.sandbox import research

    monkeypatch.setattr(research.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(research, "_capture", lambda *args, **kwargs:
                        pytest.fail("Docker subprocess must not start"))
    runner = ResearchContainerRunner("reviewed-image")
    budget = Budget(max_wall_seconds=30)
    monkeypatch.setattr(budget, "remaining_wall", lambda: 0)
    with pytest.raises(ResearchContainerError, match="wall budget"):
        runner._initialize(budget=budget)


def test_attached_client_spawn_failure_is_wrapped_and_cleans_snapshot(monkeypatch):
    from maverick.sandbox import research

    runner = object.__new__(ResearchContainerRunner)
    runner.limits = ResearchLimits()
    runner._requested_image = "reviewed-image"
    runner.image_id = "sha256:" + "1" * 64
    runner._base, runner._env = ["synthetic-controller"], {}
    roots, cleaned = [], []
    write_snapshot = research._write_snapshot

    def remember_root(root, files):
        roots.append(root)
        write_snapshot(root, files)

    def unavailable(*args, **kwargs):
        raise OSError("synthetic attached-client launch failure")

    monkeypatch.setattr(research, "_write_snapshot", remember_root)
    monkeypatch.setattr(runner, "_initialize", lambda *, budget: None)
    monkeypatch.setattr(research, "_capture", unavailable)
    monkeypatch.setattr(runner, "_control", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "_verify_created", lambda *args, **kwargs: {})
    monkeypatch.setattr(runner, "_cleanup", lambda name: cleaned.append(name) or True)
    with pytest.raises(ResearchContainerError, match="start research container"):
        runner.run({"main.py": b"pass"}, budget=Budget(max_wall_seconds=30))
    assert len(cleaned) == 1 and len(roots) == 1
    assert not roots[0].exists()


@pytest.mark.parametrize("output,reason", [(b"ok", "completed"), (b"\xff", "invalid_utf8_output")])
def test_authenticated_tenant_snapshot_materializes_under_its_owned_directory(tmp_path, monkeypatch, output, reason):
    from maverick.paths import data_dir, tenant_scope
    from maverick.sandbox import research

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    runner = object.__new__(ResearchContainerRunner)
    runner.limits, runner.image_id = ResearchLimits(), "sha256:" + "1" * 64
    runner._requested_image = "reviewed-image"
    runner._base, runner._env = ["synthetic-controller"], {}
    roots = []
    original = research._write_snapshot

    def capture(root, files):
        roots.append(root)
        original(root, files)

    monkeypatch.setattr(research, "_write_snapshot", capture)
    monkeypatch.setattr(runner, "_initialize", lambda *, budget: None)
    monkeypatch.setattr(research, "_capture", lambda *a, **kw: research._Capture(0, output, b"", "completed"))
    monkeypatch.setattr(runner, "_control", lambda *a, **kw: None)
    monkeypatch.setattr(runner, "_verify_created", lambda *a, **kw: {})
    monkeypatch.setattr(runner, "_cleanup", lambda name: True)
    with tenant_scope(tenant="research-tenant"):
        expected = data_dir() / "research-snapshots"
        result = runner.run({"main.py": b"pass"}, budget=Budget(max_wall_seconds=30))
    assert len(roots) == 1 and roots[0].parent == expected.resolve()
    assert not roots[0].exists()
    assert result.reason == reason


def test_policy_digest_binds_inspected_effective_policy_and_entrypoint(tmp_path, monkeypatch):
    from maverick.sandbox import research

    runner = object.__new__(ResearchContainerRunner)
    runner.limits, runner.image_id = ResearchLimits(), "sha256:" + "1" * 64
    runner._requested_image = "reviewed-image"
    runner._base, runner._env = ["synthetic-controller"], {}
    inspected = {"image_id": runner.image_id, "user": "65532:65532", "network": "none",
                 "readonly_root": True, "mounts": [], "security_opt": ["no-new-privileges"],
                 "cap_drop": ["ALL"], "tmpfs": {"/scratch": "noexec"}, "shm_bytes": 1024,
                 "command": ["python3", "/candidate/worker.py"], "limits": asdict(runner.limits)}
    monkeypatch.setattr(runner, "_initialize", lambda *, budget: None)
    monkeypatch.setattr(runner, "_control", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "_verify_created", lambda *args, **kwargs: dict(inspected))
    monkeypatch.setattr(runner, "_cleanup", lambda name: True)
    monkeypatch.setattr(research, "_capture", lambda *args, **kwargs:
                        research._Capture(0, b"ok", b"", "completed"))
    result = runner.run({"worker.py": b"print('ok')"},
                        budget=Budget(max_wall_seconds=30), entrypoint="worker.py")
    assert result.policy_sha256 == _digest(result.inspect_policy)
    assert result.entrypoint == result.inspect_policy["entrypoint"] == "worker.py"
    changed = dict(result.inspect_policy, network="bridge")
    assert _digest(changed) != result.policy_sha256


def test_controller_capture_bounds_bytes_before_retention():
    result = _capture([sys.executable, "-c", "import os;os.write(1,b'x'*100000)"],
                      _host_environment(), timeout=3, limit=1024)
    assert result.reason == "output_limit"
    assert len(result.out) + len(result.err) <= 1024


def test_controller_capture_kills_timed_out_client():
    result = _capture([sys.executable, "-c", "import time;time.sleep(5)"],
                      _host_environment(), timeout=0.1, limit=1024)
    assert result.reason == "timeout"


def test_budget_exhaustion_prevents_snapshot_and_container_creation(monkeypatch):
    runner = object.__new__(ResearchContainerRunner)
    runner.limits = ResearchLimits()
    monkeypatch.setattr(runner, "_control", lambda *_: pytest.fail("container should not be created"))
    with pytest.raises(BudgetExceeded):
        runner.run({"main.py": b"pass"}, budget=Budget(max_tool_calls=0))


@pytest.fixture
def real_runner():
    if os.environ.get("LIGHTWORK_RUN_RESEARCH_CONTAINER_TESTS") != "1":
        pytest.skip("real container acceptance requires an explicit local test run")
    image = os.environ.get("LIGHTWORK_RESEARCH_TEST_IMAGE")
    if not image:
        pytest.fail("select an existing local image with LIGHTWORK_RESEARCH_TEST_IMAGE; no image is pulled")
    return ResearchContainerRunner(image)


def _execute(runner, source: str, **files):
    return runner.run({"main.py": source.encode(), **files},
                      budget=Budget(max_wall_seconds=90, max_tool_calls=5))


def _assert_no_container(runner, result):
    assert result.cleanup_verified
    rows = runner._control(["container", "ls", "--all", "--filter",
                            f"name=^/{result.container_name}$", "--format", "{{.ID}}"])
    assert rows.out.strip() == b""


def test_real_positive_candidate_is_nonroot_with_bounded_scratch(real_runner):
    nonce = os.urandom(32).hex()
    source = f"""import hashlib,json,os
from pathlib import Path
Path('/scratch/allowed').write_text('yes')
print(json.dumps({{'uid':os.getuid(),'gid':os.getgid(),'scratch':Path('/scratch/allowed').read_text(),
                  'answer':hashlib.sha256({nonce!r}.encode()).hexdigest()}}))
"""
    result = _execute(real_runner, source)
    assert result.reason == "completed", asdict(result)
    assert result.exit_code == 0, result.stderr
    output = json.loads(result.stdout)
    assert output == {"uid": 65532, "gid": 65532, "scratch": "yes",
                      "answer": hashlib.sha256(nonce.encode()).hexdigest()}
    assert result.inspect_policy["network"] == "none"
    assert result.inspect_policy["readonly_root"] is True
    assert result.inspect_policy["shm_bytes"] == real_runner.limits.scratch_bytes
    assert result.inspect_policy["mounts"] == [{"destination": "/candidate", "type": "bind", "rw": False}]
    _assert_no_container(real_runner, result)


def test_real_candidate_cannot_read_canary_or_edit_evaluator(real_runner, tmp_path, monkeypatch):
    canary = os.urandom(32).hex()
    production = tmp_path / "production-credentials.json"
    production.write_text(canary, encoding="utf-8")
    before = hashlib.sha256(production.read_bytes()).hexdigest()
    monkeypatch.setenv("OPENAI_API_KEY", canary)
    monkeypatch.setenv("INNOCENT_SETTING", canary)
    evaluator = b"TRUSTED_SENTINEL = 'unchanged'\n"
    source = f"""import json,os
from pathlib import Path
results = {{'env':dict(os.environ)}}
paths = [{str(production)!r}, '/host/production-credentials.json',
         '/mnt/c/production-credentials.json','/proc/1/root/host/production-credentials.json']
results['canary_reads'] = []
for path in paths:
    try: results['canary_reads'].append(Path(path).read_text())
    except OSError: pass
results['denied'] = []
for name, operation in [
 ('write', lambda: Path('/candidate/evaluator.py').write_text('forged')),
 ('unlink', lambda: Path('/candidate/evaluator.py').unlink()),
 ('rename', lambda: Path('/candidate/evaluator.py').rename('/scratch/stolen.py')),
 ('chmod', lambda: os.chmod('/candidate/evaluator.py',0o777)),
 ('root', lambda: Path('/root/forged').write_text('forged')),
 ('setuid', lambda: os.setuid(0)),
 ('authority', lambda: Path('/candidate/authority.json').write_text('{{}}'))]:
    try: operation()
    except OSError: results['denied'].append(name)
print(json.dumps(results))
"""
    result = _execute(real_runner, source, **{"evaluator.py": evaluator})
    assert result.exit_code == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed["canary_reads"] == []
    assert set(observed["denied"]) == {"write", "unlink", "rename", "chmod", "root", "setuid", "authority"}
    assert "OPENAI_API_KEY" not in observed["env"] and "INNOCENT_SETTING" not in observed["env"]
    assert set(observed["env"]) == {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE"}
    assert canary not in result.stdout
    assert hashlib.sha256(production.read_bytes()).hexdigest() == before
    assert result.input_sha256 == _input_digest({"main.py": source.encode(), "evaluator.py": evaluator})
    _assert_no_container(real_runner, result)


def test_real_candidate_has_no_nonloopback_interface_or_network_route(real_runner):
    source = """import errno,json,socket
from pathlib import Path
client=socket.socket()
client.settimeout(0.5)
try:
    code=client.connect_ex(('192.0.2.1',65000))
finally:
    client.close()
print(json.dumps({'interfaces':[p.name for p in Path('/sys/class/net').iterdir()],
                  'route':Path('/proc/net/route').read_text(),'connect_errno':code}))
"""
    result = _execute(real_runner, source)
    assert result.exit_code == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed["interfaces"] == ["lo"]
    assert len(observed["route"].strip().splitlines()) == 1
    assert observed["connect_errno"] == 101  # Linux ENETUNREACH, not an absent remote server.
    assert result.inspect_policy["network"] == "none"
    _assert_no_container(real_runner, result)


def test_real_output_quota_removes_whole_container(real_runner):
    real_runner.limits = ResearchLimits(output_bytes=4096)
    result = _execute(real_runner, "import os\nwhile True: os.write(1,b'x'*4096)")
    assert result.reason == "output_limit"
    assert result.captured_bytes <= 4096
    _assert_no_container(real_runner, result)


def test_real_timeout_removes_background_children(real_runner):
    real_runner.limits = ResearchLimits(timeout_seconds=1)
    source = """import subprocess,sys,time
subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
time.sleep(60)
"""
    result = _execute(real_runner, source)
    assert result.reason == "timeout"
    _assert_no_container(real_runner, result)


def test_controller_cancellation_kills_owned_client_without_retry():
    result = _capture([sys.executable, "-c", "import time;time.sleep(5)"],
                      _host_environment(), timeout=3, limit=1024, cancelled=lambda: True)
    assert result.reason == "cancelled"
    assert result.code != 0
