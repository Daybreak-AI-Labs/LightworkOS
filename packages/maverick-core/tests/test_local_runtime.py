"""Local-runtime launcher + autoscaler: continuous batching, persistent
KV-cache / KV offload to disk, autoscaling local backends and mixed-precision
local inference. All offline: fake runner, fake probe,
virtual clock."""
from __future__ import annotations

import os

import pytest
from maverick import local_runtime as lr


@pytest.fixture(autouse=True)
def _no_active_scaler():
    """Autoscaler.start registers module-global state; never leak it."""
    yield
    lr._ACTIVE = None


def _val(argv: list[str], flag: str) -> str:
    """The value right after ``flag``, asserting the flag appears exactly once."""
    assert argv.count(flag) == 1, f"{flag} not exactly-once in {argv}"
    return argv[argv.index(flag) + 1]


# ---------------------------------------------------------------- argv: vllm

def test_vllm_argv_minimal_exact():
    assert lr.build_argv("vllm", {"model": "org/m"}) == [
        "vllm", "serve", "org/m", "--host", "127.0.0.1", "--port", "8000",
    ]


def test_vllm_argv_batching_kv_precision():
    cfg = {
        "model": "org/m", "port": 9000,
        "max_concurrent": 64, "max_batch_tokens": 8192,
        "kv_cache": "persistent", "kv_swap_gb": 8,
        "precision": "fp16", "extra_args": ["--seed", "7"],
    }
    argv = lr.build_argv("vllm", cfg)
    assert argv[:3] == ["vllm", "serve", "org/m"]
    assert _val(argv, "--port") == "9000"
    assert _val(argv, "--max-num-seqs") == "64"
    assert _val(argv, "--max-num-batched-tokens") == "8192"
    assert "--enable-prefix-caching" in argv
    assert _val(argv, "--swap-space") == "8"
    assert _val(argv, "--dtype") == "float16"
    assert argv[-2:] == ["--seed", "7"]
    assert lr.build_env("vllm", cfg) == {}


# ----------------------------------------------------------------- argv: tgi

def test_tgi_argv_batching_kv_precision():
    cfg = {
        "model": "org/m", "max_concurrent": 32, "max_batch_tokens": 16384,
        "kv_cache": "persistent", "precision": "bf16",
    }
    argv = lr.build_argv("tgi", cfg)
    assert argv[0] == "text-generation-launcher"
    assert _val(argv, "--model-id") == "org/m"
    assert _val(argv, "--hostname") == "127.0.0.1"
    assert _val(argv, "--port") == "8080"
    assert _val(argv, "--max-concurrent-requests") == "32"
    assert _val(argv, "--max-batch-total-tokens") == "16384"
    assert _val(argv, "--dtype") == "bfloat16"
    # TGI's prefix cache is env-toggled, not a launcher flag:
    assert "--enable-prefix-caching" not in argv
    assert lr.build_env("tgi", cfg) == {"PREFIX_CACHING": "1"}


def test_tgi_no_kv_env_by_default():
    assert lr.build_env("tgi", {"model": "org/m"}) == {}


# ------------------------------------------------------------ argv: llamacpp

def test_llamacpp_argv_batching_kv(tmp_path):
    cfg = {
        "model": "/models/m-q4_k_m.gguf", "max_concurrent": 4,
        "max_batch_tokens": 2048, "kv_cache": "persistent",
        "kv_offload_dir": str(tmp_path),
    }
    argv = lr.build_argv("llamacpp", cfg)
    assert argv[:3] == ["llama-server", "-m", "/models/m-q4_k_m.gguf"]
    assert _val(argv, "--port") == "8080"
    assert _val(argv, "--parallel") == "4"
    assert "--cont-batching" in argv
    assert _val(argv, "--batch-size") == "2048"
    assert _val(argv, "--prompt-cache") == os.path.join(str(tmp_path), "llamacpp.promptcache")
    assert "--prompt-cache-all" in argv
    assert lr.build_env("llamacpp", cfg) == {}


def test_llamacpp_offload_dir_alone_writes_prompt_cache(tmp_path):
    # KV offload to disk: the dir knob alone is enough on llama.cpp.
    argv = lr.build_argv("llamacpp", {"model": "m.gguf", "kv_offload_dir": str(tmp_path)})
    assert "--prompt-cache-all" in argv


def test_llamacpp_persistent_kv_requires_dir():
    with pytest.raises(lr.LocalRuntimeError, match="kv_offload_dir"):
        lr.build_argv("llamacpp", {"model": "m.gguf", "kv_cache": "persistent"})


# ------------------------------------------------------------------ precision

@pytest.mark.parametrize("engine,precision,flag,value", [
    ("vllm", "fp16", "--dtype", "float16"),
    ("vllm", "bf16", "--dtype", "bfloat16"),
    ("vllm", "int8", "--quantization", "bitsandbytes"),
    ("vllm", "int4", "--quantization", "awq"),
    ("tgi", "fp16", "--dtype", "float16"),
    ("tgi", "bf16", "--dtype", "bfloat16"),
    ("tgi", "int8", "--quantize", "bitsandbytes"),
    ("tgi", "int4", "--quantize", "awq"),
])
def test_precision_flag_matrix(engine, precision, flag, value):
    argv = lr.build_argv(engine, {"model": "org/m", "precision": precision})
    assert _val(argv, flag) == value


def test_precision_auto_adds_no_flags():
    for engine in lr.ENGINES:
        argv = lr.build_argv(engine, {"model": "m", "precision": "auto"})
        for flag in ("--dtype", "--quantization", "--quantize"):
            assert flag not in argv, (engine, argv)


def test_llamacpp_precision_is_a_note_not_a_flag():
    # Quantization is baked into the GGUF file; no flag must be emitted.
    argv = lr.build_argv("llamacpp", {"model": "m-q4.gguf", "precision": "int4"})
    for flag in ("--dtype", "--quantization", "--quantize"):
        assert flag not in argv


def test_unknown_precision_rejected():
    with pytest.raises(lr.LocalRuntimeError, match="precision"):
        lr.build_argv("vllm", {"model": "m", "precision": "fp4"})
    with pytest.raises(lr.LocalRuntimeError, match="precision"):
        lr.load_local_runtime({"precision": "q4"})


def test_unknown_engine_rejected():
    with pytest.raises(lr.LocalRuntimeError, match="engine"):
        lr.build_argv("sglang", {"model": "m"})


def test_model_required():
    with pytest.raises(lr.LocalRuntimeError, match="model"):
        lr.build_argv("vllm", {})


# --------------------------------------------------------------------- config

def test_defaults_are_off():
    cfg = lr.load_local_runtime({})
    assert cfg["enabled"] is False
    assert cfg["autoscale"] is False
    assert cfg["engine"] == "vllm" and cfg["precision"] == "auto"
    assert cfg["model"] == ""  # users own model choice: never defaulted


def test_config_file_read_and_env_wins(tmp_path, monkeypatch):
    cfgdir = tmp_path / ".maverick"
    cfgdir.mkdir(parents=True, exist_ok=True)
    (cfgdir / "config.toml").write_text(
        "[local_runtime]\n"
        "enabled = true\n"
        'engine = "tgi"\n'
        'model = "org/m"\n'
        'precision = "fp16"\n'
        "max_concurrent = 16\n",
        encoding="utf-8",
    )
    cfg = lr.load_local_runtime()  # HOME is tmp_path via the autouse fixture
    assert cfg["enabled"] is True
    assert cfg["engine"] == "tgi" and cfg["model"] == "org/m"
    assert cfg["precision"] == "fp16" and cfg["max_concurrent"] == 16
    # MAVERICK_LOCAL_RUNTIME_* beats the file:
    monkeypatch.setenv("MAVERICK_LOCAL_RUNTIME_PRECISION", "bf16")
    monkeypatch.setenv("MAVERICK_LOCAL_RUNTIME_ENGINE", "vllm")
    monkeypatch.setenv("MAVERICK_LOCAL_RUNTIME_MAX_CONCURRENT", "64")
    cfg = lr.load_local_runtime()
    assert cfg["engine"] == "vllm" and cfg["precision"] == "bf16"
    assert cfg["max_concurrent"] == 64


def test_env_overrides_explicit_section(monkeypatch):
    monkeypatch.setenv("MAVERICK_LOCAL_RUNTIME_ENABLED", "1")
    cfg = lr.load_local_runtime({"enabled": False, "model": "m"})
    assert cfg["enabled"] is True


# ------------------------------------------------------------------- launcher

class FakeRunner:
    """Records spawns/stops; never starts a process."""

    def __init__(self):
        self.spawned: list[dict] = []
        self.stopped: list[dict] = []

    def spawn(self, argv, *, env=None):
        handle = {"argv": argv, "env": env, "alive": True}
        self.spawned.append(handle)
        return handle

    def alive(self, handle):
        return handle["alive"]

    def stop(self, handle):
        handle["alive"] = False
        self.stopped.append(handle)


def test_launcher_default_off_refuses_politely():
    runner = FakeRunner()
    launcher = lr.Launcher({"model": "m"}, runner=runner)  # no enabled=true anywhere
    with pytest.raises(lr.LocalRuntimeDisabled, match="enabled = true"):
        launcher.start()
    assert runner.spawned == []  # refusing means refusing


def test_launcher_start_stop_records_with_fake_runner():
    runner = FakeRunner()
    launcher = lr.Launcher(
        {"enabled": True, "engine": "vllm", "model": "org/m"}, runner=runner)
    assert launcher.start() == "http://127.0.0.1:8000"
    assert launcher.start(replica=1) == "http://127.0.0.1:8001"  # port+replica
    assert _val(runner.spawned[0]["argv"], "--port") == "8000"
    assert _val(runner.spawned[1]["argv"], "--port") == "8001"
    assert launcher.start() == "http://127.0.0.1:8000"  # idempotent while alive
    assert len(runner.spawned) == 2
    assert [r["alive"] for r in launcher.status()["replicas"]] == [True, True]
    launcher.stop(1)
    assert len(runner.stopped) == 1
    assert [r["replica"] for r in launcher.status()["replicas"]] == [0]
    launcher.stop()  # stop all
    assert len(runner.stopped) == 2
    assert launcher.status()["replicas"] == []


def test_launcher_passes_tgi_prefix_cache_env():
    runner = FakeRunner()
    launcher = lr.Launcher(
        {"enabled": True, "engine": "tgi", "model": "org/m", "kv_cache": "persistent"},
        runner=runner)
    launcher.start()
    assert runner.spawned[0]["env"] == {"PREFIX_CACHING": "1"}


def test_launcher_plan_is_dry():
    runner = FakeRunner()
    launcher = lr.Launcher({"model": "m.gguf", "engine": "llamacpp"}, runner=runner)
    argv, env = launcher.plan()  # works even while disabled
    assert argv[0] == "llama-server" and env == {}
    assert runner.spawned == []


# ----------------------------------------------------------------- autoscaler

class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def _scaler(clock, **overrides):
    cfg = {"autoscale": True, "min_replicas": 1, "max_replicas": 3,
           "scale_up_depth": 5, "scale_down_depth": 1, "hold_seconds": 10.0}
    cfg.update(overrides)
    spawned, stopped, depth = [], [], {"v": 0}

    def spawn(i):
        spawned.append(i)
        return f"ep{i}"

    scaler = lr.Autoscaler(cfg, spawn=spawn, stop=stopped.append,
                           probe=lambda: depth["v"], clock=clock)
    return scaler, depth, spawned, stopped


def test_autoscaler_default_off():
    scaler, depth, spawned, _ = _scaler(FakeClock(), autoscale=False)
    with pytest.raises(lr.LocalRuntimeDisabled, match="autoscale"):
        scaler.start()
    depth["v"] = 99
    assert scaler.tick() == 0  # no-op while off
    assert spawned == []


def test_autoscaler_scales_up_on_sustained_depth():
    clock = FakeClock()
    scaler, depth, spawned, _ = _scaler(clock)
    assert scaler.start() == ["ep0"]
    assert spawned == [0]
    depth["v"] = 9
    assert scaler.tick() == 1   # arms the window; never an instant scale
    clock.advance(5)
    assert scaler.tick() == 1   # 5s < hold_seconds: not sustained yet
    clock.advance(5)
    assert scaler.tick() == 2   # sustained 10s -> one step up
    assert spawned == [0, 1]


def test_autoscaler_spike_does_not_scale():
    clock = FakeClock()
    scaler, depth, spawned, _ = _scaler(clock)
    scaler.start()
    depth["v"] = 50             # spike...
    scaler.tick()
    clock.advance(9)
    depth["v"] = 3              # ...back inside the band before the hold elapses
    scaler.tick()               # resets the window
    depth["v"] = 50
    scaler.tick()
    clock.advance(9)
    assert scaler.tick() == 1   # still not sustained: no scale
    assert spawned == [0]


def test_autoscaler_scales_down_with_hysteresis_never_below_min():
    clock = FakeClock()
    scaler, depth, spawned, stopped = _scaler(clock)
    scaler.start()
    depth["v"] = 9              # drive up to 2 replicas first
    scaler.tick()
    clock.advance(10)
    assert scaler.tick() == 2
    depth["v"] = 0              # queue drained
    scaler.tick()               # arms the low window
    clock.advance(9)
    assert scaler.tick() == 2   # hysteresis: not down yet
    clock.advance(1)
    assert scaler.tick() == 1   # sustained low -> one step down
    assert stopped == [1]       # highest replica index stopped
    for _ in range(5):          # sustained low forever: never below min
        clock.advance(60)
        scaler.tick()
    assert scaler.replicas == 1
    assert stopped == [1]


def test_autoscaler_never_above_max():
    clock = FakeClock()
    scaler, depth, spawned, _ = _scaler(clock, max_replicas=2)
    scaler.start()
    depth["v"] = 99
    for _ in range(10):
        clock.advance(60)
        scaler.tick()
    assert scaler.replicas == 2
    assert spawned == [0, 1]


def test_endpoints_round_robin_and_module_export():
    assert lr.endpoints() == []  # no active autoscaler
    scaler, _, _, _ = _scaler(FakeClock(), min_replicas=2, max_replicas=3)
    scaler.start()
    assert scaler.endpoints() == ["ep0", "ep1"]
    assert scaler.endpoints() == ["ep1", "ep0"]  # rotates one step per call
    assert scaler.endpoints() == ["ep0", "ep1"]
    assert lr.endpoints() == ["ep1", "ep0"]      # module fn consults the active scaler
    scaler.shutdown()
    assert scaler.replicas == 0
    assert lr.endpoints() == []


def test_clock_is_virtual_and_module_never_blocks():
    # The autoscaler tests above advance a fake clock only; belt-and-braces,
    # the module must contain no blocking call at all.
    import inspect
    src = inspect.getsource(lr)
    assert "sleep(" not in src


# ------------------------------------------------------------------------ cli

def test_cli_plan_prints_argv(tmp_path):
    cfgdir = tmp_path / ".maverick"
    cfgdir.mkdir(parents=True, exist_ok=True)
    (cfgdir / "config.toml").write_text(
        '[local_runtime]\nengine = "llamacpp"\nmodel = "/m/q4.gguf"\n',
        encoding="utf-8",
    )
    from click.testing import CliRunner
    from maverick.cli import main
    res = CliRunner().invoke(main, ["local-runtime", "plan"])
    assert res.exit_code == 0, res.output
    assert "llama-server" in res.output and "/m/q4.gguf" in res.output
    assert "DISABLED" in res.output  # enabled defaults to false: plan is dry


def test_cli_plan_without_model_is_polite():
    from click.testing import CliRunner
    from maverick.cli import main
    res = CliRunner().invoke(main, ["local-runtime", "plan"])
    assert res.exit_code != 0
    assert "model" in res.output


def test_every_knob_has_its_named_environment_override(monkeypatch):
    from maverick import local_runtime

    assert set(local_runtime.ENV_VARS) == set(local_runtime.DEFAULTS)
    for key, name in local_runtime.ENV_VARS.items():
        assert name == "MAVERICK_LOCAL_RUNTIME_" + key.upper()
    monkeypatch.setenv("MAVERICK_LOCAL_RUNTIME_PORT", "9123")
    assert local_runtime.load_local_runtime({})["port"] == 9123
