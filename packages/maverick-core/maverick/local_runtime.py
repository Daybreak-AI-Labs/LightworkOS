"""Local model-runtime launcher + autoscaler (vLLM / TGI / llama.cpp).

vLLM and TGI implement continuous batching, prefix/KV caching and quantized
inference *server-side*; llama.cpp bakes precision into the GGUF file. What
Lightwork adds — and all this module claims to add — is honest plumbing:

* translate ``[local_runtime]`` config knobs into the *correct* server argv
  per engine (:func:`build_argv`, pure) plus the env vars an engine toggles
  via environment instead of flags (:func:`build_env`);
* start/supervise the server process (:class:`Launcher`, injectable runner so
  tests never spawn anything);
* scale N replicas between min/max on a queue-depth signal with hysteresis
  (:class:`Autoscaler`, injectable spawn/stop/probe/clock — pure bookkeeping,
  driven by :meth:`Autoscaler.tick`; nothing here sleeps);
* a round-robin endpoint picker routers can consult (:func:`endpoints`).

Everything defaults OFF: ``Launcher.start`` refuses unless ``[local_runtime]
enabled = true`` and ``Autoscaler.start`` refuses unless ``autoscale = true``.
``model`` is never defaulted — users own model choice (CLAUDE.md #2). Any
``MAVERICK_LOCAL_RUNTIME_<KNOB>`` env var beats the config file.

Engine flag map (knob -> argv/env)
==================================

Server binaries: ``vllm serve MODEL`` | ``text-generation-launcher`` |
``llama-server`` (llama.cpp).

=====================  ===========================  ==============================  =================================
[local_runtime] knob   vllm                         tgi                             llamacpp
=====================  ===========================  ==============================  =================================
model (required)       positional after ``serve``   --model-id MODEL                -m MODEL  (a .gguf file)
host / port            --host H --port P            --hostname H --port P           --host H --port P
max_concurrent = N     --max-num-seqs N             --max-concurrent-requests N     --parallel N --cont-batching
max_batch_tokens = N   --max-num-batched-tokens N   --max-batch-total-tokens N      --batch-size N
kv_cache="persistent"  --enable-prefix-caching      env PREFIX_CACHING=1 (env-      --prompt-cache FILE
                                                    toggled, no launcher flag;      --prompt-cache-all, where FILE =
                                                    default-on since TGI v3)        <kv_offload_dir>/llamacpp.promptcache
kv_offload_dir = DIR   no first-party disk-KV       no disk-KV flag (warned,        directory for the prompt-cache
                       flag (warned, ignored —      ignored)                        file above — the only engine here
                       use kv_swap_gb)                                              that persists KV to disk
kv_swap_gb = N         --swap-space N (KV swap      (none; warned)                  (none; warned)
                       to CPU RAM, GiB)
precision = auto       (omitted — engine default)   (omitted)                       (omitted)
precision = fp16       --dtype float16              --dtype float16                 no flag — pick an F16 .gguf (warned)
precision = bf16       --dtype bfloat16             --dtype bfloat16                no flag — pick a BF16 .gguf (warned)
precision = int8       --quantization bitsandbytes  --quantize bitsandbytes         no flag — pick a Q8_0 .gguf (warned)
precision = int4       --quantization awq           --quantize awq                  no flag — pick a Q4_K_M .gguf (warned)
extra_args = [...]     appended verbatim            appended verbatim               appended verbatim
=====================  ===========================  ==============================  =================================

Notes: ``int4`` assumes an AWQ-quantized checkpoint on vLLM/TGI (the portable
4-bit format); the engine is authoritative and refuses unsupported combos at
startup. llama.cpp quantization lives in the model file, so precision maps to
a model-selection note, not a flag. Autoscaler knobs (``autoscale``,
``min_replicas``, ``max_replicas``, ``scale_up_depth``, ``scale_down_depth``,
``hold_seconds``) never reach the server argv.
"""
from __future__ import annotations

import logging
import os
import shlex
import time

log = logging.getLogger(__name__)

ENGINES = ("vllm", "tgi", "llamacpp")
PRECISIONS = ("auto", "fp16", "bf16", "int8", "int4")
_KV_MODES = ("", "persistent")

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", ""})

# Engine default ports (mirrors provider_local_first._LOCAL_PORTS).
_DEFAULT_PORTS = {"vllm": 8000, "tgi": 8080, "llamacpp": 8080}

DEFAULTS: dict = {
    "enabled": False,        # master switch: Launcher.start refuses when off
    "engine": "vllm",
    "model": "",             # required to launch; never defaulted (users own model choice)
    "host": "127.0.0.1",
    "port": 0,               # 0 = engine default; replica i listens on port+i
    "max_concurrent": 0,     # 0 = engine default
    "max_batch_tokens": 0,   # 0 = engine default
    "kv_cache": "",          # "persistent" = prefix/prompt caching across requests
    "kv_offload_dir": "",    # llamacpp: directory holding the on-disk prompt cache
    "kv_swap_gb": 0,         # vllm: --swap-space (KV swap to CPU RAM, GiB)
    "precision": "auto",
    "extra_args": [],        # appended to the server argv verbatim
    "autoscale": False,      # Autoscaler master switch
    "min_replicas": 1,
    "max_replicas": 1,
    "scale_up_depth": 8,     # queue depth at/above which up-scaling is considered
    "scale_down_depth": 1,   # queue depth at/below which down-scaling is considered
    "hold_seconds": 30.0,    # hysteresis: the signal must sustain this long per step
}

_LOWERCASE_KEYS = frozenset({"engine", "precision", "kv_cache"})

# precision -> extra argv per engine ("auto" and llamacpp map to no flag).
_PRECISION_FLAGS: dict[str, dict[str, list[str]]] = {
    "vllm": {
        "fp16": ["--dtype", "float16"],
        "bf16": ["--dtype", "bfloat16"],
        "int8": ["--quantization", "bitsandbytes"],
        "int4": ["--quantization", "awq"],
    },
    "tgi": {
        "fp16": ["--dtype", "float16"],
        "bf16": ["--dtype", "bfloat16"],
        "int8": ["--quantize", "bitsandbytes"],
        "int4": ["--quantize", "awq"],
    },
}


class LocalRuntimeError(ValueError):
    """Bad ``[local_runtime]`` config (unknown engine/precision, missing model, ...)."""


class LocalRuntimeDisabled(LocalRuntimeError):
    """A start was refused because the feature is off (the default)."""


def _coerce(key: str, raw, default):
    if isinstance(default, bool):  # before int: bool is an int subclass
        if isinstance(raw, bool):
            return raw
        s = str(raw).strip().lower()
        if s in _TRUE:
            return True
        if s in _FALSE:
            return False
        raise LocalRuntimeError(f"[local_runtime] {key}: expected a boolean, got {raw!r}")
    if isinstance(default, int):
        try:
            return int(raw)
        except (TypeError, ValueError):
            raise LocalRuntimeError(
                f"[local_runtime] {key}: expected an integer, got {raw!r}") from None
    if isinstance(default, float):
        try:
            return float(raw)
        except (TypeError, ValueError):
            raise LocalRuntimeError(
                f"[local_runtime] {key}: expected a number, got {raw!r}") from None
    if isinstance(default, list):
        if isinstance(raw, (list, tuple)):
            return [str(x) for x in raw]
        return shlex.split(str(raw))
    s = str(raw).strip()
    return s.lower() if key in _LOWERCASE_KEYS else s


def _validate(cfg: dict) -> None:
    if cfg["engine"] not in ENGINES:
        raise LocalRuntimeError(
            f"[local_runtime] engine must be one of {'|'.join(ENGINES)}, got {cfg['engine']!r}")
    if cfg["precision"] not in PRECISIONS:
        raise LocalRuntimeError(
            f"[local_runtime] precision must be one of {'|'.join(PRECISIONS)}, "
            f"got {cfg['precision']!r}")
    if cfg["kv_cache"] not in _KV_MODES:
        raise LocalRuntimeError(
            f'[local_runtime] kv_cache must be "persistent" or unset, got {cfg["kv_cache"]!r}')
    if cfg["min_replicas"] < 1:
        raise LocalRuntimeError("[local_runtime] min_replicas must be >= 1")
    if cfg["max_replicas"] < cfg["min_replicas"]:
        raise LocalRuntimeError("[local_runtime] max_replicas must be >= min_replicas")
    if cfg["scale_down_depth"] >= cfg["scale_up_depth"]:
        raise LocalRuntimeError(
            "[local_runtime] scale_down_depth must be below scale_up_depth (hysteresis band)")


def _normalize(section: dict | None) -> dict:
    """Fill defaults, coerce types, validate. Pure — no env or config-file reads."""
    section = section or {}
    cfg = {}
    for key, default in DEFAULTS.items():
        if key in section:
            cfg[key] = _coerce(key, section[key], default)
        else:
            cfg[key] = list(default) if isinstance(default, list) else default
    _validate(cfg)
    return cfg


# Each knob's environment override, spelled out so a reader (and the Settings
# catalogue's audit) can find it by name. Keep in step with DEFAULTS.
ENV_VARS: dict[str, str] = {
    "enabled": "MAVERICK_LOCAL_RUNTIME_ENABLED",
    "engine": "MAVERICK_LOCAL_RUNTIME_ENGINE",
    "model": "MAVERICK_LOCAL_RUNTIME_MODEL",
    "host": "MAVERICK_LOCAL_RUNTIME_HOST",
    "port": "MAVERICK_LOCAL_RUNTIME_PORT",
    "max_concurrent": "MAVERICK_LOCAL_RUNTIME_MAX_CONCURRENT",
    "max_batch_tokens": "MAVERICK_LOCAL_RUNTIME_MAX_BATCH_TOKENS",
    "kv_cache": "MAVERICK_LOCAL_RUNTIME_KV_CACHE",
    "kv_offload_dir": "MAVERICK_LOCAL_RUNTIME_KV_OFFLOAD_DIR",
    "kv_swap_gb": "MAVERICK_LOCAL_RUNTIME_KV_SWAP_GB",
    "precision": "MAVERICK_LOCAL_RUNTIME_PRECISION",
    "extra_args": "MAVERICK_LOCAL_RUNTIME_EXTRA_ARGS",
    "autoscale": "MAVERICK_LOCAL_RUNTIME_AUTOSCALE",
    "min_replicas": "MAVERICK_LOCAL_RUNTIME_MIN_REPLICAS",
    "max_replicas": "MAVERICK_LOCAL_RUNTIME_MAX_REPLICAS",
    "scale_up_depth": "MAVERICK_LOCAL_RUNTIME_SCALE_UP_DEPTH",
    "scale_down_depth": "MAVERICK_LOCAL_RUNTIME_SCALE_DOWN_DEPTH",
    "hold_seconds": "MAVERICK_LOCAL_RUNTIME_HOLD_SECONDS",
}


def load_local_runtime(section: dict | None = None) -> dict:
    """The normalized ``[local_runtime]`` config.

    ``section`` defaults to the ``[local_runtime]`` table of
    ``~/.maverick/config.toml``. A ``MAVERICK_LOCAL_RUNTIME_<KNOB>`` env var
    beats both (e.g. ``MAVERICK_LOCAL_RUNTIME_PRECISION=bf16``).
    """
    if section is None:
        try:
            from .config import load_config
            section = (load_config() or {}).get("local_runtime", {}) or {}
        except Exception:  # pragma: no cover -- the kernel runs without config
            section = {}
    merged = dict(section)
    for key in DEFAULTS:
        raw = os.environ.get(ENV_VARS[key])
        if raw is not None:
            merged[key] = raw
    return _normalize(merged)


def _port(cfg: dict, replica: int = 0) -> int:
    base = cfg["port"] or _DEFAULT_PORTS[cfg["engine"]]
    return base + replica


def endpoint_for(cfg: dict, replica: int = 0) -> str:
    """Base URL of replica N (provider clients normalize the ``/v1`` suffix)."""
    cfg = _normalize(cfg)
    return f"http://{cfg['host']}:{_port(cfg, replica)}"


def _warn_ignored(engine: str, knob: str, why: str) -> None:
    log.warning("[local_runtime] %s does not support %s; ignored (%s)", engine, knob, why)


def _argv_vllm(cfg: dict) -> list[str]:
    argv = ["vllm", "serve", cfg["model"],
            "--host", cfg["host"], "--port", str(_port(cfg))]
    if cfg["max_concurrent"]:
        argv += ["--max-num-seqs", str(cfg["max_concurrent"])]
    if cfg["max_batch_tokens"]:
        argv += ["--max-num-batched-tokens", str(cfg["max_batch_tokens"])]
    if cfg["kv_cache"] == "persistent":
        argv.append("--enable-prefix-caching")
    if cfg["kv_swap_gb"]:
        argv += ["--swap-space", str(cfg["kv_swap_gb"])]
    if cfg["kv_offload_dir"]:
        _warn_ignored("vllm", "kv_offload_dir",
                      "no first-party disk-KV flag; use kv_swap_gb for CPU swap")
    return argv + _PRECISION_FLAGS["vllm"].get(cfg["precision"], [])


def _argv_tgi(cfg: dict) -> list[str]:
    argv = ["text-generation-launcher", "--model-id", cfg["model"],
            "--hostname", cfg["host"], "--port", str(_port(cfg))]
    if cfg["max_concurrent"]:
        argv += ["--max-concurrent-requests", str(cfg["max_concurrent"])]
    if cfg["max_batch_tokens"]:
        argv += ["--max-batch-total-tokens", str(cfg["max_batch_tokens"])]
    # kv_cache="persistent" is env-toggled on TGI -- see build_env().
    if cfg["kv_offload_dir"]:
        _warn_ignored("tgi", "kv_offload_dir", "no disk-KV flag")
    if cfg["kv_swap_gb"]:
        _warn_ignored("tgi", "kv_swap_gb", "no KV swap flag")
    return argv + _PRECISION_FLAGS["tgi"].get(cfg["precision"], [])


def _argv_llamacpp(cfg: dict) -> list[str]:
    argv = ["llama-server", "-m", cfg["model"],
            "--host", cfg["host"], "--port", str(_port(cfg))]
    if cfg["max_concurrent"]:
        argv += ["--parallel", str(cfg["max_concurrent"]), "--cont-batching"]
    if cfg["max_batch_tokens"]:
        argv += ["--batch-size", str(cfg["max_batch_tokens"])]
    if cfg["kv_offload_dir"]:
        argv += ["--prompt-cache",
                 os.path.join(cfg["kv_offload_dir"], "llamacpp.promptcache"),
                 "--prompt-cache-all"]
    elif cfg["kv_cache"] == "persistent":
        raise LocalRuntimeError(
            "[local_runtime] kv_cache = 'persistent' on llamacpp needs kv_offload_dir: "
            "llama.cpp persists its prompt cache to a file on disk")
    if cfg["kv_swap_gb"]:
        _warn_ignored("llamacpp", "kv_swap_gb", "no KV swap flag")
    if cfg["precision"] != "auto":
        log.warning(
            "[local_runtime] llama.cpp bakes precision into the GGUF file; precision=%s "
            "ignored -- point model at an F16/BF16/Q8_0/Q4_K_M .gguf instead",
            cfg["precision"])
    return argv


_ARGV_BUILDERS = {"vllm": _argv_vllm, "tgi": _argv_tgi, "llamacpp": _argv_llamacpp}


def build_argv(engine: str, cfg: dict) -> list[str]:
    """The exact server argv for ``engine`` from a ``[local_runtime]`` mapping.

    Pure: no env, config-file or network reads — same inputs, same argv.
    ``engine`` wins over any ``cfg["engine"]``. Raises :class:`LocalRuntimeError`
    on an unknown engine/precision or a missing model.
    """
    cfg = _normalize({**(cfg or {}), "engine": engine})
    if not cfg["model"]:
        raise LocalRuntimeError(
            "[local_runtime] model is not set; Lightwork never picks a model for you. "
            "Set it in ~/.maverick/config.toml or via MAVERICK_LOCAL_RUNTIME_MODEL.")
    return _ARGV_BUILDERS[cfg["engine"]](cfg) + list(cfg["extra_args"])


def build_env(engine: str, cfg: dict) -> dict[str, str]:
    """Extra env vars for the server process (pure, like :func:`build_argv`).

    TGI toggles its prefix cache via the ``PREFIX_CACHING`` env var (no
    launcher flag; default-on since TGI v3) — everything else is argv-driven.
    """
    cfg = _normalize({**(cfg or {}), "engine": engine})
    if cfg["engine"] == "tgi" and cfg["kv_cache"] == "persistent":
        return {"PREFIX_CACHING": "1"}
    return {}


class SubprocessRunner:
    """Default runner: a plain ``subprocess.Popen`` supervisor.

    The launcher starts a long-lived inference server the operator explicitly
    configured — infrastructure supervision, not agent-initiated shell — so it
    does not route through ``sandbox.exec()`` (request/response, not
    supervision). Inject your own spawn/alive/stop runner to containerize, or
    a fake one to test.
    """

    def spawn(self, argv: list[str], *, env: dict[str, str] | None = None):
        import subprocess
        return subprocess.Popen(argv, env={**os.environ, **env} if env else None)

    def alive(self, handle) -> bool:
        return handle.poll() is None

    def stop(self, handle) -> None:
        handle.terminate()
        try:
            handle.wait(timeout=10)
        except Exception:  # pragma: no cover -- stubborn server process
            handle.kill()


class Launcher:
    """Start/stop/inspect one engine's server replicas (replica i on port+i).

    ``cfg`` is a raw ``[local_runtime]`` mapping (defaults to the config file;
    env vars win either way). Refuses to start unless ``enabled = true`` —
    the default install never spawns a server.
    """

    def __init__(self, cfg: dict | None = None, *, runner=None):
        self.cfg = load_local_runtime(cfg)
        self.runner = runner or SubprocessRunner()
        self._replicas: dict = {}  # replica index -> runner handle

    def plan(self, replica: int = 0) -> tuple[list[str], dict[str, str]]:
        """The (argv, extra-env) this launcher WOULD run for ``replica``.

        Pure — works (and is printable via ``maverick local-runtime plan``)
        even while the runtime is disabled.
        """
        cfg = {**self.cfg, "port": _port(self.cfg, replica)}
        return build_argv(cfg["engine"], cfg), build_env(cfg["engine"], cfg)

    def start(self, replica: int = 0) -> str:
        """Start replica N and return its endpoint URL (idempotent while alive)."""
        if not self.cfg["enabled"]:
            raise LocalRuntimeDisabled(
                "local runtime is off (the default). Set [local_runtime] enabled = true "
                "in ~/.maverick/config.toml (or MAVERICK_LOCAL_RUNTIME_ENABLED=1) to let "
                "Lightwork start a local model server.")
        handle = self._replicas.get(replica)
        if handle is not None and self.runner.alive(handle):
            return endpoint_for(self.cfg, replica)
        if handle is not None:
            # The prior handle is dead. Reap it before spawning the replacement
            # so a crashed replica doesn't leak a zombie on restart.
            self.runner.stop(handle)
        argv, env = self.plan(replica)
        self._replicas[replica] = self.runner.spawn(argv, env=env or None)
        return endpoint_for(self.cfg, replica)

    def stop(self, replica: int | None = None) -> None:
        """Stop one replica, or every replica when ``replica`` is None."""
        targets = [replica] if replica is not None else sorted(self._replicas)
        for r in targets:
            handle = self._replicas.pop(r, None)
            if handle is not None:
                self.runner.stop(handle)

    def status(self) -> dict:
        """Supervision snapshot: enabled/engine/model + per-replica liveness."""
        return {
            "enabled": self.cfg["enabled"],
            "engine": self.cfg["engine"],
            "model": self.cfg["model"],
            "replicas": [
                {"replica": r, "endpoint": endpoint_for(self.cfg, r),
                 "alive": bool(self.runner.alive(h))}
                for r, h in sorted(self._replicas.items())
            ],
        }


class Autoscaler:
    """Scale local server replicas between min/max on a queue-depth signal.

    Pure bookkeeping: ``spawn(replica_index) -> endpoint``,
    ``stop(replica_index)``, ``probe() -> queue depth`` and ``clock() ->
    seconds`` are all injected, and nothing here blocks — drive it by calling
    :meth:`tick` from your scheduler. Hysteresis: the depth must hold past a
    threshold for ``hold_seconds`` (as observed across ticks) before a scale
    step, and each step needs a fresh sustained window, so a spike can't
    thrash replicas.

    Default OFF via ``[local_runtime] autoscale = false``; :meth:`start`
    refuses politely when off. Wiring example::

        launcher = Launcher()
        scaler = Autoscaler(spawn=launcher.start, stop=launcher.stop,
                            probe=my_queue.qsize)
        scaler.start()   # spawns min_replicas, registers for endpoints()
        scaler.tick()    # call periodically; routers consult endpoints()
    """

    def __init__(self, cfg: dict | None = None, *, spawn, stop, probe,
                 clock=time.monotonic):
        self.cfg = load_local_runtime(cfg)
        self._spawn, self._stop = spawn, stop
        self._probe, self._clock = probe, clock
        self._endpoints: list[str] = []
        self._rr = 0
        self._high_since: float | None = None
        self._low_since: float | None = None

    @property
    def replicas(self) -> int:
        return len(self._endpoints)

    def start(self) -> list[str]:
        """Spawn ``min_replicas`` and register as the active scaler."""
        if not self.cfg["autoscale"]:
            raise LocalRuntimeDisabled(
                "autoscaling is off (the default). Set [local_runtime] autoscale = true "
                "(or MAVERICK_LOCAL_RUNTIME_AUTOSCALE=1) to scale local replicas.")
        while len(self._endpoints) < self.cfg["min_replicas"]:
            self._endpoints.append(self._spawn(len(self._endpoints)))
        global _ACTIVE
        _ACTIVE = self
        return list(self._endpoints)

    def tick(self) -> int:
        """Sample the queue depth once and scale at most one step. Returns the
        replica count. No-op while autoscaling is off."""
        if not self.cfg["autoscale"]:
            return len(self._endpoints)
        depth = int(self._probe())
        now = float(self._clock())
        if depth >= self.cfg["scale_up_depth"]:
            self._low_since = None
            if self._high_since is None:
                self._high_since = now
            elif (now - self._high_since >= self.cfg["hold_seconds"]
                  and len(self._endpoints) < self.cfg["max_replicas"]):
                self._endpoints.append(self._spawn(len(self._endpoints)))
                self._high_since = None  # the next step needs a fresh sustained window
        elif depth <= self.cfg["scale_down_depth"]:
            self._high_since = None
            if self._low_since is None:
                self._low_since = now
            elif (now - self._low_since >= self.cfg["hold_seconds"]
                  and len(self._endpoints) > self.cfg["min_replicas"]):
                self._stop(len(self._endpoints) - 1)
                self._endpoints.pop()
                self._low_since = None
        else:  # inside the hysteresis band: both windows reset
            self._high_since = self._low_since = None
        return len(self._endpoints)

    def endpoints(self) -> list[str]:
        """Live endpoints, rotated one step per call (round-robin: take ``[0]``)."""
        eps = list(self._endpoints)
        if not eps:
            return []
        i = self._rr % len(eps)
        self._rr += 1
        return eps[i:] + eps[:i]

    def shutdown(self) -> None:
        """Stop every replica (below min is fine — we're exiting) and deregister."""
        global _ACTIVE
        while self._endpoints:
            self._stop(len(self._endpoints) - 1)
            self._endpoints.pop()
        if _ACTIVE is self:
            _ACTIVE = None


_ACTIVE: Autoscaler | None = None


def endpoints() -> list[str]:
    """Round-robin endpoints of the active :class:`Autoscaler`, for routers to
    consult. ``[]`` when no autoscaler is running (callers fall back to the
    engine's default port)."""
    return _ACTIVE.endpoints() if _ACTIVE is not None else []


__all__ = [
    "ENGINES", "PRECISIONS", "DEFAULTS",
    "LocalRuntimeError", "LocalRuntimeDisabled",
    "load_local_runtime", "build_argv", "build_env", "endpoint_for",
    "SubprocessRunner", "Launcher", "Autoscaler", "endpoints",
]
