"""Continuous profiling daemon.

A long-running agent process is a black box once it's deployed: when a run
goes slow, you want a flame graph of where the time actually went, not a guess.
This is a lightweight **sampling profiler daemon** — on an interval it asks
``py-spy`` to record the live process and drops a profile (speedscope JSON /
flame-graph SVG) under ``data_dir("profiles/")`` for later inspection.

``py-spy`` samples from *outside* the interpreter (no instrumentation, no GIL
cost), so this is safe to leave running against production. The daemon itself
is the scheduling + bookkeeping; the sampling is py-spy's.

Why a direct subprocess and not the sandbox chokepoint (CLAUDE.md #4): that
rule governs *model-driven* tool shell, which must run on the configured
backend. This is an operator ops daemon profiling **its own host process** —
py-spy must attach to the live PID on the host, so it runs there by design.
The command runner is injected, so tests exercise the scheduling without
spawning py-spy.

Opt-in via ``[perf.profiling]`` (``enabled = true`` / ``interval_seconds`` /
``duration_seconds`` / ``format``); env ``MAVERICK_PROFILING`` wins either way.
Off by default — nothing samples a process that didn't ask for it. When it is
on, the dashboard starts it against its own process (see
``maverick_dashboard.background_programs``); ``python -m
maverick.profiling_daemon`` still runs it standalone.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass

log = logging.getLogger(__name__)

# py-spy --format value -> output file extension.
_FORMATS = {"speedscope": "json", "flamegraph": "svg", "raw": "txt"}

DEFAULT_INTERVAL = 300.0   # sample every 5 minutes
DEFAULT_DURATION = 30.0    # record for 30s each sample


def _envf(name: str, default: float) -> float:
    v = os.environ.get(name, "").strip()
    try:
        return float(v) if v else default
    except ValueError:
        return default


@dataclass(frozen=True)
class ProfilingConfig:
    enabled: bool = False
    interval_seconds: float = DEFAULT_INTERVAL
    duration_seconds: float = DEFAULT_DURATION
    fmt: str = "speedscope"


def config_from_env() -> ProfilingConfig:
    """Build the config from ``[perf.profiling]`` (each env variable wins)."""
    raw = os.environ.get("MAVERICK_PROFILING", "").strip().lower()
    enabled = raw in {"1", "true", "yes", "on"}
    interval = _envf("MAVERICK_PROFILING_INTERVAL", DEFAULT_INTERVAL)
    duration = _envf("MAVERICK_PROFILING_DURATION", DEFAULT_DURATION)
    fmt = os.environ.get("MAVERICK_PROFILING_FORMAT", "").strip().lower()
    try:
        from .config import load_config
        cfg = ((load_config() or {}).get("perf") or {}).get("profiling") or {}
        if not raw:
            enabled = bool(cfg.get("enabled", False))
        interval = _envf("MAVERICK_PROFILING_INTERVAL",
                         float(cfg.get("interval_seconds", interval)))
        duration = _envf("MAVERICK_PROFILING_DURATION",
                         float(cfg.get("duration_seconds", duration)))
        fmt = fmt or str(cfg.get("format", "")).strip().lower()
    except Exception:  # pragma: no cover -- config never blocks startup
        pass
    fmt = fmt if fmt in _FORMATS else "speedscope"
    return ProfilingConfig(
        enabled=enabled,
        interval_seconds=interval if interval > 0 else DEFAULT_INTERVAL,
        duration_seconds=duration if duration > 0 else DEFAULT_DURATION,
        fmt=fmt,
    )


def _default_runner(argv: list[str], timeout: float) -> tuple[int, str, str]:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"TIMEOUT after {timeout}s"
    except FileNotFoundError:
        return 127, "", "py-spy not found"


class ProfilingDaemon:
    """Schedule periodic ``py-spy record`` samples of a target process.

    ``runner(argv, timeout) -> (code, stdout, stderr)`` and ``clock``/``sleep``
    are injected so tests drive the loop without spawning py-spy or waiting.
    """

    def __init__(
        self,
        config: ProfilingConfig | None = None,
        *,
        pid: int | None = None,
        output_dir=None,
        runner: Callable[[list[str], float], tuple[int, str, str]] | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.config = config or config_from_env()
        self.pid = pid if pid is not None else os.getpid()
        self._output_dir = output_dir
        self._runner = runner or _default_runner
        self._clock = clock
        self._sleep = sleep
        self.samples = 0

    def _out_dir(self):
        if self._output_dir is not None:
            from pathlib import Path
            return Path(self._output_dir)
        from .paths import data_dir
        return data_dir("profiles")

    def sample_once(self) -> str:
        """Take one sample. Returns the written path, or an ``ERROR: ...``."""
        if not self._runner_is_injected() and shutil.which("py-spy") is None:
            return "ERROR: py-spy not on PATH. Install: pip install py-spy"
        ext = _FORMATS.get(self.config.fmt, "json")
        out_dir = self._out_dir()
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return f"ERROR: cannot create {out_dir}: {e}"
        ts = int(self._clock())
        path = out_dir / f"profile-{ts}-pid{self.pid}.{ext}"
        argv = [
            "py-spy", "record",
            "--pid", str(self.pid),
            "--duration", str(int(self.config.duration_seconds)),
            "--format", self.config.fmt,
            "--output", str(path),
        ]
        # Allow ~10s of slack over the record window for startup/teardown.
        code, _out, stderr = self._runner(argv, self.config.duration_seconds + 10)
        if code != 0:
            return f"ERROR: py-spy ({code}): {stderr.strip()[-300:]}"
        self.samples += 1
        return str(path)

    def _runner_is_injected(self) -> bool:
        return self._runner is not _default_runner

    def run(self, *, max_samples: int | None = None,
            stop: Callable[[], bool] | None = None) -> int:
        """Sample on the configured interval until ``stop()`` or ``max_samples``.

        Returns the number of successful samples. A no-op (returns 0) when
        profiling is disabled. ``stop`` is checked before each sample so a
        caller can halt the daemon cleanly.
        """
        if not self.config.enabled:
            return 0
        taken = 0
        while True:
            if stop is not None and stop():
                break
            if max_samples is not None and taken >= max_samples:
                break
            result = self.sample_once()
            if result.startswith("ERROR"):
                log.warning("profiling sample failed: %s", result)
            else:
                taken += 1
                log.info("profiling sample written: %s", result)
            if max_samples is not None and taken >= max_samples:
                break
            self._sleep(self.config.interval_seconds)
        return taken


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(prog="maverick.profiling_daemon",
                                description="Continuous py-spy sampling daemon.")
    p.add_argument("--pid", type=int, default=os.getpid(),
                   help="target process (default: this process)")
    p.add_argument("--once", action="store_true", help="take a single sample and exit")
    args = p.parse_args(argv)
    cfg = config_from_env()
    if not cfg.enabled:
        # An explicit invocation is its own opt-in.
        cfg = ProfilingConfig(enabled=True, interval_seconds=cfg.interval_seconds,
                              duration_seconds=cfg.duration_seconds, fmt=cfg.fmt)
    daemon = ProfilingDaemon(cfg, pid=args.pid)
    if args.once:
        result = daemon.sample_once()
        print(result)
        return 0 if not result.startswith("ERROR") else 1
    print(f"profiling pid {args.pid} every {cfg.interval_seconds}s "
          f"(format={cfg.fmt}); Ctrl-C to stop")
    try:
        daemon.run()
    except KeyboardInterrupt:
        print(f"\nstopped after {daemon.samples} sample(s)")
    return 0


__all__ = ["ProfilingConfig", "ProfilingDaemon", "config_from_env"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
