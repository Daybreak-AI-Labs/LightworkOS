"""Tests for the continuous profiling daemon.

Offline: the py-spy invocation is an injected runner and time is virtualized,
so the scheduling loop is exercised without spawning py-spy or sleeping.
"""
from __future__ import annotations

from maverick.profiling_daemon import (
    ProfilingConfig,
    ProfilingDaemon,
    config_from_env,
)


class Runner:
    """Records (argv, timeout) calls; returns scripted results."""

    def __init__(self, results=(0, "", "")):
        self.calls: list = []
        self._results = results

    def __call__(self, argv, timeout):
        self.calls.append((argv, timeout))
        if isinstance(self._results, list):
            i = min(len(self.calls) - 1, len(self._results) - 1)
            return self._results[i]
        return self._results


def _cfg(**kw):
    base = dict(enabled=True, interval_seconds=60.0, duration_seconds=10.0,
                fmt="speedscope")
    base.update(kw)
    return ProfilingConfig(**base)


def test_disabled_by_default(monkeypatch):
    for k in ("MAVERICK_PROFILING", "MAVERICK_PROFILING_FORMAT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    cfg = config_from_env()
    assert cfg.enabled is False
    d = ProfilingDaemon(cfg, runner=Runner(), pid=4321)
    assert d.run(max_samples=5) == 0  # no-op when disabled


def test_sample_once_builds_pyspy_command(tmp_path):
    r = Runner((0, "", ""))
    d = ProfilingDaemon(_cfg(), pid=4321, output_dir=tmp_path, runner=r)
    out = d.sample_once()
    assert out.endswith(".json")
    argv, timeout = r.calls[0]
    assert argv[:2] == ["py-spy", "record"]
    assert "--pid" in argv and "4321" in argv
    assert "--duration" in argv and "10" in argv
    assert "--format" in argv and "speedscope" in argv
    assert "--output" in argv
    assert timeout == 20.0  # duration + 10s slack
    assert d.samples == 1


def test_sample_once_nonzero_surfaces_stderr(tmp_path):
    d = ProfilingDaemon(_cfg(), output_dir=tmp_path,
                        runner=Runner((1, "", "could not attach to pid")))
    out = d.sample_once()
    assert out.startswith("ERROR: py-spy (1)") and "could not attach" in out
    assert d.samples == 0


def test_format_extension_mapping(tmp_path):
    for fmt, ext in (("flamegraph", "svg"), ("raw", "txt"), ("speedscope", "json")):
        d = ProfilingDaemon(_cfg(fmt=fmt), output_dir=tmp_path, runner=Runner())
        assert d.sample_once().endswith("." + ext)


def test_missing_pyspy_with_default_runner(monkeypatch, tmp_path):
    monkeypatch.setattr("maverick.profiling_daemon.shutil.which", lambda n: None)
    d = ProfilingDaemon(_cfg(), output_dir=tmp_path, runner=None)
    out = d.sample_once()
    assert out.startswith("ERROR") and "py-spy not on PATH" in out


def test_run_loops_max_samples(tmp_path):
    r = Runner((0, "", ""))
    sleeps: list = []
    d = ProfilingDaemon(_cfg(), output_dir=tmp_path, runner=r,
                        clock=lambda: 1000 + len(r.calls), sleep=sleeps.append)
    assert d.run(max_samples=3) == 3
    assert len(r.calls) == 3
    assert len(sleeps) == 2  # sleeps between samples, not after the last


def test_run_stops_on_predicate(tmp_path):
    r = Runner((0, "", ""))
    flags = iter([False, False, True])
    d = ProfilingDaemon(_cfg(), output_dir=tmp_path, runner=r,
                        sleep=lambda _s: None)
    taken = d.run(stop=lambda: next(flags))
    assert taken == 2


def test_run_continues_past_sample_error(tmp_path):
    r = Runner([(1, "", "transient"), (0, "", ""), (0, "", "")])
    d = ProfilingDaemon(_cfg(), output_dir=tmp_path, runner=r,
                        sleep=lambda _s: None)
    # first sample errors (not counted), next two succeed -> 2 taken, 3 calls
    assert d.run(max_samples=2) == 2
    assert len(r.calls) == 3


def test_config_from_env_overrides(monkeypatch):
    monkeypatch.setenv("MAVERICK_PROFILING", "1")
    monkeypatch.setenv("MAVERICK_PROFILING_INTERVAL", "60")
    monkeypatch.setenv("MAVERICK_PROFILING_DURATION", "10")
    monkeypatch.setenv("MAVERICK_PROFILING_FORMAT", "flamegraph")
    cfg = config_from_env()
    assert cfg.enabled and cfg.interval_seconds == 60.0
    assert cfg.duration_seconds == 10.0 and cfg.fmt == "flamegraph"


def test_unknown_format_falls_back(monkeypatch):
    monkeypatch.setenv("MAVERICK_PROFILING", "1")
    monkeypatch.setenv("MAVERICK_PROFILING_FORMAT", "bogus")
    assert config_from_env().fmt == "speedscope"


def test_output_lands_under_profiles_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    d = ProfilingDaemon(_cfg(), pid=7, runner=Runner())
    out = d.sample_once()
    assert "profiles/" in out.replace("\\", "/")
