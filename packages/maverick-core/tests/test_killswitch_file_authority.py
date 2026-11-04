"""The hot HALT cache belongs to an observed pathname and security posture."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick import killswitch


@pytest.fixture
def file_cache(monkeypatch):
    # Narrow per-test ownership; production invalidation is exercised below.
    monkeypatch.setattr(killswitch, "_last_file_check_ts", 0.0)
    monkeypatch.setattr(killswitch, "_last_file_present", False)
    monkeypatch.setattr(killswitch, "_last_file_authority", None)
    clock = SimpleNamespace(now=100.0)
    monkeypatch.setattr(killswitch, "time", SimpleNamespace(monotonic=lambda: clock.now))
    return clock


@pytest.mark.parametrize("first_present", [False, True])
@pytest.mark.parametrize("authority_kind", ["home", "override", "cwd"])
def test_real_authority_switch_never_reuses_other_paths_result(
    tmp_path, monkeypatch, file_cache, first_present, authority_kind,
):
    roots = [tmp_path / "first", tmp_path / "second"]
    for root in roots:
        root.mkdir()
    paths = [root / "HALT" for root in roots]
    paths[0 if first_present else 1].write_text("operator stop", encoding="utf-8")

    def select(index):
        if authority_kind == "home":
            monkeypatch.delenv("MAVERICK_HALT_FILE", raising=False)
            monkeypatch.setenv("MAVERICK_HOME", str(roots[index]))
        elif authority_kind == "override":
            monkeypatch.setenv("MAVERICK_HALT_FILE", str(paths[index]))
        else:
            monkeypatch.chdir(roots[index])
            monkeypatch.setenv("MAVERICK_HALT_FILE", "HALT")

    select(0)
    assert killswitch._file_halt_active() is first_present
    select(1)
    assert killswitch._file_halt_active() is not first_present


def test_same_authority_cache_reset_force_refresh_and_clock_regression(
    tmp_path, monkeypatch, file_cache,
):
    path = tmp_path / "HALT"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(path))
    assert killswitch._file_halt_active() is False
    path.write_text("stop", encoding="utf-8")
    assert killswitch._file_halt_active() is False  # Preserve the hot-path cache.
    assert killswitch._file_halt_active(min_interval=0) is True
    path.unlink()
    killswitch._last_file_check_ts = 0.0
    assert killswitch._file_halt_active() is False
    path.write_text("stop", encoding="utf-8")
    file_cache.now -= 1
    assert killswitch._file_halt_active() is True


def test_relative_authority_stat_uses_the_same_captured_cwd_as_its_cache_key(
    tmp_path, monkeypatch, file_cache,
):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "HALT").write_text("stop", encoding="utf-8")
    monkeypatch.chdir(first)
    monkeypatch.setenv("MAVERICK_HALT_FILE", "HALT")
    real_stat = Path.stat
    observed = []

    def move_before_stat(path, *args, **kwargs):
        if not observed and path in {Path("HALT"), first / "HALT"}:
            observed.append(path)
            # Deterministically interleave a process-CWD change after key
            # capture, while still performing the actual filesystem stat.
            monkeypatch.chdir(second)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", move_before_stat)
    assert killswitch._file_halt_active() is True
    assert observed == [first / "HALT"]
    monkeypatch.chdir(first)
    assert killswitch._file_halt_active() is True


def test_absolute_capture_preserves_parent_traversal_spelling(
    tmp_path, monkeypatch, file_cache,
):
    (tmp_path / "segment").mkdir()
    (tmp_path / "HALT").write_text("stop", encoding="utf-8")
    authority = tmp_path / "segment" / ".." / "HALT"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(authority))
    real_stat = Path.stat
    observed = []

    def observe(path, *args, **kwargs):
        observed.append(path)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", observe)
    assert killswitch._file_halt_active() is True
    assert observed == [authority]
    assert killswitch._last_file_authority[0] == str(authority)


def test_native_symlink_parent_traversal_retains_direct_stat_semantics(
    tmp_path, monkeypatch, file_cache,
):
    local = tmp_path / "local"
    destination = tmp_path / "destination"
    local.mkdir()
    (destination / "child").mkdir(parents=True)
    (destination / "HALT").write_text("stop", encoding="utf-8")
    alias = local / "alias"
    try:
        alias.symlink_to(destination / "child", target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"native directory symlink unavailable: {type(exc).__name__}")
    authority = alias / ".." / "HALT"
    expected = authority.exists()
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(authority))
    assert killswitch._file_halt_active() is expected
    assert killswitch._last_file_authority[0] == str(authority)


def test_case_distinct_path_spellings_get_distinct_observations(
    tmp_path, monkeypatch, file_cache,
):
    upper = tmp_path / "HALT"
    lower = tmp_path / "halt"
    upper.write_text("stop", encoding="utf-8")
    # Both native filesystem policies are valid; do not enable case-sensitive
    # directories just for this test. Each spelling still needs its own read.
    lower_present = lower.exists()
    real_stat = Path.stat
    observed = []

    def observe(path, *args, **kwargs):
        observed.append(str(path))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", observe)
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(upper))
    assert killswitch._file_halt_active() is True
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(lower))
    assert killswitch._file_halt_active() is lower_present
    assert observed == [str(upper), str(lower)]
    assert killswitch._last_file_authority[0] == str(lower)


def test_fail_open_cached_denial_cannot_satisfy_strict_observation(
    tmp_path, monkeypatch, file_cache,
):
    path = tmp_path / "HALT"
    path.write_text("stop", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(path))
    real_stat = Path.stat
    calls = []

    def denied(candidate, *args, **kwargs):
        if candidate == path:
            calls.append(candidate)
            raise PermissionError("authority unavailable")
        return real_stat(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", denied)
    assert killswitch._file_halt_active() is False
    for _ in range(2):
        with pytest.raises(killswitch.Halted, match="source=file-error"):
            killswitch._file_halt_active(fail_closed=True)
    assert calls == [path, path, path]
    monkeypatch.setattr(Path, "stat", real_stat)
    assert killswitch._file_halt_active(fail_closed=True) is True


def test_failed_forced_refresh_invalidates_previous_strict_negative(
    tmp_path, monkeypatch, file_cache,
):
    path = tmp_path / "HALT"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(path))
    assert killswitch._file_halt_active(fail_closed=True) is False
    real_stat = Path.stat

    def denied(candidate, *args, **kwargs):
        if candidate == path:
            raise PermissionError("authority unavailable")
        return real_stat(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", denied)
    with pytest.raises(killswitch.Halted):
        killswitch._file_halt_active(min_interval=0, fail_closed=True)
    with pytest.raises(killswitch.Halted):
        killswitch._file_halt_active(fail_closed=True)


def test_explicit_missing_mount_is_not_a_default_path_negative(
    tmp_path, monkeypatch, file_cache,
):
    root = tmp_path / "missing-mount"
    monkeypatch.delenv("MAVERICK_HALT_FILE", raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(root))
    assert killswitch._file_halt_active(fail_closed=True) is False
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(root / "HALT"))
    with pytest.raises(killswitch.Halted, match="source=file-error"):
        killswitch._file_halt_active(fail_closed=True)


@pytest.mark.parametrize("error", [OSError, ValueError])
def test_path_normalization_failure_invalidates_and_respects_caller_posture(
    tmp_path, monkeypatch, file_cache, error,
):
    path = tmp_path / "HALT"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(path))
    assert killswitch._file_halt_active(fail_closed=True) is False
    real_absolute = Path.absolute

    def failed_normalization(candidate):
        if candidate == path:
            raise error("authority pathname cannot be made absolute")
        return real_absolute(candidate)

    monkeypatch.setattr(Path, "absolute", failed_normalization)
    assert killswitch._file_halt_active() is False
    assert killswitch._last_file_authority is None
    assert killswitch._last_file_check_ts == 0.0
    with pytest.raises(killswitch.Halted, match="source=file-error"):
        killswitch._file_halt_active(fail_closed=True)
    assert killswitch._last_file_authority is None
    assert killswitch._last_file_check_ts == 0.0


def test_concurrent_path_checks_publish_matching_authority_and_result(
    tmp_path, monkeypatch, file_cache,
):
    present = tmp_path / "present-HALT"
    absent = tmp_path / "absent-HALT"
    present.write_text("stop", encoding="utf-8")
    local = threading.local()
    entered = threading.Event()
    release = threading.Event()
    second_started = threading.Event()
    real_stat = Path.stat

    def observed_stat(path, *args, **kwargs):
        if path == present:
            entered.set()
            assert release.wait(5)
        return real_stat(path, *args, **kwargs)

    def observe(path):
        local.path = path
        if path == absent:
            second_started.set()
        return killswitch._file_halt_active()

    monkeypatch.setattr(killswitch, "_halt_file_path", lambda: local.path)
    monkeypatch.setattr(Path, "stat", observed_stat)
    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(observe, present)
        try:
            assert entered.wait(5)
            second = workers.submit(observe, absent)
            assert second_started.wait(5)
        finally:
            release.set()
        assert first.result(timeout=5) is True
        assert second.result(timeout=5) is False
    # Last published result belongs to the last checked path, not its rival.
    local.path = absent
    assert killswitch._file_halt_active() is False
    assert killswitch._last_file_present is False
