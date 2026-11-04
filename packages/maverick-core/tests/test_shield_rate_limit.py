"""Tests for the per-goal shield-scan rate limiter: sliding-window refill via
a fake clock, per-goal isolation, once-per-window throttle alerts, parse_rate
validation, and off-by-default config. No sleeps; the test owns the clock."""
from __future__ import annotations

import pytest
from maverick.safety import shield_rate_limit as srl


@pytest.fixture(autouse=True)
def _fresh_shared(monkeypatch):
    """Isolate the process-wide limiter and the env knob around every test."""
    monkeypatch.delenv("MAVERICK_SHIELD_RATE_LIMIT", raising=False)
    srl.reset_shared()
    yield
    srl.reset_shared()


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class TestLimiter:
    def test_allows_under_limit_then_throttles(self):
        clock = FakeClock()
        lim = srl.ShieldRateLimiter(2, 60, clock=clock)
        assert lim.allow("g1") is True
        assert lim.allow("g1") is True
        assert lim.allow("g1") is False  # window full -> caller skips the scan

    def test_window_refills_via_fake_clock(self):
        clock = FakeClock()
        lim = srl.ShieldRateLimiter(2, 10, clock=clock)
        assert lim.allow("g") and lim.allow("g")
        assert lim.allow("g") is False
        clock.now = 9.9
        assert lim.allow("g") is False   # still inside the window
        clock.now = 10.0
        assert lim.allow("g") is True    # hits exactly one window old expired

    def test_sliding_not_fixed_window(self):
        clock = FakeClock()
        lim = srl.ShieldRateLimiter(2, 10, clock=clock)
        assert lim.allow("g")            # t=0
        clock.now = 6.0
        assert lim.allow("g")            # t=6
        clock.now = 10.0
        assert lim.allow("g") is True    # t=0 hit expired, t=6 remains
        assert lim.allow("g") is False   # window now holds t=6 and t=10

    def test_goals_are_independent(self):
        clock = FakeClock()
        lim = srl.ShieldRateLimiter(1, 60, clock=clock)
        assert lim.allow("goal-a") is True
        assert lim.allow("goal-a") is False
        assert lim.allow("goal-b") is True   # untouched by goal-a's hammering

    def test_validation(self):
        with pytest.raises(ValueError):
            srl.ShieldRateLimiter(0, 60)
        with pytest.raises(ValueError):
            srl.ShieldRateLimiter(10, 0)


class TestThrottleCallback:
    def test_fires_once_per_goal_per_window(self):
        clock = FakeClock()
        fired: list[tuple[str, int]] = []
        lim = srl.ShieldRateLimiter(
            2, 60, clock=clock, on_throttle=lambda g, n: fired.append((g, n)))
        lim.allow("g"), lim.allow("g")
        clock.now = 1.0
        assert lim.allow("g") is False
        assert fired == [("g", 1)]       # timely: first suppression alerts
        for t in (2.0, 3.0, 30.0):
            clock.now = t
            assert lim.allow("g") is False
        assert fired == [("g", 1)]       # still one alert inside the window

    def test_next_window_alert_carries_suppressed_count(self):
        clock = FakeClock()
        fired: list[tuple[str, int]] = []
        lim = srl.ShieldRateLimiter(
            2, 60, clock=clock, on_throttle=lambda g, n: fired.append((g, n)))
        lim.allow("g"), lim.allow("g")                 # t=0: window full
        for t in (1.0, 2.0, 3.0, 4.0, 5.0, 30.0):
            clock.now = t
            lim.allow("g")                             # 6 suppressed; alert at t=1
        clock.now = 61.0
        assert lim.allow("g") is True                  # t=0 hits expired
        assert lim.allow("g") is True
        assert lim.allow("g") is False                 # throttled again
        # one alert per window; the second reports everything since the first
        assert fired == [("g", 1), ("g", 6)]

    def test_callbacks_are_per_goal(self):
        clock = FakeClock()
        fired: list[tuple[str, int]] = []
        lim = srl.ShieldRateLimiter(
            1, 60, clock=clock, on_throttle=lambda g, n: fired.append((g, n)))
        lim.allow("a"), lim.allow("b")
        lim.allow("a"), lim.allow("b")
        assert sorted(fired) == [("a", 1), ("b", 1)]

    def test_callback_exception_is_swallowed(self):
        clock = FakeClock()

        def _boom(goal, n):
            raise RuntimeError("observer crashed")

        lim = srl.ShieldRateLimiter(1, 60, clock=clock, on_throttle=_boom)
        assert lim.allow("g") is True
        assert lim.allow("g") is False  # must not raise


class TestParseRate:
    def test_valid_specs(self):
        assert srl.parse_rate("100/60") == (100, 60.0)
        assert srl.parse_rate("10/2.5") == (10, 2.5)
        assert srl.parse_rate(" 5 / 30s ") == (5, 30.0)

    @pytest.mark.parametrize("bad", ["", "banana", "0/60", "100/0", "-1/60",
                                     "100", "1/2/3", None, 100])
    def test_invalid_specs_raise(self, bad):
        with pytest.raises(ValueError):
            srl.parse_rate(bad)


class TestConfig:
    def test_off_by_default(self):
        # conftest isolates HOME, so no config file exists and no env is set.
        assert srl.configured_rate() is None
        assert srl.shared() is None

    def test_config_file_enables(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.toml"
        cfg.write_text('[safety]\nshield_rate_limit = "3/60"\n')
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
        assert srl.configured_rate() == (3, 60.0)
        lim = srl.shared()
        assert lim is not None and lim.max_calls == 3 and lim.per_seconds == 60.0
        assert srl.shared() is lim  # cached process instance

    def test_env_wins_over_config(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.toml"
        cfg.write_text('[safety]\nshield_rate_limit = "3/60"\n')
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
        monkeypatch.setenv("MAVERICK_SHIELD_RATE_LIMIT", "7/30")
        assert srl.configured_rate() == (7, 30.0)

    def test_env_off_disables_configured_limit(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.toml"
        cfg.write_text('[safety]\nshield_rate_limit = "3/60"\n')
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
        monkeypatch.setenv("MAVERICK_SHIELD_RATE_LIMIT", "off")
        assert srl.configured_rate() is None
        assert srl.shared() is None

    def test_bad_spec_fails_open_to_disabled(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.toml"
        cfg.write_text('[safety]\nshield_rate_limit = "lots"\n')
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
        assert srl.configured_rate() is None  # warn + OFF, never raise

    def test_reset_shared_rebuilds_from_new_config(self, monkeypatch):
        assert srl.shared() is None
        monkeypatch.setenv("MAVERICK_SHIELD_RATE_LIMIT", "2/10")
        assert srl.shared() is None  # decision is cached until reset
        srl.reset_shared()
        lim = srl.shared()
        assert lim is not None and lim.max_calls == 2


class TestIdleKeySweep:
    """Regression: per-goal dicts must not grow without bound over a long run.

    Goal ids are unique per goal and never recur; before the idle sweep, every
    distinct goal that ever called ``allow`` left a permanent ``{gid: deque}``
    entry, leaking memory for the process lifetime of a `maverick serve`.
    """

    def test_idle_goal_keys_are_swept_so_dict_stays_bounded(self, monkeypatch):
        clock = FakeClock()
        # Make the sweep fire frequently so the test drives a realistic many-goal
        # stream without millions of iterations.
        monkeypatch.setattr(srl.ShieldRateLimiter, "_SWEEP_EVERY", 64)
        lim = srl.ShieldRateLimiter(5, 10.0, clock=clock)
        # Each "goal" hits the limiter once then never again, while time marches
        # forward so prior goals' windows fully expire.
        for i in range(10_000):
            clock.now += 1.0
            assert lim.allow(f"goal-{i}") is True
        # Without the sweep this would hold ~10_000 keys. With it, the live set
        # is bounded by how many goals fit inside one window plus one sweep
        # interval — a small constant, not O(goals).
        assert len(lim._hits) <= srl.ShieldRateLimiter._SWEEP_EVERY + lim.max_calls
        assert len(lim._suppressed) <= srl.ShieldRateLimiter._SWEEP_EVERY + lim.max_calls
        assert len(lim._last_alert) <= srl.ShieldRateLimiter._SWEEP_EVERY + lim.max_calls

    def test_sweep_keeps_active_goal(self, monkeypatch):
        """A goal still inside its window is never swept (correctness preserved)."""
        clock = FakeClock()
        monkeypatch.setattr(srl.ShieldRateLimiter, "_SWEEP_EVERY", 4)
        lim = srl.ShieldRateLimiter(100, 100.0, clock=clock)
        lim.allow("hot")  # one hit at t=0, window is 100s
        for i in range(20):  # trigger several sweeps with throwaway goals
            clock.now += 0.1
            lim.allow(f"cold-{i}")
        # "hot" is still within its 100s window -> must survive the sweeps.
        assert "hot" in lim._hits
