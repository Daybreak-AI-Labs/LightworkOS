"""Operational alerting seam: off by default, routes through notifications when
enabled, and never raises. Wired into the killswitch trip + provider cost cap."""
from __future__ import annotations

import pytest
from maverick import ops_alert


@pytest.fixture
def _spy_notify(monkeypatch):
    calls = []
    monkeypatch.setattr("maverick.notifications.notify",
                        lambda body, **kw: calls.append((body, kw)) or 1)
    return calls


def test_disabled_by_default_is_noop(_spy_notify, monkeypatch):
    monkeypatch.delenv("MAVERICK_ALERTS", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    assert ops_alert.alert("x", "detail") is False
    assert _spy_notify == []


def test_enabled_via_env_routes_to_notify(_spy_notify, monkeypatch):
    monkeypatch.setenv("MAVERICK_ALERTS", "1")
    assert ops_alert.alert("killswitch_tripped", "boom", severity="critical") is True
    assert len(_spy_notify) == 1
    body, kw = _spy_notify[0]
    assert body == "boom"
    assert kw["priority"] == "max" and kw["category"] == "ops_alert"


def test_enabled_via_config(_spy_notify, monkeypatch):
    monkeypatch.delenv("MAVERICK_ALERTS", raising=False)
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"alerts": {"enabled": True}})
    assert ops_alert.alert("e") is True


def test_alert_never_raises(monkeypatch):
    monkeypatch.setenv("MAVERICK_ALERTS", "1")

    def _boom(*a, **k):
        raise RuntimeError("transport down")

    monkeypatch.setattr("maverick.notifications.notify", _boom)
    assert ops_alert.alert("e") is False  # swallowed


# ---- wiring -----------------------------------------------------------------


def test_killswitch_halt_alerts(_spy_notify, monkeypatch):
    monkeypatch.setenv("MAVERICK_ALERTS", "1")
    from maverick import killswitch
    killswitch.halt("manual stop", source="test")
    try:
        assert any("killswitch_tripped" in kw.get("title", "")
                   for _b, kw in _spy_notify)
    finally:
        killswitch.clear()


def test_provider_cap_alerts_once_per_period(_spy_notify, monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ALERTS", "1")
    from maverick import provider_cost_cap as cap
    cap._alerted.clear()
    monkeypatch.setattr(cap, "check",
                        lambda provider, **kw: cap.CapStatus(
                            allowed=False, spent=10.0, cap=5.0, remaining=0.0))
    with pytest.raises(cap.ProviderCapExceeded):
        cap.enforce("anthropic")
    with pytest.raises(cap.ProviderCapExceeded):
        cap.enforce("anthropic")  # second blocked call must NOT re-alert
    titles = [kw.get("title", "") for _b, kw in _spy_notify]
    assert sum("provider_cost_cap_exhausted" in t for t in titles) == 1
