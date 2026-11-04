"""Energy-aware routing."""
from __future__ import annotations

from maverick.energy_aware_router import (
    BatteryState,
    pick_model,
    should_downgrade,
)


def test_downgrade_on_low_battery():
    assert should_downgrade(BatteryState(on_battery=True, percent=15))
    assert should_downgrade(BatteryState(on_battery=True, percent=20))  # at threshold


def test_no_downgrade_on_wall_power():
    assert not should_downgrade(BatteryState(on_battery=False, percent=5))


def test_no_downgrade_when_charged():
    assert not should_downgrade(BatteryState(on_battery=True, percent=80))


def test_no_downgrade_when_state_unknown():
    assert not should_downgrade(None)
    assert not should_downgrade(BatteryState(on_battery=True, percent=None))


def test_custom_threshold():
    assert should_downgrade(BatteryState(True, 45), threshold=50)
    assert not should_downgrade(BatteryState(True, 45), threshold=40)


def test_pick_model():
    low = BatteryState(on_battery=True, percent=10)
    high = BatteryState(on_battery=False, percent=100)
    assert pick_model("opus", "sonnet", state=low) == "sonnet"
    assert pick_model("opus", "sonnet", state=high) == "opus"
    assert pick_model("opus", "sonnet", state=None) == "opus"
