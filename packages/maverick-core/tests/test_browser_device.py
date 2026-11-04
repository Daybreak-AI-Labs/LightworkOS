"""Browser device emulation presets."""
from __future__ import annotations

import pytest
from maverick.browser_device import get_device, list_devices


def test_list_has_known_devices():
    devices = list_devices()
    assert "iphone-15" in devices
    assert "desktop-1080p" in devices
    assert devices == sorted(devices)


def test_get_returns_full_profile():
    d = get_device("iphone-15")
    assert d["width"] == 393 and d["height"] == 852
    assert d["mobile"] is True and d["has_touch"] is True
    assert "iPhone" in d["user_agent"]


def test_name_normalisation():
    assert get_device("iPhone 15") == get_device("iphone-15")
    assert get_device("DESKTOP_1080P") == get_device("desktop-1080p")


def test_unknown_device_raises():
    with pytest.raises(KeyError):
        get_device("nokia-3310")


def test_get_returns_copy_not_reference():
    d = get_device("pixel-8")
    d["width"] = 1
    assert get_device("pixel-8")["width"] != 1  # mutation didn't leak
