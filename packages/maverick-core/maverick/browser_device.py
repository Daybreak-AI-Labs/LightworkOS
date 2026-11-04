"""Browser device emulation presets: viewport + UA + touch for the browser tool.

A small, dependency-free registry of device profiles (phones / tablets / desktop)
so a browser session can emulate a real device — the viewport size, device-scale
factor, user-agent, and touch/mobile flags that change how a page renders and how
responsive layouts behave. The presets mirror the well-known Playwright/Chrome
DevTools device list. ``get_device`` / ``list_devices`` are pure and unit-tested;
the ``browser_device`` tool surfaces them, and the browser tool consumes a preset
dict to configure its context.
"""
from __future__ import annotations

# Canonical, stable device profiles. width/height are CSS pixels.
_DEVICES: dict[str, dict] = {
    "iphone-15": {
        "width": 393, "height": 852, "device_scale_factor": 3,
        "mobile": True, "has_touch": True,
        "user_agent": ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                       "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
                       "Mobile/15E148 Safari/604.1"),
    },
    "iphone-se": {
        "width": 375, "height": 667, "device_scale_factor": 2,
        "mobile": True, "has_touch": True,
        "user_agent": ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
                       "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 "
                       "Mobile/15E148 Safari/604.1"),
    },
    "pixel-8": {
        "width": 412, "height": 915, "device_scale_factor": 2.625,
        "mobile": True, "has_touch": True,
        "user_agent": ("Mozilla/5.0 (Linux; Android 14; Pixel 8) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
                       "Mobile Safari/537.36"),
    },
    "ipad-pro-11": {
        "width": 834, "height": 1194, "device_scale_factor": 2,
        "mobile": True, "has_touch": True,
        "user_agent": ("Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) "
                       "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
                       "Mobile/15E148 Safari/604.1"),
    },
    "galaxy-s23": {
        "width": 360, "height": 780, "device_scale_factor": 3,
        "mobile": True, "has_touch": True,
        "user_agent": ("Mozilla/5.0 (Linux; Android 13; SM-S911B) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
                       "Mobile Safari/537.36"),
    },
    "desktop-1080p": {
        "width": 1920, "height": 1080, "device_scale_factor": 1,
        "mobile": False, "has_touch": False,
        "user_agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
                       "Safari/537.36"),
    },
    "desktop-macbook": {
        "width": 1440, "height": 900, "device_scale_factor": 2,
        "mobile": False, "has_touch": False,
        "user_agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                       "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
                       "Safari/605.1.15"),
    },
}


def list_devices() -> list[str]:
    """Available device preset names."""
    return sorted(_DEVICES)


def get_device(name: str) -> dict:
    """Return a copy of the named preset. Raises ``KeyError`` if unknown.

    Names are matched case-insensitively with spaces/underscores normalised to
    hyphens (``"iPhone 15"`` → ``"iphone-15"``).
    """
    key = (name or "").strip().lower().replace(" ", "-").replace("_", "-")
    if key not in _DEVICES:
        raise KeyError(
            f"unknown device {name!r}; available: {', '.join(list_devices())}")
    return dict(_DEVICES[key])


_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["list", "get"]},
        "device": {"type": "string", "description": "preset name (get op)"},
    },
    "required": ["op"],
}


def _run(args: dict) -> str:
    import json as _json
    op = args.get("op")
    if op == "list":
        return "\n".join(list_devices())
    if op == "get":
        try:
            return _json.dumps(get_device(args.get("device") or ""), indent=2)
        except KeyError as e:
            return f"ERROR: {e}"
    return f"ERROR: unknown op {op!r}"


def browser_device():
    from .tools import Tool
    return Tool(
        name="browser_device",
        description=(
            "Device-emulation presets for the browser tool (viewport, "
            "device-scale, user-agent, mobile/touch). ops: list, get (device). "
            "Presets: " + ", ".join(list_devices()) + "."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )


__all__ = ["list_devices", "get_device", "browser_device"]
