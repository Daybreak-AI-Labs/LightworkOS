"""channel_autoroute: pure rule-based channel selection + fallback.

NO network: pure routing logic; every test runs the router directly.
"""
from __future__ import annotations

from maverick.tools.channel_autoroute import _route, channel_autoroute

_CHANNELS = [
    {"name": "sms", "supports_media": False, "max_len": 160, "realtime": False},
    {"name": "push", "supports_media": False, "max_len": 200, "realtime": True},
    {"name": "email", "supports_media": True, "max_len": 100000, "realtime": False},
]


def test_urgent_prefers_realtime():
    res = _route({"urgency": "urgent", "length": 50, "has_media": False}, _CHANNELS)
    assert res["channel"] == "push"
    assert res["fallback"] is False


def test_media_requires_supports_media():
    res = _route({"urgency": "low", "length": 50, "has_media": True}, _CHANNELS)
    assert res["channel"] == "email"  # only channel that supports media


def test_length_constraint_filters():
    # 180 chars exceeds sms(160) but fits push(200); non-urgent picks first eligible
    res = _route({"urgency": "low", "length": 180, "has_media": False}, _CHANNELS)
    assert res["channel"] == "push"


def test_fallback_to_widest_when_none_fit():
    res = _route(
        {"urgency": "low", "length": 50, "has_media": True},
        [{"name": "sms", "supports_media": False, "max_len": 160, "realtime": False},
         {"name": "push", "supports_media": False, "max_len": 500, "realtime": True}],
    )
    assert res["fallback"] is True
    assert res["channel"] == "push"  # widest max_len


def test_non_urgent_first_eligible_in_order():
    res = _route({"urgency": "normal", "length": 50, "has_media": False}, _CHANNELS)
    assert res["channel"] == "sms"  # first eligible, no realtime preference


def test_run_string_and_errors():
    out = channel_autoroute().fn({
        "op": "route",
        "message": {"urgency": "urgent", "length": 10, "has_media": False},
        "channels": _CHANNELS,
    })
    assert out.startswith("push")
    t = channel_autoroute()
    assert t.fn({"op": "route", "channels": _CHANNELS}).startswith("ERROR")
    assert t.fn({"op": "route", "message": {}, "channels": []}).startswith("ERROR")
    assert t.fn({"op": "nope", "message": {}, "channels": _CHANNELS}).startswith("ERROR")


def test_factory_tool():
    t = channel_autoroute()
    assert t.name == "channel_autoroute"
    assert t.parallel_safe is True
    assert t.input_schema["required"] == ["message", "channels"]
