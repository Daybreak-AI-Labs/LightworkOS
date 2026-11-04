"""discord_slash: slash-command registration JSON builder. No network."""
from __future__ import annotations

import json

from maverick.tools.discord_slash import discord_slash


def _run(**kw):
    return discord_slash().fn(kw)


def test_build_minimal():
    out = _run(op="build", name="deploy", description="Deploy the app")
    obj = json.loads(out)
    assert obj["name"] == "deploy"
    assert obj["description"] == "Deploy the app"
    assert obj["type"] == 1  # CHAT_INPUT
    assert "options" not in obj


def test_build_with_options_type_int_and_alias():
    out = _run(
        op="build",
        name="echo",
        description="Echo text",
        options=[
            {"name": "text", "description": "what to say", "type": "string", "required": True},
            {"name": "count", "description": "times", "type": 4},
        ],
    )
    obj = json.loads(out)
    opts = obj["options"]
    assert opts[0] == {"type": 3, "name": "text", "description": "what to say", "required": True}
    assert opts[1] == {"type": 4, "name": "count", "description": "times", "required": False}


def test_build_rejects_bad_name():
    assert _run(op="build", name="Bad Name", description="x").startswith("ERROR")
    assert _run(op="build", name="a" * 33, description="x").startswith("ERROR")


def test_build_rejects_bad_option_type():
    out = _run(
        op="build",
        name="cmd",
        description="d",
        options=[{"name": "o", "description": "d", "type": 99}],
    )
    assert out.startswith("ERROR") and "out of range" in out
    boolean = _run(
        op="build",
        name="cmd",
        description="d",
        options=[{"name": "o", "description": "d", "type": True}],
    )
    assert boolean.startswith("ERROR")


def test_build_required_before_optional():
    out = _run(
        op="build",
        name="cmd",
        description="d",
        options=[
            {"name": "opt", "description": "d", "type": "string", "required": False},
            {"name": "req", "description": "d", "type": "string", "required": True},
        ],
    )
    assert out.startswith("ERROR") and "before optional" in out


def test_errors():
    t = discord_slash()
    assert t.fn({"op": "build", "name": "ok"}).startswith("ERROR")  # no description
    assert t.fn({"op": "nope", "name": "ok", "description": "d"}).startswith("ERROR")
    assert t.fn({"op": "build", "name": "ok", "description": "d", "options": "x"}).startswith("ERROR")
