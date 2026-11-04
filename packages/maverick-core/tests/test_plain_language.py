"""plain_language: plain-English narration of a plan/trace."""
from __future__ import annotations

from maverick.tools.plain_language import plain_language


def _run(steps, op="explain"):
    return plain_language().fn({"op": op, "steps": steps})


def test_numbered_narration_with_ordinals():
    out = _run([
        {"action": "read_file", "args": {"path": "a.py"}},
        {"action": "write_file", "args": {"path": "b.py"}},
    ])
    lines = out.splitlines()
    assert lines[0] == "1. First, I will read the file a.py."
    assert lines[1] == "2. Then, I will write to the file b.py."


def test_known_verb_friendly_phrasing():
    out = _run([{"action": "shell", "args": {"command": "ls -la"}}])
    assert "run the command ls -la" in out


def test_unknown_action_generic_phrasing():
    out = _run([{"action": "frobnicate", "args": {"target": "widget"}}])
    assert "perform 'frobnicate' on widget" in out


def test_unknown_action_no_target():
    out = _run([{"action": "reticulate"}])
    assert "perform the 'reticulate' action" in out


def test_args_as_plain_string():
    out = _run([{"action": "web_search", "args": "latest news"}])
    assert "search the web for latest news" in out


def test_known_verb_missing_target_drops_placeholder():
    out = _run([{"action": "read_file"}])
    assert "{target}" not in out
    assert "read the file" in out


def test_errors():
    t = plain_language()
    assert t.fn({"op": "explain", "steps": []}).startswith("ERROR")
    assert t.fn({"op": "explain", "steps": [{"no": "action"}]}).startswith("ERROR")
    assert t.fn({"op": "nope", "steps": [{"action": "x"}]}).startswith("ERROR")
