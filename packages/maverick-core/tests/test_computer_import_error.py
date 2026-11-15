"""The computer tool must RETURN an error string when pyautogui is missing,
not raise ImportError.

Every action, not only the screenshot path, catches the missing-dep
ImportError from ``_ensure_pyautogui()``. A raised ImportError would crash
direct callers and break the ``fn -> str`` contract (the browser tool returns
a string in the same situation).
"""
from __future__ import annotations

import maverick.tools.computer as computer
from maverick.tools.computer import _run_computer_action


def test_non_screenshot_action_returns_error_string_when_dep_absent(monkeypatch):
    def _boom():
        raise ImportError("pyautogui not installed. Run: pip install 'maverick-agent[computer-use]'")

    monkeypatch.setattr(computer, "_ensure_pyautogui", _boom)
    # This test isolates the optional-dependency contract. Exact-operation
    # approval is covered separately by test_action_gate.py.
    monkeypatch.setattr(
        computer, "gate_computer_action", lambda *_args, **_kwargs: None,
    )
    for action in ("left_click", "mouse_move", "type", "key", "scroll"):
        res = _run_computer_action({"action": action, "coordinate": [10, 10], "text": "x"})
        assert isinstance(res, str), (action, type(res))
        assert res.startswith("ERROR:") and "pyautogui" in res, (action, res)


def test_unknown_action_still_rejected_before_dep_import(monkeypatch):
    # An unknown action is refused before the dep is needed (no crash either way).
    res = _run_computer_action({"action": "explode"})
    assert isinstance(res, str) and res.startswith("ERROR:")


def test_driver_installed_under_the_working_folder(monkeypatch, tmp_path):
    # A project virtualenv started from the project folder: reads still work,
    # and input is refused with the real reason, not "not installed".
    (tmp_path / "pyautogui.py").write_text("def position():\n    return (3, 4)\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(__import__("sys").modules, "pyautogui", raising=False)
    monkeypatch.setattr(computer, "_host_safety_error", lambda: None)
    assert _run_computer_action({"action": "cursor_position"}) == "(3, 4)"
    res = _run_computer_action({"action": "left_click", "coordinate": [1, 1]})
    assert res.startswith("ERROR:") and "working folder" in res and "not installed" not in res
