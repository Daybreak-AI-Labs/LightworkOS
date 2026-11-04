"""TUI mouse mode: SGR parsing, hit-testing, focus/expand, enable plumbing."""
from __future__ import annotations

import io

from maverick import tui_mouse as tm


def test_parse_left_click_press():
    e = tm.parse_mouse_event("\033[<0;12;5M")
    assert e is not None
    assert e.button == 0 and e.col == 12 and e.row == 5
    assert e.pressed is True and e.is_left_click is True


def test_parse_release_is_not_left_click():
    e = tm.parse_mouse_event("\033[<0;12;5m")
    assert e.pressed is False and e.is_left_click is False


def test_parse_right_click_not_left():
    e = tm.parse_mouse_event("\033[<2;1;1M")
    assert e.is_left_click is False  # button 2 = right


def test_parse_non_mouse_returns_none():
    assert tm.parse_mouse_event("q") is None
    assert tm.parse_mouse_event("\033[A") is None  # arrow key


def test_scroll_and_motion_are_not_left_clicks():
    # Scroll-wheel-up (button 64) and motion-with-left-held (button 32) have
    # zero low-2 bits and must not be misread as left clicks.
    scroll = tm.parse_mouse_event("\033[<64;10;3M")
    assert scroll.button == 64 and scroll.is_left_click is False
    motion = tm.parse_mouse_event("\033[<32;10;3M")
    assert motion.button == 32 and motion.is_left_click is False


def test_hitmap_maps_rows_to_nodes():
    hm = tm.NodeHitMap()
    hm.register(3, "goal:1")
    hm.register(4, "goal:2")
    assert hm.node_at(3) == "goal:1"
    assert hm.node_at(4) == "goal:2"
    assert hm.node_at(99) is None
    assert len(hm) == 2
    hm.clear()
    assert len(hm) == 0


def test_focus_model_click_focuses_and_toggles():
    fm = tm.FocusModel()
    hm = tm.NodeHitMap()
    hm.register(5, "goal:42")
    click = tm.parse_mouse_event("\033[<0;1;5M")
    acted = fm.handle_click(click, hm)
    assert acted == "goal:42"
    assert fm.focused == "goal:42"
    assert fm.is_expanded("goal:42") is True
    # a second click collapses it again, focus stays
    fm.handle_click(tm.parse_mouse_event("\033[<0;1;5M"), hm)
    assert fm.is_expanded("goal:42") is False
    assert fm.focused == "goal:42"


def test_click_on_empty_row_is_noop():
    fm = tm.FocusModel()
    hm = tm.NodeHitMap()  # nothing registered
    acted = fm.handle_click(tm.parse_mouse_event("\033[<0;1;9M"), hm)
    assert acted is None and fm.focused is None


def test_release_does_not_toggle():
    fm = tm.FocusModel()
    hm = tm.NodeHitMap()
    hm.register(2, "n")
    assert fm.handle_click(tm.parse_mouse_event("\033[<0;1;2m"), hm) is None
    assert fm.is_expanded("n") is False


def test_enable_disable_write_sequences():
    buf = io.StringIO()
    tm.write_enable(buf)
    assert buf.getvalue() == tm.ENABLE
    buf2 = io.StringIO()
    tm.write_disable(buf2)
    assert buf2.getvalue() == tm.DISABLE


def test_write_never_raises_on_bad_stream():
    class _Bad:
        def write(self, _):
            raise OSError("closed")

        def flush(self):
            pass

    tm.write_enable(_Bad())  # no exception


def test_enabled_off_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_TUI_MOUSE", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    assert tm.enabled() is False


def test_enabled_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_TUI_MOUSE", "1")
    assert tm.enabled() is True
