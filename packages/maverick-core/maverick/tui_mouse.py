"""TUI mouse mode.

The `maverick monitor` plan-tree is keyboard/auto-refresh only. Mouse mode
makes the plan tree **clickable**: enable SGR mouse tracking, map a click at
(row, col) to the plan-tree node rendered there, and focus/expand it. This is
the pure, terminal-free core — escape-sequence control + a click→node hit-test
over the rendered layout — so it's deterministic and unit-tested without a
real terminal; the monitor loop wires it to the tty.

SGR mouse protocol (xterm 1006): enabling writes ``\\033[?1000;1006h``
(button events + SGR coordinates), disabling writes ``\\033[?1000;1006l``. A
click arrives as ``\\033[<b;col;rowM`` (press) / ``...m`` (release);
:func:`parse_mouse_event` decodes one.

Opt-in via ``[tui] mouse`` (env ``MAVERICK_TUI_MOUSE``); off by default — the
monitor behaves exactly as before unless enabled, and it degrades to
keyboard/auto-refresh on any terminal that doesn't report mouse events.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

ENABLE = "\033[?1000;1006h"
DISABLE = "\033[?1000;1006l"

# \033[<button;col;row(M|m)
_SGR = re.compile(r"\033\[<(\d+);(\d+);(\d+)([Mm])")


def enabled() -> bool:
    if os.environ.get("MAVERICK_TUI_MOUSE", "").strip().lower() in {
        "1", "true", "yes", "on",
    }:
        return True
    try:
        from .config import load_config
        return bool(((load_config() or {}).get("tui") or {}).get("mouse"))
    except Exception:  # pragma: no cover -- config never blocks the monitor
        return False


@dataclass(frozen=True)
class MouseEvent:
    button: int
    col: int          # 1-based terminal column
    row: int          # 1-based terminal row
    pressed: bool     # True = press, False = release

    @property
    def is_left_click(self) -> bool:
        # Reject wheel (0x40) and motion (0x20) events before checking the
        # button number is 0 — otherwise a scroll (button 64) or drag (32)
        # masks to 0 on the low 2 bits and is misread as a left click.
        return (self.pressed
                and (self.button & 0b01100000) == 0
                and (self.button & 0b11) == 0)


def parse_mouse_event(data: str) -> MouseEvent | None:
    """Decode one SGR (1006) mouse event from ``data``; None if not one."""
    m = _SGR.search(data)
    if not m:
        return None
    button, col, row, kind = m.groups()
    return MouseEvent(button=int(button), col=int(col), row=int(row),
                      pressed=(kind == "M"))


@dataclass
class NodeHitMap:
    """Maps terminal rows to plan-tree node ids for click hit-testing.

    The renderer registers ``(row -> node_id)`` as it lays out the tree; a
    click's row is looked up to the node under it. Rows are 1-based to match
    terminal coordinates.
    """

    _rows: dict[int, str] = field(default_factory=dict)

    def register(self, row: int, node_id: str) -> None:
        self._rows[int(row)] = str(node_id)

    def node_at(self, row: int) -> str | None:
        return self._rows.get(int(row))

    def clear(self) -> None:
        self._rows.clear()

    def __len__(self) -> int:
        return len(self._rows)


@dataclass
class FocusModel:
    """Which plan-tree node is focused + which are expanded.

    A click toggles expansion of the clicked node and focuses it. Pure state;
    the renderer reads ``focused`` / ``is_expanded`` to draw the cursor and
    the collapsed/expanded children. Unknown clicks (gutter, empty row) are
    no-ops.
    """

    focused: str | None = None
    _expanded: set[str] = field(default_factory=set)

    def is_expanded(self, node_id: str) -> bool:
        return node_id in self._expanded

    def focus(self, node_id: str) -> None:
        self.focused = node_id

    def toggle(self, node_id: str) -> None:
        if node_id in self._expanded:
            self._expanded.discard(node_id)
        else:
            self._expanded.add(node_id)

    def handle_click(self, event: MouseEvent, hitmap: NodeHitMap) -> str | None:
        """Apply a click: focus + toggle the node under it. Returns the node
        id acted on, or None when the click hit no node."""
        if not event.is_left_click:
            return None
        node_id = hitmap.node_at(event.row)
        if node_id is None:
            return None
        self.focus(node_id)
        self.toggle(node_id)
        return node_id


def write_enable(stream) -> None:
    """Turn on mouse tracking on ``stream`` (best-effort; never raises)."""
    _safe_write(stream, ENABLE)


def write_disable(stream) -> None:
    """Turn off mouse tracking on ``stream`` (best-effort; never raises)."""
    _safe_write(stream, DISABLE)


def _safe_write(stream, seq: str) -> None:
    try:
        stream.write(seq)
        stream.flush()
    except Exception:  # pragma: no cover -- a dumb terminal must not crash us
        pass


__all__ = ["ENABLE", "DISABLE", "MouseEvent", "parse_mouse_event",
           "NodeHitMap", "FocusModel", "enabled", "write_enable",
           "write_disable"]
