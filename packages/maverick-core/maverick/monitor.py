"""Live plan/activity monitor for Lightwork agents.

Reads the world model and renders a real-time view of:
  - the active goal (title, status, parent chain)
  - sub-goals (the plan tree)
  - recent events (tool calls, agent transitions, decisions)
  - cost and budget consumption
  - latest LLM activity

Designed to be reactive: the user starts an agent in one terminal, runs
`maverick monitor` in another, and watches the swarm work in real time.

This is the open-source equivalent of Devin's "watch over my shoulder"
UI -- without a paid VM. The plumbing is just the SQLite world model,
which agents write to as they progress.

Keys (in a terminal): the power-user keymap (:mod:`maverick.keymap`,
``[tui.keys]`` / ``MAVERICK_TUI_KEYS``) is loaded when the monitor starts --
quit, refresh now, move through the plan tree, open or close a step, and
pause or resume following the run. Ctrl-C always quits. When the input is
not a terminal the monitor just refreshes, as before.
"""
from __future__ import annotations

import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .world_model import Goal, WorldModel

log = logging.getLogger(__name__)


# Single source of truth for goal/sub-goal status -> Rich color. Two separate
# inline maps used to drift: 'active' (the normal running state goals are set
# to via world_model.set_goal_status('active')) was in neither, so a live goal
# rendered uncolored; 'blocked' was missing from the plan-tree map. Centralize
# so the main status line and the plan tree can't disagree again.
# Keyed on the statuses the orchestrator actually writes
# (pending/active/blocked/done/cancelled) -- the old map also listed
# in_progress/running/succeeded/failed (never written) and lacked cancelled.
_STATUS_COLORS = {
    "pending": "yellow",
    "active": "cyan",
    "done": "green",
    "blocked": "red",
    "cancelled": "red",
}


def _status_color(status: str) -> str:
    return _STATUS_COLORS.get((status or "").lower(), "white")


@dataclass
class MonitorState:
    """Snapshot of one goal + its plan tree + recent activity."""
    goal: Goal
    children: list[Goal]
    recent_events: list  # list[GoalEvent]
    episodes: list  # list[EpisodeSpend]
    total_dollars: float

    @property
    def status_color(self) -> str:
        return _status_color(self.goal.status)


def _fetch_subgoals(world: WorldModel, parent_id: int) -> list[Goal]:
    """Return immediate children of a goal, sorted by created_at. Locked +
    backend-portable (was a raw world.conn.execute with `?` placeholders)."""
    return world.subgoals(parent_id, limit=50)


def _resolve_active_goal(world: WorldModel) -> Goal | None:
    """Pick the most-recently-touched in-flight goal as 'active'.

    Routes through the locked ``inflight_goal`` helper (vocab active/pending --
    what the orchestrator actually writes) instead of a raw query on the stale
    pending/in_progress/running set, which missed every `active` goal. Falls
    back to the most-recent goal regardless of status.
    """
    goal = world.inflight_goal()
    if goal is not None:
        return goal
    return world.most_recent_goal()


def snapshot(world: WorldModel, goal_id: int | None = None) -> MonitorState | None:
    """Read a complete monitor snapshot for ``goal_id`` (or active goal)."""
    if goal_id is None:
        goal = _resolve_active_goal(world)
        if goal is None:
            return None
    else:
        goal = world.get_goal(goal_id)
        if goal is None:
            return None
    children = _fetch_subgoals(world, goal.id)
    events = world.goal_events(goal.id, limit=40)
    # Show most-recent events at the bottom; trim to last 20.
    events = events[-20:]
    episodes = world.list_episodes(limit=10, goal_id=goal.id)
    totals = world.total_spend()
    return MonitorState(
        goal=goal,
        children=children,
        recent_events=events,
        episodes=episodes,
        total_dollars=float(totals.get("dollars") or 0.0),
    )


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"


# A Rich markup tag (or something shaped like one) with any backslashes before it.
_MARKUP_TAG = re.compile(r"(\\*)(\[[a-z#/@][^[]*?\])")


def _esc(text) -> str:
    """Escape goal and agent text so Rich shows it literally.

    The same rule as ``rich.markup.escape``, kept here because the plain
    fallback runs without Rich: unescaped, ``[coder]`` is hidden as an unknown
    style tag and ``wrote [/tmp/out]`` raises ``MarkupError``.
    """
    text = _MARKUP_TAG.sub(lambda m: m.group(1) * 2 + "\\" + m.group(2), str(text))
    if text.endswith("\\") and not text.endswith("\\\\"):
        text += "\\"
    return text


def _plain(markup: str) -> str:
    """:func:`render` output without its style tags, with :func:`_esc` undone."""
    def _strip(m: re.Match) -> str:
        slashes, tag = m.groups()
        kept = "\\" * (len(slashes) // 2)
        return kept + tag if len(slashes) % 2 else kept

    return _MARKUP_TAG.sub(_strip, markup)


def _fmt_event(ev) -> str:
    """One-line summary for a GoalEvent."""
    age = time.time() - ev.ts
    return (f"[dim]{_fmt_duration(age)} ago[/dim] {_esc(f'[{ev.agent}]')} {_esc(ev.kind)}: "
            f"{_esc((ev.content or '')[:120])}")


@dataclass
class MonitorKeys:
    """What the pressed keys have done to the live view (pure state).

    ``bindings`` is the effective keymap (action -> key); :meth:`press` maps a
    decoded key name to its action and applies it. ``focus`` is the index of
    the focused plan-tree step, ``expanded`` the steps opened to show their
    details, and ``follow`` whether the view keeps refreshing.
    """

    bindings: dict[str, str]
    follow: bool = True
    focus: int | None = None
    expanded: set[int] = field(default_factory=set)

    def press(self, key: str, steps: int) -> str | None:
        from . import keymap

        action = keymap.handle_key(key, bindings=self.bindings)
        if action == "focus_next" and steps:
            self.focus = 0 if self.focus is None else min(steps - 1, self.focus + 1)
        elif action == "focus_prev" and steps:
            self.focus = 0 if self.focus is None else max(0, self.focus - 1)
        elif action == "expand" and self.focus is not None:
            self.expanded.add(self.focus)
        elif action == "collapse" and self.focus is not None:
            self.expanded.discard(self.focus)
        elif action == "toggle_follow":
            self.follow = not self.follow
        return action

    def footer(self) -> str:
        b = self.bindings
        state = "following the run" if self.follow else "paused"
        return (f"[dim]{b['quit']} quit · {b['refresh']} refresh · {b['focus_prev']}/"
                f"{b['focus_next']} move · {b['expand']} open · {b['collapse']} close · "
                f"{b['toggle_follow']} pause or follow ({state})[/dim]")


# Escape sequences terminals send for the named keys the keymap knows.
_SEQUENCES = {
    "\x1b[A": "up", "\x1b[B": "down", "\x1b[C": "right", "\x1b[D": "left",
    "\x1bOA": "up", "\x1bOB": "down", "\x1bOC": "right", "\x1bOD": "left",
    "\x1bOP": "f1", "\x1bOQ": "f2", "\x1bOR": "f3", "\x1bOS": "f4",
    "\x1b[15~": "f5", "\x1b[17~": "f6", "\x1b[18~": "f7", "\x1b[19~": "f8",
    "\x1b[20~": "f9", "\x1b[21~": "f10", "\x1b[23~": "f11", "\x1b[24~": "f12",
    "\x1b": "esc", "\r": "enter", "\n": "enter", "\t": "tab",
}
# Windows console: a special key arrives as a prefix character then a code.
_WINDOWS_KEYS = {"H": "up", "P": "down", "K": "left", "M": "right",
                 **{chr(0x3A + i): f"f{i}" for i in range(1, 11)},
                 "\x85": "f11", "\x86": "f12"}


def decode_key(data: str) -> str | None:
    """The keymap name of one key read from a terminal, or None."""
    if not data:
        return None
    if data in _SEQUENCES:
        return _SEQUENCES[data]
    if len(data) == 2 and data[0] in ("\x00", "\xe0"):
        return _WINDOWS_KEYS.get(data[1])
    if len(data) == 1 and data.isprintable():
        return data.lower()
    return None


class _KeyReader:
    """Read single keys from the terminal without waiting for Enter.

    Only when standard input is a terminal; otherwise :meth:`read` just waits,
    so piped or scripted use behaves exactly as before.
    """

    def __init__(self, stream=None) -> None:
        self._stream = stream if stream is not None else sys.stdin
        self._saved = None
        try:
            self._tty = bool(self._stream.isatty())
        except Exception:
            self._tty = False

    def __enter__(self) -> _KeyReader:
        if self._tty and os.name != "nt":
            try:
                import termios
                import tty

                fd = self._stream.fileno()
                self._saved = termios.tcgetattr(fd)
                tty.setcbreak(fd)
            except Exception:  # pragma: no cover -- an odd terminal stays line-mode
                self._tty = False
        return self

    def __exit__(self, *_exc) -> None:
        if self._saved is not None:
            import termios

            termios.tcsetattr(self._stream.fileno(), termios.TCSADRAIN, self._saved)
            self._saved = None

    def read(self, timeout: float) -> str | None:
        if not self._tty:
            time.sleep(timeout)
            return None
        if os.name == "nt":  # pragma: no cover -- Windows console
            import msvcrt

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if msvcrt.kbhit():
                    first = msvcrt.getwch()
                    if first in ("\x00", "\xe0"):
                        return decode_key(first + msvcrt.getwch())
                    return decode_key(first)
                time.sleep(0.05)
            return None
        import select

        fd = self._stream.fileno()
        ready, _, _ = select.select([fd], [], [], timeout)
        if not ready:
            return None
        return decode_key(os.read(fd, 32).decode("utf-8", "replace"))


def render(state: MonitorState, keys: MonitorKeys | None = None) -> str:
    """Render a MonitorState to a rich-formatted string.

    Returns plain text with rich-tag markup. Callers decide how to
    display (Console.print, file, websocket, etc). With ``keys`` the focused
    plan step is marked, opened steps show their details, and a key guide is
    added at the bottom.
    """
    parts: list[str] = []
    goal = state.goal
    age = time.time() - goal.created_at
    color = state.status_color
    parts.append(
        f"[bold]Goal #{goal.id}[/bold] [{color}]{goal.status}[/{color}]  "
        f"[dim]{_fmt_duration(age)} elapsed[/dim]"
    )
    parts.append(f"[bold]{_esc(goal.title)}[/bold]")
    if goal.description:
        parts.append(f"[dim]{_esc(goal.description[:200])}[/dim]")
    parts.append("")

    if state.children:
        parts.append("[bold]Plan tree[/bold]")
        for index, c in enumerate(state.children):
            cc = _status_color(c.status)
            mark = "▸" if keys is not None and keys.focus == index else "├─"
            parts.append(f"  {mark} [{cc}]{c.status:>11}[/{cc}]  #{c.id} {_esc(c.title[:80])}")
            if keys is not None and index in keys.expanded:
                detail = (getattr(c, "result", None) or c.description or "").strip()
                parts.append(f"      [dim]{_esc((detail or 'No details yet.')[:300])}[/dim]")
        parts.append("")

    if state.episodes:
        run = state.episodes[0]
        ended = run.ended_at and "done" or "running"
        parts.append(
            f"[bold]Latest episode #{run.id}[/bold] ({ended})  "
            f"${run.cost_dollars:.4f}  "
            f"in={run.input_tokens:,} out={run.output_tokens:,} "
            f"tools={run.tool_calls}"
        )
        parts.append("")

    if state.recent_events:
        parts.append("[bold]Recent activity[/bold]")
        for ev in state.recent_events:
            parts.append("  " + _fmt_event(ev))
        parts.append("")

    parts.append(
        f"[dim]Cumulative spend on this DB: ${state.total_dollars:.2f}[/dim]"
    )
    if keys is not None:
        parts.append(keys.footer())
    return "\n".join(parts)


def monitor_loop(
    db_path: Path | None = None,
    goal_id: int | None = None,
    interval_seconds: float = 1.5,
) -> int:
    """Run a live monitor in the terminal.

    Returns 0 when the user Ctrl-C's out. Returns 2 if no goal exists
    yet (db is empty).
    """
    try:
        from rich.console import Console
        from rich.live import Live
    except ImportError:
        return _monitor_loop_plain(db_path, goal_id, interval_seconds)

    console = Console()
    world = WorldModel(db_path)
    try:
        state = snapshot(world, goal_id)
        if state is None:
            console.print(
                f"[yellow]No goals found in {world.path}.[/yellow]\n"
                "Start one with: maverick start \"your task here\""
            )
            return 2
        # Opt-in mouse mode ([tui] mouse): enable SGR mouse tracking so the
        # plan tree is clickable. Best-effort + restored on exit; a terminal
        # that ignores the sequence just keeps the keyboard/auto-refresh view.
        import sys as _sys

        from . import tui_mouse
        _mouse = tui_mouse.enabled()
        if _mouse:
            tui_mouse.write_enable(_sys.stdout)
        try:
            from . import keymap

            view = MonitorKeys(keymap.resolve())
            with _KeyReader() as reader, Live(render(state, view), console=console,
                                              refresh_per_second=2) as live:
                try:
                    _run_live(live, reader, view, world, goal_id, state, interval_seconds)
                except KeyboardInterrupt:
                    pass
        finally:
            if _mouse:
                tui_mouse.write_disable(_sys.stdout)
        return 0
    finally:
        world.close()


def _run_live(live, reader, view: MonitorKeys, world, goal_id, state, interval: float) -> None:
    """Refresh the live view and apply pressed keys until the quit key."""
    while True:
        action = None
        key = reader.read(interval)
        if key is not None:
            action = view.press(key, len(state.children) if state is not None else 0)
            if action == "quit":
                return
        if view.follow or action == "refresh":
            fresh = snapshot(world, goal_id)
            if fresh is None:
                live.update("[red]Goal not found.[/red]")
                continue
            state = fresh
        live.update(render(state, view))


def _monitor_loop_plain(
    db_path: Path | None, goal_id: int | None, interval: float,
) -> int:
    """Fallback when rich isn't installed: print snapshot every N seconds.

    Less pretty but works in any terminal. ANSI escape codes for clear.
    """
    import sys

    world = WorldModel(db_path)
    try:
        try:
            while True:
                state = snapshot(world, goal_id)
                # Clear screen + home cursor.
                sys.stdout.write("\033[2J\033[H")
                if state is None:
                    sys.stdout.write(
                        f"No goals found in {world.path}.\n"
                        "Start one with: maverick start \"your task here\"\n"
                    )
                else:
                    # Strip rich tags for plain output.
                    sys.stdout.write(_plain(render(state)) + "\n")
                sys.stdout.flush()
                time.sleep(interval)
        except KeyboardInterrupt:
            pass
        return 0
    finally:
        world.close()
