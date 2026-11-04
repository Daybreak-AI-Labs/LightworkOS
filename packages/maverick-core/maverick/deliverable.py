"""Render a goal's free-text result as the deliverable its pack declares.

A domain pack's :class:`~maverick.domain.OutputContract` says a result is a
``forecast`` or ``table`` rather than ``prose``; this turns the agent's text
into the structured artifact the consumer expects, so the dashboard can show a
risk officer or an FP&A analyst a real grid instead of a wall of monospace.

Pure and dependency-free. The structure agents already emit is a GitHub-style
pipe table (the persona asks them to "label every figure"), so that is what we
parse; anything else -- a misdeclared shape, a table-less memo, a malformed
grid -- degrades gracefully to prose. Server-side by design: the parsed cells
go through the template's autoescaping, so a result can't inject markup.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Shapes that earn a titled deliverable card (vs. plain prose). Mirrors the
# render archetypes in :data:`maverick.domain._VALID_SHAPES` minus ``prose``.
_STRUCTURED_SHAPES = frozenset({"report", "table", "forecast"})

# A markdown table separator cell: dashes with optional alignment colons.
_SEP_CELL = re.compile(r"^:?-+:?$")

# Bounds so a pathological result can't build an enormous DOM.
_MAX_ROWS = 500
_MAX_COLS = 40


@dataclass
class Table:
    """A parsed grid: a header row and zero or more body rows (ragged rows are
    padded/truncated to the header width so the rendered ``<table>`` stays
    rectangular)."""
    headers: list[str]
    rows: list[list[str]]


@dataclass
class RenderedDeliverable:
    """What the dashboard shows for a goal result: a parsed :class:`Table` when
    the pack declares structure and the result contains one, otherwise the raw
    text as ``prose``."""
    shape: str
    table: Table | None = None
    prose: str = ""

    @property
    def structured(self) -> bool:
        """Whether to present this as a titled deliverable card. True for a
        declared structured shape even when no table was found (a memo-style
        ``report`` still gets its header); ``prose`` never is."""
        return self.shape in _STRUCTURED_SHAPES


def _split_row(line: str) -> list[str]:
    """Cells of a pipe-table row, trimming the optional leading/trailing pipes
    (``| a | b |`` and ``a | b`` both yield ``['a', 'b']``)."""
    s = line.strip().removeprefix("|").removesuffix("|")
    return [c.strip() for c in s.split("|")]


def _is_separator(cells: list[str]) -> bool:
    return bool(cells) and all(_SEP_CELL.match(c) for c in cells)


def parse_pipe_table(text: str) -> Table | None:
    """The first GitHub-style pipe table in ``text`` (a header line, a
    ``---`` separator, then body rows), or ``None`` if there isn't one.

    Forgiving: it scans for the header/separator pair anywhere in the text (so
    surrounding narrative is ignored), and stops the body at the first line
    that isn't a table row."""
    lines = (text or "").splitlines()
    for i in range(len(lines) - 1):
        if "|" not in lines[i] or "|" not in lines[i + 1]:
            continue
        header = _split_row(lines[i])
        sep = _split_row(lines[i + 1])
        if len(sep) != len(header) or not _is_separator(sep):
            continue
        width = min(len(header), _MAX_COLS)
        header = header[:width]
        rows: list[list[str]] = []
        for line in lines[i + 2:]:
            if "|" not in line or not line.strip():
                break
            cells = _split_row(line)[:width]
            cells += [""] * (width - len(cells))  # pad ragged rows
            rows.append(cells)
            if len(rows) >= _MAX_ROWS:
                break
        return Table(headers=header, rows=rows)
    return None


def render_deliverable(shape: str | None, result: str | None) -> RenderedDeliverable:
    """Render a goal ``result`` per its pack's declared output ``shape``.

    A structured shape whose result carries a pipe table renders as that
    table; everything else (a ``prose`` shape, or a structured shape with no
    parseable table) falls back to prose -- never raising, so the goal page is
    robust to whatever the agent produced."""
    shape = (shape or "prose").strip() or "prose"
    if shape in _STRUCTURED_SHAPES:
        table = parse_pipe_table(result or "")
        if table is not None:
            return RenderedDeliverable(shape=shape, table=table)
    return RenderedDeliverable(shape=shape, prose=result or "")


__all__ = ["Table", "RenderedDeliverable", "parse_pipe_table", "render_deliverable"]
