"""Markdown to a printable PDF, with no external program.

Asked for "a printable PDF I can download", an agent had no way to make one:
write_file refused .pdf, the conversion worker is optional, and the run
stopped to ask the person. ``write_file`` to a .pdf path uses this writer.

US Letter pages with one-inch margins in the standard PDF fonts (Helvetica,
Helvetica-Bold, Courier), so nothing is embedded: ``#`` headings, wrapped
paragraphs, ``**bold**``, bullets and numbered items with indent levels,
``- [ ]`` checklist boxes drawn as squares, Markdown tables, fenced code and
``---`` rules, with page numbers. Text is encoded as Windows-1252; a
character outside it prints as ``?``.

The character widths below are those of Liberation Sans, which is
metric-compatible with Helvetica (space 278, A 667, a 556 per 1000 units).
"""
from __future__ import annotations

import re
import zlib

_REGULAR_W = (
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, 0,
    556, 0, 222, 556, 333, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0,
    0, 222, 222, 333, 333, 350, 556, 1000, 333, 1000, 500, 333, 944, 0, 500, 667,
    278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 552,
    400, 549, 333, 333, 333, 576, 537, 333, 333, 333, 365, 556, 834, 834, 834, 611,
    667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278,
    722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611,
    556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 549, 611, 556, 556, 556, 556, 500, 556, 500,
)
_BOLD_W = (
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
    975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
    333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
    611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584, 0,
    556, 0, 278, 556, 500, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0,
    0, 278, 278, 500, 500, 350, 556, 1000, 333, 1000, 556, 333, 944, 0, 500, 667,
    278, 333, 556, 556, 556, 556, 280, 556, 333, 737, 370, 556, 584, 333, 737, 552,
    400, 549, 333, 333, 333, 576, 556, 333, 333, 333, 365, 556, 834, 834, 834, 611,
    722, 722, 722, 722, 722, 722, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278,
    722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611,
    556, 556, 556, 556, 556, 556, 889, 556, 556, 556, 556, 556, 278, 278, 278, 278,
    611, 611, 611, 611, 611, 611, 611, 549, 611, 611, 611, 611, 611, 556, 611, 556,
)

MAX_PAGES = 500
_PAGE_W, _PAGE_H, _MARGIN = 612.0, 792.0, 72.0
_WIDTH = _PAGE_W - 2 * _MARGIN
_BODY, _CODE_SIZE = 11.0, 9.5
_HEADING_SIZES = {1: 20.0, 2: 15.0, 3: 12.5}
_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_ITEM = re.compile(r"^(\s*)([-*+]|\d{1,3}[.)])\s+(\[[ xX]\]\s+)?(.*)$")
_RULE = re.compile(r"^\s*([-*_])(\s*\1){2,}\s*$")
_TABLE_RULE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
# A backslash before ASCII punctuation is a Markdown escape ("\\$8,400"):
# the reader sees the character alone.
_ESCAPED = re.compile(r"\\([!-/:-@\[-`{-~])")
_READABLE = str.maketrans({"✓": "x", "✔": "x", "☐": "[ ]", "☑": "[x]", " ": " ",
                           " ": " ", " ": " ", " ": " ", "−": "-"})


class UnwritablePdf(ValueError):
    """The text cannot become a PDF (no content, or too many pages)."""


def _encode(text: str) -> bytes:
    return text.translate(_READABLE).encode("cp1252", errors="replace")


def _width(text: str, size: float, bold: bool = False, mono: bool = False) -> float:
    if mono:
        return len(_encode(text)) * 0.6 * size
    table = _BOLD_W if bold else _REGULAR_W
    total = 0
    for byte in _encode(text):
        total += table[byte - 32] if 32 <= byte < 256 and table[byte - 32] else 556
    return total * size / 1000.0




def _pdf_string(text: str) -> str:
    raw = _encode(text)
    out = []
    for byte in raw:
        ch = chr(byte)
        if ch in "()\\":
            out.append("\\" + ch)
        elif 32 <= byte < 127:
            out.append(ch)
        else:
            out.append(f"\\{byte:03o}")
    return "(" + "".join(out) + ")"


_GLUE = "\x00"  # a word that follows the previous one with no space ("**bold**.")


def _words(text: str) -> list[tuple[str, bool]]:
    """``[(word, bold), ...]`` with ``**bold**`` spans split into words; a
    word written right after the previous one starts with :data:`_GLUE`."""
    out: list[tuple[str, bool]] = []
    spaced = True
    for index, part in enumerate(_BOLD.split(text.replace(_GLUE, ""))):
        part = _ESCAPED.sub(r"\1", part)
        tokens = part.split()
        if not tokens:
            spaced = spaced or bool(part)
            continue
        glued = bool(out) and not spaced and not part[0].isspace()
        out.extend((_GLUE + word if glued and n == 0 else word, index % 2 == 1) for n, word in enumerate(tokens))
        spaced = part[-1].isspace()
    return out


def _wrap(words: list[tuple[str, bool]], size: float, width: float) -> list[list[tuple[str, bool]]]:
    lines: list[list[tuple[str, bool]]] = []
    line: list[tuple[str, bool]] = []
    used = 0.0
    space = _width(" ", size)
    for word, bold in words:
        if word.startswith(_GLUE) and line:
            line.append((word, bold))
            used += _width(word[1:], size, bold)
            continue
        word = word.lstrip(_GLUE)
        w = _width(word, size, bold)
        # A column sized to its widest word must still fit it ("Hours" broke as
        # "Hour/s" by a float rounding hair): compare with a small tolerance.
        while w > width + 0.01 and len(word) > 1:  # a word wider than the line breaks by characters
            cut = len(word)
            while cut > 1 and _width(word[:cut], size, bold) > width + 0.01:
                cut -= 1
            if line:
                lines.append(line)
                line, used = [], 0.0
            lines.append([(word[:cut], bold)])
            word = word[cut:]
            w = _width(word, size, bold)
        if line and used + space + w > width + 0.01:
            lines.append(line)
            line, used = [], 0.0
        used += (space if line else 0) + w
        line.append((word, bold))
    if line:
        lines.append(line)
    return lines


class _Pages:
    def __init__(self) -> None:
        self.pages: list[list[str]] = []
        self.y = 0.0
        self._new()

    def _new(self) -> None:
        if len(self.pages) >= MAX_PAGES:
            raise UnwritablePdf(f"a PDF here holds at most {MAX_PAGES} pages")
        self.pages.append([])
        self.y = _PAGE_H - _MARGIN

    def need(self, height: float) -> None:
        if self.y - height < _MARGIN and self.pages[-1]:
            self._new()

    def gap(self, height: float) -> None:
        self.y -= height

    def text_line(self, x: float, line: list[tuple[str, bool]], size: float, mono: bool = False,
                  marker: tuple[str, object, float] | None = None) -> None:
        """One line of words at ``x``; ``marker`` is ``("text", "1.", mx)`` or
        ``("box", checked, mx)`` drawn on the same line, never split from it."""
        self.need(size * 1.35)
        self.y -= size * 1.35
        ops, cursor, space = [], x, _width(" ", size)
        if marker is not None:
            kind, value, mx = marker
            if kind == "box":
                side = size * 0.75
                ops.append(f"0.6 w {mx:.2f} {self.y - 0.5:.2f} {side:.2f} {side:.2f} re S")
                if value:
                    ops.append(f"BT /F2 {size:.2f} Tf {mx + 1.2:.2f} {self.y:.2f} Td (x) Tj ET")
            else:
                ops.append(f"BT /F1 {size:.2f} Tf {mx:.2f} {self.y:.2f} Td {_pdf_string(str(value))} Tj ET")
        for index, (word, bold) in enumerate(line):
            if word.startswith(_GLUE):
                word = word[1:]
                cursor -= space if index else 0  # written right after the previous word
            font = "F3" if mono else ("F2" if bold else "F1")
            ops.append(f"BT /{font} {size:.2f} Tf {cursor:.2f} {self.y:.2f} Td {_pdf_string(word)} Tj ET")
            cursor += _width(word, size, bold, mono) + (space if index < len(line) - 1 else 0)
        self.pages[-1].extend(ops)

    def draw(self, op: str) -> None:
        self.pages[-1].append(op)


def _paragraph(pages: _Pages, text: str, *, x: float = _MARGIN, size: float = _BODY, bold: bool = False,
               marker: tuple[str, object] | None = None) -> None:
    """Wrapped text at ``x``; a bullet, number or checkbox ``marker`` hangs
    to its left on the first line."""
    words = [(w, bold or b) for w, b in _words(text)]
    lines = _wrap(words, size, _WIDTH - (x - _MARGIN)) or [[]]
    for number, line in enumerate(lines):
        hang = None
        if number == 0 and marker is not None:
            kind, value = marker
            offset = size * 1.3 if kind == "box" else _width(f"{value} ", size)
            hang = (kind, value, x - offset)
        pages.text_line(x, line, size, marker=hang)


def _cells(line: str) -> list[str]:
    stripped = line.strip()
    stripped = stripped.removeprefix("|")
    stripped = stripped.removesuffix("|")
    return [cell.strip() for cell in stripped.split("|")]


def _column_widths(rows: list[list[str]], natural: list[float], size: float, header: bool) -> list[float]:
    """Column widths that fit the page. Each column first gets its widest
    single word, so a short column beside long ones keeps "Square" whole (it
    broke as "Squ"/"are"); the rest of the page is shared in proportion to
    how much more text each column holds. If even the words cannot all fit,
    every column shrinks in proportion."""
    total = sum(natural) or 1.0
    if total <= _WIDTH:
        return natural
    floors = []
    for c, width in enumerate(natural):
        words = [_width(w.replace("**", ""), size, bold=header and i == 0)
                 for i, row in enumerate(rows) for w in row[c].split()]
        floors.append(min(width, max(words, default=0.0) + 8))
    spare = _WIDTH - sum(floors)
    if spare <= 0:
        return [_WIDTH * n / total for n in natural]
    extra = [n - f for n, f in zip(natural, floors, strict=True)]
    room = sum(extra) or 1.0
    return [f + spare * e / room for f, e in zip(floors, extra, strict=True)]


def _table(pages: _Pages, rows: list[list[str]], header: bool) -> None:
    columns = max(len(row) for row in rows)
    rows = [row + [""] * (columns - len(row)) for row in rows]
    size = _BODY - 1.5
    natural = [max(_width(cell.replace("**", ""), size, bold=header and i == 0) for i, row in enumerate(rows)
                   for cell in [row[c]]) + 8 for c in range(columns)]
    widths = _column_widths(rows, natural, size, header)
    for index, row in enumerate(rows):
        wrapped = [_wrap([(w, b or (header and index == 0)) for w, b in _words(cell)], size, max(widths[c] - 8, 20))
                   or [[]] for c, cell in enumerate(row)]
        height = max(len(cell) for cell in wrapped) * size * 1.35
        pages.need(height + 4)
        top = pages.y
        x = _MARGIN
        for c, cell_lines in enumerate(wrapped):
            pages.y = top
            for line in cell_lines:
                pages.text_line(x, line, size)
            x += widths[c]
        pages.y = top - height - 3
        if header and index == 0:
            pages.draw(f"0.5 w {_MARGIN:.2f} {pages.y + 1:.2f} m {_MARGIN + sum(widths):.2f} {pages.y + 1:.2f} l S")
            pages.y -= 2


def _blocks(markdown: str, pages: _Pages) -> None:
    lines = markdown.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    index, paragraph = 0, []

    def flush() -> None:
        if paragraph:
            _paragraph(pages, " ".join(paragraph))
            pages.gap(_BODY * 0.5)
            paragraph.clear()

    while index < len(lines):
        line = lines[index]
        if line.lstrip().startswith(("```", "~~~")):
            flush()
            index += 1
            while index < len(lines) and not lines[index].lstrip().startswith(("```", "~~~")):
                pages.text_line(_MARGIN + 8, [(lines[index].rstrip() or " ", False)], _CODE_SIZE, mono=True)
                index += 1
            pages.gap(_BODY * 0.5)
        elif heading := _HEADING.match(line):
            flush()
            size = _HEADING_SIZES.get(len(heading.group(1)), 11.5)
            pages.need(size * 3)
            pages.gap(size * 0.4)
            _paragraph(pages, heading.group(2).replace("**", ""), size=size, bold=True)
            pages.gap(size * 0.3)
        elif _RULE.match(line):
            flush()
            pages.need(12)
            pages.gap(6)
            pages.draw(f"0.5 w {_MARGIN:.2f} {pages.y:.2f} m {_PAGE_W - _MARGIN:.2f} {pages.y:.2f} l S")
            pages.gap(6)
        elif "|" in line and index + 1 < len(lines) and _TABLE_RULE.match(lines[index + 1]):
            flush()
            rows = [_cells(line)]
            index += 2
            pages.gap(_BODY * 0.4)
            while index < len(lines) and "|" in lines[index] and lines[index].strip():
                rows.append(_cells(lines[index]))
                index += 1
            _table(pages, rows, header=True)
            pages.gap(_BODY * 0.5)
            continue
        elif item := _ITEM.match(line):
            flush()
            depth = min(len(item.group(1).replace("\t", "    ")) // 2, 4)
            x = _MARGIN + 14 + depth * 18
            mark, check, text = item.group(2), item.group(3), item.group(4)
            if check is not None:
                _paragraph(pages, text, x=x + 4, marker=("box", "x" in check.lower()))
            else:
                _paragraph(pages, text, x=x, marker=("text", mark if mark[0].isdigit() else "•"))
            pages.gap(2)
        elif not line.strip():
            flush()
        else:
            paragraph.append(line.strip())
        index += 1
    flush()


def pdf_from_markdown(markdown: str, title: str = "") -> bytes:
    """A PDF for ``markdown``. Raises :class:`UnwritablePdf`."""
    if not markdown.strip():
        raise UnwritablePdf("there is no text to put in the PDF")
    pages = _Pages()
    _blocks(markdown, pages)
    if pages.pages and not pages.pages[-1]:
        pages.pages.pop()
    count = len(pages.pages)
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    catalog = add(b"")  # filled once the page tree number is known
    tree = add(b"")
    fonts = [add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{name} /Encoding /WinAnsiEncoding >>".encode())
             for name in ("Helvetica", "Helvetica-Bold", "Courier")]
    resources = f"<< /Font << /F1 {fonts[0]} 0 R /F2 {fonts[1]} 0 R /F3 {fonts[2]} 0 R >> >>"
    kids = []
    for number, ops in enumerate(pages.pages, 1):
        footer = f"Page {number} of {count}"
        ops = [*ops, f"BT /F1 9 Tf {(_PAGE_W - _width(footer, 9)) / 2:.2f} 36 Td {_pdf_string(footer)} Tj ET"]
        stream = zlib.compress("\n".join(ops).encode("latin-1"))
        content = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream) + stream + b"\nendstream")
        kids.append(add(f"<< /Type /Page /Parent {tree} 0 R /MediaBox [0 0 {_PAGE_W:.0f} {_PAGE_H:.0f}] "
                        f"/Resources {resources} /Contents {content} 0 R >>".encode()))
    objects[catalog - 1] = f"<< /Type /Catalog /Pages {tree} 0 R >>".encode()
    objects[tree - 1] = (f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] "
                         f"/Count {count} >>").encode()
    first = next((m.group(2) for m in map(_HEADING.match, markdown.splitlines()) if m), "")
    info = add(f"<< /Title {_pdf_string((title or first).replace('**', '')[:200])} "
               f"/Producer (Lightwork) >>".encode())
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root {catalog} 0 R /Info {info} 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n").encode()
    return bytes(out)


__all__ = ["MAX_PAGES", "UnwritablePdf", "pdf_from_markdown"]
