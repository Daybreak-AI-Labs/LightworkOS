"""Editable Word answers using Chat's current, selected-answer release policy."""
from __future__ import annotations

import io
import re
import zipfile
from xml.etree import ElementTree as ET

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from maverick.docx_redline import build_docx

from .goal_export_ops_api import _current_export, _export_source

router = APIRouter(tags=["chat-answer-exports"])
_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_XML = "http://www.w3.org/XML/1998/namespace"
_TYPES = "http://schemas.openxmlformats.org/package/2006/content-types"
_BOLD = re.compile(r"\*\*([^*\n]+)\*\*")
_HEADING = re.compile(r"^(#{1,6}) ([^#].*)$")
_BULLET = re.compile(r"^[-+*] (\S.*)$")
_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})([^`~]*)$")
_CELL_RULE = re.compile(r":?-{3,}:?")


def _runs(text):
    # Inline code, links and nested emphasis remain literal instead of guessed.
    if "`" in text:
        return [(text, False)]
    runs, start = [], 0
    for match in _BOLD.finditer(text):
        runs.extend([(text[start:match.start()], False), (match[1], {"bold": True})])
        start = match.end()
    return runs + [(text[start:], False)]


def _blocks(text, title):
    blocks = [("title", [(title, False)])] if title else []
    fence, opening = None, None
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        marker = _FENCE.fullmatch(line)
        if fence is not None:
            if marker and marker[1][0] == fence[0] and len(marker[1]) >= len(fence) and not marker[2].strip():
                blocks[opening] = ("skip", [])
                fence = None
                continue
            blocks.append(("code", [(line, False)]))
            continue
        if marker:
            fence = marker[1]
            opening = len(blocks)
            blocks.append(("code", [(line, False)]))
            continue
        heading, bullet = _HEADING.fullmatch(line), _BULLET.fullmatch(line)
        if heading:
            blocks.append(("heading", _runs(heading[2])))
        elif bullet:
            blocks.append(("bullet", _runs(bullet[1])))
        else:
            # Paragraph-per-line retains blanks, indentation and complex layouts.
            blocks.append(("para", _runs(line), line))
    return _tables([block for block in blocks if block[0] != "skip"])


def _cells(line):
    """Split only actual Markdown cell separators, preserving escaped/code pipes."""
    cells, cell, fence, separators, index = [], [], "", 0, 0
    while index < len(line):
        char = line[index]
        if char == "\\" and index + 1 < len(line):
            following = line[index + 1]
            cell.append(following if following == "|" and not fence else char + following)
            index += 2
            continue
        if char == "`":
            end = index + 1
            while end < len(line) and line[end] == "`":
                end += 1
            marker = line[index:end]
            if not fence:
                fence = marker
            elif marker == fence:
                fence = ""
            cell.append(marker)
            index = end
            continue
        if char == "|" and not fence:
            cells.append("".join(cell).strip())
            cell, separators = [], separators + 1
        else:
            cell.append(char)
        index += 1
    if fence or not separators:
        return None
    cells.append("".join(cell).strip())
    if not cells[0]:
        cells.pop(0)
    if cells and not cells[-1]:
        cells.pop()
    return cells or None


def _tables(blocks):
    output, index = [], 0
    while index < len(blocks):
        header = _cells(blocks[index][2]) if blocks[index][0] == "para" else None
        following = blocks[index + 1] if index + 1 < len(blocks) else None
        rules = _cells(following[2]) if following and following[0] == "para" else None
        if not header or not rules or len(header) != len(rules) or not all(_CELL_RULE.fullmatch(cell) for cell in rules):
            output.append(blocks[index])
            index += 1
            continue
        rows, index = [header], index + 2
        while index < len(blocks) and blocks[index][0] == "para":
            cells = _cells(blocks[index][2])
            if cells is None or len(cells) != len(header):
                break  # Keep malformed/extra cells literally instead of losing data.
            rows.append(cells)
            index += 1
        output.append(("table", [], rows, rules))
    return output


def _word_table(rows, rules):
    table = ET.Element(f"{{{_W}}}tbl")
    properties = ET.SubElement(table, f"{{{_W}}}tblPr")
    ET.SubElement(properties, f"{{{_W}}}tblW", {f"{{{_W}}}w": "5000", f"{{{_W}}}type": "pct"})
    borders = ET.SubElement(properties, f"{{{_W}}}tblBorders")
    for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
        ET.SubElement(borders, f"{{{_W}}}{side}", {f"{{{_W}}}val": "single", f"{{{_W}}}sz": "4", f"{{{_W}}}color": "D5D9DF"})
    grid = ET.SubElement(table, f"{{{_W}}}tblGrid")
    for _cell in rules:
        ET.SubElement(grid, f"{{{_W}}}gridCol", {f"{{{_W}}}w": str(9600 // len(rules))})
    for index, cells in enumerate(rows):
        row = ET.SubElement(table, f"{{{_W}}}tr")
        if not index:
            ET.SubElement(ET.SubElement(row, f"{{{_W}}}trPr"), f"{{{_W}}}tblHeader")
        for cell, rule in zip(cells, rules, strict=True):
            target = ET.SubElement(row, f"{{{_W}}}tc")
            if not index:
                ET.SubElement(ET.SubElement(target, f"{{{_W}}}tcPr"), f"{{{_W}}}shd", {f"{{{_W}}}fill": "F2F4F7"})
            paragraph = ET.SubElement(target, f"{{{_W}}}p")
            alignment = "center" if rule.startswith(":") and rule.endswith(":") else "right" if rule.endswith(":") else "left"
            ET.SubElement(ET.SubElement(paragraph, f"{{{_W}}}pPr"), f"{{{_W}}}jc", {f"{{{_W}}}val": alignment})
            for text, options in _runs(cell):
                run = ET.SubElement(paragraph, f"{{{_W}}}r")
                if not index or isinstance(options, dict) and options.get("bold"):
                    ET.SubElement(ET.SubElement(run, f"{{{_W}}}rPr"), f"{{{_W}}}b")
                ET.SubElement(run, f"{{{_W}}}t", {f"{{{_XML}}}space": "preserve"}).text = text
    return table


def _word_tabs(document):
    for paragraph in document.iter(f"{{{_W}}}p"):
        for run in paragraph.findall(f"{{{_W}}}r"):
            for node in list(run):
                if node.tag != f"{{{_W}}}t" or "\t" not in (node.text or ""):
                    continue
                position = list(run).index(node)
                for index, value in enumerate((node.text or "").split("\t")):
                    if index:
                        run.insert(position, ET.Element(f"{{{_W}}}tab"))
                        position += 1
                    segment = ET.Element(f"{{{_W}}}t", {f"{{{_XML}}}space": "preserve"})
                    segment.text = value
                    run.insert(position, segment)
                    position += 1
                run.remove(node)


def word_answer(text: str, title: str) -> bytes:
    """Editable business text and tables; exact original retained in the ZIP."""
    if any(not (char in "\t\n\r" or 32 <= ord(char) <= 0xD7FF
                or 0xE000 <= ord(char) <= 0xFFFD or 0x10000 <= ord(char) <= 0x10FFFF)
           for char in text + title):
        raise HTTPException(409, "This answer contains characters Word cannot display. Download Markdown to keep the complete original.")
    blocks = _blocks(text, title)
    original = build_docx(blocks)
    with zipfile.ZipFile(io.BytesIO(original)) as source:
        parts = {name: source.read(name) for name in source.namelist()}
    settings = ET.fromstring(parts["word/settings.xml"])
    for node in list(settings):
        if node.tag in {f"{{{_W}}}trackRevisions", f"{{{_W}}}trackChanges", f"{{{_W}}}documentProtection"}:
            settings.remove(node)
    parts["word/settings.xml"] = ET.tostring(settings, encoding="utf-8", xml_declaration=True)
    styles = ET.fromstring(parts["word/styles.xml"])
    for node in styles.iter(f"{{{_W}}}color"):
        node.set(f"{{{_W}}}val", "000000")
    for paragraph in styles.iter(f"{{{_W}}}pPr"):
        for node in list(paragraph):
            if node.tag == f"{{{_W}}}pBdr":
                paragraph.remove(node)
    parts["word/styles.xml"] = ET.tostring(styles, encoding="utf-8", xml_declaration=True)
    document = ET.fromstring(parts["word/document.xml"])
    body = document.find(f"{{{_W}}}body")
    paragraphs = body.findall(f"{{{_W}}}p")
    tables = {}
    for paragraph, block in zip(paragraphs, blocks, strict=True):
        if block[0] == "table":
            tables[paragraph] = _word_table(block[2], block[3])
            continue
        if block[0] == "code":
            ppr = ET.Element(f"{{{_W}}}pPr")
            paragraph.insert(0, ppr)
            ET.SubElement(ppr, f"{{{_W}}}spacing", {f"{{{_W}}}after": "0"})
            for run in paragraph.findall(f"{{{_W}}}r"):
                props = ET.Element(f"{{{_W}}}rPr")
                run.insert(0, props)
                ET.SubElement(props, f"{{{_W}}}rFonts", {f"{{{_W}}}ascii": "Consolas", f"{{{_W}}}hAnsi": "Consolas"})
                ET.SubElement(props, f"{{{_W}}}sz", {f"{{{_W}}}val": "19"})
    body[:] = [tables.get(child, child) for child in body]
    _word_tabs(body)
    section = body.find(f"{{{_W}}}sectPr")
    for node in list(section):
        if node.tag == f"{{{_W}}}headerReference":
            section.remove(node)
    parts["word/document.xml"] = ET.tostring(document, encoding="utf-8", xml_declaration=True)
    # Keep a neutral page footer; no report, legal-review or redline branding.
    footer = ET.fromstring(parts["word/footer1.xml"])
    first_text = footer.find(f".//{{{_W}}}t")
    if first_text is not None:
        first_text.text = ""
    parts["word/footer1.xml"] = ET.tostring(footer, encoding="utf-8", xml_declaration=True)
    parts["lightwork/source.md"] = text.encode("utf-8")
    types = ET.fromstring(parts["[Content_Types].xml"])
    ET.SubElement(types, f"{{{_TYPES}}}Default", {"Extension": "md", "ContentType": "text/markdown"})
    parts["[Content_Types].xml"] = ET.tostring(types, encoding="utf-8", xml_declaration=True)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in parts.items():
            archive.writestr(name, value)
    return output.getvalue()


@router.get("/chat/goal/{goal_id}/download.docx")
def download_word_answer(request: Request, goal_id: int, turn_id: int | None = None) -> Response:
    from .app import download_chat_answer

    _world, goal, _artifacts, version = _export_source(request, goal_id)
    selected = download_chat_answer(request, goal_id, turn_id)
    text = selected.body.decode("utf-8")
    document = word_answer(text, goal.title)
    _current_export(request, goal_id, version)
    current = download_chat_answer(request, goal_id, turn_id)
    if current.body != selected.body:
        raise HTTPException(409, "This answer changed. Reload before downloading its Word document.")
    _current_export(request, goal_id, version)
    suffix = f"-message-{turn_id}" if turn_id is not None else ""
    return Response(document, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", headers={
        "Content-Disposition": f'attachment; filename="lightwork-answer-{goal_id}{suffix}.docx"',
        "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff",
    })
