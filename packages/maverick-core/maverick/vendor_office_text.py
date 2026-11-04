"""Bounded, non-executing Office evidence reader; no document rendering or OCR."""
from __future__ import annotations

import io
import posixpath
import re
import stat
import zipfile
from xml.etree import ElementTree as ET

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
OFFICE_MIMES = frozenset({DOCX_MIME, XLSX_MIME})
MAX_OFFICE_BYTES = 8 * 1024 * 1024
MAX_TEXT_CHARS = 120_000
_MAX_EXPANDED = 16 * 1024 * 1024
_MAX_PART = 4 * 1024 * 1024
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"


def _xml(raw):
    try:
        text = raw.decode("utf-8-sig", errors="strict")
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper() or "\x00" in text:
            raise ValueError("Office XML declarations are unsupported")
        return ET.fromstring(text)
    except (UnicodeError, ET.ParseError) as exc:
        raise ValueError("Office XML must be valid UTF-8 without external entities") from exc


def _parts(content):
    if len(content) > MAX_OFFICE_BYTES:
        raise ValueError("Office document exceeds the 8 MiB upload limit")
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            infos = archive.infolist()
            if len(infos) > 256 or sum(item.file_size for item in infos) > _MAX_EXPANDED:
                raise ValueError("Office archive exceeds the extraction limits")
            names, parts = set(), {}
            for item in infos:
                name = item.filename
                folded = name.casefold()
                if (not name or name.startswith("/") or "\\" in name or ":" in name
                        or any(bit in {"", ".", ".."} for bit in name.rstrip("/").split("/"))
                        or folded in names or stat.S_ISLNK(item.external_attr >> 16)):
                    raise ValueError("Office archive contains ambiguous or unsafe paths")
                names.add(folded)
                if (item.flag_bits & 1 or item.file_size > _MAX_PART
                        or item.file_size > max(1, item.compress_size) * 200
                        or any(part in folded for part in ("vbaproject", "activex/", "embeddings/", "externallinks/"))):
                    raise ValueError("Encrypted, active, embedded or oversized Office content is unsupported")
                if item.is_dir():
                    continue
                # Read every bounded member to verify CRC; never extract paths to disk.
                raw = archive.read(item)
                if len(raw) != item.file_size:
                    raise ValueError("Office archive member size changed")
                if folded.endswith((".xml", ".rels")):
                    node = _xml(raw)
                    if folded.endswith(".rels") and any(
                        rel.get("TargetMode", "").lower() == "external"
                        or re.match(r"(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//|\\\\)", rel.get("Target", ""))
                        for rel in node
                    ):
                        raise ValueError("Office documents with external links are unsupported; provide a copy without links")
                    if folded == "[content_types].xml" and any(
                        any(marker in value.lower() for marker in ("macroenabled", "vbaproject", "activex", "oleobject"))
                        for child in node for value in child.attrib.values()
                    ):
                        raise ValueError("Macro-enabled Office documents are unsupported")
                    parts[name] = node
            if "[Content_Types].xml" not in parts:
                raise ValueError("Office package has no content-type manifest")
            return parts
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
        raise ValueError("Office document is damaged or uses unsupported compression") from exc


def _append(chunks, spans, text, location):
    text = text.strip()
    if not text:
        return
    start = spans[-1]["end"] + 2 if spans else 0
    if start + len(text) > MAX_TEXT_CHARS or len(chunks) >= 10_000:
        raise ValueError("Office text exceeds the review limit; split the document into smaller evidence files")
    chunks.append(text)
    spans.append(dict(start=start, end=start + len(text), **location))


def _word(parts, chunks, spans):
    root = parts.get("word/document.xml")
    if root is None or root.tag != _W + "document":
        raise ValueError("Word document body is missing")
    if any(node.tag in {_W + name for name in ("altChunk", "object", "instrText", "ins", "del", "txbxContent")}
           for node in root.iter()):
        raise ValueError("Word fields, embedded content and tracked changes require a reviewed plain-text copy")
    body = root.find(_W + "body")
    if body is None:
        raise ValueError("Word document body is missing")
    for index, paragraph in enumerate(body.iter(_W + "p"), 1):
        values = []
        for run in paragraph.iter(_W + "r"):
            if run.find("./" + _W + "rPr/" + _W + "vanish") is not None:
                continue
            values.extend(node.text or "" if node.tag == _W + "t" else " "
                          for node in run if node.tag in {_W + "t", _W + "tab", _W + "br"})
        _append(chunks, spans, "".join(values), {"paragraph": index})


def _sheet_cells(sheet, strings, label, chunks, spans):
    hidden = []
    for column in sheet.findall("./" + _S + "cols/" + _S + "col"):
        if column.get("hidden") in {"1", "true"}:
            hidden.append((int(column.get("min", "0")), int(column.get("max", "0"))))
    seen, count, cached = set(), 0, False
    for row in sheet.findall("./" + _S + "sheetData/" + _S + "row"):
        if row.get("hidden") in {"1", "true"}:
            continue
        for cell in row.findall(_S + "c"):
            count += 1
            ref = cell.get("r", "")
            if count > 10_000 or not re.fullmatch(r"[A-Z]{1,3}[1-9][0-9]{0,6}", ref) or ref in seen:
                raise ValueError("Worksheet cells exceed limits or have ambiguous locations")
            seen.add(ref)
            column = 0
            for char in re.match(r"[A-Z]+", ref)[0]:
                column = column * 26 + ord(char) - 64
            if any(left <= column <= right for left, right in hidden):
                continue
            cached = cached or cell.find(_S + "f") is not None
            value = cell.findtext(_S + "v", "")
            if cell.get("t") == "s":
                try:
                    index = int(value)
                    if index < 0:
                        raise ValueError("negative string index")
                    value = strings[index]
                except (ValueError, IndexError) as exc:
                    raise ValueError("Worksheet shared-string reference is invalid") from exc
            elif cell.get("t") == "inlineStr":
                value = "".join(node.text or "" for node in cell.iter(_S + "t"))
            _append(chunks, spans, value, {"sheet": label, "cell": ref})
    return cached


def _excel(parts, chunks, spans):
    workbook = parts.get("xl/workbook.xml")
    relationships = parts.get("xl/_rels/workbook.xml.rels")
    if workbook is None or relationships is None:
        raise ValueError("Workbook structure is missing")
    targets = {rel.get("Id"): rel.get("Target", "") for rel in relationships}
    if len(targets) != len(relationships):
        raise ValueError("Workbook relationships are ambiguous")
    shared = parts.get("xl/sharedStrings.xml")
    strings = [] if shared is None else ["".join(node.text or "" for node in item.iter(_S + "t")) for item in shared]
    sheets = workbook.findall("./" + _S + "sheets/" + _S + "sheet")
    if not sheets or len(sheets) > 32:
        raise ValueError("Workbook must contain between 1 and 32 sheets")
    cached, seen = False, set()
    for sheet in sheets:
        if sheet.get("state", "visible") != "visible":
            continue
        target = targets.get(sheet.get(_R + "id"), "")
        path = target.lstrip("/") if target.startswith("/xl/") else posixpath.normpath("xl/" + target)
        if not re.fullmatch(r"xl/worksheets/[^/]+\.xml", path) or path in seen or path not in parts:
            raise ValueError("Workbook sheet relationship is unsupported")
        seen.add(path)
        cached = _sheet_cells(parts[path], strings, sheet.get("name", "Worksheet")[:255], chunks, spans) or cached
    return cached


def extract_office(content, mime):
    """Return transient text and source-relative locations, never evaluate formulas."""
    if mime not in OFFICE_MIMES:
        raise ValueError("Unsupported Office format")
    parts, chunks, spans = _parts(content), [], []
    cached = False
    if mime == DOCX_MIME:
        _word(parts, chunks, spans)
    else:
        cached = _excel(parts, chunks, spans)
    return "\n\n".join(chunks), {
        "method": "word_body_text" if mime == DOCX_MIME else "excel_visible_cell_text",
        "scope": "body_paragraphs_and_tables" if mime == DOCX_MIME else "visible_worksheet_cells",
        "confidence": "best_effort", "review_required": True, "location_spans": spans,
        "cached_formula_values": cached,
        "limits": ["No rendering, OCR, images, charts, comments or layout interpretation.",
                   "Headers, footers, hidden content and formatting are outside this extraction.",
                   "Excel values are stored text or cached values; formulas and dates are not calculated or formatted."],
    }
