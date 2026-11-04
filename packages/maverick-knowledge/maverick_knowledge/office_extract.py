"""Bounded OOXML text projection, without native execution or formula evaluation."""
from __future__ import annotations

import io
import posixpath
import re
import stat
import zipfile
from xml.etree import ElementTree as ET

from .extraction import ExtractionBuilder

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"


def _parts(data: bytes, max_expanded: int) -> dict:
    parts = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > 2048 or (max_expanded > 0 and sum(i.file_size for i in infos) > max_expanded):
            raise ValueError("Office package decompresses too large")
        seen = set()
        for item in infos:
            name = item.filename
            folded = name.casefold()
            if (not name or name.startswith("/") or "\\" in name or ":" in name
                    or any(p in {"", ".", ".."} for p in name.rstrip("/").split("/"))
                    or folded in seen or stat.S_ISLNK(item.external_attr >> 16)
                    or item.flag_bits & 1 or item.file_size > 16 * 1024 * 1024
                    or item.file_size > max(1, item.compress_size) * 200):
                raise ValueError("Office package has unsafe, duplicate, encrypted or oversized members")
            seen.add(folded)
            if any(p in folded for p in ("vbaproject", "activex/", "embeddings/", "externallinks/")):
                raise ValueError("Active or embedded Office content requires a reviewed text copy")
            if item.is_dir():
                continue
            raw = archive.read(item)  # bounded above; CRC checked, no disk extraction
            if len(raw) != item.file_size:
                raise ValueError("Office member size changed")
            if folded.endswith((".xml", ".rels")):
                text = raw.decode("utf-8-sig", errors="strict")
                if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper() or "\x00" in text:
                    raise ValueError("Office XML entities/declarations are unsupported")
                node = ET.fromstring(text)
                if folded.endswith(".rels") and any(
                    rel.get("TargetMode", "").lower() == "external"
                    or re.match(r"(?:[A-Za-z][A-Za-z0-9+.-]*:|//|\\\\)", rel.get("Target", ""))
                    for rel in node
                ):
                    raise ValueError("Office external links require a reviewed text copy")
                if folded == "[content_types].xml" and any(
                    marker in value.lower() for child in node for value in child.attrib.values()
                    for marker in ("macroenabled", "vbaproject", "activex", "oleobject")
                ):
                    raise ValueError("Macro-enabled Office content is unsupported")
                parts[name] = node
            else:
                parts[name] = None
    if "[Content_Types].xml" not in parts:
        raise ValueError("Office package content-type manifest is missing")
    return parts


def _paragraph(node) -> str:
    values = []
    for run in node.iter(W + "r"):
        if run.find("./" + W + "rPr/" + W + "vanish") is not None:
            continue
        for item in run:
            if item.tag == W + "t":
                values.append(item.text or "")
            elif item.tag in {W + "tab", W + "br"}:
                values.append("\t" if item.tag == W + "tab" else "\n")
    return "".join(values)


def _word(parts, builder):
    root = parts.get("word/document.xml")
    if root is None or root.tag != W + "document":
        raise ValueError("Word document body is missing")
    if any(node.tag in {W + name for name in ("altChunk", "object", "instrText", "ins", "del", "txbxContent")}
           for node in root.iter()):
        raise ValueError("Word fields, embedded content and tracked changes need a reviewed text copy")
    body = root.find(W + "body")
    if body is None:
        raise ValueError("Word document body is missing")
    for i, node in enumerate(body, 1):
        if node.tag == W + "p":
            builder.append(_paragraph(node), f"word/body/paragraph[{i}]", "paragraph")
        elif node.tag == W + "tbl":
            for row_index, row in enumerate(node.findall(W + "tr"), 1):
                for cell_index, cell in enumerate(row.findall(W + "tc"), 1):
                    for paragraph_index, paragraph in enumerate(cell.findall(W + "p"), 1):
                        builder.append(_paragraph(paragraph),
                                       f"word/body/table[{i}]/row[{row_index}]/cell[{cell_index}]/paragraph[{paragraph_index}]",
                                       "table_cell")
                    if cell.find(W + "tbl") is not None:
                        builder.omit(f"word/body/table[{i}]/row[{row_index}]/cell[{cell_index}]/nested-table")
        elif node.tag != W + "sectPr":
            builder.omit(f"word/body/element[{i}]")
    if any(node.tag == W + "vanish" for node in root.iter()):
        builder.omit("word/body/hidden-runs")
    builder.omitted.extend(name for name in parts if any(
        marker in name.lower() for marker in ("header", "footer", "footnote", "endnote", "comments", "/media/", "/charts/")
    ))
    builder.warnings.append("Body text and table cells only; no rendering or layout interpretation.")


def _worksheet_cells(root):
    previous_row = count = 0
    for row in root.findall("./" + S + "sheetData/" + S + "row"):
        row_number = int(row.get("r", previous_row + 1))
        if not previous_row < row_number <= 1048576:
            raise ValueError("Worksheet rows are invalid or unordered")
        previous_row, previous_column = row_number, 0
        for cell in row.findall(S + "c"):
            count += 1
            ref = cell.get("r", "")
            if count > 100_000 or not re.fullmatch(r"[A-Z]{1,3}[1-9][0-9]{0,6}", ref):
                raise ValueError("Worksheet cell count or locations exceed extraction bounds")
            column = 0
            for char in re.match("[A-Z]+", ref)[0]:
                column = column * 26 + ord(char) - 64
            if not previous_column < column <= 16384 or int(re.search("[0-9]+", ref)[0]) != row_number:
                raise ValueError("Worksheet cell coordinates are invalid or unordered")
            previous_column = column
            yield cell, ref, column, row.get("hidden") in {"1", "true"}


def _excel(parts, builder):
    workbook = parts.get("xl/workbook.xml")
    relationships = parts.get("xl/_rels/workbook.xml.rels")
    if workbook is None or relationships is None:
        raise ValueError("Workbook structure is missing")
    targets = {rel.get("Id"): rel.get("Target", "") for rel in relationships}
    if len(targets) != len(relationships):
        raise ValueError("Workbook relationships are ambiguous")
    shared = parts.get("xl/sharedStrings.xml")
    strings = [] if shared is None else ["".join(n.text or "" for n in item.iter(S + "t")) for item in shared]
    sheets = workbook.findall("./" + S + "sheets/" + S + "sheet")
    if not sheets or len(sheets) > 256:
        raise ValueError("Workbook sheet count exceeds its extraction boundary")
    seen_paths = set()
    for sheet in sheets:
        label = sheet.get("name", "Worksheet")[:255]
        target = targets.get(sheet.get(R + "id"), "")
        path = target.lstrip("/") if target.startswith("/xl/") else posixpath.normpath("xl/" + target)
        if not re.fullmatch(r"xl/worksheets/[^/]+\.xml", path) or path in seen_paths or path not in parts:
            raise ValueError("Worksheet relationship is unsupported or ambiguous")
        seen_paths.add(path)
        if sheet.get("state", "visible") != "visible":
            builder.omit(f"worksheet:{label}:hidden")
            continue
        root = parts[path]
        hidden = [(int(c.get("min", "0")), int(c.get("max", "0")))
                  for c in root.findall("./" + S + "cols/" + S + "col") if c.get("hidden") in {"1", "true"}]
        for cell, ref, column, row_hidden in _worksheet_cells(root):
            location = f"worksheet:{label}!{ref}"
            if row_hidden or any(a <= column <= b for a, b in hidden):
                builder.omit(location + ":hidden")
                continue
            value = cell.findtext(S + "v", "")
            if cell.get("t") == "s":
                index = int(value)
                if index < 0 or index >= len(strings):
                    raise ValueError("Worksheet shared string reference is invalid")
                value = strings[index]
            elif cell.get("t") == "inlineStr":
                value = "".join(n.text or "" for n in cell.iter(S + "t"))
            formula = cell.find(S + "f")
            if formula is not None:
                value = "=" + (formula.text or "") + (f" [cached value: {value}]" if value else " [uncalculated]")
                warning = "Formula values are cached or uncalculated; extraction never evaluates formulas."
                if warning not in builder.warnings:
                    builder.warnings.append(warning)
                if not formula.text:
                    builder.omit(location + ": shared/array formula expression unavailable")
            if value:
                builder.append(f"{label}!{ref}: {value}", location, "cell")
    builder.omitted.extend(name for name in parts if any(
        marker in name.lower() for marker in ("/media/", "/charts/", "comments", "pivot")
    ))
    builder.warnings.append("Raw visible-cell values; number/date display formats and visual layout are not interpreted.")


def extract_office(data: bytes, format: str, max_expanded: int) -> ExtractionBuilder:
    parts = _parts(data, max_expanded)
    builder = ExtractionBuilder()
    (_word if format == "docx" else _excel)(parts, builder)
    return builder
