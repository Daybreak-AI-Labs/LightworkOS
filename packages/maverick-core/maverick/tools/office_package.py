"""Bounded OOXML edits that preserve untouched workbook/VBA parts byte for byte."""
from __future__ import annotations

import copy
import io
import math
import posixpath
import re
import zipfile
from pathlib import Path

_S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
MAX_BYTES = 64 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024


def _xml(raw: bytes):
    try:
        from lxml import etree
    except ImportError as exc:
        raise RuntimeError("Workbook preservation needs the maverick-core[spreadsheet] extra") from exc
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True,
                             huge_tree=False, remove_blank_text=False)
    node = etree.fromstring(raw, parser)
    if node.getroottree().docinfo.doctype or any(isinstance(n, etree._Entity) for n in node.iter()):
        raise ValueError("Workbook XML declarations/entities are unsupported")
    return node


def _serialized(node) -> bytes:
    from lxml import etree
    return etree.tostring(node, encoding="UTF-8", xml_declaration=True)


class WorkbookPackage:
    def __init__(self, source: Path | bytes):
        if isinstance(source, Path):
            with source.open("rb") as stream:
                source = stream.read(MAX_BYTES + 1)
        if len(source) > MAX_BYTES:
            raise ValueError("Workbook exceeds the 64 MiB input limit")
        self.parts: dict[str, bytes] = {}
        self.infos: list[zipfile.ZipInfo] = []
        with zipfile.ZipFile(io.BytesIO(source)) as archive:
            infos = archive.infolist()
            if len(infos) > 4000 or sum(info.file_size for info in infos) > MAX_EXPANDED:
                raise ValueError("Workbook expanded size or part count exceeds limits")
            aliases: set[str] = set()
            for info in infos:
                name = info.filename
                if (name.casefold() in aliases or name.startswith("/") or "\\" in name or ":" in name
                        or any(p in {"", ".", ".."} for p in name.rstrip("/").split("/"))
                        or info.flag_bits & 1 or info.file_size > MAX_BYTES):
                    raise ValueError("Workbook contains ambiguous, encrypted or oversized parts")
                aliases.add(name.casefold())
                self.parts[name] = archive.read(info)
                self.infos.append(info)
            self.comment = archive.comment
        if any(name.casefold().startswith("_xmlsignatures/") for name in self.parts):
            raise ValueError("Digitally signed workbooks require an unsigned reviewed copy before editing")
        self.book = _xml(self.parts["xl/workbook.xml"])
        relations = _xml(self.parts["xl/_rels/workbook.xml.rels"])
        targets = {rel.get("Id"): rel.get("Target", "") for rel in relations
                   if rel.get("TargetMode", "").lower() != "external"}
        self.sheets: dict[str, str] = {}
        for sheet in self.book.findall(f"{_S}sheets/{_S}sheet"):
            target = targets.get(sheet.get(_R + "id"), "")
            path_name = posixpath.normpath(target.lstrip("/") if target.startswith("/") else "xl/" + target)
            if not path_name.startswith("xl/worksheets/") or path_name not in self.parts:
                raise ValueError("Workbook worksheet relationship is invalid")
            self.sheets[sheet.get("name")] = path_name

    def write(self, destination: Path) -> None:
        with zipfile.ZipFile(destination, "w") as archive:
            archive.comment = self.comment
            for info in self.infos:
                archive.writestr(info, self.parts[info.filename])

    def formulas(self) -> dict[str, list[str]]:
        found = {}
        for name, path in self.sheets.items():
            sheet = _xml(self.parts[path])
            found[name] = [cell.get("r") for cell in sheet.iter(_S + "c") if cell.find(_S + "f") is not None]
        if sum(map(len, found.values())) > 100_000:
            raise ValueError("Workbook exceeds the 100,000 formula recalculation limit")
        return found

    def invalidate_caches(self) -> None:
        for path in self.sheets.values():
            sheet = _xml(self.parts[path])
            changed = False
            for cell in sheet.iter(_S + "c"):
                if cell.find(_S + "f") is not None:
                    for value in list(cell):
                        if value.tag in {_S + "v", _S + "is"}:
                            cell.remove(value)
                            changed = True
            if changed:
                self.parts[path] = _serialized(sheet)
        calc = self.book.find(_S + "calcPr")
        if calc is None:
            from lxml import etree
            calc = etree.SubElement(self.book, _S + "calcPr")
        calc.set("fullCalcOnLoad", "1")
        calc.set("forceFullCalc", "1")
        self.parts["xl/workbook.xml"] = _serialized(self.book)

    def set_cell(self, cell_name: str, value, sheet_name: str | None) -> None:
        from lxml import etree
        from openpyxl.utils.cell import coordinate_to_tuple

        cell_name = cell_name.upper()
        if not re.fullmatch(r"[A-Z]{1,3}[1-9][0-9]{0,6}", cell_name):
            raise ValueError("Cell must be a single A1 coordinate")
        row_number, column = coordinate_to_tuple(cell_name)
        if row_number > 1048576 or column > 16384:
            raise ValueError("Cell is outside the Excel worksheet limits")
        if sheet_name is None:
            views = self.book.find(f"{_S}bookViews/{_S}workbookView")
            index = int(views.get("activeTab", "0")) if views is not None else 0
            sheet_name = list(self.sheets)[index]
        if sheet_name not in self.sheets:
            raise ValueError("Macro-preserving edits require an existing worksheet")
        path = self.sheets[sheet_name]
        sheet = _xml(self.parts[path])
        _check_edit_range(sheet, row_number, column)
        data = sheet.find(_S + "sheetData")
        if data is None:
            raise ValueError("Workbook worksheet data is missing")
        row = data.find(f'{_S}row[@r="{row_number}"]')
        if row is None:
            row = etree.Element(_S + "row", r=str(row_number))
            _insert_sorted(data, row, row_number, lambda n: int(n.get("r")))
        cell = row.find(f'{_S}c[@r="{cell_name}"]')
        if cell is None:
            cell = etree.Element(_S + "c", r=cell_name)
            _insert_sorted(row, cell, column, lambda n: coordinate_to_tuple(n.get("r"))[1])
        formula = cell.find(_S + "f")
        if formula is not None and formula.get("t", "normal") != "normal":
            raise ValueError("Editing shared, array or table formulas requires a native spreadsheet editor")
        for child in list(cell):
            if child.tag in {_S + "v", _S + "is", _S + "f"}:
                cell.remove(child)
        cell.attrib.pop("t", None)
        _set_value(cell, value)
        dimension = sheet.find(_S + "dimension")
        if dimension is not None:
            # Excel/openpyxl will derive bounds; a stale bound would hide the new cell.
            sheet.remove(dimension)
        self.parts[path] = _serialized(sheet)
        self.invalidate_caches()

    def check_recalculable(self) -> None:
        dangerous = ("externallinks/", "connections.xml", "querytables/", "embeddings/", "macrosheets/")
        for name, raw in self.parts.items():
            if any(part in name.casefold() for part in dangerous):
                raise ValueError("Recalculation requires a workbook without external data, embedded objects or XLM macros")
            if name.endswith(".rels") and any(n.get("TargetMode", "").lower() == "external" for n in _xml(raw)):
                raise ValueError("Recalculation does not refresh external workbook or network links")
        for path in self.sheets.values():
            for formula in _xml(self.parts[path]).iter(_S + "f"):
                text = formula.text or ""
                if (formula.get("t") in {"array", "dataTable"} or "|" in text
                        or re.search(r"(?:WEBSERVICE|DDE|RTD|CALL|REGISTER\.ID|SQL\.REQUEST|IMAGE)\s*\(", text, re.IGNORECASE)):
                    raise ValueError("Workbook needs a native editor for array/table or external-service formulas")

    def import_caches(self, calculated: WorkbookPackage) -> int:
        count = 0
        for name, path in self.sheets.items():
            source = _xml(calculated.parts[calculated.sheets[name]])
            values = {cell.get("r"): cell for cell in source.iter(_S + "c")}
            sheet = _xml(self.parts[path])
            for cell in sheet.iter(_S + "c"):
                if cell.find(_S + "f") is None:
                    continue
                computed = values.get(cell.get("r"))
                if computed is None or computed.find(_S + "v") is None or computed.get("t") == "e":
                    raise ValueError(f"Calculation did not produce a usable value for {name}!{cell.get('r')}")
                for old in list(cell):
                    if old.tag in {_S + "v", _S + "is"}:
                        cell.remove(old)
                cell.attrib.pop("t", None)
                kind = computed.get("t")
                value = copy.deepcopy(computed.find(_S + "v"))
                if kind == "s":
                    strings = _xml(calculated.parts["xl/sharedStrings.xml"])
                    value.text = "".join(strings[int(value.text)].itertext())
                    kind = "str"
                if kind:
                    cell.set("t", kind)
                cell.append(value)
                count += 1
            self.parts[path] = _serialized(sheet)
        return count


def _insert_sorted(parent, node, position, key):
    for index, other in enumerate(parent):
        if key(other) > position:
            parent.insert(index, node)
            return
    parent.append(node)


def _check_edit_range(sheet, row, column):
    from openpyxl.utils.cell import range_boundaries
    for node in sheet.iter():
        if node.tag not in {_S + "f", _S + "mergeCell"} or not node.get("ref"):
            continue
        left, top, right, bottom = range_boundaries(node.get("ref"))
        if left <= column <= right and top <= row <= bottom:
            if node.tag == _S + "f" or (column, row) != (left, top):
                raise ValueError("This cell belongs to a shared/array formula or non-anchor merged range; use a native editor")


def _set_value(cell, value):
    from lxml import etree
    if value is None:
        return
    if isinstance(value, bool):
        cell.set("t", "b")
        etree.SubElement(cell, _S + "v").text = "1" if value else "0"
    elif isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError("Spreadsheet numbers must be finite")
        etree.SubElement(cell, _S + "v").text = str(value)
    elif isinstance(value, str) and len(value) <= 32767:
        cell.set("t", "inlineStr")
        text = etree.SubElement(etree.SubElement(cell, _S + "is"), _S + "t")
        text.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        text.text = value
    else:
        raise ValueError("Cell value must be text (at most 32767 characters), a finite number, boolean or null")
