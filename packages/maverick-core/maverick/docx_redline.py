"""Word track-changes redlines -- real OOXML ``w:ins`` / ``w:del`` revisions,
written with the stdlib alone.

When a vendor sends their own paper, the deliverable a privacy reviewer
actually forwards is not a memo -- it is *their* document with our changes
marked up, so counsel on the other side can accept or reject each edit in
Word. That means genuine tracked revisions, not bold text pretending to be a
redline: ``<w:del>`` around the language we strike (its runs carry
``w:delText``) and ``<w:ins>`` around the language we add, each stamped with an
author and date so Word's review pane attributes them.

Two entry points, because a vendor sends either format:

* :func:`redline_docx` -- rewrite an uploaded ``.docx`` in place, preserving
  every other part of the package (styles, numbering, headers) and each edited
  paragraph's own properties, so the redline looks like their document.
* :func:`build_redlined_docx` -- synthesize a document from extracted
  paragraphs, for a PDF upload where there is no ``.docx`` to edit. The output
  says so rather than implying we modified their original file.

Edits are matched on normalized paragraph text, so run-splitting inside Word
(which shatters a sentence across arbitrary ``w:r`` elements) cannot cause a
miss. Only a unique full-paragraph match is replaced wholesale. Containment,
ambiguous duplicates and unsupported inline structures are reported for manual
review instead of expanding a clause edit into surrounding prose. An immutable
source location can disambiguate an exact paragraph in the same document.

Stdlib only (``zipfile`` + string templating): no python-docx, so this ships
everywhere the kernel ships and adds no dependency.
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from hashlib import sha256
from html import unescape
from xml.etree import ElementTree as ET

# Untrusted-input bounds. A vendor .docx is attacker-controlled: mirror the
# zip-bomb ceilings privacy_ops uses for extraction so redlining one cannot
# blow up memory either.
_MAX_DOCX_BYTES = 16 * 1024 * 1024
_MAX_ENTRIES = 1024
_MAX_TOTAL_UNCOMPRESSED = 64 * 1024 * 1024
_MAX_DOCUMENT_XML = 8 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 200

DOCX_MIME = ("application/vnd.openxmlformats-officedocument"
             ".wordprocessingml.document")

_W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_PARA_RE = re.compile(r"<w:p(?:\s[^>]*)?>.*?</w:p>|<w:p(?:\s[^>]*)?/>",
                      re.DOTALL)
_TEXT_RE = re.compile(r"<w:t(?:\s[^>]*)?>(.*?)</w:t>", re.DOTALL)
_PPR_RE = re.compile(r"<w:pPr(?:\s[^>]*)?>.*?</w:pPr>|<w:pPr(?:\s[^>]*)?/>", re.DOTALL)
_BODY_CLOSE_RE = re.compile(r"</w:body>")


class RedlineError(ValueError):
    """The upload is not a document we can redline."""


@dataclass(frozen=True)
class ParagraphLocation:
    """Zero-based paragraph index bound to the exact source package bytes.

    For a synthesized document the digest covers the generated, unedited
    document XML instead. This is a location, never permission to edit a
    substring or to ignore a mismatched full-paragraph anchor.
    """

    source_sha256: str
    paragraph_index: int


@dataclass
class ClauseEdit:
    """One tracked change.

    ``find`` is the existing paragraph text to strike (empty = a pure
    insertion, appended as a proposed new clause). ``replace`` is the language
    we require (empty = a pure deletion). ``note`` is the reviewer-facing
    reason, carried into the analysis report rather than into the document.
    Only ``scope="paragraph"`` is currently supported: both anchor and proposed
    replacement describe the entire paragraph. Partial anchors are refused.
    ``location`` can disambiguate duplicate full paragraphs but cannot broaden
    scope, bypass a stale source or permit unsupported inline rewriting.
    """

    find: str = ""
    replace: str = ""
    note: str = ""
    clause_key: str = ""
    scope: str = "paragraph"
    location: ParagraphLocation | None = None

    @property
    def is_insertion(self) -> bool:
        return not (self.find or "").strip()

    @property
    def is_deletion(self) -> bool:
        return not (self.replace or "").strip()


@dataclass
class RedlineResult:
    """The redlined package plus what actually happened -- an edit whose
    anchor text was not found is reported, never silently dropped."""

    content: bytes
    applied: list[ClauseEdit] = field(default_factory=list)
    unmatched: list[ClauseEdit] = field(default_factory=list)
    inserted: list[ClauseEdit] = field(default_factory=list)
    synthesized: bool = False
    source_sha256: str = ""
    edit_results: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "bytes": len(self.content),
            "applied": len(self.applied),
            "inserted": len(self.inserted),
            "unmatched": [e.find[:120] for e in self.unmatched],
            "synthesized": self.synthesized,
            "source_sha256": self.source_sha256,
            "edit_results": self.edit_results,
        }


def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _norm(text: str) -> str:
    """Normalized form for anchor matching: tags already stripped, whitespace
    collapsed, case folded. Word splits a sentence across arbitrary runs, so
    only normalized comparison is reliable."""
    return re.sub(r"\s+", " ", (text or "")).strip().lower()


def _para_text(para_xml: str) -> str:
    return "".join(_TEXT_RE.findall(para_xml))


def _unescape(text: str) -> str:
    return unescape(text)


class _Ids:
    """Revision ids must be unique within the document."""

    def __init__(self, start: int = 9000) -> None:
        self._n = start

    def next(self) -> int:
        self._n += 1
        return self._n


def _del_run(text: str, ids: _Ids, author: str, date: str) -> str:
    if not text:
        return ""
    return (f'<w:del w:id="{ids.next()}" w:author="{_esc(author)}" '
            f'w:date="{_esc(date)}"><w:r><w:delText xml:space="preserve">'
            f'{_esc(text)}</w:delText></w:r></w:del>')


def _ins_run(text: str, ids: _Ids, author: str, date: str) -> str:
    if not text:
        return ""
    return (f'<w:ins w:id="{ids.next()}" w:author="{_esc(author)}" '
            f'w:date="{_esc(date)}"><w:r><w:t xml:space="preserve">'
            f'{_esc(text)}</w:t></w:r></w:ins>')


def _revised_paragraph(para_xml: str, original_text: str, new_text: str,
                       ids: _Ids, author: str, date: str) -> str:
    """Rebuild one paragraph as struck-original + inserted-replacement,
    keeping its ``w:pPr`` so numbering and style survive the edit."""
    ppr = _PPR_RE.search(para_xml)
    body = (_del_run(original_text, ids, author, date)
            + _ins_run(new_text, ids, author, date))
    opening = re.match(r"<w:p(?:\s[^>]*)?>", para_xml)
    return f"{opening.group(0) if opening else '<w:p>'}{ppr.group(0) if ppr else ''}{body}</w:p>"


def _plain_paragraph(text: str) -> str:
    return (f'<w:p><w:r><w:t xml:space="preserve">{_esc(text)}</w:t>'
            f"</w:r></w:p>")


def _heading_paragraph(text: str) -> str:
    return (f'<w:p><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">'
            f"{_esc(text)}</w:t></w:r></w:p>")


def _inserted_paragraph(text: str, ids: _Ids, author: str, date: str) -> str:
    """A wholly new clause: the paragraph mark itself is marked inserted
    (``w:rPr/w:ins`` inside ``w:pPr``) so Word attributes the new paragraph,
    not just its text."""
    return (f'<w:p><w:pPr><w:rPr><w:ins w:id="{ids.next()}" '
            f'w:author="{_esc(author)}" w:date="{_esc(date)}"/></w:rPr>'
            f"</w:pPr>{_ins_run(text, ids, author, date)}</w:p>")


def _apply_edits_to_document_xml(
    xml: str, edits: list[ClauseEdit], *, author: str, date: str, source_sha256: str,
) -> tuple[str, list[ClauseEdit], list[ClauseEdit], list[ClauseEdit], list[dict]]:
    existing_ids = re.findall(r'\bw:id=[\'"](\d{1,10})[\'"]', xml)
    ids = _Ids(start=max([9000, *(int(value) for value in existing_ids)]))
    paragraphs = list(_PARA_RE.finditer(xml))
    texts = [_unescape(_para_text(match.group(0))) for match in paragraphs]
    keys = [_norm(text) for text in texts]
    positions: dict[str, list[int]] = {}
    for index, key in enumerate(keys):
        positions.setdefault(key, []).append(index)
    selected: dict[int, ClauseEdit] = {}
    applied: list[ClauseEdit] = []
    unmatched: list[ClauseEdit] = []
    insertions: list[ClauseEdit] = []
    results: list[dict] = []
    for edit_index, edit in enumerate(edits):
        index, reason = _resolve_edit(edit, keys, positions, source_sha256)
        if not reason and index is not None:
            if index in selected:
                reason = "conflicting_edit"
            elif not _plain_editable_paragraph(paragraphs[index].group(0)):
                reason = "unsupported_inline_structure"
        if reason:
            unmatched.append(edit)
        elif edit.is_insertion:
            insertions.append(edit)
        else:
            assert index is not None
            selected[index] = edit
            applied.append(edit)
        results.append({
            "edit_index": edit_index, "scope": edit.scope,
            "status": "needs_review" if reason else "inserted" if edit.is_insertion else "applied",
            "reason": reason or "", "source_sha256": source_sha256,
            "paragraph_index": index,
        })

    # Select against the original document, then replace without re-matching a
    # previous edit's output. Untouched paragraph bytes and all package parts stay intact.
    chunks: list[str] = []
    end = 0
    for index, match in enumerate(paragraphs):
        chunks.append(xml[end:match.start()])
        edit = selected.get(index)
        chunks.append(match.group(0) if edit is None else _revised_paragraph(
            match.group(0), texts[index], edit.replace, ids, author, date))
        end = match.end()
    chunks.append(xml[end:])
    out = "".join(chunks)

    if insertions:
        block = [_heading_paragraph(
            "Proposed additional clauses (Lightwork privacy review)")]
        block += [_inserted_paragraph(e.replace, ids, author, date)
                  for e in insertions if e.replace]
        # Section properties must remain the final body child. This also
        # preserves the synthesized document's existing section layout.
        body = ET.fromstring(out).find(f"{{{_W_NS}}}body")
        if body is not None and len(body) and body[-1].tag == f"{{{_W_NS}}}sectPr":
            sections = list(re.finditer(r"<w:sectPr(?=[\s>/])", out))
            offset = sections[-1].start()
            out = out[:offset] + "".join(block) + out[offset:]
        else:
            out = _BODY_CLOSE_RE.sub("".join(block) + "</w:body>", out, count=1)
    return out, applied, unmatched, insertions, results


def _resolve_edit(edit, keys, positions, source_sha256) -> tuple[int | None, str]:
    if edit.scope != "paragraph":
        return None, "unsupported_scope"
    if edit.location is not None:
        location = edit.location
        if not isinstance(location, ParagraphLocation):
            return None, "invalid_location"
        if location.source_sha256 != source_sha256:
            return None, "stale_source"
        index = location.paragraph_index
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(keys):
            return None, "invalid_location"
        if edit.is_insertion or keys[index] != _norm(edit.find):
            return index, "scope_mismatch"
        return index, ""
    if edit.is_insertion:
        return None, "" if edit.replace else "empty_edit"
    key = _norm(edit.find)
    matches = positions.get(key, [])
    if len(matches) > 1:
        return None, "ambiguous_match"
    if matches:
        return matches[0], ""
    return None, "scope_mismatch" if any(key in target for target in keys) else "not_found"


def _plain_editable_paragraph(xml: str) -> bool:
    """Reject fields, links, bookmarks, prior revisions and styled runs.

    The current full-paragraph writer cannot preserve those inline structures
    faithfully. Paragraph properties and split plain text runs are supported.
    """
    try:
        paragraph = ET.fromstring(f'<root xmlns:w="{_W_NS}">{xml}</root>')[0]
    except ET.ParseError:
        return False
    for child in paragraph:
        if child.tag == f"{{{_W_NS}}}pPr":
            continue
        if child.tag != f"{{{_W_NS}}}r":
            return False
        if any(node.tag != f"{{{_W_NS}}}t" for node in child):
            return False
    return True


def _safe_docx_entries(data: bytes) -> zipfile.ZipFile:
    if not isinstance(data, bytes) or not data:
        raise RedlineError("empty upload")
    if len(data) > _MAX_DOCX_BYTES:
        raise RedlineError("document too large to redline")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError) as e:
        raise RedlineError("not a readable .docx package") from e
    infos = zf.infolist()
    if len(infos) > _MAX_ENTRIES:
        raise RedlineError("document has too many parts")
    if sum(i.file_size for i in infos) > _MAX_TOTAL_UNCOMPRESSED:
        raise RedlineError("document expands too large")
    return zf


def redline_docx(
    original: bytes, edits: list[ClauseEdit], *,
    author: str = "Lightwork Privacy Review", date: str,
) -> RedlineResult:
    """Apply ``edits`` to an uploaded ``.docx`` as tracked revisions.

    Every other part of the package is copied through byte-for-byte, so the
    result is *their* document with our changes marked -- openable in Word with
    Accept/Reject per edit."""
    zf = _safe_docx_entries(original)
    try:
        names = zf.namelist()
        if "word/document.xml" not in names:
            raise RedlineError("package has no word/document.xml")
        info = next(i for i in zf.infolist() if i.filename == "word/document.xml")
        if info.file_size > _MAX_DOCUMENT_XML:
            raise RedlineError("document body too large to redline")
        if (info.compress_size
                and info.file_size > info.compress_size * _MAX_COMPRESSION_RATIO):
            raise RedlineError("document body compression ratio rejected")
        with zf.open(info) as fh:
            raw = fh.read(_MAX_DOCUMENT_XML + 1)
        if len(raw) > _MAX_DOCUMENT_XML:
            raise RedlineError("document body too large to redline")
        try:
            xml = raw.decode("utf-8")
            if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
                raise RedlineError("document entity declarations are unsupported")
            ET.fromstring(xml)
        except (UnicodeError, ET.ParseError) as exc:
            raise RedlineError("document body is not valid UTF-8 XML") from exc

        source_sha256 = sha256(original).hexdigest()
        revised, applied, unmatched, inserted, results = _apply_edits_to_document_xml(
            xml, edits, author=author, date=date, source_sha256=source_sha256)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
            for item in zf.infolist():
                if item.filename == "word/document.xml":
                    out.writestr(item.filename, revised)
                elif not item.is_dir():
                    # Read by ZipInfo, not by name: a package with duplicate
                    # entry names would otherwise copy the last one repeatedly.
                    out.writestr(item, zf.read(item))
    finally:
        zf.close()
    return RedlineResult(content=buf.getvalue(), applied=applied,
                         unmatched=unmatched, inserted=inserted,
                         source_sha256=source_sha256, edit_results=results)


_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
    'content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-'
    'package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.'
    'openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '<Override PartName="/word/settings.xml" ContentType="application/vnd.'
    'openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
    "</Types>"
)

_ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
    'relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
    'officeDocument/2006/relationships/officeDocument" '
    'Target="word/document.xml"/>'
    "</Relationships>"
)

# The document part's own relationships. Word writes this part even when it is
# empty, and a strict OPC consumer expects the relationship source to exist for
# the part it is opening.
_DOCUMENT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
    'relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
    'officeDocument/2006/relationships/settings" Target="settings.xml"/>'
    "</Relationships>"
)

# ``w:trackChanges`` leaves revision tracking ON, so any further edit counsel
# makes in Word is captured too -- the negotiation stays fully tracked rather
# than silently going clean after the first save.
_SETTINGS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<w:settings xmlns:w="{_W_NS}"><w:trackChanges/></w:settings>'
)

# Every Word document body ends with section properties; some consumers treat
# a body without one as malformed.
_SECT_PR = ('<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
            '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" '
            'w:left="1440"/></w:sectPr>')


def build_redlined_docx(
    paragraphs: list[str], edits: list[ClauseEdit], *,
    author: str = "Lightwork Privacy Review", date: str, title: str = "",
) -> RedlineResult:
    """Synthesize a redlined ``.docx`` from extracted ``paragraphs``.

    Used when the vendor sent a PDF: there is no ``.docx`` to edit, so we
    rebuild the text we could read and mark our changes on it. The header says
    so explicitly -- this is a reconstruction for negotiation, not a claim to
    have modified their original file."""
    body: list[str] = []
    if title:
        body.append(_heading_paragraph(title))
        body.append(_plain_paragraph(
            "Reconstructed from the supplied PDF for redlining; the vendor's "
            "original file was not modified. Tracked changes below are the "
            "edits required by our standard position."))
    for para in paragraphs:
        text = (para or "").strip()
        if text:
            body.append(_plain_paragraph(text))

    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{_W_NS}"><w:body>{"".join(body)}{_SECT_PR}'
        "</w:body></w:document>"
    )
    source_sha256 = sha256(document.encode("utf-8")).hexdigest()
    document, applied, unmatched, insertions, results = _apply_edits_to_document_xml(
        document, edits, author=author, date=date, source_sha256=source_sha256)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        out.writestr("[Content_Types].xml", _CONTENT_TYPES)
        out.writestr("_rels/.rels", _ROOT_RELS)
        out.writestr("word/_rels/document.xml.rels", _DOCUMENT_RELS)
        out.writestr("word/settings.xml", _SETTINGS)
        out.writestr("word/document.xml", document)
    return RedlineResult(content=buf.getvalue(), applied=applied,
                         unmatched=unmatched, inserted=insertions,
                         synthesized=True, source_sha256=source_sha256,
                         edit_results=results)


# --- plain document builder (generated deliverables) -----------------------

# Auto-inserted values in a generated draft are rendered in this colour so
# counsel can see at a glance exactly what the machine filled in. Red is the
# convention the receiving lawyer already knows.
FILL_COLOR = "FF0000"


def _styled_run(text: str, *, red: bool = False, bold: bool = False) -> str:
    props = ""
    if red or bold:
        props = ("<w:rPr>" + ("<w:b/>" if bold else "")
                 + (f'<w:color w:val="{FILL_COLOR}"/>' if red else "")
                 + "</w:rPr>")
    return (f"<w:r>{props}<w:t xml:space=\"preserve\">{_esc(text)}</w:t>"
            "</w:r>")


# ---- styled report package -------------------------------------------------
# Generated deliverables (risk analyses, notice cross-checks, our-paper
# drafts) ship as designed documents, not bare paragraphs: a real styles part
# (type ramp + brand palette), bullets via a numbering part, a branded header,
# and a footer with page numbers. The redline path above keeps its own minimal
# parts -- counterparty documents are edited, never re-dressed.
_INK = "1A2433"          # body ink (near-black navy)
_NAVY = "21426F"         # headings / title
_ACCENT = "4F7BD0"       # rules and accents
_MUTED = "5B6575"        # secondary ink
_HAIRLINE = "D9DEE8"
_SEVERITY_COLORS = {
    "CRITICAL": "C0392B", "HIGH": "C0392B", "MEDIUM": "9A6A12",
    "LOW": "1F9D57", "MINIMAL": "1F9D57", "INFO": "5B6575",
}

_REPORT_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
    'content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-'
    'package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.'
    'openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '<Override PartName="/word/settings.xml" ContentType="application/vnd.'
    'openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
    '<Override PartName="/word/styles.xml" ContentType="application/vnd.'
    'openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
    '<Override PartName="/word/numbering.xml" ContentType="application/vnd.'
    'openxmlformats-officedocument.wordprocessingml.numbering+xml"/>'
    '<Override PartName="/word/header1.xml" ContentType="application/vnd.'
    'openxmlformats-officedocument.wordprocessingml.header+xml"/>'
    '<Override PartName="/word/footer1.xml" ContentType="application/vnd.'
    'openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
    "</Types>"
)

_REPORT_DOCUMENT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
    'relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
    'officeDocument/2006/relationships/settings" Target="settings.xml"/>'
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/'
    'officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/'
    'officeDocument/2006/relationships/numbering" Target="numbering.xml"/>'
    '<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/'
    'officeDocument/2006/relationships/header" Target="header1.xml"/>'
    '<Relationship Id="rId5" Type="http://schemas.openxmlformats.org/'
    'officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
    "</Relationships>"
)

_REPORT_STYLES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<w:styles xmlns:w="{_W_NS}">'
    "<w:docDefaults><w:rPrDefault><w:rPr>"
    '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/>'
    f'<w:sz w:val="21"/><w:szCs w:val="21"/><w:color w:val="{_INK}"/>'
    "</w:rPr></w:rPrDefault><w:pPrDefault><w:pPr>"
    '<w:spacing w:after="120" w:line="276" w:lineRule="auto"/>'
    "</w:pPr></w:pPrDefault></w:docDefaults>"
    '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">'
    '<w:name w:val="Normal"/></w:style>'
    '<w:style w:type="paragraph" w:styleId="Title">'
    '<w:name w:val="Title"/><w:basedOn w:val="Normal"/>'
    '<w:pPr><w:spacing w:before="40" w:after="60"/></w:pPr>'
    f'<w:rPr><w:b/><w:sz w:val="48"/><w:szCs w:val="48"/>'
    f'<w:color w:val="{_NAVY}"/></w:rPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="Subtitle">'
    '<w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/>'
    '<w:pPr><w:spacing w:after="80"/></w:pPr>'
    f'<w:rPr><w:sz w:val="22"/><w:szCs w:val="22"/>'
    f'<w:color w:val="{_MUTED}"/></w:rPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="Heading1">'
    '<w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>'
    '<w:next w:val="Normal"/>'
    '<w:pPr><w:keepNext/><w:spacing w:before="320" w:after="120"/>'
    '<w:pBdr><w:bottom w:val="single" w:sz="6" w:space="3" '
    f'w:color="{_ACCENT}"/></w:pBdr><w:outlineLvl w:val="0"/></w:pPr>'
    f'<w:rPr><w:b/><w:sz w:val="24"/><w:szCs w:val="24"/>'
    f'<w:color w:val="{_NAVY}"/><w:spacing w:val="16"/></w:rPr></w:style>'
    "</w:styles>"
)

_REPORT_NUMBERING = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<w:numbering xmlns:w="{_W_NS}">'
    '<w:abstractNum w:abstractNumId="0">'
    '<w:lvl w:ilvl="0"><w:numFmt w:val="bullet"/>'
    '<w:lvlText w:val="\u2022"/><w:lvlJc w:val="left"/>'
    '<w:pPr><w:ind w:left="418" w:hanging="209"/></w:pPr>'
    f'<w:rPr><w:color w:val="{_ACCENT}"/></w:rPr></w:lvl>'
    "</w:abstractNum>"
    '<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>'
    "</w:numbering>"
)

_REPORT_HEADER = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<w:hdr xmlns:w="{_W_NS}">'
    '<w:p><w:pPr><w:jc w:val="right"/><w:spacing w:after="0"/></w:pPr>'
    f'<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="{_MUTED}"/>'
    '<w:spacing w:val="30"/><w:caps/></w:rPr>'
    '<w:t xml:space="preserve">Lightwork \u00b7 Daybreak AI Labs</w:t>'
    "</w:r></w:p></w:hdr>"
)


def _report_footer(title: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:ftr xmlns:w="{_W_NS}"><w:p><w:pPr>'
        '<w:pBdr><w:top w:val="single" w:sz="4" w:space="6" '
        f'w:color="{_HAIRLINE}"/></w:pBdr>'
        '<w:tabs><w:tab w:val="right" w:pos="9360"/></w:tabs>'
        '<w:spacing w:after="0"/>'
        f'<w:rPr><w:sz w:val="16"/><w:color w:val="{_MUTED}"/></w:rPr></w:pPr>'
        f'<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="{_MUTED}"/></w:rPr>'
        f'<w:t xml:space="preserve">{_esc(title)}</w:t></w:r>'
        f'<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="{_MUTED}"/></w:rPr>'
        "<w:tab/><w:t xml:space=\"preserve\">Page </w:t></w:r>"
        '<w:fldSimple w:instr=" PAGE "><w:r><w:rPr><w:sz w:val="16"/>'
        f'<w:color w:val="{_MUTED}"/></w:rPr><w:t>1</w:t></w:r></w:fldSimple>'
        f'<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="{_MUTED}"/></w:rPr>'
        '<w:t xml:space="preserve"> of </w:t></w:r>'
        '<w:fldSimple w:instr=" NUMPAGES "><w:r><w:rPr><w:sz w:val="16"/>'
        f'<w:color w:val="{_MUTED}"/></w:rPr><w:t>1</w:t></w:r></w:fldSimple>'
        "</w:p></w:ftr>"
    )


_REPORT_SECT_PR = (
    '<w:sectPr>'
    '<w:headerReference w:type="default" r:id="rId4" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/'
    'relationships"/>'
    '<w:footerReference w:type="default" r:id="rId5" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/'
    'relationships"/>'
    '<w:pgSz w:w="12240" w:h="15840"/>'
    '<w:pgMar w:top="1200" w:right="1320" w:bottom="1200" w:left="1320" '
    'w:header="620" w:footer="620"/></w:sectPr>'
)


def _report_run(text: str, opts: object) -> str:
    """A run from the report block vocabulary. ``opts`` is the legacy bool
    (True = auto-filled, rendered in the red fill color) or a dict with any of
    ``red`` / ``bold`` / ``italic`` / ``color`` / ``size`` / ``muted``."""
    if isinstance(opts, dict):
        red = bool(opts.get("red"))
        bold = bool(opts.get("bold"))
        italic = bool(opts.get("italic"))
        color = opts.get("color")
        size = opts.get("size")
        if opts.get("muted") and not color:
            color = _MUTED
    else:
        red, bold, italic, color, size = bool(opts), False, False, None, None
    props = []
    if bold:
        props.append("<w:b/>")
    if italic:
        props.append("<w:i/>")
    if red:
        props.append(f'<w:color w:val="{FILL_COLOR}"/>')
    elif color:
        props.append(f'<w:color w:val="{color}"/>')
    if size:
        props.append(f'<w:sz w:val="{int(size)}"/>')
    rpr = f"<w:rPr>{''.join(props)}</w:rPr>" if props else ""
    return (f"<w:r>{rpr}<w:t xml:space=\"preserve\">{_esc(text)}</w:t></w:r>")


def _kv_table(pairs: list[tuple]) -> str:
    """A borderless two-column metadata table (label / value)."""
    rows = []
    for label, value, red in pairs:
        label_run = _report_run(str(label), {"bold": True, "muted": True,
                                             "size": 20})
        value_run = _report_run(str(value), {"red": bool(red)})
        rows.append(
            "<w:tr>"
            '<w:tc><w:tcPr><w:tcW w:w="2530" w:type="dxa"/></w:tcPr>'
            f'<w:p><w:pPr><w:spacing w:after="40"/></w:pPr>{label_run}</w:p>'
            "</w:tc>"
            '<w:tc><w:tcPr><w:tcW w:w="7070" w:type="dxa"/></w:tcPr>'
            f'<w:p><w:pPr><w:spacing w:after="40"/></w:pPr>{value_run}</w:p>'
            "</w:tc></w:tr>")
    return (
        "<w:tbl><w:tblPr>"
        '<w:tblW w:w="9600" w:type="dxa"/>'
        '<w:tblBorders><w:top w:val="none"/><w:left w:val="none"/>'
        '<w:bottom w:val="none"/><w:right w:val="none"/>'
        '<w:insideH w:val="none"/><w:insideV w:val="none"/></w:tblBorders>'
        '<w:tblCellMar><w:left w:w="0" w:type="dxa"/>'
        '<w:right w:w="108" w:type="dxa"/></w:tblCellMar>'
        "</w:tblPr>"
        '<w:tblGrid><w:gridCol w:w="2530"/><w:gridCol w:w="7070"/></w:tblGrid>'
        f"{''.join(rows)}</w:tbl>"
    )


def build_docx(blocks: list[tuple], *, footer_title: str = "") -> bytes:
    """A designed (untracked) ``.docx`` from ``(style, runs)`` blocks.

    ``style`` is one of ``title`` / ``subtitle`` / ``heading`` / ``para`` /
    ``bullet`` / ``indent`` / ``rule`` / ``kv``. For text styles ``runs`` is a
    list of ``(text, opts)`` pairs where ``opts`` is the legacy red-fill bool
    or a dict (``red``/``bold``/``italic``/``color``/``size``/``muted``); for
    ``kv`` it is ``(label, value, red)`` triples rendered as a metadata
    table. Used for generated deliverables -- the our-paper draft, the
    risk-analysis and notice reports -- so everything the agent files opens as
    a designed Word document. Revision tracking stays ON (same
    ``w:trackChanges`` settings as the redline writer) so counsel's edits are
    captured."""
    body: list[str] = []
    for block in blocks:
        style, runs = block[0], (block[1] if len(block) > 1 else [])
        if style == "kv":
            body.append(_kv_table(list(runs)))
            continue
        if style == "rule":
            body.append('<w:p><w:pPr><w:pBdr><w:bottom w:val="single" '
                        f'w:sz="18" w:space="1" w:color="{_ACCENT}"/></w:pBdr>'
                        '<w:spacing w:after="240"/></w:pPr></w:p>')
            continue
        rendered = "".join(_report_run(text, opts)
                           for text, opts in runs if text)
        if not rendered:
            body.append("<w:p/>")
            continue
        ppr = ""
        if style == "title":
            ppr = '<w:pPr><w:pStyle w:val="Title"/></w:pPr>'
        elif style == "subtitle":
            ppr = '<w:pPr><w:pStyle w:val="Subtitle"/></w:pPr>'
        elif style == "heading":
            ppr = '<w:pPr><w:pStyle w:val="Heading1"/></w:pPr>'
        elif style == "bullet":
            ppr = ('<w:pPr><w:numPr><w:ilvl w:val="0"/>'
                   '<w:numId w:val="1"/></w:numPr></w:pPr>')
        elif style == "indent":
            ppr = ('<w:pPr><w:ind w:left="418"/>'
                   '<w:spacing w:after="60"/></w:pPr>')
        body.append(f"<w:p>{ppr}{rendered}</w:p>")
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{_W_NS}"><w:body>{"".join(body)}'
        f"{_REPORT_SECT_PR}</w:body></w:document>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        out.writestr("[Content_Types].xml", _REPORT_CONTENT_TYPES)
        out.writestr("_rels/.rels", _ROOT_RELS)
        out.writestr("word/_rels/document.xml.rels", _REPORT_DOCUMENT_RELS)
        out.writestr("word/settings.xml", _SETTINGS)
        out.writestr("word/styles.xml", _REPORT_STYLES)
        out.writestr("word/numbering.xml", _REPORT_NUMBERING)
        out.writestr("word/header1.xml", _REPORT_HEADER)
        out.writestr("word/footer1.xml", _report_footer(footer_title))
        out.writestr("word/document.xml", document)
    return buf.getvalue()


_RULE_LINE = re.compile(r"^[=\-]{4,}$")
_KV_LINE = re.compile(r"^(\S[^:]{0,30}?)\s+:\s(.*)$")
_FINDING_LINE = re.compile(r"^(\d+)\.\s\[([A-Z]+)\]\s*(.*)$")
_BULLET_LINE = re.compile(r"^\s*[-\u2022]\s+(.*)$")
_INDENT_LEAD = re.compile(r"^(\s{2,})(\S[^:]{0,24}):\s*(.*)$")


def text_to_docx(text: str, *, title: str = "", subtitle: str = "") -> bytes:
    """Render a plain-text report as a designed ``.docx``.

    Keeps the report writers' single source of truth (the text) and derives
    the Word document from its conventions: a line followed by a ``----``/
    ``====`` rule becomes a section heading; runs of padded ``key : value``
    lines become a metadata table; ``N. [SEVERITY] ...`` findings get the
    severity rendered in its status color with follow-on indented lines
    attached; ``- `` lines become real bullets. Blank lines disappear -- the
    style sheet carries the rhythm."""
    lines = (text or "").split("\n")
    blocks: list[tuple] = []
    if title:
        blocks.append(("title", [(title, False)]))
        if subtitle:
            blocks.append(("subtitle", [(subtitle, False)]))
        blocks.append(("rule", []))
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.strip()
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if not stripped:
            i += 1
            continue
        if _RULE_LINE.match(nxt):
            blocks.append(("heading", [(stripped, False)]))
            i += 2
            continue
        kv = _KV_LINE.match(line)
        if kv:
            pairs = []
            while i < len(lines):
                m = _KV_LINE.match(lines[i].rstrip())
                if not m:
                    break
                pairs.append((m.group(1).strip(), m.group(2).strip(), False))
                i += 1
            blocks.append(("kv", pairs))
            continue
        finding = _FINDING_LINE.match(stripped)
        if finding:
            n, sev, rest = finding.groups()
            runs = [(f"{n}. ", {"bold": True}),
                    (sev, {"bold": True,
                           "color": _SEVERITY_COLORS.get(sev, _MUTED)}),
                    (f"  {rest}", False)]
            blocks.append(("para", runs))
            i += 1
            continue
        bullet = _BULLET_LINE.match(line)
        if bullet:
            blocks.append(("bullet", [(bullet.group(1), False)]))
            i += 1
            continue
        if line[:1].isspace():
            lead = _INDENT_LEAD.match(line)
            if lead:
                blocks.append(("indent",
                               [(lead.group(2) + ":  ",
                                 {"bold": True, "muted": True}),
                                (lead.group(3), False)]))
            else:
                blocks.append(("indent", [(stripped, False)]))
            i += 1
            continue
        blocks.append(("para", [(line, False)]))
        i += 1
    return build_docx(blocks, footer_title=title)


def revision_count(docx_bytes: bytes) -> tuple[int, int]:
    """``(insertions, deletions)`` actually present in a package -- used by
    tests and by the filing step to prove the artifact really carries tracked
    changes before it is attached to a vendor record."""
    zf = _safe_docx_entries(docx_bytes)
    try:
        xml = zf.read("word/document.xml").decode("utf-8", errors="ignore")
    except KeyError:
        return (0, 0)
    finally:
        zf.close()
    return (len(re.findall(r"<w:ins\b", xml)),
            len(re.findall(r"<w:del\b", xml)))


__all__ = ["ClauseEdit", "RedlineResult", "RedlineError", "DOCX_MIME",
           "FILL_COLOR", "redline_docx", "build_redlined_docx", "build_docx",
           "text_to_docx", "revision_count"]
