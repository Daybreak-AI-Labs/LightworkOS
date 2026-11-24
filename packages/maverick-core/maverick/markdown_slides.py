"""Markdown to a PowerPoint deck (.pptx), with no external program.

Asked for a PowerPoint presentation, agents had no way to make one where
pandoc is not installed (a container sandbox): their only route was a
python-pptx script waiting on a person's approval. ``write_file`` to a .pptx
path and the ``pandoc`` tool without pandoc use this writer.

Each ``#`` heading starts a slide (``##`` when the text has no ``#``
headings); the heading is the slide title and the lines under it are its
body: ``-``, ``*`` and ``1.`` items become bullets (indented ones one level
down), other lines plain paragraphs, and ``**bold**`` stays bold. Text before
the first heading becomes a title slide. The package is a minimal
PresentationML document: one master, one layout, one theme, 16:9 slides.
"""
from __future__ import annotations

import io
import re
import zipfile
from xml.sax.saxutils import escape

_P = "http://schemas.openxmlformats.org/presentationml/2006/main"
_A = "http://schemas.openxmlformats.org/drawingml/2006/main"
_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_RELS = "http://schemas.openxmlformats.org/package/2006/relationships"
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_NS = f'xmlns:a="{_A}" xmlns:r="{_R}" xmlns:p="{_P}"'
_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'

MAX_SLIDES = 200
_WIDTH, _HEIGHT = 12192000, 6858000  # 16:9, in EMU
_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_ITEM = re.compile(r"^(\s*)(?:[-*+]|\d{1,3}[.)])\s+(.*)$")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
# A backslash before ASCII punctuation is a Markdown escape ("\\$8,400"):
# the reader sees the character alone.
_ESCAPED = re.compile(r"\\([!-/:-@\[-`{-~])")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


class UnwritableSlides(ValueError):
    """The text cannot become a deck (no content, or too many slides)."""


def _clean(text: str) -> str:
    return _CONTROL.sub("", text).strip()


def _slides(markdown: str) -> list[tuple[str, list[tuple[int, bool, str]]]]:
    """``[(title, [(level, bullet, text), ...]), ...]``."""
    lines = markdown.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    levels = [len(m.group(1)) for line in lines if (m := _HEADING.match(line))]
    top = min(levels) if levels else 0
    slides: list[tuple[str, list[tuple[int, bool, str]]]] = []
    title, body = "", []
    in_fence = False
    for line in lines:
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        heading = None if in_fence else _HEADING.match(line)
        if heading and len(heading.group(1)) == top:
            if title or body:
                slides.append((title, body))
            title, body = _clean(heading.group(2)), []
            continue
        if heading:  # a lower heading inside a slide: a bold line
            body.append((0, False, f"**{_clean(heading.group(2))}**"))
            continue
        if not line.strip() or re.fullmatch(r"\s*([-*_])(\s*\1){2,}\s*", line):
            continue
        item = None if in_fence else _ITEM.match(line)
        if item:
            depth = min(len(item.group(1).replace("\t", "    ")) // 2, 4)
            body.append((depth, True, _clean(item.group(2))))
        else:
            body.append((0, False, _clean(line)))
    if title or body:
        slides.append((title, body))
    if not slides:
        raise UnwritableSlides("there is no text to put on slides")
    if len(slides) > MAX_SLIDES:
        raise UnwritableSlides(f"a deck holds at most {MAX_SLIDES} slides")
    return slides


def _runs(text: str, size: int | None = None) -> str:
    parts = _BOLD.split(text)
    out = []
    for index, part in enumerate(parts):
        if not part:
            continue
        attrs = ' lang="en-US"' + (f' sz="{size}"' if size else "") + (' b="1"' if index % 2 else "")
        shown = escape(_ESCAPED.sub(r"\1", part))
        out.append(f'<a:r><a:rPr{attrs} dirty="0"/><a:t>{shown}</a:t></a:r>')
    return "".join(out) or '<a:endParaRPr lang="en-US" dirty="0"/>'


def _shape(shape_id: int, name: str, placeholder: str, xfrm: tuple[int, int, int, int], body: str) -> str:
    x, y, cx, cy = xfrm
    return (f'<p:sp><p:nvSpPr><p:cNvPr id="{shape_id}" name="{name}"/><p:cNvSpPr><a:spLocks noGrp="1"/>'
            f'</p:cNvSpPr><p:nvPr>{placeholder}</p:nvPr></p:nvSpPr><p:spPr><a:xfrm><a:off x="{x}" y="{y}"/>'
            f'<a:ext cx="{cx}" cy="{cy}"/></a:xfrm></p:spPr>{body}</p:sp>')


_TITLE_BOX = (838200, 365125, 10515600, 1325563)
_BODY_BOX = (838200, 1825625, 10515600, 4351338)
_COVER_TITLE = (1524000, 1122363, 9144000, 2387600)
_COVER_BODY = (1524000, 3602038, 9144000, 1655762)


def _slide_xml(title: str, body: list[tuple[int, bool, str]], cover: bool) -> str:
    paragraphs = []
    for level, bullet, text in body:
        if bullet:
            margin = 342900 + level * 457200
            ppr = (f'<a:pPr marL="{margin}" lvl="{level}" indent="-342900"><a:buFont typeface="Arial"/>'
                   '<a:buChar char="&#8226;"/></a:pPr>')
        else:
            ppr = '<a:pPr marL="0" indent="0"><a:buNone/></a:pPr>'
        paragraphs.append(f"<a:p>{ppr}{_runs(text)}</a:p>")
    title_body = (f'<p:txBody><a:bodyPr><a:normAutofit/></a:bodyPr><a:lstStyle/>'
                  f'<a:p>{_runs(title or " ")}</a:p></p:txBody>')
    empty = '<a:p><a:endParaRPr lang="en-US" dirty="0"/></a:p>'
    text_body = ('<p:txBody><a:bodyPr><a:normAutofit/></a:bodyPr><a:lstStyle/>'
                 f'{"".join(paragraphs) or empty}</p:txBody>')
    shapes = _shape(2, "Title 1", '<p:ph type="title"/>', _COVER_TITLE if cover else _TITLE_BOX, title_body)
    if body:
        shapes += _shape(3, "Content 2", '<p:ph idx="1"/>', _COVER_BODY if cover else _BODY_BOX, text_body)
    return (f'{_DECL}<p:sld {_NS}><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/>'
            '<p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
            f'<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>{shapes}</p:spTree></p:cSld>'
            '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>')


_EMPTY_TREE = ('<p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
               '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/>'
               '<a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>')


def _placeholders() -> str:
    title = _shape(2, "Title Placeholder 1", '<p:ph type="title"/>', _TITLE_BOX,
                   '<p:txBody><a:bodyPr anchor="ctr"/><a:lstStyle/><a:p><a:r><a:rPr lang="en-US"/>'
                   '<a:t>Title</a:t></a:r></a:p></p:txBody>')
    body = _shape(3, "Text Placeholder 2", '<p:ph type="body" idx="1"/>', _BODY_BOX,
                  '<p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:pPr lvl="0"/><a:r><a:rPr lang="en-US"/>'
                  '<a:t>Text</a:t></a:r></a:p></p:txBody>')
    return title + body


def _level(n: int, size: int, bullet: bool) -> str:
    margin = 228600 + n * 457200
    bu = '<a:buFont typeface="Arial"/><a:buChar char="&#8226;"/>' if bullet else "<a:buNone/>"
    return (f'<a:lvl{n + 1}pPr marL="{margin if bullet else 0}" indent="{-228600 if bullet else 0}" algn="l">'
            f'<a:spcBef><a:spcPts val="1000"/></a:spcBef>{bu}<a:defRPr sz="{size}" kern="1200">'
            '<a:solidFill><a:schemeClr val="tx1"/></a:solidFill><a:latin typeface="+mn-lt"/></a:defRPr>'
            f'</a:lvl{n + 1}pPr>')


_MASTER = (f'{_DECL}<p:sldMaster {_NS}><p:cSld><p:bg><p:bgRef idx="1001"><a:schemeClr val="bg1"/></p:bgRef></p:bg>'
           f'{_EMPTY_TREE}{{placeholders}}</p:spTree></p:cSld>'
           '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" '
           'accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" '
           'folHlink="folHlink"/><p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>'
           '<p:txStyles><p:titleStyle><a:lvl1pPr algn="l"><a:defRPr sz="4000" b="1" kern="1200">'
           '<a:solidFill><a:schemeClr val="tx1"/></a:solidFill><a:latin typeface="+mj-lt"/></a:defRPr>'
           '</a:lvl1pPr></p:titleStyle><p:bodyStyle>{body_levels}</p:bodyStyle><p:otherStyle><a:lvl1pPr>'
           '<a:defRPr lang="en-US"/></a:lvl1pPr></p:otherStyle></p:txStyles></p:sldMaster>')

_LAYOUT = (f'{_DECL}<p:sldLayout {_NS} type="obj" preserve="1"><p:cSld name="Title and Content">'
           f'{_EMPTY_TREE}{{placeholders}}</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>'
           '</p:sldLayout>')


def _fill(color: str) -> str:
    return f'<a:solidFill><a:schemeClr val="{color}"/></a:solidFill>'


_THEME = (f'{_DECL}<a:theme xmlns:a="{_A}" name="Lightwork"><a:themeElements>'
          '<a:clrScheme name="Lightwork"><a:dk1><a:srgbClr val="1F2328"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/>'
          '</a:lt1><a:dk2><a:srgbClr val="1B365D"/></a:dk2><a:lt2><a:srgbClr val="EEF1F5"/></a:lt2>'
          '<a:accent1><a:srgbClr val="2F6FDE"/></a:accent1><a:accent2><a:srgbClr val="E07A1F"/></a:accent2>'
          '<a:accent3><a:srgbClr val="2E9E6A"/></a:accent3><a:accent4><a:srgbClr val="8456C9"/></a:accent4>'
          '<a:accent5><a:srgbClr val="D1495B"/></a:accent5><a:accent6><a:srgbClr val="2A9DB0"/></a:accent6>'
          '<a:hlink><a:srgbClr val="2F6FDE"/></a:hlink><a:folHlink><a:srgbClr val="8456C9"/></a:folHlink>'
          '</a:clrScheme><a:fontScheme name="Lightwork"><a:majorFont><a:latin typeface="Calibri"/>'
          '<a:ea typeface=""/><a:cs typeface=""/></a:majorFont><a:minorFont><a:latin typeface="Calibri"/>'
          '<a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme><a:fmtScheme name="Lightwork">'
          f'<a:fillStyleLst>{_fill("phClr") * 3}</a:fillStyleLst><a:lnStyleLst>'
          + '<a:ln w="9525">' + _fill("phClr") + '</a:ln>'
          + '<a:ln w="19050">' + _fill("phClr") + '</a:ln>'
          + '<a:ln w="28575">' + _fill("phClr") + '</a:ln>'
          + '</a:lnStyleLst><a:effectStyleLst>' + '<a:effectStyle><a:effectLst/></a:effectStyle>' * 3
          + f'</a:effectStyleLst><a:bgFillStyleLst>{_fill("phClr") * 3}</a:bgFillStyleLst></a:fmtScheme>'
          '</a:themeElements><a:objectDefaults/><a:extraClrSchemeLst/></a:theme>')


def _rels(*items: tuple[str, str, str]) -> str:
    body = "".join(f'<Relationship Id="{rid}" Type="{kind}" Target="{escape(target)}"/>'
                   for rid, kind, target in items)
    return f'{_DECL}<Relationships xmlns="{_RELS}">{body}</Relationships>'


def _content_types(count: int) -> str:
    base = "application/vnd.openxmlformats-officedocument.presentationml"
    overrides = [("/ppt/presentation.xml", f"{base}.presentation.main+xml"),
                 ("/ppt/slideMasters/slideMaster1.xml", f"{base}.slideMaster+xml"),
                 ("/ppt/slideLayouts/slideLayout1.xml", f"{base}.slideLayout+xml"),
                 ("/ppt/theme/theme1.xml", "application/vnd.openxmlformats-officedocument.theme+xml"),
                 ("/ppt/presProps.xml", f"{base}.presProps+xml"),
                 ("/ppt/viewProps.xml", f"{base}.viewProps+xml"),
                 ("/ppt/tableStyles.xml", f"{base}.tableStyles+xml"),
                 ("/docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml"),
                 ("/docProps/app.xml", "application/vnd.openxmlformats-officedocument.extended-properties+xml")]
    overrides += [(f"/ppt/slides/slide{n}.xml", f"{base}.slide+xml") for n in range(1, count + 1)]
    body = "".join(f'<Override PartName="{name}" ContentType="{kind}"/>' for name, kind in overrides)
    return (f'{_DECL}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            f'<Default Extension="xml" ContentType="application/xml"/>{body}</Types>')


def slides_from_markdown(markdown: str, title: str = "") -> bytes:
    """A .pptx package for ``markdown``. Raises :class:`UnwritableSlides`."""
    slides = _slides(markdown)
    count = len(slides)
    deck_title = title or next((t for t, _ in slides if t), "Presentation")
    slide_ids = "".join(f'<p:sldId id="{255 + n}" r:id="rId{n + 1}"/>' for n in range(1, count + 1))
    presentation = (f'{_DECL}<p:presentation {_NS} saveSubsetFonts="1"><p:sldMasterIdLst>'
                    '<p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
                    f'<p:sldIdLst>{slide_ids}</p:sldIdLst><p:sldSz cx="{_WIDTH}" cy="{_HEIGHT}"/>'
                    '<p:notesSz cx="6858000" cy="9144000"/><p:defaultTextStyle><a:lvl1pPr>'
                    '<a:defRPr lang="en-US"/></a:lvl1pPr></p:defaultTextStyle></p:presentation>')
    rel = f"{_REL}/"
    presentation_rels = _rels(("rId1", rel + "slideMaster", "slideMasters/slideMaster1.xml"),
                              *[(f"rId{n + 1}", rel + "slide", f"slides/slide{n}.xml") for n in range(1, count + 1)],
                              (f"rId{count + 2}", rel + "presProps", "presProps.xml"),
                              (f"rId{count + 3}", rel + "viewProps", "viewProps.xml"),
                              (f"rId{count + 4}", rel + "theme", "theme/theme1.xml"),
                              (f"rId{count + 5}", rel + "tableStyles", "tableStyles.xml"))
    core = (f'{_DECL}<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/'
            'core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>'
            f'{escape(_clean(deck_title))}</dc:title><dc:creator>Lightwork</dc:creator></cp:coreProperties>')
    app = (f'{_DECL}<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
           f'<Application>Lightwork</Application><Slides>{count}</Slides></Properties>')
    body_levels = "".join(_level(n, size, True) for n, size in enumerate((2800, 2400, 2000, 1800, 1800)))
    parts = {
        "[Content_Types].xml": _content_types(count),
        "_rels/.rels": _rels(("rId1", rel + "officeDocument", "ppt/presentation.xml"),
                             ("rId2", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/"
                                      "core-properties", "docProps/core.xml"),
                             ("rId3", rel + "extended-properties", "docProps/app.xml")),
        "docProps/core.xml": core,
        "docProps/app.xml": app,
        "ppt/presentation.xml": presentation,
        "ppt/_rels/presentation.xml.rels": presentation_rels,
        "ppt/slideMasters/slideMaster1.xml": _MASTER.format(placeholders=_placeholders(),
                                                           body_levels=body_levels),
        "ppt/slideMasters/_rels/slideMaster1.xml.rels": _rels(
            ("rId1", rel + "slideLayout", "../slideLayouts/slideLayout1.xml"),
            ("rId2", rel + "theme", "../theme/theme1.xml")),
        "ppt/slideLayouts/slideLayout1.xml": _LAYOUT.format(placeholders=_placeholders()),
        "ppt/slideLayouts/_rels/slideLayout1.xml.rels": _rels(
            ("rId1", rel + "slideMaster", "../slideMasters/slideMaster1.xml")),
        "ppt/theme/theme1.xml": _THEME,
        "ppt/presProps.xml": f"{_DECL}<p:presentationPr {_NS}/>",
        "ppt/viewProps.xml": f'{_DECL}<p:viewPr {_NS}><p:gridSpacing cx="76200" cy="76200"/></p:viewPr>',
        "ppt/tableStyles.xml": (f'{_DECL}<a:tblStyleLst xmlns:a="{_A}" '
                                'def="{5C22544A-7EE6-4342-B048-85BDC9FD1C3A}"/>'),
    }
    if not slides[0][0] and slides[0][1]:
        # Text before the first heading is a cover: its first line the title.
        first = slides[0][1]
        slides[0] = (first[0][2].replace("**", ""), first[1:])
    for n, (slide_title, body) in enumerate(slides, 1):
        cover = n == 1 and count > 1 and not markdown.lstrip().startswith("#")
        parts[f"ppt/slides/slide{n}.xml"] = _slide_xml(slide_title or (deck_title if n == 1 else ""), body,
                                                      cover or (n == 1 and not body))
        parts[f"ppt/slides/_rels/slide{n}.xml.rels"] = _rels(
            ("rId1", rel + "slideLayout", "../slideLayouts/slideLayout1.xml"))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as package:
        for name in ("[Content_Types].xml", *[key for key in parts if key != "[Content_Types].xml"]):
            package.writestr(name, parts[name])
    return output.getvalue()


__all__ = ["MAX_SLIDES", "UnwritableSlides", "slides_from_markdown"]
