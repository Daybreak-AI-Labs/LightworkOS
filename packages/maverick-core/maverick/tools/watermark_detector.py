"""Text watermark detector.

Scans text for the invisible/steganographic markers used to fingerprint
machine-generated or leaked content: zero-width characters, Unicode tag
characters, variation selectors, bidi controls, and Latin/Cyrillic-Greek
homoglyph mixing. Unlike the shield's unicode *filter* (which silently strips
these), this *reports* what it found and where — a forensic/triage aid for
"was this text watermarked or tampered with?".

ops:
  - scan(text)  — categories found, counts, first positions, and a verdict.
"""
from __future__ import annotations

import unicodedata
from typing import Any

from . import Tool

# Invisible code points that essentially never occur unintentionally -- except
# inside emoji: U+FE0F after a symbol selects emoji presentation ("❤️") and
# U+200D joins emoji into one ("👨‍👩‍👧"). Those uses are skipped below.
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


def _category(cp: int) -> str | None:
    if cp in _ZERO_WIDTH:
        return "zero-width"
    if 0xE0000 <= cp <= 0xE007F:
        return "tag-chars"  # Unicode tag block — classic steganography channel
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return "variation-selector"
    if cp in _BIDI:
        return "bidi-control"
    return None


# Cyrillic/Greek letters that look identical to Latin ones (homoglyph attacks).
_HOMOGLYPHS = set("аеорсхуАВЕКМНОРСТХ" "οατνρ")  # Cyrillic + a few Greek


def _emoji_base(ch: str) -> bool:
    """A symbol or emoji modifier (not a selector) that can start an emoji."""
    return bool(ch) and unicodedata.category(ch) in ("So", "Sk")


def _emoji_use(text: str, i: int) -> bool:
    """True when the invisible char at ``i`` is ordinary emoji syntax.

    A selector counts only directly after its base character (one per base),
    so a run of selectors after one symbol is still reported. A joiner counts
    between a base (optionally with its one selector) and the next base.
    """
    cp = ord(text[i])
    prev = text[i - 1] if i > 0 else ""
    if cp in (0xFE0E, 0xFE0F):
        return _emoji_base(prev) or (bool(prev) and prev in "0123456789#*")
    if cp == 0x200D:
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if prev in ("\ufe0e", "\ufe0f") and i > 1:
            prev = text[i - 2]
        return _emoji_base(prev) and _emoji_base(nxt)
    return False


def _scan(text: str) -> str:
    found: dict[str, list[int]] = {}
    homoglyphs: list[int] = []
    has_latin = any("a" <= c.lower() <= "z" for c in text)
    for i, ch in enumerate(text):
        cat = _category(ord(ch))
        if cat and _emoji_use(text, i):
            continue
        if cat:
            found.setdefault(cat, []).append(i)
        elif has_latin and ch in _HOMOGLYPHS:
            homoglyphs.append(i)
    if homoglyphs:
        found["homoglyph"] = homoglyphs

    if not found:
        return "CLEAN: no watermark/steganography markers found"

    # Invisible markers are near-certainly intentional; homoglyphs alone are
    # suspicious but can be benign (genuinely non-Latin text).
    invisible = any(c != "homoglyph" for c in found)
    verdict = "LIKELY WATERMARKED" if invisible else "SUSPICIOUS"
    lines = [f"{verdict}: {sum(len(v) for v in found.values())} marker(s)"]
    for cat in sorted(found):
        pos = found[cat]
        head = ", ".join(str(p) for p in pos[:5]) + (" ..." if len(pos) > 5 else "")
        lines.append(f"  {cat}: {len(pos)} at [{head}]")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "scan"):
        return f"ERROR: unknown op {args.get('op')!r}"
    text = args.get("text")
    if not isinstance(text, str) or text == "":
        return "ERROR: text (non-empty string) is required"
    return _scan(text)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["scan"]},
        "text": {"type": "string", "description": "text to scan for hidden watermark markers"},
    },
    "required": ["text"],
}


def watermark_detector() -> Tool:
    return Tool(
        name="watermark_detector",
        description=(
            "Detect hidden text watermarks / steganography: zero-width chars, "
            "Unicode tag characters, variation selectors, bidi controls, and "
            "Cyrillic/Greek homoglyphs in Latin text. op=scan with 'text'. "
            "Reports categories, counts, and positions with a verdict "
            "(LIKELY WATERMARKED / SUSPICIOUS / CLEAN) — it reports, doesn't strip."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
