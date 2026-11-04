"""Obfuscation-decode pre-pass for the Shield.

The cheap probe and ``builtin_rules`` match attack signatures (``rm -rf /``,
``ignore previous instructions``, ``.ssh/id_rsa`` ...) against the *literal*
text. An attacker bypasses that by encoding the payload: base64, ``\\xHH`` hex,
percent-encoding, or Unicode homoglyphs (Cyrillic ``іgnore`` reads as
"ignore" but is a different codepoint NFKC does **not** fold). The signature
never fires because the malicious words are not present in the surface form.

This module canonicalises the input into a small set of *decoded variants* so
the existing detectors can be run over each. It does NOT classify anything --
it only de-obfuscates; the caller scans every variant through the real
detectors and takes the most-severe verdict. That keeps the design monotonic:
scanning extra variants can only ADD a block, never remove one, so a clean
input stays clean and the existing floor is never weakened.

Everything is bounded (variant count, per-string length, recursion depth) so a
hostile input cannot turn the pre-pass into a decode bomb, and every layer is
fail-safe -- a decode error yields no variant rather than raising.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from urllib.parse import unquote

# Bounds: a hostile input must not be able to amplify into unbounded work.
# _MAX_LEN matches builtin_rules' own scan cap (256 KB) so the pre-pass does not
# silently *stop decoding* on inputs the detectors still scan -- the prior 20k
# bail let `"a"*20001 + base64(payload)` slip an encoded attack past the decode
# step. The first decode layer is bounded by _MAX_LEN (and _HARD_CAP); deeper,
# multiplicative recursion is bounded by _MAX_VARIANTS.
# _MAX_VARIANTS bounds deeper-layer expansion. It is NOT used to cap the count of
# first-layer decodes: a count cap there would be order-dependent, letting an
# attacker prepend >cap benign base64 tokens to starve the real (trailing)
# payload out of the scanned set. _decode_base64 therefore grants every blob all
# four phase alignments unconditionally (per-blob work is constant and the input
# is bounded by _MAX_LEN), so no order-dependent budget can be starved.
_MAX_VARIANTS = 24
# Absolute ceiling on total variants (incl. a fully-decoded first layer) so a
# pathological many-blob input can't exhaust memory; the first layer is bounded
# anyway by _MAX_LEN, so this only ever trips on adversarial decode-bomb input.
_HARD_CAP = 4096
_MAX_LEN = 262_144
_MAX_DEPTH = 3  # tolerate triple-nested encodings (deeper layers bounded by _MAX_VARIANTS)

# Zero-width / bidi / tag chars (mirrors cascade; combining marks added so a
# "zalgo"-stacked payload collapses to its base letters). Written with \\uXXXX
# escapes -- never literal control chars -- so the source itself stays free of
# the bidi characters bandit's trojan-source check (B613) flags.
_TAG_RE = re.compile(r"[\U000E0000-\U000E007F]")
_INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")

# Curated homoglyph -> ASCII skeleton. NFKC already folds fullwidth and most
# math-alphanumerics, so this focuses on the Cyrillic/Greek lookalikes NFKC
# leaves alone -- the codepoints actually used to disguise ASCII attack words.
_HOMOGLYPHS = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "һ": "h", "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "ν": "v",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Χ": "X", "Ζ": "Z",
}
_HOMOGLYPH_TABLE = {ord(k): v for k, v in _HOMOGLYPHS.items()}

# Floor of 10 charset chars covers a ~7-8 byte payload (``rm -rf /`` -> an
# 11-char base64 run + ``=``) while staying long enough to skip short
# identifiers; decoded output is still printable-filtered, so a false match
# decodes to garbage that trips no rule.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{10,}={0,2}")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]{10,}={0,2}")
_HEX_ESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_HEX_RUN_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}\s*){8,}\b")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\t\n\r")
    return ok / len(s)


def _maybe_text(raw: bytes) -> str | None:
    """Decode bytes to text only if the result is mostly printable -- skip
    binary blobs (decoded keys/images) so we don't scan or log garbage."""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        s = raw.decode("latin-1", errors="replace")
    if len(s) > _MAX_LEN or _printable_ratio(s) < 0.8:
        return None
    return s.strip() or None


def _fold_homoglyphs(text: str) -> str | None:
    folded = text.translate(_HOMOGLYPH_TABLE)
    return folded if folded != text else None


def _strip_unicode(text: str) -> str | None:
    nfkc = unicodedata.normalize("NFKC", text)
    cleaned = _INVISIBLE_RE.sub("", _TAG_RE.sub("", nfkc))
    cleaned = "".join(c for c in cleaned if not unicodedata.combining(c))
    return cleaned if cleaned != text else None


def _decode_base64(text: str) -> list[str]:
    out: list[str] = []
    # Every blob gets ALL 4 phase alignments, unconditionally. Per-blob work is
    # constant (<=4 phases x 2 decoders) and the input is bounded by _MAX_LEN
    # upstream (decoded_variants refuses longer text), so the total stays linear.
    # A shared, iteration-order phase budget was starvable: a run of benign decoy
    # blobs (which fail phase 0 and each drew from the pool) exhausted it before
    # finditer reached a trailing, filler-prefixed (misaligned) payload -- which
    # needs phases 1-3 to realign and was then left with only its phase-0 garbage
    # decode, evading every downstream detector. Granting only phase 0 after the
    # budget spent protected an ALIGNED trailing payload but not a misaligned one.
    for rx in (_B64_RE, _B64URL_RE):
        for m in rx.finditer(text):
            blob = m.group(0)
            # The regex greedily grabs any leading base64-alphabet chars, so an
            # attacker can prepend 1-3 filler chars to shift every 4-byte
            # boundary and make the real payload decode to garbage at phase 0.
            # Decoding from each offset re-aligns one of them.
            for phase in range(4):
                shifted = blob[phase:]
                if len(shifted) < 4:
                    break
                pad = "=" * (-len(shifted) % 4)
                hit = False
                for fn in (base64.b64decode, base64.urlsafe_b64decode):
                    try:
                        decoded = _maybe_text(fn(shifted + pad))
                    except (binascii.Error, ValueError):
                        continue
                    if decoded and decoded != text:
                        out.append(decoded)
                        hit = True
                        break
                if hit and phase == 0:
                    # Phase 0 already yielded text -- the blob was 4-byte
                    # aligned, so the other phases would only produce shifted
                    # garbage. Skip them to keep the pre-pass linear.
                    break
    return out


def _decode_hex(text: str) -> list[str]:
    out: list[str] = []
    for m in _HEX_ESC_RE.finditer(text):
        hexes = re.findall(r"\\x([0-9a-fA-F]{2})", m.group(0))
        try:
            decoded = _maybe_text(bytes(int(h, 16) for h in hexes))
        except ValueError:
            decoded = None
        if decoded:
            out.append(decoded)
    for m in _HEX_RUN_RE.finditer(text):
        compact = re.sub(r"\s", "", m.group(0))
        if len(compact) % 2:
            continue
        try:
            decoded = _maybe_text(bytes.fromhex(compact))
        except ValueError:
            decoded = None
        if decoded:
            out.append(decoded)
    return out


def _decode_percent(text: str) -> str | None:
    if "%" not in text:
        return None
    decoded = unquote(text)
    return decoded if decoded != text and len(decoded) <= _MAX_LEN else None


def _layer(text: str) -> list[str]:
    """All single-step de-obfuscations of ``text`` (excluding ``text``)."""
    variants: list[str] = []
    for fn in (_strip_unicode, _fold_homoglyphs, _decode_percent):
        v = fn(text)
        if v:
            variants.append(v)
    variants.extend(_decode_base64(text))
    variants.extend(_decode_hex(text))
    return variants


def decoded_variants(text: str) -> list[str]:
    """De-obfuscated variants of ``text`` for the detectors to additionally scan.

    Excludes ``text`` itself and any duplicates. Recurses up to ``_MAX_DEPTH``
    (an attacker may double-encode). The FIRST decode layer is scanned in full
    (its size is already bounded by ``_MAX_LEN``) so a payload blob is never
    starved by benign decoys preceding it -- capping the first layer by *count*
    would be order-dependent, letting an attacker prepend >cap benign base64
    tokens to push the real payload past the limit. Deeper layers, where an
    attacker could otherwise multiply the work, are bounded by ``_MAX_VARIANTS``;
    an absolute ``_HARD_CAP`` ceiling guards against a pathological first layer.
    Never raises -- a decode failure simply yields fewer variants.
    """
    if not isinstance(text, str) or not text or len(text) > _MAX_LEN:
        return []
    seen = {text}
    ordered: list[str] = []
    frontier = [text]
    depth = 0
    try:
        while frontier and depth < _MAX_DEPTH and len(ordered) < _HARD_CAP:
            # The first layer (depth 0) is decoded fully so a trailing payload is
            # always scanned; from depth 1 on, stop once _MAX_VARIANTS variants
            # have accumulated to keep recursive expansion bounded.
            if depth >= 1 and len(ordered) >= _MAX_VARIANTS:
                break
            nxt: list[str] = []
            for item in frontier:
                for v in _layer(item):
                    if v in seen:
                        continue
                    seen.add(v)
                    ordered.append(v)
                    nxt.append(v)
                    if len(ordered) >= _HARD_CAP:
                        return ordered
            frontier = nxt
            depth += 1
    except Exception:  # pragma: no cover -- pre-pass must never break the scan
        return ordered
    return ordered
