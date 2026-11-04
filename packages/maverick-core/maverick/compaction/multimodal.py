"""Multi-modal compaction.

History items carrying heavy media content blocks — the vision blocks
``attachments.content_blocks_for_goal`` produces, screenshots inside
``tool_result`` content lists — dominate token spend long after the model has
looked at them. This strategy replaces each old media block with a compact
text stub so the *fact* the media existed (type, size, dimensions, what it
showed) survives while the base64 payload does not:

    [image: 1.2MB image/png 1280x800, described: login page with error toast]

The description comes through the injected ``llm`` seam (configured vision
role model) when available; otherwise the stub is deterministic — media type,
byte size, and dimensions sniffed from the PNG/GIF/JPEG header with no
imaging dependency. Text blocks are never touched, the first message and the
recent tail pass through verbatim (mirroring ``compact_messages``), and any
per-block failure keeps the original block — fail-open, never lossy by
accident.
"""
from __future__ import annotations

import base64
import logging
import struct

from ..llm import model_for_role
from . import KEEP_RECENT_TURNS
from .requests import request, run_async, run_sync

log = logging.getLogger(__name__)

# Content-block types treated as media. Anthropic vision uses "image";
# "audio" covers providers that attach voice-note blocks the same way.
MEDIA_BLOCK_TYPES = ("image", "audio")

_DESCRIBE_SYSTEM = (
    "Describe this media in one short line (under 20 words) so an agent that "
    "can no longer see it still knows what it showed. No preamble."
)
_DESCRIBE_MAX_TOKENS = 100


def _media_bytes(block: dict) -> bytes:
    """Decoded payload bytes of a base64 media block (b"" when absent)."""
    src = block.get("source")
    if not isinstance(src, dict):
        return b""
    data = src.get("data")
    if not isinstance(data, str) or not data:
        return b""
    try:
        return base64.b64decode(data, validate=False)
    except (ValueError, TypeError):
        return b""


def _dimensions(data: bytes) -> tuple[int, int] | None:
    """Sniff (width, height) from PNG/GIF/JPEG bytes; None when unknown."""
    try:
        if data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
            w, h = struct.unpack(">II", data[16:24])
            return w, h
        if data[:6] in (b"GIF87a", b"GIF89a"):
            w, h = struct.unpack("<HH", data[6:10])
            return w, h
        if data[:2] == b"\xff\xd8":  # JPEG: scan for a SOFn frame header
            i = 2
            while i + 9 < len(data):
                if data[i] != 0xFF:
                    i += 1
                    continue
                marker = data[i + 1]
                if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                    h, w = struct.unpack(">HH", data[i + 5:i + 9])
                    return w, h
                i += 2 + struct.unpack(">H", data[i + 2:i + 4])[0]
    except (struct.error, IndexError):
        return None
    return None


def _human_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f}MB"
    if n >= 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n}B"


def _describe(block: dict, llm, budget=None) -> str:
    """Synchronous entry for the shared compaction algorithm."""
    return run_sync(_describe_steps(block, llm, budget))

def _describe_steps(block: dict, llm, budget=None):
    """One-line description via the injected llm seam; "" on any failure."""
    if llm is None:
        return ""
    try:
        resp = yield request(llm,
            system=_DESCRIBE_SYSTEM,
            messages=[{
                "role": "user",
                "content": [block, {"type": "text", "text": "Describe it."}],
            }],
            max_tokens=_DESCRIBE_MAX_TOKENS,
            model=model_for_role("vision"),
            budget=budget,
        )
        return (getattr(resp, "text", "") or "").strip().replace("\n", " ")
    except Exception as e:
        log.warning("multimodal compaction describe failed (%s); using stub", e)
        return ""


def stub_for_block(block: dict, llm=None, budget=None) -> dict:
    """Synchronous entry for the shared compaction algorithm."""
    return run_sync(_stub_for_block_steps(block, llm, budget))

async def stub_for_block_async(block: dict, llm=None, budget=None) -> dict:
    """Native async entry; cancellation never falls back to sync I/O."""
    return await run_async(_stub_for_block_steps(block, llm, budget))

def _stub_for_block_steps(block: dict, llm=None, budget=None):
    """Compact text block standing in for one media block.

    Always records that media existed, its type and byte size; adds sniffed
    dimensions, and an llm description when the seam is available.
    """
    kind = block.get("type", "media")
    src = block.get("source") if isinstance(block.get("source"), dict) else {}
    media_type = str(src.get("media_type", "") or "") or kind
    data = _media_bytes(block)
    parts = [f"{kind}: {_human_size(len(data))} {media_type}"]
    dims = _dimensions(data) if kind == "image" else None
    if dims:
        parts.append(f"{dims[0]}x{dims[1]}")
    described = yield from _describe_steps(block, llm, budget=budget)
    head = " ".join(parts)
    if described:
        text = f"[{head}, described: {described}]"
    else:
        text = f"[{head} — removed during compaction; re-attach to view again]"
    return {"type": "text", "text": text}


def _compact_block_list(blocks: list, llm, budget=None) -> tuple[list, bool]:
    """Synchronous entry for the shared compaction algorithm."""
    return run_sync(_compact_block_list_steps(blocks, llm, budget))

def _compact_block_list_steps(blocks: list, llm, budget=None):
    """Replace media blocks in a content list (recursing into tool_results)."""
    out: list = []
    changed = False
    for blk in blocks:
        if not isinstance(blk, dict):
            out.append(blk)
            continue
        btype = blk.get("type")
        if btype in MEDIA_BLOCK_TYPES:
            try:
                out.append((yield from _stub_for_block_steps(blk, llm, budget=budget)))
                changed = True
            except Exception:  # fail-open: keep the original block
                out.append(blk)
        elif btype == "tool_result" and isinstance(blk.get("content"), list):
            inner, inner_changed = yield from _compact_block_list_steps(
                blk["content"], llm, budget=budget)
            if inner_changed:
                new_blk = dict(blk)
                new_blk["content"] = inner
                out.append(new_blk)
                changed = True
            else:
                out.append(blk)
        else:
            out.append(blk)
    return out, changed


def compact_media(
    messages: list[dict], *,
    keep_recent: int = KEEP_RECENT_TURNS,
    llm=None,
    budget=None,
) -> list[dict]:
    """Synchronous entry for the shared compaction algorithm."""
    return run_sync(_compact_media_steps(messages, keep_recent=keep_recent, llm=llm, budget=budget))

async def compact_media_async(
    messages: list[dict], *,
    keep_recent: int = KEEP_RECENT_TURNS,
    llm=None,
    budget=None,
) -> list[dict]:
    """Native async entry; cancellation never falls back to sync I/O."""
    return await run_async(_compact_media_steps(messages, keep_recent=keep_recent, llm=llm, budget=budget))

def _compact_media_steps(
    messages: list[dict], *,
    keep_recent: int = KEEP_RECENT_TURNS,
    llm=None,
    budget=None,
):
    """Return a copy of ``messages`` with old heavy media replaced by stubs.

    Mirrors ``compact_messages`` boundaries: the first message and the last
    ``keep_recent`` pass through verbatim (the model may still need to *see*
    recent media). Text content is never modified.
    """
    if len(messages) <= keep_recent + 1:
        return list(messages)
    out: list[dict] = []
    cutoff = len(messages) - keep_recent
    for i, msg in enumerate(messages):
        content = msg.get("content")
        if i == 0 or i >= cutoff or not isinstance(content, list):
            out.append(msg)
            continue
        new_content, changed = yield from _compact_block_list_steps(content, llm, budget=budget)
        if changed:
            new_msg = dict(msg)
            new_msg["content"] = new_content
            out.append(new_msg)
        else:
            out.append(msg)
    return out


__all__ = ["MEDIA_BLOCK_TYPES", "stub_for_block", "compact_media"]
