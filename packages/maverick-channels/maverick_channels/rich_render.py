"""KaTeX / Mermaid rich-render layer.

Chat channels are plain-text: a reply carrying display math (``$$...$$`` /
``\\(...\\)``) or a ```` ```mermaid ```` diagram arrives as unreadable source.
This layer renders those blocks into a **standalone HTML artifact** (KaTeX +
Mermaid loaded in the page; raw source kept in a ``<pre>`` fallback so the
file degrades gracefully offline) and rewrites the outgoing text to point at
it, so any adapter — including ones with no rich-message API — can deliver a
readable result.

``RichRenderChannel`` wraps any :class:`maverick_channels.base.Channel`:
on ``send`` it detects rich blocks, writes the artifact under
``data_dir("rich_render/")`` (0600), and either hands the file to an injected
``deliver(user_id, path)`` (adapters that can ship files). Without a file
transport it explains that limitation; a server-local path is never a link.
Native server replies are instead prepared inside durable delivery custody.

Opt-in via ``[channels] rich_render = true`` (env
``MAVERICK_CHANNELS_RICH_RENDER``); off by default — no adapter behavior
changes unless configured. Rendering is **client-side in the artifact**
(script tags), so this module is fully offline and deterministic.
"""
from __future__ import annotations

import hashlib
import html as _html
import logging
import os
import re
from collections.abc import Awaitable, Callable
from pathlib import Path

log = logging.getLogger(__name__)

# Display math ($$...$$), inline \( ... \), and ```mermaid fences.
_MERMAID = re.compile(r"```mermaid\s+(.+?)```", re.DOTALL)

_KATEX_CSS = "https://cdn.jsdelivr.net/npm/katex@0.16/dist/katex.min.css"
_KATEX_JS = "https://cdn.jsdelivr.net/npm/katex@0.16/dist/katex.min.js"
_KATEX_AUTO = "https://cdn.jsdelivr.net/npm/katex@0.16/dist/contrib/auto-render.min.js"
_MERMAID_JS = "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"


def enabled() -> bool:
    """``MAVERICK_CHANNELS_RICH_RENDER`` decides when it is set (so a
    deployment can force it either way); otherwise ``[channels] rich_render``
    (the All settings page)."""
    env = os.environ.get("MAVERICK_CHANNELS_RICH_RENDER", "").strip().lower()
    if env:
        return env in {"1", "true", "yes", "on"}
    try:
        from maverick.config import load_config
        return bool(((load_config() or {}).get("channels") or {}).get("rich_render"))
    except Exception:  # pragma: no cover -- config never blocks a send
        return False


def _count_paired_delimiter(text: str, delimiter: str) -> int:
    """Count non-overlapping pairs of a symmetric delimiter in one pass."""
    count = 0
    open_seen = False
    index = 0
    step = len(delimiter)
    while True:
        index = text.find(delimiter, index)
        if index == -1:
            return count
        if open_seen:
            count += 1
        open_seen = not open_seen
        index += step


def _count_inline_math(text: str) -> int:
    r"""Count ``\(...\)`` spans without regex backtracking on unmatched opens."""
    count = 0
    open_seen = False
    index = 0
    while index < len(text) - 1:
        pair = text[index:index + 2]
        if not open_seen and pair == r"\(":
            open_seen = True
            index += 2
            continue
        if open_seen and pair == r"\)":
            count += 1
            open_seen = False
            index += 2
            continue
        index += 1
    return count


def detect_rich_blocks(text: str) -> dict[str, int]:
    """Count renderable blocks: ``{"math": n, "mermaid": m}`` (zeros = none)."""
    if not text:
        return {"math": 0, "mermaid": 0}
    math = _count_paired_delimiter(text, "$$") + _count_inline_math(text)
    return {"math": math, "mermaid": len(_MERMAID.findall(text))}


def has_rich_blocks(text: str) -> bool:
    counts = detect_rich_blocks(text)
    return bool(counts["math"] or counts["mermaid"])


def render_html(text: str, *, title: str = "Lightwork reply") -> str:
    """Render a message into a standalone HTML doc.

    Math is left inline for KaTeX auto-render; mermaid fences become
    ``<pre class="mermaid">`` (the source itself is the graceful no-JS
    fallback). The body is HTML-escaped first so message content can never
    inject markup; only the structural tags this function emits are live.
    """
    escaped = _html.escape(text)
    # Mermaid fences -> live <pre class="mermaid"> blocks (escaped source).
    escaped = re.sub(
        r"```mermaid\s+(.+?)```",
        lambda m: f'</p><pre class="mermaid">{m.group(1).strip()}</pre><p>',
        escaped,
        flags=re.DOTALL,
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{_html.escape(title)}</title>
<link rel="stylesheet" href="{_KATEX_CSS}">
<script defer src="{_KATEX_JS}"></script>
<script defer src="{_KATEX_AUTO}"
  onload="renderMathInElement(document.body,{{delimiters:[
    {{left:'$$',right:'$$',display:true}},{{left:'\\\\(',right:'\\\\)',display:false}}]}})"></script>
<script src="{_MERMAID_JS}"></script>
<script>window.addEventListener("load", function () {{
  if (window.mermaid) window.mermaid.initialize({{startOnLoad: true}});
}});</script>
<style>body{{font:16px/1.5 system-ui;margin:2rem auto;max-width:48rem;
white-space:pre-wrap}}pre.mermaid{{white-space:pre}}</style>
</head><body><p>{escaped}</p></body></html>
"""


def write_artifact(text: str, *, out_dir: Path | None = None) -> Path:
    """Write the rendered HTML under ``data_dir("rich_render/")`` (0600)."""
    if out_dir is None:
        from maverick.paths import data_dir
        out_dir = data_dir("rich_render")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    path = out_dir / f"reply-{digest}.html"
    from maverick.file_lock import atomic_write_text

    atomic_write_text(path, render_html(text))
    return path


class RichRenderChannel:
    """Wrap any Channel: rich replies also ship as a rendered HTML artifact.

    ``deliver(user_id, path)`` is the adapter-specific file hand-off (e.g. a
    Telegram sendDocument call); without one, text explains that a rendered
    file cannot be attached in this chat. Plain messages pass through
    untouched. Wrapping is a pure decorator — ``start``/``stop``/attribute
    access proxy to the inner channel.
    """

    def __init__(self, inner, *,
                 deliver: Callable[[str, Path], Awaitable[None]] | None = None,
                 out_dir: Path | None = None):
        self._inner = inner
        self._deliver = deliver
        self._out_dir = out_dir

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def send(self, user_id: str, text: str) -> None:
        if not has_rich_blocks(text):
            await self._inner.send(user_id, text)
            return
        if self._deliver is None:
            await self._inner.send(user_id, text +
                "\n\nThis chat cannot attach a rendered copy. The original reply is shown above.")
            return
        try:
            path = write_artifact(text, out_dir=self._out_dir)
        except Exception:  # rendering must never lose the reply
            log.exception("rich render failed; sending plain text")
            await self._inner.send(user_id, text)
            return
        counts = detect_rich_blocks(text)
        note = (f"[rendered: {counts['math']} math + {counts['mermaid']} "
                f"diagram block(s)]")
        if self._deliver is not None:
            await self._inner.send(user_id, f"{text}\n\n{note}")
            try:
                await self._deliver(user_id, path)
            except Exception:  # pragma: no cover -- delivery is best-effort
                log.exception("rich artifact delivery failed (%s)", path)


def maybe_wrap(channel, *, deliver=None):
    """Wrap ``channel`` when ``[channels] rich_render`` is on; else as-is."""
    return RichRenderChannel(channel, deliver=deliver) if enabled() else channel


__all__ = ["RichRenderChannel", "detect_rich_blocks", "has_rich_blocks",
           "render_html", "write_artifact", "maybe_wrap", "enabled"]
