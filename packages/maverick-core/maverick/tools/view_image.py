"""Image-understanding tool.

Sends an image to a vision-capable model and returns the description /
analysis. The tool itself is provider-agnostic: it picks the agent's
current LLM (or a configured override) and dispatches with a structured
image block.

Supports local file paths and http(s) URLs (which are passed through to
the provider where possible; otherwise downloaded and base64-encoded).
"""
from __future__ import annotations

import base64
import logging
import os
import stat
from pathlib import Path
from typing import Any

from ..budget import BudgetExceeded, UsageAccountingError
from ..killswitch import Halted
from . import Tool

log = logging.getLogger(__name__)


_VIEW_IMAGE_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "source": {
            "type": "string",
            "description": "Local image file path or http(s) URL (PNG/JPG/WebP/GIF).",
        },
        "prompt": {
            "type": "string",
            "description": "What to look for in the image. Default: 'Describe this image in detail.'",
        },
    },
    "required": ["source"],
}


_MIME_BY_EXT = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
}


def _guess_mime(source: str) -> str:
    ext = os.path.splitext(source)[1].lower()
    return _MIME_BY_EXT.get(ext, "image/jpeg")


def _load_image(source: str, sandbox=None, *, workdir: Path | None = None) -> tuple[bytes, str] | None:
    """Return (image_bytes, mime_type) for the source, or None on failure."""
    if source.startswith(("http://", "https://")):
        try:
            import httpx  # noqa: F401  (presence check; safe_client imports it)
        except ImportError:
            return None
        from ._ssrf import BlockedHost, safe_client
        # safe_client pins the connection to the validated public IP (SSRF /
        # DNS-rebinding); stream with a hard ceiling so a model-supplied URL to
        # a multi-GB resource can't be fully buffered into memory BEFORE the cap
        # rejects it (the old safe_get materialized resp.content first).
        _MAX = 20 * 1024 * 1024  # 20 MiB
        try:
            with safe_client(source, timeout=30.0) as client:
                with client.stream("GET", source) as resp:
                    resp.raise_for_status()
                    clen = resp.headers.get("content-length")
                    if clen is not None and clen.isdigit() and int(clen) > _MAX:
                        log.warning("image fetch refused: %s bytes > 20 MiB cap", clen)
                        return None
                    buf = bytearray()
                    for chunk in resp.iter_bytes():
                        buf += chunk
                        if len(buf) > _MAX:
                            log.warning("image fetch refused: body exceeded 20 MiB cap")
                            return None
                    mime = (resp.headers.get("content-type") or _guess_mime(source)).split(";")[0].strip()
                    return bytes(buf), mime
        except BlockedHost as e:
            log.warning("image fetch refused: %s", e)
            return None
        except Exception as e:
            log.warning("image fetch failed: %s", e)
            return None
    workdir = Path(getattr(sandbox, "workdir", None) or workdir or Path.cwd()).resolve()
    path = Path(os.path.expanduser(source))
    if not path.is_absolute():
        path = (workdir / path).resolve()
    else:
        path = path.resolve()
    try:
        path.relative_to(workdir)
    except ValueError:
        return None
    from .fs import _open_contained

    try:
        fd = _open_contained(workdir, path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as source_file:
            if not stat.S_ISREG(os.fstat(source_file.fileno()).st_mode):
                return None
            data = source_file.read(20 * 1024 * 1024 + 1)
        if len(data) > 20 * 1024 * 1024:
            return None
        return data, _guess_mime(source)
    except (OSError, ValueError):
        return None


def _run_view_image(args: dict[str, Any], sandbox=None, *, budget=None) -> str:
    source = (args.get("source") or "").strip()
    if not source:
        return "ERROR: source is required"
    prompt = (args.get("prompt") or "Describe this image in detail.").strip()
    from ..llm import model_for_role
    if "model" in args:
        return "ERROR: the vision model is configured by the operator"
    if budget is None:
        return "ERROR: image analysis requires an active run budget"
    model = os.environ.get("MAVERICK_VISION_MODEL") or model_for_role("vision")

    loaded = _load_image(source, sandbox)
    if loaded is None:
        return f"ERROR: could not load image from {source!r}"
    image_bytes, mime = loaded
    # Anthropic format -- providers' adapters translate to OpenAI / Gemini
    # vision schemas in their `complete()` methods.
    image_block: dict[str, Any] = {
        "type": "image",
        "source": {
            "type": "base64",
            "media_type": mime,
            "data": base64.b64encode(image_bytes).decode("ascii"),
        },
    }
    messages = [{
        "role": "user",
        "content": [image_block, {"type": "text", "text": prompt}],
    }]

    try:
        from ..llm import LLM
    except ImportError as e:
        return f"ERROR: maverick.llm unavailable: {e}"

    try:
        llm = LLM(model=model)
        resp = llm.complete(
            system="You analyze images carefully and concisely.",
            messages=messages,
            max_tokens=1024,
            budget=budget,
        )
        return (resp.text or "").strip() or "(no description returned)"
    except (BudgetExceeded, UsageAccountingError, Halted):
        raise
    except Exception as e:
        return f"ERROR: vision call failed: {type(e).__name__}: {e}"


def view_image(sandbox=None, *, budget=None) -> Tool:
    """Factory: builds the view_image tool."""
    return Tool(
        name="view_image",
        description=(
            "Look at an image (local path or http(s) URL) and describe / "
            "analyze it. Provide a `prompt` to focus the analysis (e.g. "
            "'What's the error message?'). Picks the configured vision "
            "model automatically from the operator's settings."
        ),
        input_schema=_VIEW_IMAGE_INPUT_SCHEMA,
        fn=lambda args: _run_view_image(args, sandbox, budget=budget),
    )
