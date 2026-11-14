"""Hugging Face Inference API tool.

Wraps the HF serverless inference endpoint so the agent can invoke
non-text models without leaving Lightwork: image classification,
audio transcription (Whisper-on-HF), object detection, summarization
via a specific HF model, etc.

ops:
  - infer(model, inputs)          — run any HF inference task
  - image_classify(model, url)    — convenience: download + send image
  - summarize(model, text)        — convenience for summarization models

Auth: ``HUGGINGFACE_API_TOKEN`` (https://huggingface.co/settings/tokens).
For public models inference can work unauthenticated, but is rate-
limited; token grants the free tier limits + access to gated models
the user has accepted licensing for.
"""
from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlparse

from ..fastjson import dumps_compact
from ..governed_http import guarded_sender as _governed_sender
from . import Tool, safe_path_segment

log = logging.getLogger(__name__)


_HF_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["infer", "image_classify", "summarize"],
        },
        "model": {
            "type": "string",
            "description": "HF model id, e.g. 'facebook/bart-large-cnn'.",
        },
        "inputs": {
            "description": "Raw inputs payload (str / dict / list).",
        },
        "url": {
            "type": "string",
            "description": "Image URL (image_classify only).",
        },
        "text": {
            "type": "string",
            "description": "Text to summarize (summarize only).",
        },
        "parameters": {
            "type": "object",
            "description": "Optional model-specific params.",
        },
    },
    "required": ["op", "model"],
}


_API_BASE = "https://api-inference.huggingface.co/models"
_MAX_IMAGE_FETCH_BYTES = 5_000_000


def _token() -> str:
    return os.environ.get("HUGGINGFACE_API_TOKEN", "").strip()


def _headers() -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    tok = _token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _post_json(model: str, payload: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(
        f"{_API_BASE}/{model}",
        json=payload,
        headers=_headers(),
        timeout=60.0,
    )
    try:
        body = r.json()
    except ValueError:
        body = r.text
    return r.status_code, body


def _post_bytes(model: str, blob: bytes, content_type: str) -> tuple[int, Any]:
    import httpx
    headers = _headers()
    headers["Content-Type"] = content_type
    r = _governed_sender(httpx.post)(
        f"{_API_BASE}/{model}",
        content=blob,
        headers=headers,
        timeout=60.0,
    )
    try:
        body = r.json()
    except ValueError:
        body = r.text
    return r.status_code, body


def _format_body(body: Any, *, max_chars: int = 3000) -> str:
    if isinstance(body, (dict, list)):
        out = dumps_compact(body)
    else:
        out = str(body)
    if len(out) > max_chars:
        out = out[:max_chars] + "\n... (truncated)"
    return out


def _op_infer(model: str, inputs: Any, parameters: dict | None) -> str:
    payload: dict = {"inputs": inputs}
    if parameters:
        payload["parameters"] = parameters
    code, body = _post_json(model, payload)
    if code >= 400:
        return f"ERROR: HF inference {code}: {_format_body(body, max_chars=400)}"
    return _format_body(body)


def _op_image_classify(model: str, url: str) -> str:
    if not url:
        return "ERROR: image_classify requires url"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return f"ERROR: only http/https supported; got scheme={parsed.scheme!r}"
    if not parsed.netloc:
        return "ERROR: missing host in URL"
    # The image URL is model-chosen, so the network posture and the tenant and
    # per-tool egress lists apply to it as they do to http_fetch.
    try:
        from ..tenant.egress import egress_allowed
        allowed = egress_allowed("huggingface", parsed.hostname or "")
    except Exception as e:
        return f"ERROR: egress policy could not be evaluated ({type(e).__name__}); refusing to fetch."
    if not allowed:
        return f"ERROR: egress policy blocks huggingface from reaching {parsed.hostname!r}."
    # safe_get pins the validated IP, closing the DNS-rebinding TOCTOU window
    # that is_blocked_host()+httpx.get() leaves open (separate resolutions).
    from ._ssrf import BlockedHost, safe_get
    try:
        r = safe_get(url, timeout=30.0)
    except BlockedHost as e:
        return (
            f"ERROR: refusing to fetch private/loopback/reserved address ({e}). "
            "Set MAVERICK_FETCH_ALLOW_PRIVATE=1 to override."
        )
    if r.status_code >= 300:
        return f"ERROR: image fetch {r.status_code}: {url}"
    if len(r.content) > _MAX_IMAGE_FETCH_BYTES:
        return f"ERROR: image too large ({len(r.content)} bytes > {_MAX_IMAGE_FETCH_BYTES})"
    content_type = r.headers.get("content-type", "application/octet-stream")
    code, body = _post_bytes(model, r.content, content_type)
    if code >= 400:
        return f"ERROR: HF inference {code}: {_format_body(body, max_chars=400)}"
    return _format_body(body)


def _op_summarize(model: str, text: str, parameters: dict | None) -> str:
    if not text.strip():
        return "ERROR: summarize requires non-empty text"
    return _op_infer(model, text, parameters or {})


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    model = (args.get("model") or "").strip()
    if not model:
        return "ERROR: model is required"
    # Model ids are "name" or "owner/name"; each part is one encoded segment
    # so a value like "../../api/whoami-v2" cannot retarget the token.
    segments = [safe_path_segment(part) for part in model.split("/")]
    if len(segments) > 2 or any(seg is None for seg in segments):
        return "ERROR: model must be a Hugging Face model id like 'owner/name'"
    model = "/".join(segments)  # type: ignore[arg-type]
    parameters = args.get("parameters") or None
    try:
        if op == "infer":
            import httpx  # noqa: F401
            inputs = args.get("inputs")
            if inputs is None:
                return "ERROR: infer requires inputs"
            return _op_infer(model, inputs, parameters)
        if op == "image_classify":
            return _op_image_classify(model, args.get("url") or "")
        if op == "summarize":
            return _op_summarize(model, args.get("text") or "", parameters)
    except ImportError:
        return "ERROR: httpx not installed…195 tokens truncated…puter-use]'"
    except Exception as e:
        return f"ERROR: HF request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def huggingface() -> Tool:
    return Tool(
        name="huggingface",
        description=(
            "Hugging Face Inference API. ops: infer (model + raw "
            "inputs/parameters), image_classify (model + image url), "
            "summarize (model + text). Auth: HUGGINGFACE_API_TOKEN "
            "(optional but recommended)."
        ),
        input_schema=_HF_SCHEMA,
        fn=_run,
    )
