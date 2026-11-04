"""Translation tool — text-to-text MT.

Wraps two backends:

  - DeepL (preferred for accuracy; auth via ``DEEPL_API_KEY``)
  - LibreTranslate (open, free-tier; configurable endpoint via
    ``LIBRETRANSLATE_URL``, default ``https://libretranslate.com``;
    optional ``LIBRETRANSLATE_API_KEY``)

ops:
  - translate(text, target, source)    — translate to target lang code
  - detect(text)                       — detect source lang code

Choose backend per call via ``backend`` (default: deepl when key
present, else libretranslate).
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_TRANS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["translate", "detect"]},
        "text": {"type": "string"},
        "target": {"type": "string", "description": "ISO 639-1 (e.g. 'es')."},
        "source": {"type": "string", "description": "ISO 639-1 (optional)."},
        "backend": {
            "type": "string",
            "enum": ["deepl", "libretranslate"],
        },
    },
    "required": ["op", "text"],
}


def _pick_backend(explicit: str) -> str:
    # Normalize the backend arg so a model-supplied "DeepL" / " deepl "
    # routes correctly instead of silently falling through to the default.
    # Matches the `voice`/`ocr` tools, which already strip+lowercase.
    explicit = (explicit or "").strip().lower()
    if explicit:
        return explicit
    if os.environ.get("DEEPL_API_KEY", "").strip():
        return "deepl"
    return "libretranslate"


def _translate_deepl(text: str, target: str, source: str) -> str:
    import httpx
    key = os.environ.get("DEEPL_API_KEY", "").strip()
    if not key:
        return "ERROR: DEEPL_API_KEY not set"
    # Free-tier hosts use api-free.deepl.com; paid uses api.deepl.com.
    host = "api-free.deepl.com" if key.endswith(":fx") else "api.deepl.com"
    payload = {"text": [text], "target_lang": target.upper()}
    if source:
        payload["source_lang"] = source.upper()
    r = _governed_sender(httpx.post)(
        f"https://{host}/v2/translate",
        headers={"Authorization": f"DeepL-Auth-Key {key}"},
        json=payload, timeout=30.0,
    )
    if r.status_code >= 400:
        return f"ERROR: DeepL ({r.status_code}): {r.text[:300]}"
    data = r.json()
    out = (data.get("translations") or [{}])[0]
    detected = out.get("detected_source_language", "?")
    return f"[from={detected} to={target}]\n{out.get('text', '')}"


def _translate_libre(text: str, target: str, source: str) -> str:
    import httpx
    base = os.environ.get("LIBRETRANSLATE_URL", "https://libretranslate.com").rstrip("/")
    payload = {"q": text, "target": target.lower(), "source": source.lower() or "auto",
               "format": "text"}
    key = os.environ.get("LIBRETRANSLATE_API_KEY", "").strip()
    if key:
        payload["api_key"] = key
    r = _governed_sender(httpx.post)(f"{base}/translate", json=payload, timeout=30.0)
    if r.status_code >= 400:
        return f"ERROR: LibreTranslate ({r.status_code}): {r.text[:300]}"
    data = r.json()
    return f"[to={target}]\n{data.get('translatedText', '')}"


def _detect_deepl(text: str) -> str:
    # DeepL detects as a side effect of translate; round-trip to en.
    return _translate_deepl(text, "EN", "")


def _detect_libre(text: str) -> str:
    import httpx
    base = os.environ.get("LIBRETRANSLATE_URL", "https://libretranslate.com").rstrip("/")
    payload = {"q": text}
    key = os.environ.get("LIBRETRANSLATE_API_KEY", "").strip()
    if key:
        payload["api_key"] = key
    r = _governed_sender(httpx.post)(f"{base}/detect", json=payload, timeout=30.0)
    if r.status_code >= 400:
        return f"ERROR: LibreTranslate detect ({r.status_code}): {r.text[:300]}"
    data = r.json()
    if isinstance(data, list) and data:
        top = data[0]
        return f"{top.get('language', '?')}  conf={top.get('confidence', 0):.2f}"
    return "(no detection)"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    text = str(args.get("text") or "")
    if not text.strip():
        return "ERROR: text is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    backend = _pick_backend((args.get("backend") or "").strip())
    target = (args.get("target") or "en").strip()
    source = (args.get("source") or "").strip()
    try:
        if op == "translate":
            if backend == "deepl":
                return _translate_deepl(text, target, source)
            return _translate_libre(text, target, source)
        if op == "detect":
            if backend == "deepl":
                return _detect_deepl(text)
            return _detect_libre(text)
    except Exception as e:
        return f"ERROR: translate failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def translate() -> Tool:
    return Tool(
        name="translate",
        description=(
            "Text translation via DeepL (DEEPL_API_KEY) or "
            "LibreTranslate (LIBRETRANSLATE_URL). ops: translate "
            "(text + target + optional source), detect (lang only). "
            "backend chooses 'deepl' or 'libretranslate' (default: "
            "deepl when key present, else libretranslate)."
        ),
        input_schema=_TRANS_SCHEMA,
        fn=_run,
    )
