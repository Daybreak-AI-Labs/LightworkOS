"""OCR tool — extract text from images.

Wraps the local ``tesseract`` binary (preferred — fast, no network)
with an optional fallback to the Hugging Face Inference API for
users who don't want to install a system dep.

ops:
  - extract(path, lang)       — local image (png/jpg/tiff/pdf/...)
  - extract_url(url, lang)    — fetch image first, then OCR

Lang defaults to ``eng``; ``eng+deu`` etc. for multi-language docs.

Requires tesseract on PATH for the default backend; fail-loud with
the install hint when missing. Set ``OCR_BACKEND=hf`` (and the
``HUGGINGFACE_API_TOKEN`` env) to route through the HF
``microsoft/trocr-base-printed`` (or any other HF OCR model) instead.
"""
from __future__ import annotations

import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import Tool

log = logging.getLogger(__name__)

_HF_MODEL_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
_MAX_IMAGE_BYTES = 50 * 1024 * 1024


_OCR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["extract", "extract_url"]},
        "path": {"type": "string"},
        "url": {"type": "string"},
        "lang": {"type": "string", "description": "Tesseract lang code (default 'eng')."},
        "backend": {
            "type": "string",
            "enum": ["tesseract", "hf"],
            "description": "Override default backend.",
        },
        "hf_model": {
            "type": "string",
            "description": "HF model id (backend=hf only).",
        },
    },
    "required": ["op"],
}


def _default_backend(explicit: str) -> str:
    if explicit:
        return explicit
    env = (os.environ.get("OCR_BACKEND") or "").strip().lower()
    return env or "tesseract"




def _run_tesseract(path: str, lang: str, sandbox) -> str:
    from ..sandbox.workspace_transfer import _read
    from .document_processing import ocr_pdf, run_document_job, workspace_path

    root, relative = workspace_path(sandbox, path)
    data = _read(root, relative)
    suffix = Path(relative).suffix.lstrip(".").lower()
    if suffix == "pdf":
        return ocr_pdf(data, "", sandbox)
    return run_document_job({"operation": "image_ocr", "input_suffix": suffix,
                             "language": lang}, data, sandbox)



def _run_hf(path: str, model: str) -> str:
    # This legacy backend consumes one operator-global token. It cannot express
    # per-principal grants, so an authenticated enterprise agent must not borrow
    # it. Local tesseract remains available and does not cross this boundary.
    try:
        from ..connections import current_principal
        from ..enterprise import enterprise_enabled

        if enterprise_enabled() and current_principal():
            return (
                "REFUSED (credentials): authenticated enterprise OCR cannot "
                "use the operator-global Hugging Face token; use local "
                "tesseract or a principal-scoped OCR connection."
            )
    except Exception:
        return "REFUSED (credentials): OCR credential policy is unavailable"
    if not _HF_MODEL_RE.fullmatch(model):
        return "ERROR: hf_model must be a bounded 'owner/model' identifier"
    tok = os.environ.get("HUGGINGFACE_API_TOKEN", "").strip()
    if not tok:
        return "ERROR: backend=hf requires HUGGINGFACE_API_TOKEN."
    try:
        if Path(path).stat().st_size > _MAX_IMAGE_BYTES:
            return "ERROR: HF OCR input exceeds the 50 MiB limit"
        with open(path, "rb") as f:
            blob = f.read(_MAX_IMAGE_BYTES + 1)
        if len(blob) > _MAX_IMAGE_BYTES:
            return "ERROR: HF OCR input exceeds the 50 MiB limit"
    except OSError as e:
        return f"ERROR: OCR input could not be read ({type(e).__name__})"
    url = f"https://api-inference.huggingface.co/models/{model}"
    from ..enterprise import enterprise_egress_denial
    if denial := enterprise_egress_denial(url, tool="ocr"):
        return f"ERROR: {denial}"
    from ._ssrf import BlockedHost, safe_client
    try:
        with safe_client(url, timeout=60.0) as client:
            r = client.post(
                url,
                headers={
                    "Authorization": f"Bearer {tok}",
                    "Content-Type": "application/octet-stream",
                },
                content=blob,
            )
    except BlockedHost:
        return "ERROR: HF OCR endpoint was blocked by the SSRF policy"
    except Exception as e:  # noqa: BLE001
        return f"ERROR: HF OCR request failed ({type(e).__name__[:120]})"
    if r.status_code >= 400:
        return f"ERROR: HF OCR ({r.status_code}): upstream request failed"
    try:
        data = r.json()
    except ValueError:
        return r.text[:3000]
    # TrOCR-style: list[{generated_text}]; some models return dicts.
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data[0].get("generated_text", str(data[0]))[:3000]
    if isinstance(data, dict):
        return data.get("generated_text", str(data))[:3000]
    return str(data)[:3000]


def _op_extract(path: str, lang: str, backend: str, hf_model: str, sandbox) -> str:
    if not path:
        return "ERROR: extract requires path"
    workdir = Path(sandbox.workdir).resolve() if sandbox is not None else Path.cwd().resolve()
    candidate = Path(path)
    candidate = (workdir / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    try:
        candidate.relative_to(workdir)
    except ValueError:
        return f"ERROR: path escapes workspace: {path}"
    if not candidate.exists():
        return f"ERROR: file not found: {path}"
    if backend == "hf":
        return _run_hf(str(candidate), hf_model or "microsoft/trocr-base-printed")
    return _run_tesseract(str(candidate), lang or "eng", sandbox)


def _op_extract_url(url: str, lang: str, backend: str, hf_model: str, sandbox) -> str:
    if not url:
        return "ERROR: extract_url requires url"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return f"ERROR: invalid URL: {url!r}"
    from ._ssrf import BlockedHost, safe_client
    # safe_client pins the connection to the validated public IP (no rebinding
    # window), AND we stream with a hard byte ceiling so a model-supplied URL
    # to a multi-GB / endless body can't be fully buffered into memory before
    # any size check runs (the old safe_get materialized resp.content first).
    _MAX = 50 * 1024 * 1024  # 50 MiB
    try:
        with safe_client(url, timeout=30.0) as client:
            with client.stream("GET", url) as resp:
                if resp.status_code >= 400:
                    return f"ERROR: image fetch {resp.status_code}: {url}"
                clen = resp.headers.get("content-length")
                if clen is not None and clen.isdigit() and int(clen) > _MAX:
                    return f"ERROR: image fetch refused: {clen} bytes > 50 MiB cap: {url}"
                buf = bytearray()
                for chunk in resp.iter_bytes():
                    buf += chunk
                    if len(buf) > _MAX:
                        return f"ERROR: image fetch refused: body exceeded 50 MiB cap: {url}"
                ct = resp.headers.get("content-type", "").split(";")[0].strip().lower()
    except BlockedHost as e:
        return (
            f"ERROR: refusing to fetch {parsed.hostname!r}: {e}. "
            "Set MAVERICK_FETCH_ALLOW_PRIVATE=1 to override."
        )
    except Exception as e:
        return f"ERROR: fetch failed: {type(e).__name__}: {e}"
    # Pick a sensible extension from content-type for tesseract.
    ext = {
        "image/png": ".png", "image/jpeg": ".jpg",
        "image/jpg": ".jpg", "image/tiff": ".tiff",
        "image/webp": ".webp", "application/pdf": ".pdf",
    }.get(ct, ".png")
    tmp_dir = Path(sandbox.workdir) if sandbox is not None else Path.cwd()
    with tempfile.NamedTemporaryFile(suffix=ext, delete=False, dir=tmp_dir) as f:
        f.write(bytes(buf))
        tmp = f.name
    try:
        return _op_extract(tmp, lang, backend, hf_model, sandbox)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _run(args: dict[str, Any], sandbox) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    backend = _default_backend((args.get("backend") or "").strip().lower())
    if backend not in ("tesseract", "hf"):
        backend = "tesseract"
    if backend == "hf":
        try:
            import httpx  # noqa: F401
        except ImportError:
            return "ERROR: httpx not installed (backend=hf). Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    lang = (args.get("lang") or "eng").strip()
    hf_model = (args.get("hf_model") or "").strip()
    try:
        if op == "extract":
            return _op_extract(
                (args.get("path") or "").strip(), lang, backend, hf_model, sandbox,
            )
        if op == "extract_url":
            return _op_extract_url(
                (args.get("url") or "").strip(), lang, backend, hf_model, sandbox,
            )
    except Exception as e:
        return f"ERROR: ocr failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def ocr(sandbox=None) -> Tool:
    return Tool(
        name="ocr",
        description=(
            "Extract text from images. ops: extract (local path), "
            "extract_url (remote image). backend = tesseract "
            "(default; requires binary on PATH) | hf "
            "(HUGGINGFACE_API_TOKEN, default model "
            "microsoft/trocr-base-printed). lang accepts "
            "tesseract codes like 'eng' / 'eng+deu'."
        ),
        input_schema=_OCR_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )
