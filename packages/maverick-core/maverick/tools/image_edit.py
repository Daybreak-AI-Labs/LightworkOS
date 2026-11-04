"""Image EDIT tool.

Generation already ships via tools/replicate_tool.py (generic ``run`` of any
hosted model, e.g. SDXL/FLUX). What was missing is the *edit* verbs; this
tool adds them in two tiers:

* **Hosted edits** via the same Replicate API surface (auth:
  ``REPLICATE_API_TOKEN``; reuses replicate_tool's request helpers):
  - inpaint(image, mask, prompt)   — repaint the masked region
  - variation(image[, prompt])     — re-imagine the image
  - upscale(image[, scale])        — super-resolution
  Models are chosen in All settings > AI models > Images; the existing
  ``MAVERICK_INPAINT_MODEL``, ``MAVERICK_VARIATION_MODEL`` and
  ``MAVERICK_UPSCALE_MODEL`` environment choices still win. ``image``/``mask``
  accept a workspace image file path (uploaded as a data URI) or an http(s)/
  data URL.

* **Local edits** via Pillow (``[computer-use]`` extra), no network/key:
  - crop(input_path, output_path, box=[l,t,r,b])
  - resize(input_path, output_path, width, height)
  - rotate(input_path, output_path, degrees)

All model-supplied paths are confined to the sandbox workspace (an
unconfined read ships file bytes to Replicate = exfiltration; an unconfined
write is arbitrary host write).
"""

from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Any

from . import Tool
from .ffmpeg_tool import _safe_path

_REMOTE_OPS = ("inpaint", "variation", "upscale")

# op -> (env knob, default model)
_DEFAULT_MODELS = {
    "inpaint": ("MAVERICK_INPAINT_MODEL", "stability-ai/stable-diffusion-inpainting"),
    "variation": ("MAVERICK_VARIATION_MODEL", "lambdal/stable-diffusion-image-variation"),
    "upscale": ("MAVERICK_UPSCALE_MODEL", "nightmareai/real-esrgan"),
}

_MIME = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
}
_MAX_REMOTE_IMAGE_BYTES = 10 * 1024 * 1024


# ---------- shared bits ----------


def _image_ref(value: str, sandbox: Any) -> str:
    """A remote-op image input: pass URLs through, inline local files.

    Local paths are workspace-confined, then base64'd into a data URI —
    Replicate accepts data URIs for file inputs, so no upload endpoint is
    needed.
    """
    if value.startswith(("http://", "https://", "data:")):
        return value
    path = Path(_safe_path(sandbox, value))
    if not path.exists() or not path.is_file():
        raise ValueError(f"image file not found: {value!r}")
    mime = _MIME.get(path.suffix.lower())
    if not mime:
        raise ValueError("local remote-op inputs must be .png, .jpg, .jpeg, .webp, or .gif images")
    size = path.stat().st_size
    if size > _MAX_REMOTE_IMAGE_BYTES:
        raise ValueError(
            f"local image is too large for hosted edit ({size} bytes > "
            f"{_MAX_REMOTE_IMAGE_BYTES} bytes)"
        )
    data = path.read_bytes()
    actual_mime = _sniff_image_mime(data)
    if actual_mime != mime:
        raise ValueError(f"local file is not a valid {mime} image")
    return f"data:{mime};base64,{base64.b64encode(data).decode()}"


def _sniff_image_mime(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _model_for(op: str) -> str | None:
    from ..image_edit_models import current_model

    env, default = _DEFAULT_MODELS[op]
    try:
        return current_model(op + "_model", env, default)
    except ValueError:
        return None


def _predict(model: str, inp: dict[str, Any], wait: bool) -> str:
    """Create a prediction (and optionally poll), via replicate_tool's
    auth + request helpers so the HTTP shape stays in one place."""
    from .replicate_tool import _fmt_prediction, _get, _post, _resolve_version

    version = _resolve_version(model)
    if not version:
        return f"ERROR: could not resolve version for model {model!r}"
    code, data = _post("/predictions", {"version": version, "input": inp})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: predict ({code}): {data}"
    pid = data.get("id")
    if not wait:
        return (
            f"created prediction {pid} (status={data.get('status')}); "
            "poll with replicate predict_get"
        )
    deadline = time.time() + 90
    while time.time() < deadline:
        c2, p2 = _get(f"/predictions/{pid}")
        if c2 >= 400 or not isinstance(p2, dict):
            return f"ERROR: poll ({c2}): {p2}"
        if p2.get("status") in ("succeeded", "failed", "canceled"):
            return _fmt_prediction(p2)
        time.sleep(2)
    return f"prediction {pid} still running after 90s; use replicate predict_get to poll"


# ---------- remote ops ----------


def _op_remote(op: str, args: dict[str, Any], sandbox: Any) -> str:
    image = (args.get("image") or "").strip()
    if not image:
        return f"ERROR: {op} requires image"
    model = _model_for(op)
    if not model:
        return "ERROR: image model choice is invalid. Review Images in All settings."
    try:
        inp: dict[str, Any] = {"image": _image_ref(image, sandbox)}
    except ValueError as e:
        return f"ERROR: {e}"
    prompt = (args.get("prompt") or "").strip()
    if op == "inpaint":
        mask = (args.get("mask") or "").strip()
        if not mask or not prompt:
            return "ERROR: inpaint requires mask and prompt"
        try:
            inp["mask"] = _image_ref(mask, sandbox)
        except ValueError as e:
            return f"ERROR: {e}"
        inp["prompt"] = prompt
    elif op == "variation":
        if prompt:
            inp["prompt"] = prompt
    elif op == "upscale":
        scale = args.get("scale")
        if scale is not None:
            if not isinstance(scale, (int, float)) or isinstance(scale, bool) or scale <= 0:
                return "ERROR: scale must be a positive number"
            inp["scale"] = scale
    return _predict(model, inp, bool(args.get("wait")))


# ---------- local ops (Pillow, [computer-use] extra) ----------


def _load_pil():
    try:
        from PIL import Image
    except ImportError as e:
        raise ImportError(
            "local image ops need Pillow. From the reviewed checkout run: "
            "python -m pip install -e './packages/maverick-core[computer-use]'"
        ) from e
    return Image


def _local_edit(op: str, args: dict[str, Any], sandbox: Any, transform) -> str:
    src = (args.get("input_path") or "").strip()
    dst = (args.get("output_path") or "").strip()
    if not src or not dst:
        return f"ERROR: {op} requires input_path and output_path"
    try:
        src = _safe_path(sandbox, src)
        dst = _safe_path(sandbox, dst)
    except ValueError as e:
        return f"ERROR: {e}"
    try:
        image_mod = _load_pil()
    except ImportError as e:
        return f"ERROR: {e}"
    try:
        with image_mod.open(src) as im:
            transform(im).save(dst)
    except FileNotFoundError:
        return f"ERROR: no such file: {src}"
    except Exception as e:
        return f"ERROR: {op} failed: {e}"
    return f"wrote {dst}"


def _op_crop(args: dict[str, Any], sandbox: Any) -> str:
    box = args.get("box")
    if (
        not isinstance(box, list)
        or len(box) != 4
        or not all(isinstance(v, int) and not isinstance(v, bool) for v in box)
    ):
        return "ERROR: crop requires box=[left, top, right, bottom] (integers)"
    return _local_edit("crop", args, sandbox, lambda im: im.crop(tuple(box)))


def _op_resize(args: dict[str, Any], sandbox: Any) -> str:
    width, height = args.get("width"), args.get("height")
    if not all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in (width, height)):
        return "ERROR: resize requires positive integer width and height"
    return _local_edit("resize", args, sandbox, lambda im: im.resize((width, height)))


def _op_rotate(args: dict[str, Any], sandbox: Any) -> str:
    degrees = args.get("degrees")
    if not isinstance(degrees, (int, float)) or isinstance(degrees, bool):
        return "ERROR: rotate requires degrees (number)"
    return _local_edit("rotate", args, sandbox, lambda im: im.rotate(degrees, expand=True))


# ---------- tool ----------


def _run(args: dict[str, Any], sandbox: Any) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    if not isinstance(op, str):
        return f"ERROR: unknown op {op!r}"
    local = {"crop": _op_crop, "resize": _op_resize, "rotate": _op_rotate}
    if op in local:
        return local[op](args, sandbox)
    if op not in _REMOTE_OPS:
        return f"ERROR: unknown op {op!r}"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed."
    try:
        return _op_remote(op, args, sandbox)
    except RuntimeError as e:  # missing REPLICATE_API_TOKEN
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: {op} failed: {type(e).__name__}: {e}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["inpaint", "variation", "upscale", "crop", "resize", "rotate"],
        },
        "image": {
            "type": "string",
            "description": "Workspace file path or http(s)/data URL (remote ops).",
        },
        "mask": {"type": "string", "description": "Inpaint mask: white = repaint (path or URL)."},
        "prompt": {"type": "string"},
        "scale": {"type": "number", "description": "Upscale factor."},
        "wait": {"type": "boolean", "description": "Poll the prediction to completion."},
        "input_path": {"type": "string", "description": "Local-op source image."},
        "output_path": {"type": "string", "description": "Local-op destination."},
        "box": {
            "type": "array",
            "items": {"type": "integer"},
            "description": "crop box [left, top, right, bottom].",
        },
        "width": {"type": "integer"},
        "height": {"type": "integer"},
        "degrees": {"type": "number", "description": "Counter-clockwise rotation."},
    },
    "required": ["op"],
}


def image_edit(sandbox: Any = None) -> Tool:
    return Tool(
        name="image_edit",
        description=(
            "Edit images. Hosted (Replicate, REPLICATE_API_TOKEN): inpaint "
            "(image+mask+prompt), variation, upscale — image inputs are "
            "bounded workspace image paths or URLs; model choices are in "
            "All settings > AI models > Images. Local (Pillow, no "
            "key): crop (box=[l,t,r,b]), resize (width/height), rotate "
            "(degrees). For text-to-image GENERATION use the replicate tool."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )
