"""ImageMagick tool — image transforms via the local binary.

Uses the IM 7 ``magick`` binary when present, falling back to IM 6's
``convert`` / ``identify`` / ``mogrify``. Auth: none.

ops:
  - resize(input_path, output_path, width, height)
  - convert(input_path, output_path, args)     — generic operator chain
  - identify(input_path)                       — JSON-ish summary line
  - composite(base_path, overlay_path, output_path, geometry)
"""
from __future__ import annotations

import logging
import math
import re
import shutil
from pathlib import Path
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_IM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["resize", "convert", "identify", "composite"],
        },
        "input_path": {"type": "string"},
        "output_path": {"type": "string"},
        "base_path": {"type": "string"},
        "overlay_path": {"type": "string"},
        "geometry": {"type": "string"},
        "width": {"type": "integer"},
        "height": {"type": "integer"},
        "args": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["op"],
}


def _bin(*candidates: str) -> str | None:
    for c in candidates:
        if shutil.which(c):
            return c
    return None


def _magick_or_convert() -> str | None:
    return _bin("magick", "convert")


def _identify_bin() -> str | None:
    return _bin("magick", "identify")


def _run_cmd(sandbox, cmd: list[str], *, timeout: float = 120.0) -> tuple[int, str, str]:
    """Run an ImageMagick argv through the sandbox chokepoint."""
    from . import sandbox_run
    return sandbox_run(sandbox, cmd, timeout=timeout)


def _safe_path(sandbox, user_path: str) -> str:
    if user_path.startswith("-"):
        raise ValueError("paths may not begin with '-'")
    if sandbox is None:
        raise ValueError("image processing requires a workspace")
    workdir = Path(sandbox.workdir).resolve()
    candidate = (workdir / user_path).resolve()
    try:
        candidate.relative_to(workdir)
    except ValueError as e:
        raise ValueError(f"path {user_path!r} escapes the workspace") from e
    return str(candidate)


def _safe_convert_args(raw: Any) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or len(raw) > 16 or any(not isinstance(item, str) for item in raw):
        raise ValueError("invalid image options")
    safe = []
    i = 0
    while i < len(raw):
        flag = raw[i]
        if flag in {"-strip", "-auto-orient"}:
            safe.append(flag)
            i += 1
            continue
        if flag not in {"-quality", "-rotate", "-resize"} or i + 1 >= len(raw):
            raise ValueError("unsupported image option")
        value = raw[i + 1]
        if flag == "-quality":
            valid = len(value) <= 3 and value.isascii() and value.isdigit() and 1 <= int(value) <= 100
        elif flag == "-rotate":
            try:
                valid = bool(len(value) <= 10 and re.fullmatch(r"[+-]?[0-9]+(?:\.[0-9]+)?", value))
                degrees = float(value) if valid else 0.0
                valid = valid and math.isfinite(degrees) and -360 <= degrees <= 360
            except ValueError:
                valid = False
        else:
            match = re.fullmatch(r"([0-9]{1,4})?x([0-9]{1,4})?([!><^])?", value)
            valid = bool(match and (match.group(1) or match.group(2)) and all(
                part is None or 1 <= int(part) <= 8192 for part in match.group(1, 2)
            ))
            percent = re.fullmatch(r"([0-9]{1,4})%", value)
            valid = valid or bool(percent and 1 <= int(percent.group(1)) <= 1000)
        if not valid:
            raise ValueError("invalid image option value")
        safe.extend((flag, value))
        i += 2
    return safe


def _safe_output_path(sandbox, user_path: str) -> str:
    target = _safe_path(sandbox, user_path)
    lexical = user_path.replace("\\", "/").split("/")
    if any(part.rstrip(" .").casefold() == ".git" for part in (*lexical, *Path(target).parts)):
        raise ValueError("refusing to write under .git/")
    return target


def _op_resize(args: dict, sandbox) -> str:
    b = _magick_or_convert()
    if not b:
        return "ERROR: ImageMagick (magick/convert) not on PATH."
    src = (args.get("input_path") or "").strip()
    dst = (args.get("output_path") or "").strip()
    if not src or not dst:
        return "ERROR: resize requires input_path and output_path"
    try:
        src = _safe_path(sandbox, src)
        dst = _safe_output_path(sandbox, dst)
    except ValueError as e:
        return f"ERROR: {e}"
    w = int(args.get("width") or 0)
    h = int(args.get("height") or 0)
    if not (0 <= w <= 8192 and 0 <= h <= 8192):
        return "ERROR: image dimensions must be between 0 and 8192"
    # When neither dimension is given the f-string is "x" (truthy), so the
    # old `or "100%"` fallback never fired and ImageMagick got "-resize x".
    geom = f"{w or ''}x{h or ''}"
    if geom == "x":
        geom = "100%"
    cmd = [b] if b != "magick" else ["magick", "convert"]
    code, _o, stderr = _run_cmd(sandbox, cmd + [src, "-resize", geom, dst])
    if code != 0:
        return f"ERROR: resize ({code}): {stderr.strip()[-300:]}"
    return f"wrote {dst} ({geom})"


def _op_convert(args: dict, sandbox) -> str:
    b = _magick_or_convert()
    if not b:
        return "ERROR: ImageMagick not on PATH."
    src = (args.get("input_path") or "").strip()
    dst = (args.get("output_path") or "").strip()
    if not src or not dst:
        return "ERROR: convert requires input_path and output_path"
    try:
        src = _safe_path(sandbox, src)
        dst = _safe_output_path(sandbox, dst)
    except ValueError as e:
        return f"ERROR: {e}"
    cmd = [b] if b != "magick" else ["magick", "convert"]
    extra = _safe_convert_args(args.get("args"))
    code, _o, stderr = _run_cmd(sandbox, cmd + [src, *extra, dst])
    if code != 0:
        return f"ERROR: convert ({code}): {stderr.strip()[-300:]}"
    return f"wrote {dst}"


def _op_identify(args: dict, sandbox) -> str:
    b = _identify_bin()
    if not b:
        return "ERROR: ImageMagick identify not on PATH."
    src = (args.get("input_path") or "").strip()
    if not src:
        return "ERROR: identify requires input_path"
    try:
        src = _safe_path(sandbox, src)
    except ValueError as e:
        return f"ERROR: {e}"
    cmd = [b] if b != "magick" else ["magick", "identify"]
    code, out, stderr = _run_cmd(
        sandbox, cmd + ["-format", "%w %h %m %b %f\n", src],
    )
    if code != 0:
        return f"ERROR: identify ({code}): {stderr.strip()[-300:]}"
    line = out.strip().splitlines()[0] if out.strip() else ""
    parts = line.split()
    if len(parts) >= 4:
        w, h, fmt, size = parts[:4]
        return f"  {w}x{h}  format={fmt}  size={size}\n  path={src}"
    return out.strip()[:500]


def _op_composite(args: dict, sandbox) -> str:
    # Compositing is `magick composite` on IM7 but a SEPARATE `composite`
    # binary on IM6 -- `convert` (the IM6 fallback _magick_or_convert picks)
    # does not composite, so resolve the right binary explicitly.
    magick = _bin("magick")
    composite_bin = magick or _bin("composite")
    if not composite_bin:
        return ("ERROR: ImageMagick compositing needs the IM7 'magick' or "
                "IM6 'composite' binary on PATH.")
    base = (args.get("base_path") or "").strip()
    overlay = (args.get("overlay_path") or "").strip()
    dst = (args.get("output_path") or "").strip()
    if not base or not overlay or not dst:
        return "ERROR: composite requires base_path, overlay_path, output_path"
    try:
        base = _safe_path(sandbox, base)
        overlay = _safe_path(sandbox, overlay)
        dst = _safe_output_path(sandbox, dst)
    except ValueError as e:
        return f"ERROR: {e}"
    geom = (args.get("geometry") or "+0+0").strip()
    if not re.fullmatch(r"(?:[1-9][0-9]{0,3}x[1-9][0-9]{0,3})?(?:[+-][0-9]{1,5}){2}|[1-9][0-9]{0,3}x[1-9][0-9]{0,3}", geom):
        return "ERROR: invalid composite geometry"
    cmd = ["magick", "composite"] if magick else [composite_bin]
    code, _o, stderr = _run_cmd(
        sandbox, cmd + ["-geometry", geom, overlay, base, dst],
    )
    if code != 0:
        return f"ERROR: composite ({code}): {stderr.strip()[-300:]}"
    return f"wrote {dst}"


def _run(args: dict[str, Any], sandbox) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        handlers = {
            "resize": _op_resize,
            "convert": _op_convert,
            "identify": _op_identify,
            "composite": _op_composite,
        }
        fn = handlers.get(op)
        if not fn:
            return f"ERROR: unknown op {op!r}"
        return fn(args, sandbox)
    except Exception as e:
        return f"ERROR: imagemagick failed: {type(e).__name__}: {e}"


def imagemagick_tool(sandbox=None) -> Tool:
    return Tool(
        name="imagemagick",
        description=(
            "ImageMagick image ops. ops: resize (width x height), "
            "convert (basic bounded options), identify (w h fmt size), "
            "composite (overlay onto base with geometry). Uses "
            "magick (IM 7) or convert/identify (IM 6) on PATH."
        ),
        input_schema=_IM_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )
