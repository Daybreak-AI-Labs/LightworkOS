"""Image-content classifier.

A model-free, deterministic screen for images entering or leaving a run —
the chokepoint counterpart to the text floors. It reports measurable facts
about an image's pixels and an *advisory* flag, not a moral judgment:

  * skin-tone ratio — fraction of pixels in the classic skin chroma band
    (the standard cheap NSFW pre-filter; high ratio = route to a human or a
    real classifier, never auto-publish);
  * darkness / brightness extremes (all-black or blown-out captures are
    usually broken screenshots);
  * color diversity — distinguishes photographs (high diversity) from
    synthetic graphics / screenshots (low), which changes what checks apply;
  * dimensions sanity (1x1 tracking pixels, absurd aspect ratios).

Pixel math is pure Python over RGB triples, unit-testable without any
imaging dependency; the tool wrapper uses Pillow only to decode files
(`[computer-use]` extra) and degrades with a clear error when it's absent.

ops:
  - classify(file)                       — decode + classify an image file.
  - classify(pixels, width, height)      — classify raw RGB triples directly.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import Tool

_SKIN_FLAG_RATIO = 0.40   # advisory threshold: % skin-band pixels
_DARK_LUMA = 30.0         # mean luma below -> "very dark"
_BRIGHT_LUMA = 225.0      # mean luma above -> "blown out"


def _is_skin(r: int, g: int, b: int) -> bool:
    """Classic RGB skin-band heuristic (Peer et al.): cheap, deterministic,
    deliberately recall-leaning — it flags for *review*, it doesn't judge."""
    return (
        r > 95 and g > 40 and b > 20
        and (max(r, g, b) - min(r, g, b)) > 15
        and abs(r - g) > 15 and r > g and r > b
    )


def classify_pixels(pixels: list[tuple[int, int, int]], width: int, height: int) -> dict[str, Any]:
    """Pure pixel classification. ``pixels`` is row-major RGB triples."""
    n = len(pixels)
    if n == 0 or width <= 0 or height <= 0:
        raise ValueError("pixels must be non-empty and width/height positive")
    skin = 0
    luma_sum = 0.0
    buckets: set[tuple[int, int, int]] = set()
    for r, g, b in pixels:
        if _is_skin(r, g, b):
            skin += 1
        luma_sum += 0.2126 * r + 0.7152 * g + 0.0722 * b
        buckets.add((r // 32, g // 32, b // 32))

    skin_ratio = skin / n
    mean_luma = luma_sum / n
    # 512 possible 3-bit-per-channel buckets; photographs typically fill many.
    diversity = len(buckets) / 512.0
    aspect = width / height

    flags: list[str] = []
    if skin_ratio >= _SKIN_FLAG_RATIO:
        flags.append(f"high skin-tone ratio ({skin_ratio:.0%}) — route to human review")
    if mean_luma <= _DARK_LUMA:
        flags.append("very dark image (possible broken capture)")
    if mean_luma >= _BRIGHT_LUMA:
        flags.append("blown-out image (possible broken capture)")
    if width == 1 and height == 1:
        flags.append("1x1 pixel (tracking beacon)")
    if aspect > 20 or aspect < 0.05:
        flags.append(f"extreme aspect ratio ({width}x{height})")

    return {
        "width": width,
        "height": height,
        "skin_ratio": round(skin_ratio, 4),
        "mean_luma": round(mean_luma, 2),
        "color_diversity": round(diversity, 4),
        "kind": "photo-like" if diversity >= 0.08 else "graphic-like",
        "flags": flags,
        "verdict": "REVIEW" if flags else "OK",
    }


def _safe_image_path(sandbox: Any | None, path: str) -> Path:
    """Resolve image file paths inside the sandbox workspace.

    The image classifier is model-callable, so its file input must obey the
    same workspace confinement as filesystem tools: relative paths are resolved
    under ``sandbox.workdir`` (or the current working directory for standalone
    use), while absolute paths and ``..`` escapes are rejected.
    """
    workdir = Path(getattr(sandbox, "workdir", Path.cwd())).resolve()
    candidate = (workdir / path).resolve()
    try:
        candidate.relative_to(workdir)
    except ValueError as e:
        raise ValueError(f"path {path!r} escapes the workspace") from e
    return candidate


_MAX_FULL_DECODE_PIXELS = 50_000_000


def _classify_file(path: str, sandbox: Any | None = None) -> dict[str, Any] | str:
    try:
        target = _safe_image_path(sandbox, path)
    except ValueError as e:
        return f"ERROR: {e}"
    try:
        from PIL import Image
    except ImportError:
        return (
            "ERROR: Pillow not installed (from the reviewed checkout run: "
            "python -m pip install -e './packages/maverick-core[computer-use]') "
            "— or pass raw 'pixels' + 'width'/'height' instead of 'file'"
        )
    try:
        with Image.open(target) as im:
            # Downsample before converting so large inputs are bounded before
            # materializing RGB pixels in the host process. Only JPEG can
            # downsample while decoding (draft); other formats decode whole
            # first, so their size is capped here.
            if im.format != "JPEG" and im.width * im.height > _MAX_FULL_DECODE_PIXELS:
                return (f"ERROR: image is {im.width}x{im.height}; non-JPEG images over "
                        f"{_MAX_FULL_DECODE_PIXELS} pixels are not decoded")
            im.thumbnail((256, 256))
            im = im.convert("RGB")
            width, height = im.size
            pixels = list(im.getdata())
    except FileNotFoundError:
        return f"ERROR: no such file: {path}"
    except Exception as e:  # decode errors: corrupt/unsupported image
        return f"ERROR: cannot decode image: {e}"
    return classify_pixels(pixels, width, height)


def _render(result: dict[str, Any]) -> str:
    lines = [
        f"{result['width']}x{result['height']}  kind: {result['kind']}",
        f"skin_ratio: {result['skin_ratio']:.2%}  mean_luma: {result['mean_luma']}  "
        f"color_diversity: {result['color_diversity']:.2%}",
    ]
    if result["flags"]:
        lines.append("flags:")
        lines.extend(f"  - {f}" for f in result["flags"])
    lines.append(f"verdict: {result['verdict']}")
    return "\n".join(lines)


def _run(args: dict[str, Any], sandbox: Any | None = None) -> str:
    if args.get("op") not in (None, "classify"):
        return f"ERROR: unknown op {args.get('op')!r}"
    if args.get("file"):
        result = _classify_file(str(args["file"]), sandbox)
        if isinstance(result, str):
            return result
        return _render(result)
    pixels = args.get("pixels")
    if pixels is None:
        return "ERROR: provide 'file' or 'pixels' (+ width/height)"
    width = args.get("width")
    height = args.get("height")
    if not isinstance(width, int) or not isinstance(height, int):
        return "ERROR: width and height (integers) are required with pixels"
    try:
        triples = [(int(p[0]), int(p[1]), int(p[2])) for p in pixels]
        return _render(classify_pixels(triples, width, height))
    except (ValueError, TypeError, IndexError) as e:
        return f"ERROR: bad pixels: {e}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["classify"]},
        "file": {"type": "string", "description": "path to an image file (needs Pillow)"},
        "pixels": {"type": "array", "description": "raw RGB triples [[r,g,b], ...] (no Pillow needed)"},
        "width": {"type": "integer"},
        "height": {"type": "integer"},
    },
}


def image_content_classifier(sandbox: Any | None = None) -> Tool:
    return Tool(
        name="image_content_classifier",
        description=(
            "Model-free image content screen. op=classify with 'file' (Pillow) "
            "or raw 'pixels'+'width'+'height'. Reports skin-tone ratio (NSFW "
            "pre-filter — flags for human review), brightness extremes, "
            "photo-vs-graphic diversity, dimension sanity, and an OK/REVIEW "
            "verdict. Deterministic heuristics, not a moral judgment."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, sandbox),
        parallel_safe=True,
    )
