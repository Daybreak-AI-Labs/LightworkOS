"""3D model inspector tool.

A headless "viewer": instead of rendering pixels, it parses a 3D mesh file and
reports the structural facts an agent actually reasons over — triangle/vertex
counts, the axis-aligned bounding box, and the model's dimensions — for STL
(ASCII and binary) and OBJ. Pure parsing, no GPU, no external lib.

ops:
  - inspect(path)  — summary stats for the mesh at ``path``.
"""
from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any

from . import Tool

_MAX_BYTES = 80 * 1024 * 1024  # refuse absurd files


class _Bounds:
    """Incrementally track vertex count and an axis-aligned bounding box."""

    def __init__(self) -> None:
        self.count = 0
        self.min_x = self.min_y = self.min_z = float("inf")
        self.max_x = self.max_y = self.max_z = float("-inf")

    def add(self, x: float, y: float, z: float) -> None:
        self.count += 1
        self.min_x = min(self.min_x, x)
        self.min_y = min(self.min_y, y)
        self.min_z = min(self.min_z, z)
        self.max_x = max(self.max_x, x)
        self.max_y = max(self.max_y, y)
        self.max_z = max(self.max_z, z)

    def render(self) -> str:
        dim = (
            round(self.max_x - self.min_x, 4),
            round(self.max_y - self.min_y, 4),
            round(self.max_z - self.min_z, 4),
        )
        return (
            f"bbox_min: ({self.min_x:.4g}, {self.min_y:.4g}, {self.min_z:.4g})\n"
            f"bbox_max: ({self.max_x:.4g}, {self.max_y:.4g}, {self.max_z:.4g})\n"
            f"dimensions (w,h,d): ({dim[0]:g}, {dim[1]:g}, {dim[2]:g})"
        )


def _parse_obj(text: str) -> tuple[int, int, _Bounds]:
    bounds = _Bounds()
    faces = 0
    for line in text.splitlines():
        if line.startswith("v "):
            parts = line.split()
            if len(parts) >= 4:
                try:
                    bounds.add(float(parts[1]), float(parts[2]), float(parts[3]))
                except ValueError:
                    continue
        elif line.startswith("f "):
            faces += 1
    return bounds.count, faces, bounds


def _parse_ascii_stl(text: str) -> tuple[int, _Bounds]:
    bounds = _Bounds()
    facets = 0
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("vertex"):
            parts = s.split()
            if len(parts) >= 4:
                try:
                    bounds.add(float(parts[1]), float(parts[2]), float(parts[3]))
                except ValueError:
                    continue
        elif s.startswith("facet"):
            facets += 1
    return facets, bounds


def _parse_binary_stl(data: bytes) -> tuple[int, _Bounds]:
    if len(data) < 84:
        return 0, _Bounds()
    (count,) = struct.unpack_from("<I", data, 80)
    bounds = _Bounds()
    off = 84
    n = min(count, (len(data) - 84) // 50)
    for _ in range(n):
        # 12 floats: normal(3) + v1(3) + v2(3) + v3(3), then 2-byte attr.
        vals = struct.unpack_from("<12f", data, off)
        bounds.add(vals[3], vals[4], vals[5])
        bounds.add(vals[6], vals[7], vals[8])
        bounds.add(vals[9], vals[10], vals[11])
        off += 50
    return n, bounds


def _inspect(path: str) -> str:
    size = os.path.getsize(path)
    if size > _MAX_BYTES:
        return f"ERROR: file too large ({size} bytes)"
    ext = os.path.splitext(path)[1].lower()
    with open(path, "rb") as f:
        data = f.read()

    if ext == ".obj":
        nv, nf, bounds = _parse_obj(data.decode("utf-8", errors="replace"))
        if bounds.count == 0:
            return "ERROR: no vertices found in OBJ"
        return f"format: OBJ\nvertices: {nv}\nfaces: {nf}\n{bounds.render()}"

    # STL: detect ASCII vs binary. ASCII starts with 'solid' AND contains 'facet'.
    head = data[:512].decode("ascii", errors="replace").lower()
    is_ascii = head.lstrip().startswith("solid") and "facet" in \
        data[:4096].decode("ascii", errors="replace").lower()
    if is_ascii:
        facets, bounds = _parse_ascii_stl(data.decode("ascii", errors="replace"))
    else:
        facets, bounds = _parse_binary_stl(data)
    if bounds.count == 0:
        return "ERROR: no triangles found in STL"
    return (
        f"format: STL ({'ascii' if is_ascii else 'binary'})\n"
        f"triangles: {facets}\nvertices: {bounds.count}\n{bounds.render()}"
    )


def _resolve_path(path: str, workdir: Path) -> tuple[Path | None, str | None]:
    raw = Path(path)
    if raw.suffix.lower() not in {".stl", ".obj"}:
        return None, "ERROR: only .stl and .obj are supported"
    candidate = raw.resolve() if raw.is_absolute() else (workdir / raw).resolve()
    try:
        candidate.relative_to(workdir)
    except ValueError:
        return None, f"ERROR: path escapes workspace: {path}"
    if not candidate.is_file():
        return None, f"ERROR: no such file: {path}"
    return candidate, None


def _run(args: dict[str, Any], workdir: Path | None = None) -> str:
    if args.get("op") not in (None, "inspect"):
        return f"ERROR: unknown op {args.get('op')!r}"
    path = str(args.get("path") or "").strip()
    if not path:
        return "ERROR: path is required"
    root = (workdir or Path.cwd()).resolve()
    resolved, error = _resolve_path(path, root)
    if error is not None:
        return error
    assert resolved is not None
    try:
        return _inspect(str(resolved))
    except Exception as e:  # pragma: no cover - defensive
        return f"ERROR: parse failed: {type(e).__name__}: {e}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["inspect"]},
        "path": {"type": "string", "description": "path to a .stl or .obj mesh"},
    },
    "required": ["path"],
}


def model3d_inspect(sandbox: Any = None) -> Tool:
    workdir = Path(getattr(sandbox, "workdir", Path.cwd())).resolve()
    return Tool(
        name="model3d_inspect",
        description=(
            "Inspect a 3D mesh file (.stl ASCII/binary, .obj) without a GPU: "
            "reports triangle/vertex counts, the axis-aligned bounding box, and "
            "the model's width/height/depth. op=inspect with a 'path'."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, workdir),
        parallel_safe=False,
    )
