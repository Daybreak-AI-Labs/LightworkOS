"""Tests for the model3d_inspect tool (maverick.tools.model3d_inspect)."""
from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest
from maverick.tools.model3d_inspect import model3d_inspect

# ---- model3d_inspect ----

_ASCII_STL = """solid cube
facet normal 0 0 0
  outer loop
    vertex 0 0 0
    vertex 1 0 0
    vertex 0 2 0
  endloop
endfacet
facet normal 0 0 0
  outer loop
    vertex 0 0 0
    vertex 0 0 3
    vertex 1 0 0
  endloop
endfacet
endsolid cube
"""


def test_inspect_ascii_stl(tmp_path):
    f = tmp_path / "m.stl"
    f.write_text(_ASCII_STL)
    out = model3d_inspect(SimpleNamespace(workdir=tmp_path)).fn({"op": "inspect", "path": f.name})
    assert "format: STL (ascii)" in out
    assert "triangles: 2" in out
    assert "vertices: 6" in out
    assert "dimensions (w,h,d): (1, 2, 3)" in out


def test_inspect_binary_stl(tmp_path):
    # 1 triangle: normal + 3 verts spanning (0,0,0)-(4,5,6)
    tri = struct.pack("<12f", 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 5, 6) + b"\x00\x00"
    data = b"\x00" * 80 + struct.pack("<I", 1) + tri
    f = tmp_path / "m.stl"
    f.write_bytes(data)
    out = model3d_inspect(SimpleNamespace(workdir=tmp_path)).fn({"op": "inspect", "path": f.name})
    assert "format: STL (binary)" in out
    assert "triangles: 1" in out and "vertices: 3" in out
    assert "dimensions (w,h,d): (4, 5, 6)" in out


def test_inspect_obj(tmp_path):
    f = tmp_path / "m.obj"
    f.write_text("v 0 0 0\nv 2 0 0\nv 0 2 0\nf 1 2 3\n")
    out = model3d_inspect(SimpleNamespace(workdir=tmp_path)).fn({"op": "inspect", "path": f.name})
    assert "format: OBJ" in out and "vertices: 3" in out and "faces: 1" in out


def test_inspect_errors(tmp_path):
    tool = model3d_inspect(SimpleNamespace(workdir=tmp_path))
    assert tool.fn({"op": "inspect", "path": ""}).startswith("ERROR")
    assert tool.fn({"op": "inspect", "path": "/no/such.stl"}).startswith("ERROR")
    bad = tmp_path / "x.png"
    bad.write_text("x")
    assert "only .stl and .obj" in tool.fn({"op": "inspect", "path": bad.name})


def test_inspect_rejects_paths_outside_workspace(tmp_path):
    outside = tmp_path.parent / "outside.obj"
    outside.write_text("v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n")
    tool = model3d_inspect(SimpleNamespace(workdir=tmp_path))

    assert "path escapes workspace" in tool.fn({"op": "inspect", "path": str(outside)})


def test_inspect_rejects_symlink_escape(tmp_path):
    outside = tmp_path.parent / "outside_symlink.obj"
    outside.write_text("v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n")
    link = tmp_path / "linked.obj"
    try:
        link.symlink_to(outside)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlinks unavailable on this host: {exc}")
    tool = model3d_inspect(SimpleNamespace(workdir=tmp_path))

    assert "path escapes workspace" in tool.fn({"op": "inspect", "path": link.name})
