"""Tests for the cross_repo_deps tool (maverick.tools.cross_repo_deps)."""
from __future__ import annotations

import textwrap

from maverick.tools.cross_repo_deps import cross_repo_deps


class _FakeSandbox:
    def __init__(self, workdir):
        self.workdir = str(workdir)


# ---- cross_repo_deps ----

def _write(p, rel, body):
    f = p / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(textwrap.dedent(body))


def test_cross_repo_graph_and_cross_root(tmp_path):
    root_a = tmp_path / "repoA"
    root_b = tmp_path / "repoB"
    _write(root_a, "pkga/__init__.py", "")
    _write(root_a, "pkga/main.py", "import pkgb\n")          # cross-root edge
    _write(root_b, "pkgb/__init__.py", "")
    _write(root_b, "pkgb/util.py", "x = 1\n")
    t = cross_repo_deps(_FakeSandbox(tmp_path))
    out = t.fn({"op": "graph", "paths": ["repoA", "repoB"]})
    assert "pkga -> pkgb" in out and "[cross-root]" in out


def test_cross_repo_cycles(tmp_path):
    root = tmp_path / "mono"
    _write(root, "p/__init__.py", "import q\n")
    _write(root, "q/__init__.py", "import p\n")
    t = cross_repo_deps(_FakeSandbox(tmp_path))
    out = t.fn({"op": "cycles", "paths": ["mono"]})
    assert "p <-> q" in out or "q <-> p" in out


def test_cross_repo_requires_existing_dir(tmp_path):
    t = cross_repo_deps(_FakeSandbox(tmp_path))
    assert t.fn({"op": "graph", "paths": ["/no/such/dir"]}).startswith("ERROR")


def test_cross_repo_rejects_workspace_escape(tmp_path):
    inside = tmp_path / "inside"
    outside = tmp_path.parent / f"{tmp_path.name}_outside"
    _write(inside, "pkga/__init__.py", "import secretpkg\n")
    _write(outside, "secretpkg/__init__.py", "import os\n")
    t = cross_repo_deps(_FakeSandbox(tmp_path))

    out = t.fn({"op": "graph", "paths": [str(outside)]})

    assert out.startswith("ERROR")
    assert "escapes the workspace" in out
