"""Tests for the dep_graph tool (maverick.tools.dep_graph)."""
from __future__ import annotations

import pytest

# ---------- dep_graph tool ----------

@pytest.fixture
def small_repo(tmp_path):
    """A tiny three-file Python repo for the dep_graph tool to chew on."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("")
    (tmp_path / "pkg" / "a.py").write_text(
        "from pkg.b import helper\n\n"
        "def alpha():\n"
        "    return helper()\n"
    )
    (tmp_path / "pkg" / "b.py").write_text(
        "import os\n\n"
        "def helper():\n"
        "    return os.getcwd()\n\n"
        "class B:\n"
        "    pass\n"
    )
    (tmp_path / "main.py").write_text(
        "from pkg.a import alpha\n\n"
        "def main():\n"
        "    alpha()\n"
    )
    return tmp_path


def test_dep_graph_summary(small_repo):
    from maverick.tools.dep_graph import dep_graph

    class _Sandbox:
        workdir = str(small_repo)

    tool = dep_graph(_Sandbox())
    out = tool.fn({"view": "summary"})
    # 3 files with code + pkg/__init__.py (empty) = 4.
    assert "python files: 4" in out
    assert "top-level symbols" in out
    assert "import statements" in out


def test_dep_graph_import_graph(small_repo):
    from maverick.tools.dep_graph import dep_graph

    class _Sandbox:
        workdir = str(small_repo)

    out = dep_graph(_Sandbox()).fn({"view": "import_graph"})
    # main.py imports from pkg.a, pkg/a.py imports from pkg.b, pkg/b.py imports os.
    assert "main.py" in out and "pkg.a::alpha" in out
    assert "pkg/a.py" in out and "pkg.b::helper" in out
    assert "pkg/b.py" in out and "os" in out


def test_dep_graph_callers(small_repo):
    from maverick.tools.dep_graph import dep_graph

    class _Sandbox:
        workdir = str(small_repo)

    out = dep_graph(_Sandbox()).fn({"view": "callers", "symbol": "helper"})
    # pkg/a.py calls helper().
    assert "pkg/a.py" in out


def test_dep_graph_unknown_view():
    from maverick.tools.dep_graph import dep_graph

    class _Sandbox:
        workdir = "."

    out = dep_graph(_Sandbox()).fn({"view": "garbage"})
    assert "ERROR" in out


def test_dep_graph_skips_a_file_the_parser_cannot_handle(small_repo):
    from maverick.tools.dep_graph import dep_graph
    # 200,000 unary minuses overflow the parser stack (MemoryError on 3.12).
    (small_repo / "deep.py").write_text("x = " + "-" * 200_000 + "1\n")

    class _Sandbox:
        workdir = str(small_repo)

    out = dep_graph(_Sandbox()).fn({"view": "import_graph"})
    assert "pkg.a::alpha" in out
