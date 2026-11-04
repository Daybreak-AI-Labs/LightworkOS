"""Tests for the ast_edit tool (maverick.tools.ast_edit)."""
from __future__ import annotations

import pytest

# ---------- ast_edit tool ----------

@pytest.fixture
def ast_workdir(tmp_path):
    (tmp_path / "module.py").write_text(
        '"""A test module."""\n'
        "import os\n"
        "\n"
        "def alpha(x):\n"
        "    return x + 1\n"
        "\n"
        "class Beta:\n"
        "    def m(self):\n"
        "        return alpha(1)\n"
    )
    return tmp_path


def test_ast_edit_info(ast_workdir):
    from maverick.tools.ast_edit import ast_edit

    class _Sandbox:
        workdir = str(ast_workdir)

    out = ast_edit(_Sandbox()).fn({"op": "info", "path": "module.py"})
    assert "alpha" in out
    assert "Beta" in out
    assert "import os" in out


def test_ast_edit_rename_symbol(ast_workdir):
    from maverick.tools.ast_edit import ast_edit

    class _Sandbox:
        workdir = str(ast_workdir)

    out = ast_edit(_Sandbox()).fn({
        "op": "rename_symbol", "path": "module.py",
        "old_name": "alpha", "new_name": "renamed",
    })
    assert "wrote module.py" in out
    body = (ast_workdir / "module.py").read_text()
    assert "def renamed" in body
    assert "alpha" not in body
    # Class method's call to alpha() was renamed too (whole-word).
    assert "renamed(1)" in body


def test_ast_edit_rename_rejects_invalid_identifier(ast_workdir):
    from maverick.tools.ast_edit import ast_edit

    class _Sandbox:
        workdir = str(ast_workdir)

    out = ast_edit(_Sandbox()).fn({
        "op": "rename_symbol", "path": "module.py",
        "old_name": "alpha", "new_name": "not-an-identifier",
    })
    assert "ERROR" in out
    # File unchanged.
    assert "def alpha" in (ast_workdir / "module.py").read_text()


def test_ast_edit_add_import_idempotent(ast_workdir):
    from maverick.tools.ast_edit import ast_edit

    class _Sandbox:
        workdir = str(ast_workdir)

    tool = ast_edit(_Sandbox())
    out1 = tool.fn({"op": "add_import", "path": "module.py",
                    "import_line": "import sys"})
    assert "wrote" in out1
    body1 = (ast_workdir / "module.py").read_text()
    assert "import sys" in body1
    tool.fn({"op": "add_import", "path": "module.py",
             "import_line": "import sys"})
    body2 = (ast_workdir / "module.py").read_text()
    # Second add is a no-op (length unchanged).
    assert body1 == body2


def test_ast_edit_remove_symbol(ast_workdir):
    from maverick.tools.ast_edit import ast_edit

    class _Sandbox:
        workdir = str(ast_workdir)

    out = ast_edit(_Sandbox()).fn({
        "op": "remove_symbol", "path": "module.py", "symbol": "alpha",
    })
    assert "wrote" in out
    body = (ast_workdir / "module.py").read_text()
    assert "def alpha" not in body
    # Class still there.
    assert "class Beta" in body


def test_ast_edit_dry_run_does_not_write(ast_workdir):
    from maverick.tools.ast_edit import ast_edit

    class _Sandbox:
        workdir = str(ast_workdir)

    before = (ast_workdir / "module.py").read_text()
    out = ast_edit(_Sandbox()).fn({
        "op": "rename_symbol", "path": "module.py",
        "old_name": "alpha", "new_name": "renamed",
        "dry_run": True,
    })
    assert "DRY RUN" in out
    after = (ast_workdir / "module.py").read_text()
    assert before == after


def test_ast_edit_rejects_path_traversal(ast_workdir):
    from maverick.tools.ast_edit import ast_edit

    class _Sandbox:
        workdir = str(ast_workdir)

    out = ast_edit(_Sandbox()).fn({
        "op": "info", "path": "../escape.py",
    })
    assert "path traversal" in out.lower()
