"""Regression: file/path/source tools must not crash on non-string model args.

Each of these takes a path/patch/source straight from the model; a non-string
value (int/list/dict) must not raise an uncaught AttributeError/TypeError.
"""
from __future__ import annotations


class _Sandbox:
    def __init__(self, workdir):
        self.workdir = str(workdir)


def test_ast_edit_non_string_path(tmp_path):
    from maverick.tools.ast_edit import ast_edit
    fn = ast_edit(_Sandbox(tmp_path)).fn
    for v in (5, 1.5, True, [1, 2, 3], {"a": 1}):
        out = fn({"op": "info", "path": v})
        assert isinstance(out, str)
        assert out.startswith("ERROR")


def test_apply_patch_non_string_patch(tmp_path):
    from maverick.tools.apply_patch import apply_patch
    fn = apply_patch(_Sandbox(tmp_path)).fn
    for v in (5, 1.5, True, [1, 2, 3], {"a": 1}):
        out = fn({"patch": v})
        assert isinstance(out, str)
        assert out.startswith("ERROR")


def test_cross_repo_deps_non_list_paths(tmp_path):
    from maverick.tools.cross_repo_deps import cross_repo_deps
    fn = cross_repo_deps(_Sandbox(tmp_path)).fn
    for v in (5, 1.5, True):
        out = fn({"op": "graph", "paths": v})
        assert isinstance(out, str)
        assert out.startswith("ERROR")


def test_model3d_inspect_non_string_path(tmp_path):
    from maverick.tools.model3d_inspect import model3d_inspect
    fn = model3d_inspect(_Sandbox(tmp_path)).fn
    for v in (5, 1.5, True, [1, 2, 3], {"a": 1}):
        out = fn({"op": "inspect", "path": v})
        assert isinstance(out, str)
        assert out.startswith("ERROR")
