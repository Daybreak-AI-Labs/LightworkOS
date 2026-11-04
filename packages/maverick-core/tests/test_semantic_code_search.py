"""Tests for the semantic_code_search tool (maverick.tools.semantic_code_search)."""
from __future__ import annotations

import textwrap

from maverick.tools.semantic_code_search import semantic_code_search

# ---- semantic_code_search ----

def test_search_ranks_by_intent(tmp_path):
    f = tmp_path / "mod.py"
    f.write_text(textwrap.dedent('''
        def parse_csv_file(path):
            """Read a CSV file and return rows."""
            return []

        def send_email(to, body):
            """Deliver an email message to a recipient."""
            return True
    '''))
    t = semantic_code_search()
    out = t.fn({"op": "search", "paths": [str(f)], "query": "read csv rows from file"})
    top = out.splitlines()[0]
    assert "parse_csv_file" in top and "send_email" not in top


def test_search_splits_camel_and_snake(tmp_path):
    f = tmp_path / "m.py"
    f.write_text("def loadUserProfile():\n    pass\n")
    t = semantic_code_search()
    out = t.fn({"op": "search", "paths": [str(f)], "query": "load user profile"})
    assert "loadUserProfile" in out


def test_search_requires_query_and_paths():
    t = semantic_code_search()
    assert t.fn({"op": "search", "paths": [], "query": "x"}).startswith("ERROR")
    assert t.fn({"op": "search", "paths": ["/tmp"], "query": ""}).startswith("ERROR")


def test_search_registered_tool_confines_paths_to_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    inside = workspace / "inside.py"
    inside.write_text("def find_inside_workspace():\n    pass\n")
    outside = tmp_path / "outside.py"
    outside.write_text("def leak_outside_workspace():\n    pass\n")

    class _Sandbox:
        workdir = workspace

    t = semantic_code_search(_Sandbox())
    assert "find_inside_workspace" in t.fn({"op": "search", "paths": ["inside.py"], "query": "inside workspace"})
    out = t.fn({"op": "search", "paths": [str(outside)], "query": "outside workspace"})
    assert out.startswith("ERROR")
    assert "escapes the workspace" in out


def test_search_rejects_non_python_and_special_files():
    t = semantic_code_search()
    assert t.fn({"op": "search", "paths": ["/dev/zero"], "query": "anything"}).startswith("ERROR")
