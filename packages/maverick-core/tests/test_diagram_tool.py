"""Diagramming tool."""
from __future__ import annotations

import shlex
from pathlib import Path

from maverick.tools.diagram_tool import _argv, diagram_tool


class _FakeSandbox:
    """Creates the renderer's -o output target on success.

    ``workdir`` is the confinement root the tool resolves ``out`` against."""

    def __init__(self, workdir=".", succeed=True):
        self.workdir = str(workdir)
        self.succeed = succeed

    def exec(self, cmd, timeout=None):
        if self.succeed:
            toks = shlex.split(cmd)
            if "-o" in toks:
                Path(toks[toks.index("-o") + 1]).write_text("<svg/>", encoding="utf-8")

        class R:
            pass
        r = R()
        r.exit_code = 0 if self.succeed else 127
        r.stdout, r.stderr = "", "" if self.succeed else "not found"
        return r


def test_argv_dot():
    assert _argv("dot", "in.dot", "out.svg", "svg") == [
        "dot", "-Tsvg", "in.dot", "-o", "out.svg"]


def test_argv_mermaid():
    assert _argv("mermaid", "in.mmd", "out.png", "png") == [
        "mmdc", "-i", "in.mmd", "-o", "out.png"]


def test_render_dot_success(tmp_path):
    # `out` is workspace-relative; it lands under the sandbox workdir.
    res = diagram_tool(_FakeSandbox(tmp_path)).fn(
        {"engine": "dot", "source": "digraph{a->b}", "out": "g.svg"})
    assert "rendered dot diagram" in res
    assert (tmp_path / "g.svg").exists()


def test_render_invalid_engine():
    res = diagram_tool(_FakeSandbox()).fn({"engine": "bogus", "source": "x"})
    assert res.startswith("ERROR") and "engine" in res


def test_render_invalid_format():
    res = diagram_tool(_FakeSandbox()).fn(
        {"engine": "dot", "source": "digraph{}", "format": "gif"})
    assert res.startswith("ERROR") and "format" in res


def test_render_binary_missing(tmp_path):
    res = diagram_tool(_FakeSandbox(tmp_path, succeed=False)).fn(
        {"engine": "mermaid", "source": "graph TD; A-->B", "out": "d.svg"})
    assert res.startswith("ERROR") and "installed" in res


def test_empty_source():
    assert diagram_tool(_FakeSandbox()).fn(
        {"engine": "dot", "source": "  "}).startswith("ERROR")


def test_out_escaping_workspace_is_rejected(tmp_path):
    # A model-supplied absolute/`..` `out` must not write outside the sandbox.
    res = diagram_tool(_FakeSandbox(tmp_path)).fn(
        {"engine": "dot", "source": "digraph{a->b}", "out": "../escaped.svg"})
    assert res.startswith("ERROR") and "escape" in res.lower()
    assert not (tmp_path.parent / "escaped.svg").exists()


def test_non_string_engine_does_not_crash(tmp_path):
    fn = diagram_tool(_FakeSandbox(tmp_path)).fn
    assert fn({"engine": 5, "source": "digraph{a}"}).startswith("ERROR")


def test_non_string_source_does_not_crash(tmp_path):
    # Non-string source is coerced to str; must return a string, never raise.
    fn = diagram_tool(_FakeSandbox(tmp_path)).fn
    out = fn({"engine": "dot", "source": 5})
    assert isinstance(out, str)
    assert not out.startswith("Traceback")


def test_out_under_git_dir_is_refused(tmp_path):
    """The rendered image is a model-chosen write; like every other workspace
    writer it must not land in .git/ (repo metadata corruption)."""
    (tmp_path / ".git").mkdir()
    out = diagram_tool(_FakeSandbox(tmp_path)).fn(
        {"engine": "dot", "source": "digraph{a}", "out": ".git/config"})
    assert out.startswith("ERROR") and ".git" in out
    assert not (tmp_path / ".git" / "config").exists()


def test_render_removes_its_temp_dir(tmp_path, monkeypatch):
    import tempfile
    made: list[str] = []
    real = tempfile.mkdtemp

    def _track(*a, **kw):
        made.append(real(*a, dir=tmp_path, **kw))
        return made[-1]

    monkeypatch.setattr(tempfile, "mkdtemp", _track)
    for ok in (True, False):
        diagram_tool(_FakeSandbox(tmp_path, succeed=ok)).fn(
            {"engine": "dot", "source": "digraph{a->b}", "out": "g.svg"})
    assert len(made) == 2 and not any(Path(d).exists() for d in made)
