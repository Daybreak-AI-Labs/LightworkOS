"""Diagramming tool."""
from __future__ import annotations

import shlex
from pathlib import Path

from maverick.tools.diagram_tool import _argv, diagram_tool


class _FakeSandbox:
    """Creates the renderer's -o output target on success.

    ``workdir`` is the confinement root the tool resolves ``out`` against, and
    the only directory the command can see: like a container that mounts the
    workspace at its own root, it resolves paths against ``workdir``."""

    def __init__(self, workdir=".", succeed=True, partial=False):
        self.workdir = str(workdir)
        self.succeed = succeed
        self.partial = partial  # a failing renderer that had begun to write
        self.commands: list[list[str]] = []

    def exec(self, cmd, timeout=None):
        toks = shlex.split(cmd)
        self.commands.append(toks)
        if self.succeed or self.partial:
            if "-o" in toks:
                target = toks[toks.index("-o") + 1]
                assert not Path(target).is_absolute(), target
                (Path(self.workdir) / target).write_text("<svg/>", encoding="utf-8")

        class R:
            pass
        r = R()
        r.exit_code = 0 if self.succeed else 127
        r.stdout, r.stderr = "", "" if self.succeed else "not found"
        return r


def test_argv_dot():
    # No input file: the source arrives on standard input.
    assert _argv("dot", "./out.svg", "svg") == ["dot", "-Tsvg", "-o", "./out.svg"]


def test_argv_mermaid():
    assert _argv("mermaid", "./out.png", "png") == ["mmdc", "-i", "-", "-o", "./out.png"]


def test_render_gives_the_sandbox_no_host_path(tmp_path):
    """A container sees the workspace at its own root, not at its host path, and
    never sees the host's temp folder: the source goes in on standard input and
    the renderer writes the workspace-relative output itself."""
    import base64

    sandbox = _FakeSandbox(tmp_path)
    source = "digraph{a->b}"
    res = diagram_tool(sandbox).fn({"engine": "dot", "source": source, "out": "sub/g.svg"})

    assert "rendered dot diagram" in res
    assert (tmp_path / "sub" / "g.svg").read_text(encoding="utf-8") == "<svg/>"
    [toks] = sandbox.commands
    # Rendered under a temporary name beside the output, then moved into place.
    assert toks[-4:-1] == ["dot", "-Tsvg", "-o"]
    assert toks[-1].startswith("./sub/.g.") and toks[-1].endswith(".svg")
    assert not any(Path(tok).is_absolute() for tok in toks)
    assert base64.b64decode(toks[toks.index("%s") + 1]).decode() == source
    # Nothing but the result is left in the workspace.
    assert sorted(p.name for p in tmp_path.rglob("*")) == ["g.svg", "sub"]


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


def test_render_leaves_no_temp_files(tmp_path, monkeypatch):
    import tempfile

    def _no_temp(*a, **kw):
        raise AssertionError("the diagram tool must not stage files on the host")

    monkeypatch.setattr(tempfile, "mkdtemp", _no_temp)
    for ok in (False, True):
        diagram_tool(_FakeSandbox(tmp_path, succeed=ok)).fn(
            {"engine": "dot", "source": "digraph{a->b}", "out": "g.svg"})
        assert [p.name for p in tmp_path.iterdir()] == (["g.svg"] if ok else [])


def test_mermaid_output_name_needs_no_particular_ending(tmp_path):
    """mmdc insists on a name ending in the format, so it renders to such a
    name and the result is moved to the name that was asked for."""
    sandbox = _FakeSandbox(tmp_path)
    for name in ("arch", "arch.mmd.out"):
        res = diagram_tool(sandbox).fn(
            {"engine": "mermaid", "source": "graph TD; A-->B", "out": name, "format": "png"})
        assert "rendered mermaid diagram" in res, res
        assert (tmp_path / name).read_text(encoding="utf-8") == "<svg/>"
        assert sandbox.commands[-1][-1].endswith(".png")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["arch", "arch.mmd.out"]


def test_failed_render_leaves_an_existing_output_untouched(tmp_path):
    (tmp_path / "g.svg").write_text("the last good render", encoding="utf-8")
    res = diagram_tool(_FakeSandbox(tmp_path, succeed=False, partial=True)).fn(
        {"engine": "dot", "source": "digraph{a->", "out": "g.svg"})
    assert res.startswith("ERROR")
    assert (tmp_path / "g.svg").read_text(encoding="utf-8") == "the last good render"
    assert [p.name for p in tmp_path.iterdir()] == ["g.svg"]  # no half-written file left
