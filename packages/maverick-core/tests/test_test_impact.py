"""Tests for the test_impact tool (maverick.tools.test_impact)."""
from __future__ import annotations

# ---------- test_impact ----------

def _seed_repo(tmp_path):
    (tmp_path / "src" / "pkg").mkdir(parents=True)
    (tmp_path / "src" / "pkg" / "foo.py").write_text("def foo(): pass\n")
    (tmp_path / "src" / "pkg" / "bar.py").write_text("def bar(): pass\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_foo.py").write_text(
        "from src.pkg.foo import foo\n\ndef test_foo(): foo()\n"
    )
    (tmp_path / "tests" / "test_bar.py").write_text(
        "from src.pkg.bar import bar\n\ndef test_bar(): bar()\n"
    )
    (tmp_path / "tests" / "test_unrelated.py").write_text(
        "def test_x(): pass\n"
    )


def test_test_impact_requires_op():
    from maverick.tools.test_impact import test_impact
    assert "op is required" in test_impact().fn({})


def test_test_impact_analyze_files(tmp_path, monkeypatch):
    _seed_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    from maverick.tools.test_impact import test_impact
    out = test_impact().fn({
        "op": "analyze_files",
        "paths": ["src/pkg/foo.py"],
    })
    assert "test_foo.py" in out
    assert "test_bar.py" not in out
    assert "test_unrelated.py" not in out


def test_test_impact_parses_unified_diff(tmp_path, monkeypatch):
    _seed_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    diff = """diff --git a/src/pkg/bar.py b/src/pkg/bar.py
--- a/src/pkg/bar.py
+++ b/src/pkg/bar.py
@@ -1 +1 @@
-def bar(): pass
+def bar(): return 1
"""
    from maverick.tools.test_impact import test_impact
    out = test_impact().fn({
        "op": "analyze",
        "diff": diff,
    })
    assert "test_bar.py" in out
    assert "test_foo.py" not in out


def test_test_impact_empty_diff(tmp_path, monkeypatch):
    _seed_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    from maverick.tools.test_impact import test_impact
    out = test_impact().fn({
        "op": "analyze", "diff": "",
    })
    assert "no changed files" in out


def test_test_impact_no_test_dir(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    from maverick.tools.test_impact import test_impact
    out = test_impact().fn({
        "op": "analyze_files",
        "paths": ["src/x.py"],
    })
    assert "no test directories" in out


def test_test_impact_scans_the_sandbox_workdir_not_cwd(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from maverick.tools.test_impact import test_impact
    ws = tmp_path / "ws"
    ws.mkdir()
    _seed_repo(ws)
    monkeypatch.chdir(tmp_path)  # the server's cwd has no tests
    out = test_impact(SimpleNamespace(workdir=ws)).fn(
        {"op": "analyze_files", "paths": ["src/pkg/foo.py"]})
    assert "test_foo.py" in out
