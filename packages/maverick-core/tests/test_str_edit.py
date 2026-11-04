"""Tests for the str_replace_editor tool (maverick.tools.str_edit)."""
from __future__ import annotations

import os

import pytest

# ---- str_replace_editor tool ----

class TestStrReplaceEditor:
    def _make_sandbox(self, tmp_path):
        class _Sandbox:
            workdir = tmp_path
        return _Sandbox()

    def test_view_file_returns_numbered_lines(self, tmp_path):
        from maverick.tools.str_edit import str_replace_editor
        (tmp_path / "foo.py").write_text("a\nb\nc\n")
        tool = str_replace_editor(self._make_sandbox(tmp_path))
        out = tool.fn({"command": "view", "path": "foo.py"})
        assert "1: a" in out
        assert "2: b" in out
        assert "3: c" in out

    def test_str_replace_exact_match_succeeds(self, tmp_path):
        from maverick.tools.str_edit import str_replace_editor
        (tmp_path / "foo.py").write_text("hello world\n")
        tool = str_replace_editor(self._make_sandbox(tmp_path))
        out = tool.fn({
            "command": "str_replace", "path": "foo.py",
            "old_str": "hello world", "new_str": "hello universe",
        })
        assert "edited" in out
        assert (tmp_path / "foo.py").read_text() == "hello universe\n"

    def test_str_replace_no_match_refuses(self, tmp_path):
        from maverick.tools.str_edit import str_replace_editor
        (tmp_path / "foo.py").write_text("hello world\n")
        tool = str_replace_editor(self._make_sandbox(tmp_path))
        out = tool.fn({
            "command": "str_replace", "path": "foo.py",
            "old_str": "goodbye", "new_str": "hi",
        })
        assert "ERROR" in out
        assert "not found" in out.lower()
        # File must be unchanged.
        assert (tmp_path / "foo.py").read_text() == "hello world\n"

    def test_str_replace_ambiguous_refuses(self, tmp_path):
        from maverick.tools.str_edit import str_replace_editor
        (tmp_path / "foo.py").write_text("x = 1\nx = 1\n")
        tool = str_replace_editor(self._make_sandbox(tmp_path))
        out = tool.fn({
            "command": "str_replace", "path": "foo.py",
            "old_str": "x = 1", "new_str": "x = 2",
        })
        assert "ambiguous" in out.lower()
        assert "2 times" in out
        # File must be unchanged.
        assert (tmp_path / "foo.py").read_text() == "x = 1\nx = 1\n"

    def test_str_replace_whitespace_drift_hint(self, tmp_path):
        from maverick.tools.str_edit import str_replace_editor
        # File has trailing whitespace on the line; user supplies the
        # trimmed version (does NOT match byte-for-byte, but DOES match
        # after rstrip-per-line normalisation).
        (tmp_path / "foo.py").write_text("def f():\n    return 1   \n")
        tool = str_replace_editor(self._make_sandbox(tmp_path))
        out = tool.fn({
            "command": "str_replace", "path": "foo.py",
            "old_str": "def f():\n    return 1\n",
            "new_str": "def f():\n    return 2\n",
        })
        assert "ERROR" in out
        assert "whitespace" in out.lower()

    def test_create_new_file(self, tmp_path):
        from maverick.tools.str_edit import str_replace_editor
        tool = str_replace_editor(self._make_sandbox(tmp_path))
        out = tool.fn({
            "command": "create", "path": "new.py",
            "file_text": "x = 42\n",
        })
        assert "created" in out
        assert (tmp_path / "new.py").read_text() == "x = 42\n"

    def test_create_refuses_overwrite(self, tmp_path):
        from maverick.tools.str_edit import str_replace_editor
        (tmp_path / "existing.py").write_text("old\n")
        tool = str_replace_editor(self._make_sandbox(tmp_path))
        out = tool.fn({
            "command": "create", "path": "existing.py",
            "file_text": "new\n",
        })
        assert "already exists" in out
        assert (tmp_path / "existing.py").read_text() == "old\n"


@pytest.fixture
def opaque_mode(monkeypatch):
    monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
    monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
    from maverick.coding_mode import reset_gold_patch_cache
    reset_gold_patch_cache()
    yield
    reset_gold_patch_cache()


class TestStrReplaceEditorOpacity:
    """str_replace_editor.view was the opacity backdoor — same
    file gating as read_file must apply."""

    def test_view_blocks_test_file_in_opaque(self, tmp_path, opaque_mode):
        from maverick.tools.str_edit import str_replace_editor
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_foo.py").write_text(
            "assert expected_value == 42\n"
        )

        class _Sandbox:
            workdir = tmp_path

        tool = str_replace_editor(_Sandbox())
        out = tool.fn({"command": "view", "path": "tests/test_foo.py"})
        assert "ERROR" in out
        assert "expected_value" not in out, (
            "test content leaked through view despite opaque mode"
        )

    def test_view_blocks_dotgit(self, tmp_path, opaque_mode):
        from maverick.tools.str_edit import str_replace_editor
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")

        class _Sandbox:
            workdir = tmp_path

        tool = str_replace_editor(_Sandbox())
        out = tool.fn({"command": "view", "path": ".git/HEAD"})
        assert "ERROR" in out
        assert "ref:" not in out

    def test_view_production_file_allowed(self, tmp_path, opaque_mode):
        from maverick.tools.str_edit import str_replace_editor
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("def f():\n    return 1\n")

        class _Sandbox:
            workdir = tmp_path

        tool = str_replace_editor(_Sandbox())
        out = tool.fn({"command": "view", "path": "src/app.py"})
        assert "ERROR" not in out
        assert "def f" in out


class TestSymlinkBypass:
    """Symlink to .git or tests/ must still be
    blocked by the resolved-path check."""

    @pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink requires admin/Developer Mode on Windows (WinError 1314)",
    )
    def test_symlink_to_tests_blocked_in_view(self, tmp_path, opaque_mode):
        import os as _os

        from maverick.tools.str_edit import str_replace_editor
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_foo.py").write_text(
            "assert expected_value == 42\n"
        )
        _os.symlink("tests", tmp_path / "looks_like_src")

        class _Sandbox:
            workdir = tmp_path

        tool = str_replace_editor(_Sandbox())
        out = tool.fn({"command": "view", "path": "looks_like_src/test_foo.py"})
        assert "ERROR" in out
        assert "expected_value" not in out
