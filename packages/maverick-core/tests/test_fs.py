"""Tests for the file-system tools (maverick.tools.fs) in opaque benchmark mode."""
from __future__ import annotations

import os

import pytest

# ---- read_file refuses tests in benchmark opaque mode ----

class TestReadFileOpaqueGuard:
    def _make_sandbox(self, tmp_path):
        class _Sandbox:
            workdir = tmp_path
        return _Sandbox()

    def test_read_test_file_blocked_when_opaque(self, tmp_path, monkeypatch):
        from maverick.tools.fs import read_file
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_foo.py").write_text("assert x == 42")
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = read_file(self._make_sandbox(tmp_path))
        out = tool.fn({"path": "tests/test_foo.py"})
        assert "blocked" in out.lower()
        assert "x == 42" not in out

    def test_read_production_file_still_works(self, tmp_path, monkeypatch):
        from maverick.tools.fs import read_file
        (tmp_path / "src.py").write_text("def f(): return 42")
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = read_file(self._make_sandbox(tmp_path))
        out = tool.fn({"path": "src.py"})
        assert "return 42" in out

    def test_opaque_off_allows_test_reads(self, tmp_path, monkeypatch):
        from maverick.tools.fs import read_file
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_foo.py").write_text("assert x == 42")
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "0")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = read_file(self._make_sandbox(tmp_path))
        out = tool.fn({"path": "tests/test_foo.py"})
        assert "x == 42" in out


@pytest.fixture(autouse=True)
def _shell_consented(fresh_human_decision):
    """These tests exercise git-internals BLOCKING through the shell tool;
    the shell's exact-approval permit needs a fresh human decision, which
    the shared fixture supplies so the blocking rules are what is tested."""
    del fresh_human_decision


@pytest.fixture
def opaque_mode(monkeypatch):
    monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
    monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
    from maverick.coding_mode import reset_gold_patch_cache
    reset_gold_patch_cache()
    yield
    reset_gold_patch_cache()


class TestDotGitBlocked:
    def test_read_file_blocks_dotgit(self, tmp_path, opaque_mode):
        from maverick.tools.fs import read_file
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")

        class _Sandbox:
            workdir = tmp_path

        tool = read_file(_Sandbox())
        out = tool.fn({"path": ".git/HEAD"})
        assert "ERROR" in out
        assert "blocked" in out.lower()

    def test_read_file_blocks_nested_dotgit(self, tmp_path, opaque_mode):
        from maverick.tools.fs import read_file
        (tmp_path / "sub" / ".git").mkdir(parents=True)
        (tmp_path / "sub" / ".git" / "config").write_text("[core]\n")

        class _Sandbox:
            workdir = tmp_path

        tool = read_file(_Sandbox())
        out = tool.fn({"path": "sub/.git/config"})
        assert "ERROR" in out

    def test_read_file_allows_dotgit_in_non_opaque(self, tmp_path, monkeypatch):
        from maverick.tools.fs import read_file
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "0")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")

        class _Sandbox:
            workdir = tmp_path

        tool = read_file(_Sandbox())
        out = tool.fn({"path": ".git/HEAD"})
        # No opaque-mode block; gets through to file read.
        assert "ref: refs/heads/main" in out


class TestSymlinkBypass:
    """Symlink to .git or tests/ must still be
    blocked by the resolved-path check."""

    @pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink requires admin/Developer Mode on Windows (WinError 1314)",
    )
    def test_symlink_to_dotgit_blocked_in_read_file(self, tmp_path, opaque_mode):
        import os as _os

        from maverick.tools.fs import read_file
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        # Create symlink: safe_dir -> .git
        _os.symlink(".git", tmp_path / "safe_dir")

        class _Sandbox:
            workdir = tmp_path

        tool = read_file(_Sandbox())
        out = tool.fn({"path": "safe_dir/HEAD"})
        assert "ERROR" in out, (
            "symlink to .git/HEAD must be blocked on resolved path"
        )
        assert "ref:" not in out


class TestTestsDirAllFiles:
    """ANY file under tests/ is now blocked, not
    just files matching the test_*.py heuristic."""

    def test_conftest_under_tests_blocked(self, tmp_path, opaque_mode):
        from maverick.tools.fs import read_file
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "conftest.py").write_text("# expected_value = 42")

        class _Sandbox:
            workdir = tmp_path

        tool = read_file(_Sandbox())
        out = tool.fn({"path": "tests/conftest.py"})
        assert "ERROR" in out
        assert "expected_value" not in out

    def test_init_under_tests_blocked(self, tmp_path, opaque_mode):
        from maverick.tools.fs import read_file
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "__init__.py").write_text("EXPECTED = 'gold'")

        class _Sandbox:
            workdir = tmp_path

        tool = read_file(_Sandbox())
        out = tool.fn({"path": "tests/__init__.py"})
        assert "ERROR" in out
        assert "gold" not in out
