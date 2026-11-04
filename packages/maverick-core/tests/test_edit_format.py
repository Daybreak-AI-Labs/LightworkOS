"""Tests for the SEARCH/REPLACE edit format module."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


def _make_git_repo(tmp_path: Path) -> Path:
    """Init a tiny git repo with a single committed file for tests."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "commit.gpgsign", "false"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    (tmp_path / "seed.py").write_text(
        "def add(a, b):\n    return a + b\n"
    )
    subprocess.run(["git", "-C", str(tmp_path), "add", "seed.py"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-q", "-m", "seed"],
        check=True,
    )
    return tmp_path


# ---- parse_blocks ----

class TestParseBlocks:
    def test_single_block(self):
        from maverick.edit_format import parse_blocks
        text = (
            "Here's the fix:\n"
            "foo.py\n"
            "<<<<<<< SEARCH\n"
            "old\n"
            "=======\n"
            "new\n"
            ">>>>>>> REPLACE\n"
        )
        blocks = parse_blocks(text)
        assert len(blocks) == 1
        assert blocks[0].path == "foo.py"
        assert blocks[0].search == "old\n"
        assert blocks[0].replace == "new\n"

    def test_multiple_blocks_different_files(self):
        from maverick.edit_format import parse_blocks
        text = (
            "a.py\n<<<<<<< SEARCH\nx\n=======\ny\n>>>>>>> REPLACE\n"
            "b.py\n<<<<<<< SEARCH\nm\n=======\nn\n>>>>>>> REPLACE\n"
        )
        blocks = parse_blocks(text)
        assert len(blocks) == 2
        assert blocks[0].path == "a.py"
        assert blocks[1].path == "b.py"

    def test_empty_search_means_new_file(self):
        from maverick.edit_format import parse_blocks
        text = (
            "new.py\n"
            "<<<<<<< SEARCH\n"
            "=======\n"
            "x = 1\n"
            ">>>>>>> REPLACE\n"
        )
        blocks = parse_blocks(text)
        assert len(blocks) == 1
        assert blocks[0].search == ""
        assert blocks[0].replace == "x = 1\n"

    def test_handles_crlf_input(self):
        from maverick.edit_format import parse_blocks
        text = (
            "foo.py\r\n<<<<<<< SEARCH\r\nold\r\n=======\r\nnew\r\n>>>>>>> REPLACE\r\n"
        )
        blocks = parse_blocks(text)
        assert len(blocks) == 1
        assert blocks[0].path == "foo.py"

    def test_strips_code_fences_before_path(self):
        from maverick.edit_format import parse_blocks
        text = (
            "```python\nfoo.py\n```\n"
            "foo.py\n<<<<<<< SEARCH\nx\n=======\ny\n>>>>>>> REPLACE\n"
        )
        blocks = parse_blocks(text)
        assert len(blocks) == 1
        assert blocks[0].path == "foo.py"

    def test_no_blocks_returns_empty(self):
        from maverick.edit_format import parse_blocks
        assert parse_blocks("just prose") == []
        assert parse_blocks("") == []

    def test_accepts_extra_marker_chars(self):
        from maverick.edit_format import parse_blocks
        text = "foo.py\n<<<<<<<<< SEARCH\nx\n========\ny\n>>>>>>>>> REPLACE\n"
        blocks = parse_blocks(text)
        assert len(blocks) == 1


# ---- apply_blocks ----

class TestApplyBlocks:
    def test_exact_match_applies(self, tmp_path):
        from maverick.edit_format import SearchReplaceBlock, apply_blocks
        repo = _make_git_repo(tmp_path)
        blk = SearchReplaceBlock(
            path="seed.py",
            search="def add(a, b):\n    return a + b\n",
            replace="def add(a, b):\n    return a + b + 0\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        assert summary.results[0].match_kind == "exact"
        assert (repo / "seed.py").read_text() == "def add(a, b):\n    return a + b + 0\n"

    def test_trailing_whitespace_drift_recovered(self, tmp_path):
        from maverick.edit_format import SearchReplaceBlock, apply_blocks
        repo = _make_git_repo(tmp_path)
        # File has trailing whitespace; model supplies trimmed.
        (repo / "seed.py").write_text("def add(a, b):   \n    return a + b   \n")
        subprocess.run(["git", "-C", str(repo), "add", "seed.py"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "whitespace"],
            check=True,
        )
        blk = SearchReplaceBlock(
            path="seed.py",
            search="def add(a, b):\n    return a + b\n",
            replace="def add(a, b):\n    return a + b + 0\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        assert summary.results[0].match_kind == "rstrip"

    def test_rstrip_match_does_not_eat_following_line(self, tmp_path):
        # Regression: the rstrip fuzzy path computed end_line with a
        # `+1` that over-consumed one line past the needle, silently
        # deleting the line *after* the matched block (the `.startswith`
        # verify masked it). The earlier drift test only had the block at
        # EOF, where the extra line is empty -- so the corruption hid.
        from maverick.edit_format import SearchReplaceBlock, apply_blocks
        repo = _make_git_repo(tmp_path)
        # Block to edit is followed by an unrelated line that must survive.
        (repo / "seed.py").write_text(
            "a = 1\nif x:   \n    y = 2\nz = 3\n"
        )
        subprocess.run(["git", "-C", str(repo), "add", "seed.py"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "ws"], check=True,
        )
        blk = SearchReplaceBlock(
            path="seed.py",
            search="if x:\n    y = 2\n",
            replace="if x:\n    y = 4\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        assert summary.results[0].match_kind == "rstrip"
        # `z = 3` must NOT have been deleted.
        assert (repo / "seed.py").read_text() == "a = 1\nif x:\n    y = 4\nz = 3\n"

    def test_indent_norm_match_does_not_eat_following_line(self, tmp_path):
        # Same off-by-one shared by the indent-normalised fuzzy path.
        from maverick.edit_format import SearchReplaceBlock, apply_blocks
        repo = _make_git_repo(tmp_path)
        # Body indented one level deeper than the model's needle.
        (repo / "seed.py").write_text(
            "def f():\n        a = 1\n        b = 2\nTAIL = 9\n"
        )
        subprocess.run(["git", "-C", str(repo), "add", "seed.py"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "indent"], check=True,
        )
        blk = SearchReplaceBlock(
            path="seed.py",
            search="a = 1\nb = 2\n",
            replace="a = 1\nb = 3\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        # TAIL must survive whatever fuzzy kind matched.
        assert (repo / "seed.py").read_text().endswith("TAIL = 9\n")
        assert "b = 3" in (repo / "seed.py").read_text()

    def test_unreadable_snapshot_not_truncated_on_rollback(self, tmp_path, monkeypatch):
        # If the pre-apply snapshot read raises OSError, the file must NOT be
        # recorded as an empty snapshot -- otherwise an atomic rollback rewrites
        # it to zero bytes, destroying the original. A second failing block
        # forces the rollback; the unreadable-snapshot file must survive non-empty.
        from pathlib import Path as _P

        from maverick.edit_format import SearchReplaceBlock, apply_blocks
        repo = _make_git_repo(tmp_path)
        a = repo / "a.txt"
        a.write_text("original-A\n")
        (repo / "b.txt").write_text("original-B\n")

        real_read_bytes = _P.read_bytes

        def fake_read_bytes(self):
            if self == a:
                raise OSError("snapshot read blocked")
            return real_read_bytes(self)

        monkeypatch.setattr(_P, "read_bytes", fake_read_bytes)

        blocks = [
            SearchReplaceBlock(path="a.txt", search="original-A\n", replace="patched-A\n"),
            # This block fails to match -> atomic rollback of the whole apply.
            SearchReplaceBlock(path="b.txt", search="NO-SUCH-CONTENT\n", replace="x\n"),
        ]
        summary = apply_blocks(blocks, repo, atomic=True)
        assert not summary.ok  # the second block failed
        # The file whose snapshot couldn't be read must NOT be truncated to empty.
        assert a.read_text() != ""

    def test_no_match_reports_near_miss(self, tmp_path):
        from maverick.edit_format import SearchReplaceBlock, apply_blocks
        repo = _make_git_repo(tmp_path)
        blk = SearchReplaceBlock(
            path="seed.py",
            search="def subtract(a, b):\n    return a - b\n",
            replace="def subtract(a, b):\n    return a - b - 0\n",
        )
        summary = apply_blocks([blk], repo)
        assert not summary.ok
        assert "did not match" in summary.results[0].reason

    def test_ambiguous_match_refuses(self, tmp_path):
        from maverick.edit_format import SearchReplaceBlock, apply_blocks
        repo = _make_git_repo(tmp_path)
        (repo / "seed.py").write_text("x = 1\nx = 1\n")
        blk = SearchReplaceBlock(path="seed.py", search="x = 1\n", replace="x = 2\n")
        summary = apply_blocks([blk], repo)
        assert not summary.ok
        assert "matches 2" in summary.results[0].reason
        # File must be unchanged.
        assert (repo / "seed.py").read_text() == "x = 1\nx = 1\n"

    def test_new_file_via_empty_search(self, tmp_path):
        from maverick.edit_format import SearchReplaceBlock, apply_blocks
        repo = _make_git_repo(tmp_path)
        blk = SearchReplaceBlock(
            path="new_dir/new_file.py",
            search="",
            replace="x = 42\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        assert summary.results[0].match_kind == "created"
        assert (repo / "new_dir" / "new_file.py").read_text() == "x = 42\n"

    def test_atomic_rollback_on_partial_fail(self, tmp_path):
        from maverick.edit_format import SearchReplaceBlock, apply_blocks
        repo = _make_git_repo(tmp_path)
        original = (repo / "seed.py").read_text()
        blk_ok = SearchReplaceBlock(
            path="seed.py",
            search="def add(a, b):\n    return a + b\n",
            replace="def add(a, b):\n    return a + b + 1\n",
        )
        blk_fail = SearchReplaceBlock(
            path="seed.py",
            search="this does not exist\n",
            replace="anything\n",
        )
        summary = apply_blocks([blk_ok, blk_fail], repo, atomic=True)
        assert not summary.ok
        # File must be restored to original.
        assert (repo / "seed.py").read_text() == original

    def test_atomic_rollback_restores_every_file(self, tmp_path):
        """One failing block in a multi-file edit leaves no file half-edited."""
        from maverick.edit_format import apply_blocks, parse_blocks
        repo = _make_git_repo(tmp_path)
        (repo / "src").mkdir()
        (repo / "src" / "a.py").write_text("a = 1\n")
        (repo / "src" / "b.py").write_text("b = 2\n")
        text = (
            "src/a.py\n<<<<<<< SEARCH\na = 1\n=======\na = 11\n>>>>>>> REPLACE\n"
            "src/b.py\n<<<<<<< SEARCH\nbogus = 9\n=======\nb = 22\n>>>>>>> REPLACE\n"
        )
        summary = apply_blocks(parse_blocks(text), repo, atomic=True)
        assert not summary.ok
        assert (repo / "src" / "a.py").read_text() == "a = 1\n"
        assert (repo / "src" / "b.py").read_text() == "b = 2\n"

    def test_crlf_blocks_apply_to_lf_file(self, tmp_path):
        """Model output with CRLF line endings applies cleanly to an LF file."""
        from maverick.edit_format import apply_blocks, parse_blocks
        repo = _make_git_repo(tmp_path)
        text = (
            "seed.py\r\n"
            "<<<<<<< SEARCH\r\n"
            "def add(a, b):\r\n"
            "    return a + b\r\n"
            "=======\r\n"
            "def add(a, b):\r\n"
            "    return a + b + 1\r\n"
            ">>>>>>> REPLACE\r\n"
        )
        summary = apply_blocks(parse_blocks(text), repo)
        assert summary.ok, summary.summary_text()
        assert (repo / "seed.py").read_text() == "def add(a, b):\n    return a + b + 1\n"

    def test_path_traversal_blocked(self, tmp_path):
        from maverick.edit_format import SearchReplaceBlock, apply_blocks
        repo = _make_git_repo(tmp_path)
        blk = SearchReplaceBlock(
            path="../escape.py",
            search="",
            replace="oops\n",
        )
        summary = apply_blocks([blk], repo)
        assert not summary.ok
        assert "escape" in summary.results[0].reason

    def test_render_diff_after_apply(self, tmp_path):
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
            render_diff,
        )
        repo = _make_git_repo(tmp_path)
        blk = SearchReplaceBlock(
            path="seed.py",
            search="def add(a, b):\n    return a + b\n",
            replace="def add(a, b):\n    return a + b + 1\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        diff = render_diff(repo, paths=sorted(summary.files_touched))
        assert diff.startswith("diff --git")
        assert "-    return a + b" in diff
        assert "+    return a + b + 1" in diff

    def test_render_diff_scopes_to_paths_and_skips_unrelated_untracked(self, tmp_path):
        """Security: when `paths` is supplied, render_diff must not leak
        unrelated untracked files (scratch files, secrets, build artifacts).
        """
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
            render_diff,
        )
        repo = _make_git_repo(tmp_path)
        # Unrelated untracked file with sensitive contents.
        (repo / "secret.txt").write_text("API_KEY=sk-secret-do-not-leak\n")
        blk = SearchReplaceBlock(
            path="seed.py",
            search="def add(a, b):\n    return a + b\n",
            replace="def add(a, b):\n    return a + b + 1\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        diff = render_diff(repo, paths=sorted(summary.files_touched))
        assert "sk-secret-do-not-leak" not in diff
        assert "secret.txt" not in diff
        assert "seed.py" in diff

    def test_render_diff_includes_new_files_in_paths(self, tmp_path):
        """When `paths` includes a new file the caller created, the new
        file must still appear via intent-to-add.
        """
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
            render_diff,
        )
        repo = _make_git_repo(tmp_path)
        # Unrelated untracked secret that must NOT leak.
        (repo / "secret.txt").write_text("API_KEY=sk-secret\n")
        # SR block that creates a new file (empty SEARCH).
        blk = SearchReplaceBlock(
            path="new_module.py",
            search="",
            replace="def added():\n    return 1\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        diff = render_diff(repo, paths=sorted(summary.files_touched))
        assert "new_module.py" in diff
        assert "+def added():" in diff
        assert "sk-secret" not in diff

    def test_render_diff_combines_tracked_edits_and_new_files(self, tmp_path):
        """A tracked edit and a new file named in `paths` share one patch."""
        from maverick.edit_format import render_diff
        repo = _make_git_repo(tmp_path)
        (repo / "seed.py").write_text("def add(a, b):\n    return a - b\n")
        (repo / "newmod.py").write_text("y = 99\n")
        diff = render_diff(repo, paths=["seed.py", "newmod.py"])
        assert "diff --git a/seed.py b/seed.py" in diff
        assert "diff --git a/newmod.py b/newmod.py" in diff
        assert "+y = 99" in diff
        assert "/dev/null" in diff or "new file" in diff


    @pytest.mark.skipif(
        os.name == "nt",
        reason="git pathspec-magic filenames contain characters forbidden by Windows",
    )
    def test_render_diff_treats_scoped_paths_as_literals(self, tmp_path):
        """Security: prevent git pathspec-magic injection from model-supplied
        SEARCH/REPLACE paths such as `:(glob)*`.
        """
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
            render_diff,
        )
        repo = _make_git_repo(tmp_path)
        # Unrelated untracked secret must not be matched by `:(glob)*`.
        (repo / "secret.txt").write_text("API_KEY=sk-do-not-leak\n")

        blk = SearchReplaceBlock(
            path=":(glob)*",
            search="",
            replace="benign\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok

        diff = render_diff(repo, paths=sorted(summary.files_touched))
        assert "secret.txt" not in diff
        assert "sk-do-not-leak" not in diff
        # The literal file named `:(glob)*` should still be diffed.
        assert "diff --git a/:(glob)* b/:(glob)*" in diff
        assert "+benign" in diff

    def test_render_diff_without_paths_emits_tracked_changes_only(self, tmp_path):
        """Backward-compat path: no `paths` -> diff tracked-file changes,
        skip untracked entirely (the secure default for salvage paths).
        """
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
            render_diff,
        )
        repo = _make_git_repo(tmp_path)
        (repo / "scratch.txt").write_text("ignore me\n")
        blk = SearchReplaceBlock(
            path="seed.py",
            search="def add(a, b):\n    return a + b\n",
            replace="def add(a, b):\n    return a + b + 1\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        diff = render_diff(repo)
        assert "seed.py" in diff
        assert "scratch.txt" not in diff
        assert "ignore me" not in diff


# ---- repair prompt ----

class TestRepairPrompt:
    def test_repair_prompt_includes_block_path_and_reason(self, tmp_path):
        from maverick.edit_format import (
            ApplyResult,
            SearchReplaceBlock,
            repair_prompt_for_failure,
        )
        result = ApplyResult(
            ok=False,
            block=SearchReplaceBlock(path="foo.py", search="x", replace="y"),
            reason="SEARCH block did not match",
            near_miss_context="closest match (line 5):\n   5: x = 1",
        )
        out = repair_prompt_for_failure(result)
        assert "foo.py" in out
        assert "did not match" in out
        assert "closest match" in out
        assert "<<<<<<< SEARCH" in out
        assert ">>>>>>> REPLACE" in out


class TestSensitiveNearMiss:
    def test_sensitive_paths_do_not_include_near_miss_file_content(self, tmp_path):
        from maverick.edit_format import SearchReplaceBlock, apply_blocks

        repo = _make_git_repo(tmp_path)
        env_path = repo / ".env"
        env_path.write_text("OPENAI_API_KEY=sk-live-secret\nOTHER=value\n", encoding="utf-8")

        blk = SearchReplaceBlock(
            path=".env",
            search="API_TOKEN_DOES_NOT_EXIST",
            replace="OPENAI_API_KEY=updated",
        )
        summary = apply_blocks([blk], repo)

        assert not summary.ok
        res = summary.results[0]
        assert "sensitive path" in res.near_miss_context
        assert "sk-live-secret" not in res.near_miss_context

    def test_non_sensitive_paths_still_include_near_miss_context(self, tmp_path):
        from maverick.edit_format import SearchReplaceBlock, apply_blocks

        repo = _make_git_repo(tmp_path)
        (repo / "seed.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        blk = SearchReplaceBlock(
            path="seed.py",
            search="return a + c",
            replace="return a + b",
        )

        summary = apply_blocks([blk], repo)
        assert not summary.ok
        res = summary.results[0]
        assert "closest match" in res.near_miss_context
        assert "return a + b" in res.near_miss_context


# ---------- edit_format: fuzzy match safety ----------

def test_edit_format_indent_match_slice_actually_matches():
    """When step 3 returns an indent_norm match, the mapped-back slice
    must really indent-match the needle (the recheck guard)."""
    from maverick.edit_format import _find_with_fuzzy, _normalise_indent
    content = (
        "def a():\n"
        "    x = 1\n"
        "    return x\n"
        "\n"
        "class C:\n"
        "    def a(self):\n"
        "        y = 2\n"
        "        return y\n"
    )
    needle = "x = 1\nreturn x\n"  # uniquely indent-matches the first block
    start, end, strategy = _find_with_fuzzy(content, needle)
    assert start is not None
    needle_ni, _ = _normalise_indent(needle)
    assert _normalise_indent(content[start:end])[0].startswith(needle_ni)


def test_edit_format_refuses_two_identical_blocks():
    """Two byte-identical blocks → fuzzy tiers must refuse (ambiguous),
    never silently pick the first."""
    from maverick.edit_format import _find_with_fuzzy
    content = "    x = 1\n    return x\n\n    x = 1\n    return x\n"
    needle = "x = 1\nreturn x\n"
    start, end, strategy = _find_with_fuzzy(content, needle)
    assert strategy == "ambiguous"
    assert start is None and end is None
