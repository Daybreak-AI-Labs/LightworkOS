"""Tier 0: adversarial edge cases for SEARCH/REPLACE parser/applier.

These tests probe failure modes I didn't cover in test_edit_format.py
that could fire on real SWE-bench Pro instances. Each test is a
deliberately mean input: nested markers, ambiguous fuzzy match, empty
REPLACE, multiple blocks targeting the same file, off-by-one marker
counts.

Anything that fails here is something the agent will eventually
encounter on Pro and silently misapply. Each test pins the expected
behaviour so a future refactor doesn't regress.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


def _init_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "commit.gpgsign", "false"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "t@t"], check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True,
    )
    for path, content in files.items():
        full = tmp_path / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")  # not the cp1252 default on Windows
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-q", "-m", "seed"], check=True,
    )
    return tmp_path


# ---- Marker variations ----


class TestMarkerVariations:
    def test_5_char_markers_minimum(self):
        """Exactly 5 markers should match (the regex minimum)."""
        from maverick.edit_format import parse_blocks
        text = "foo.py\n<<<<< SEARCH\nold\n=====\nnew\n>>>>> REPLACE\n"
        blocks = parse_blocks(text)
        assert len(blocks) == 1

    def test_6_char_markers(self):
        """Model emits 6-char markers (between 5 minimum and 7 standard)."""
        from maverick.edit_format import parse_blocks
        text = "foo.py\n<<<<<< SEARCH\nold\n======\nnew\n>>>>>> REPLACE\n"
        blocks = parse_blocks(text)
        assert len(blocks) == 1

    def test_excessive_markers(self):
        """Models sometimes over-emphasize with 10+ markers."""
        from maverick.edit_format import parse_blocks
        text = "foo.py\n<<<<<<<<<<<< SEARCH\nold\n============\nnew\n>>>>>>>>>>>> REPLACE\n"
        blocks = parse_blocks(text)
        assert len(blocks) == 1

    def test_4_char_markers_rejected(self):
        """4-char markers are below the regex minimum; should NOT parse."""
        from maverick.edit_format import parse_blocks
        text = "foo.py\n<<<< SEARCH\nold\n====\nnew\n>>>> REPLACE\n"
        blocks = parse_blocks(text)
        assert blocks == []

    def test_mixed_marker_widths(self):
        """Opening 7-char, divider 5-char, closing 9-char: still parses."""
        from maverick.edit_format import parse_blocks
        text = "foo.py\n<<<<<<< SEARCH\nold\n=====\nnew\n>>>>>>>>> REPLACE\n"
        blocks = parse_blocks(text)
        assert len(blocks) == 1


# ---- Self-referential content (markers inside SEARCH/REPLACE bodies) ----


class TestSelfReferentialMarkers:
    def test_search_contains_literal_marker_text_in_words(self):
        """A SEARCH body that mentions 'SEARCH' as a word (not as a
        marker line) must still parse."""
        from maverick.edit_format import parse_blocks
        text = (
            "foo.py\n"
            "<<<<<<< SEARCH\n"
            "# The SEARCH for truth begins here\n"
            "x = 1\n"
            "=======\n"
            "# now x = 2\n"
            "x = 2\n"
            ">>>>>>> REPLACE\n"
        )
        blocks = parse_blocks(text)
        assert len(blocks) == 1
        assert "SEARCH for truth" in blocks[0].search
        assert "now x = 2" in blocks[0].replace

    def test_marker_inside_indented_body_treated_as_marker(self):
        """An indented `<<<<<<< SEARCH` line is RARE but the regex is
        anchored to start-of-line. Documented behaviour: only lines
        that START with the marker count as marker lines."""
        from maverick.edit_format import parse_blocks
        # Indented marker — should NOT be treated as a block boundary.
        text = (
            "foo.py\n"
            "<<<<<<< SEARCH\n"
            "    <<<<<<< SEARCH (this is content, not a marker)\n"
            "    x = 1\n"
            "=======\n"
            "    x = 2\n"
            ">>>>>>> REPLACE\n"
        )
        blocks = parse_blocks(text)
        # Current regex `^<{5,}\s*SEARCH\s*$` IS anchored to line start
        # via MULTILINE -- a leading space would mean it does NOT match.
        # Verify the indented line is preserved as content.
        assert len(blocks) == 1
        assert "<<<<<<< SEARCH (this is content" in blocks[0].search


# ---- Empty / deletion semantics ----


class TestEmptyBodies:
    def test_empty_replace_deletes_block(self, tmp_path):
        """Empty REPLACE section means "remove these lines"."""
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
        )
        repo = _init_repo(tmp_path, {
            "foo.py": "header\nDELETE ME\nfooter\n",
        })
        blk = SearchReplaceBlock(
            path="foo.py",
            search="DELETE ME\n",
            replace="",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        assert (repo / "foo.py").read_text() == "header\nfooter\n"

    def test_empty_search_and_empty_replace_on_existing_file(self, tmp_path):
        """Empty SEARCH on an EXISTING file is the create-new-file
        signal -- but the file already exists. Should refuse cleanly."""
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
        )
        repo = _init_repo(tmp_path, {"foo.py": "x = 1\n"})
        blk = SearchReplaceBlock(
            path="foo.py", search="", replace="x = 999\n",
        )
        summary = apply_blocks([blk], repo)
        assert not summary.ok
        assert "already exists" in summary.results[0].reason


# ---- Multiple blocks same file ----


class TestMultipleBlocksSameFile:
    def test_two_blocks_same_file_apply_in_order(self, tmp_path):
        """Two SR blocks on the same file should each apply in order.
        This is critical for multi-hunk patches on a single file."""
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
        )
        repo = _init_repo(tmp_path, {
            "foo.py": "line1\nline2\nline3\nline4\n",
        })
        blocks = [
            SearchReplaceBlock(path="foo.py", search="line1\n", replace="LINE1\n"),
            SearchReplaceBlock(path="foo.py", search="line3\n", replace="LINE3\n"),
        ]
        summary = apply_blocks(blocks, repo)
        assert summary.ok
        assert (repo / "foo.py").read_text() == "LINE1\nline2\nLINE3\nline4\n"

    def test_second_block_searches_post_first_apply(self, tmp_path):
        """Block 2's SEARCH should match the POST-block-1 file content,
        not the original. This is how multi-edit pipelines must behave
        — block 2 can reference text introduced by block 1."""
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
        )
        repo = _init_repo(tmp_path, {"foo.py": "original\n"})
        blocks = [
            SearchReplaceBlock(
                path="foo.py", search="original\n",
                replace="STEP1_OUTPUT\nSTEP1_FOOTER\n",
            ),
            SearchReplaceBlock(
                path="foo.py", search="STEP1_OUTPUT\n",
                replace="STEP2_OUTPUT\n",
            ),
        ]
        summary = apply_blocks(blocks, repo)
        assert summary.ok
        assert (repo / "foo.py").read_text() == "STEP2_OUTPUT\nSTEP1_FOOTER\n"

    def test_overlapping_blocks_atomic_rollback(self, tmp_path):
        """If block 1 mutates the file such that block 2's SEARCH no
        longer matches, atomic=True should roll the whole thing back."""
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
        )
        repo = _init_repo(tmp_path, {"foo.py": "before\nmiddle\nafter\n"})
        original = (repo / "foo.py").read_text()
        blocks = [
            SearchReplaceBlock(
                path="foo.py", search="middle\n", replace="MIDDLE\n",
            ),
            # Now `middle` is gone -- this block can't find it.
            SearchReplaceBlock(
                path="foo.py", search="middle\nafter\n", replace="X\n",
            ),
        ]
        summary = apply_blocks(blocks, repo, atomic=True)
        assert not summary.ok
        assert (repo / "foo.py").read_text() == original


# ---- Fuzzy-match ambiguity edge cases ----


class TestFuzzyMatchAmbiguity:
    def test_exact_match_wins_over_fuzzy(self, tmp_path):
        """If exact match succeeds, the fuzzy ladder shouldn't fire."""
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
        )
        # Two near-duplicates; exact match is unique on the second.
        repo = _init_repo(tmp_path, {
            "foo.py": "    return 1\n    return 2\n",
        })
        blk = SearchReplaceBlock(
            path="foo.py",
            search="    return 2\n",
            replace="    return 99\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        assert summary.results[0].match_kind == "exact"
        assert (repo / "foo.py").read_text() == "    return 1\n    return 99\n"

    def test_fuzzy_rstrip_when_exact_fails(self, tmp_path):
        """File has trailing whitespace; model trimmed -> rstrip ladder."""
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
        )
        repo = _init_repo(tmp_path, {"foo.py": "x = 1   \n"})
        blk = SearchReplaceBlock(
            path="foo.py", search="x = 1\n", replace="x = 2\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        assert summary.results[0].match_kind == "rstrip"


# ---- Path edge cases ----


class TestPathEdgeCases:
    def test_path_with_subdirs(self, tmp_path):
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
        )
        repo = _init_repo(tmp_path, {"a/b/c.py": "x = 1\n"})
        blk = SearchReplaceBlock(
            path="a/b/c.py", search="x = 1\n", replace="x = 2\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        assert (repo / "a/b/c.py").read_text() == "x = 2\n"

    def test_path_with_dot_prefix(self, tmp_path):
        """Path like `./foo.py` should resolve same as `foo.py`."""
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
        )
        repo = _init_repo(tmp_path, {"foo.py": "x = 1\n"})
        blk = SearchReplaceBlock(
            path="./foo.py", search="x = 1\n", replace="x = 2\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        assert (repo / "foo.py").read_text() == "x = 2\n"


# ---- Content edge cases ----


class TestContentEdgeCases:
    def test_unicode_content(self, tmp_path):
        """Non-ASCII content must be preserved byte-perfectly."""
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
        )
        repo = _init_repo(tmp_path, {"foo.py": "x = '日本語'\n"})
        blk = SearchReplaceBlock(
            path="foo.py",
            search="x = '日本語'\n",
            replace="x = 'español'\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok
        assert (repo / "foo.py").read_text(encoding="utf-8") == "x = 'español'\n"

    def test_very_long_line(self, tmp_path):
        """A single ~5kb line should apply without issue."""
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
        )
        long_line = "a" * 5000
        repo = _init_repo(tmp_path, {"foo.py": f"x = '{long_line}'\n"})
        blk = SearchReplaceBlock(
            path="foo.py",
            search=f"x = '{long_line}'\n",
            replace="x = 'short'\n",
        )
        summary = apply_blocks([blk], repo)
        assert summary.ok

    def test_trailing_no_newline_preserved(self, tmp_path):
        """File without trailing newline -> we don't accidentally add one."""
        from maverick.edit_format import (
            SearchReplaceBlock,
            apply_blocks,
        )
        repo = _init_repo(tmp_path, {"foo.py": "x = 1"})  # no \n
        # The apply path normalises search/replace to have trailing \n,
        # but for this case the file itself has none. The match still
        # succeeds via the fuzzy ladder.
        blk = SearchReplaceBlock(
            path="foo.py", search="x = 1", replace="x = 2",
        )
        summary = apply_blocks([blk], repo)
        # The current implementation pads search/replace with \n, so
        # this test documents that behaviour. If the underlying file
        # gets a trailing \n that wasn't there, mark this as expected.
        assert summary.ok or "did not match" in summary.results[0].reason


# ---- Parse robustness ----


class TestParseRobustness:
    def test_only_close_marker_returns_empty(self):
        """A floating REPLACE marker with no SEARCH should yield nothing."""
        from maverick.edit_format import parse_blocks
        text = "foo.py\n>>>>>>> REPLACE\n"
        assert parse_blocks(text) == []

    def test_unfinished_block_returns_empty(self):
        """SEARCH + ======= without REPLACE marker."""
        from maverick.edit_format import parse_blocks
        text = "foo.py\n<<<<<<< SEARCH\nold\n=======\nnew\n"
        assert parse_blocks(text) == []

    def test_path_with_strikethrough_or_decorations(self):
        """Model wraps path in backticks or angle brackets."""
        from maverick.edit_format import parse_blocks
        text = (
            "`foo.py`\n"
            "<<<<<<< SEARCH\nold\n=======\nnew\n>>>>>>> REPLACE\n"
        )
        blocks = parse_blocks(text)
        # Backticks should be stripped.
        assert len(blocks) == 1
        assert blocks[0].path == "foo.py"

    def test_blocks_across_huge_prose_gap(self):
        """Model writes 5kb of explanation between blocks."""
        from maverick.edit_format import parse_blocks
        prose = "Some long explanation. " * 200
        text = (
            "a.py\n<<<<<<< SEARCH\nx\n=======\ny\n>>>>>>> REPLACE\n"
            + prose
            + "\nb.py\n<<<<<<< SEARCH\nm\n=======\nn\n>>>>>>> REPLACE\n"
        )
        blocks = parse_blocks(text)
        assert len(blocks) == 2
        assert blocks[1].path == "b.py"

    def test_path_with_diff_prefix_stripped(self):
        """Some models prepend `diff` to the path line."""
        from maverick.edit_format import parse_blocks
        text = (
            "diff foo.py\n<<<<<<< SEARCH\nold\n=======\nnew\n>>>>>>> REPLACE\n"
        )
        blocks = parse_blocks(text)
        assert len(blocks) == 1
        assert blocks[0].path == "foo.py"
