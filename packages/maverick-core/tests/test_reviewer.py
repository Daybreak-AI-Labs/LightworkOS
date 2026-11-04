"""Tests for the self-reviewer agent (maverick.reviewer)."""
from __future__ import annotations

import pytest

# ---------- Self-reviewer parsing ----------

class TestReviewerParse:
    def test_clean_approval(self):
        from maverick.reviewer import _parse
        v = _parse(
            '{"approves": true, "confidence": 0.9, "comments": []}'
        )
        assert v.approves is True
        assert v.confidence == 0.9
        assert v.comments == []

    def test_rejection_with_blocker(self):
        from maverick.reviewer import _parse
        v = _parse(
            '{"approves": false, "confidence": 0.4, "comments": ['
            '{"path": "foo.py", "line": 12, "severity": "blocker", '
            '"message": "null deref"}'
            ']}'
        )
        assert v.approves is False
        assert len(v.blockers) == 1
        assert v.blockers[0].path == "foo.py"

    def test_comment_severity_clamped_to_known(self):
        from maverick.reviewer import _parse
        v = _parse(
            '{"approves": false, "confidence": 0.5, "comments": ['
            '{"path": "x.py", "line": 1, "severity": "catastrophic", '
            '"message": "x"}'
            ']}'
        )
        # Unknown severity normalized to "warning".
        assert v.comments[0].severity == "warning"

    def test_empty_response_rejects(self):
        from maverick.reviewer import _parse
        v = _parse("")
        assert v.approves is False

    def test_unparseable_rejects(self):
        from maverick.reviewer import _parse
        v = _parse("not json")
        assert v.approves is False

    def test_string_approves_value(self):
        from maverick.reviewer import _parse
        v = _parse('{"approves": "true", "confidence": 0.8, "comments": []}')
        assert v.approves is True


class TestReviewDiff:
    @pytest.mark.asyncio
    async def test_empty_diff_short_circuits(self):
        """No diff = empty pass; no LLM call."""
        from maverick.budget import Budget
        from maverick.reviewer import review_diff

        class _ShouldNotBeCalled:
            async def complete_async(self, **_kw):
                raise AssertionError("LLM called on empty diff")

        v = await review_diff("brief", "", _ShouldNotBeCalled(), Budget())
        assert v.approves is True
        assert v.comments == []

    @pytest.mark.asyncio
    async def test_reviews_diff_via_llm(self, fake_llm, make_llm_response):
        from maverick.budget import Budget
        from maverick.reviewer import review_diff
        fake_llm.scripted = [make_llm_response(
            text=(
                '{"approves": true, "confidence": 0.85, '
                '"comments": [{"path": "x.py", "line": 3, '
                '"severity": "nit", "message": "minor"}]}'
            ),
        )]
        v = await review_diff(
            "brief",
            "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n+new\n",
            fake_llm, Budget(),
        )
        assert v.approves is True
        assert v.comments[0].severity == "nit"


class TestGetDiff:
    def test_git_diff_disables_external_helpers(self, monkeypatch, tmp_path):
        from maverick.reviewer import get_diff

        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)

        class _Proc:
            stdout = "ok"

        seen = {}

        def _fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            seen["kwargs"] = kwargs
            return _Proc()

        monkeypatch.setattr("maverick.reviewer.subprocess.run", _fake_run)

        out = get_diff(repo)
        assert out == "ok"
        assert "--no-ext-diff" in seen["cmd"]
        assert "--no-textconv" in seen["cmd"]
        assert "diff.external=" in seen["cmd"]
        assert "diff.textconv=false" in seen["cmd"]

    def test_non_repo_returns_empty(self, tmp_path):
        from maverick.reviewer import get_diff

        assert get_diff(tmp_path) == ""


class TestReviewVerdictRendering:
    def test_empty_pass_is_short(self):
        from maverick.reviewer import ReviewVerdict, format_for_human
        out = format_for_human(ReviewVerdict.empty_pass())
        assert "approved" in out

    def test_blocker_uses_stop_icon(self):
        from maverick.reviewer import (
            ReviewComment,
            ReviewVerdict,
            format_for_human,
        )
        v = ReviewVerdict(approves=False, confidence=0.4, comments=[
            ReviewComment(path="x.py", line=1, severity="blocker", message="bad"),
        ])
        out = format_for_human(v)
        assert "blocker" in out
        assert "x.py:1" in out
