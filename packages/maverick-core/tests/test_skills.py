"""Skill management tests."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from maverick.skills import (
    Skill,
    _relevant_skills_lexical,
    _safe_name,
    build_skill_md,
    create_skill,
    install_skill,
    load_skills,
    relevant_skills,
    remove_skill,
)

SKILL_BODY = (
    "---\n"
    "name: my-test-skill\n"
    "triggers:\n"
    "  - test thing\n"
    "  - try this\n"
    "tools_needed:\n"
    "  - shell\n"
    "---\n"
    "\n"
    "# What it does\n"
    "\n"
    "Testing skills installation.\n"
)


class TestSafeName:
    def test_simple(self):
        assert _safe_name("my-skill") == "my-skill"

    def test_strips_special_chars(self):
        assert _safe_name("My Skill!") == "my-skill"

    def test_path_traversal_neutralized(self):
        # Slashes and dots get stripped -- no path escape via skill name.
        result = _safe_name("../etc/passwd")
        assert "/" not in result
        assert ".." not in result

    def test_empty_fallback(self):
        assert _safe_name("") == "skill"
        assert _safe_name("!!!") == "skill"


class TestCreateSkill:
    def test_authors_a_valid_skill_that_round_trips(self, tmp_path: Path):
        d = tmp_path / "skills"
        s = create_skill(
            "My Cool Skill",
            "# What this does\n\nDo the thing.\n\n# Steps\n1. One.\n2. Two.",
            triggers=["do the thing", "make it happen"],
            tools_needed=["read_file"],
            skills_dir=d,
        )
        assert s.name == "my-cool-skill"                 # display name -> kebab id
        assert (d / "my-cool-skill.md").exists()
        # loads back through the normal loader with fields intact
        loaded = {x.name: x for x in load_skills(d)}
        assert "my-cool-skill" in loaded
        assert loaded["my-cool-skill"].triggers == ["do the thing", "make it happen"]
        assert loaded["my-cool-skill"].tools_needed == ["read_file"]

    def test_requires_a_trigger(self, tmp_path: Path):
        with pytest.raises(ValueError, match="trigger"):
            create_skill("x", "body text", triggers=[], skills_dir=tmp_path / "s")

    def test_requires_a_body(self, tmp_path: Path):
        with pytest.raises(ValueError, match="instructions|body"):
            create_skill("x", "   ", triggers=["go"], skills_dir=tmp_path / "s")

    def test_build_skill_md_is_parseable(self):
        md = build_skill_md("Weekly Rollup", ["weekly status"], ["read_file"], "Body here.")
        parsed = Skill.parse(md, Path("weekly-rollup.md"))
        assert parsed.name == "weekly-rollup"
        assert parsed.triggers == ["weekly status"]
        assert parsed.tools_needed == ["read_file"]
        assert "Body here." in parsed.body

    def test_multiline_trigger_is_collapsed(self, tmp_path: Path):
        # A trigger with embedded newlines can't break the line-based frontmatter.
        s = create_skill("t", "Body.", triggers=["line one\nline two"],
                         skills_dir=tmp_path / "s")
        assert s.triggers == ["line one line two"]


class TestInstallSkill:
    def test_from_local_path(self, tmp_path: Path):
        source = tmp_path / "my.md"
        source.write_text(SKILL_BODY)
        skills_dir = tmp_path / "skills"
        s = install_skill(str(source), skills_dir=skills_dir)
        assert s.name == "my-test-skill"
        assert (skills_dir / "my-test-skill.md").exists()
        assert "test thing" in s.triggers

    def test_local_missing_raises(self, tmp_path: Path):
        with pytest.raises(ValueError, match="does not exist"):
            install_skill(str(tmp_path / "nope.md"), skills_dir=tmp_path / "skills")

    def test_creates_skills_dir(self, tmp_path: Path):
        source = tmp_path / "x.md"
        source.write_text(SKILL_BODY)
        skills_dir = tmp_path / "deep" / "path" / "that" / "doesnt" / "exist"
        install_skill(str(source), skills_dir=skills_dir)
        assert skills_dir.is_dir()

    def test_http_url_rejected(self, tmp_path: Path):
        with pytest.raises(ValueError, match="insecure URL scheme"):
            install_skill("http://example.com/skill.md", skills_dir=tmp_path / "skills")

    def test_https_download_has_size_limit(self, tmp_path: Path):
        class FakeResp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self, n: int = -1) -> bytes:
                return b"x" * (300 * 1024)

        # guarded_urlopen fetches through a custom opener (to revalidate
        # redirect hops against the SSRF guard), so patch the opener's open().
        with patch("urllib.request.OpenerDirector.open", return_value=FakeResp()):
            with pytest.raises(ValueError, match="too large"):
                install_skill("https://example.com/skill.md", skills_dir=tmp_path / "skills")


class TestRemoveSkill:
    def test_removes_existing(self, tmp_path: Path):
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "to-go.md").write_text(SKILL_BODY)
        assert remove_skill("to-go", skills_dir=skills_dir) is True
        assert not (skills_dir / "to-go.md").exists()

    def test_returns_false_when_missing(self, tmp_path: Path):
        assert remove_skill("never-installed", skills_dir=tmp_path / "skills") is False

    def test_name_sanitized(self, tmp_path: Path):
        # Even adversarial names can't escape the skills_dir.
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        outside = tmp_path / "outside.md"
        outside.write_text("important")
        # _safe_name strips '..' and '/', so this targets skills_dir/...md or similar
        remove_skill("../outside", skills_dir=skills_dir)
        assert outside.exists()  # not touched


class TestSkillParse:
    def test_missing_frontmatter_raises(self, tmp_path: Path):
        bad = tmp_path / "bad.md"
        bad.write_text("just text no frontmatter")
        with pytest.raises(ValueError, match="missing YAML frontmatter"):
            Skill.parse(bad.read_text(), bad)

    def test_parses_triggers(self, tmp_path: Path):
        path = tmp_path / "x.md"
        path.write_text(SKILL_BODY)
        s = Skill.parse(path.read_text(), path)
        assert s.triggers == ["test thing", "try this"]
        assert s.tools_needed == ["shell"]


class TestRelevantSkills:
    @pytest.fixture(autouse=True)
    def _force_lexical(self, monkeypatch):
        # These exercise the LEXICAL scorer specifically, so force it -- the
        # result must not depend on whether fastembed happens to be installed
        # (the embedding path has its own cosine gate).
        monkeypatch.setattr("maverick.skill.embeddings._have_fastembed", lambda: False)

    def _make_skill(self, name: str, triggers: list[str]) -> Skill:
        return Skill(
            name=name, triggers=triggers, tools_needed=[], body="", path=Path("/x"),
        )

    def test_relevance_gate_drops_weak_matches(self):
        # A skill sharing only a common word ("the") is noise and must be gated
        # out (precision >> recall for agent memory).
        strong = self._make_skill("strong", ["deploy the service"])
        weak = self._make_skill("weak", ["the weather forecast"])
        out = relevant_skills("deploy the service now", [strong, weak])
        assert strong in out and weak not in out

    def test_gate_is_configurable(self):
        from maverick.skills import _relevant_skills_lexical
        weak = self._make_skill("weak", ["the weather"])  # shares one content word
        assert weak in _relevant_skills_lexical("weather price", [weak], min_score=0.0)
        assert weak not in _relevant_skills_lexical("weather price", [weak], min_score=4.0)

    def test_stop_words_and_repeated_words_are_not_relevance(self):
        from maverick.skills import _relevant_skills_lexical
        # Shares only "the", "in" and "of" with the goals below.
        covenant = self._make_skill(
            "covenant", ["are we in compliance with the debt covenants",
                         "check the headroom of the loan"])
        # Shares one content word ("plan"), repeated in two triggers.
        recovery = self._make_skill(
            "recovery", ["write a DR plan", "plan disaster recovery for our systems"])
        churn = self._make_skill("churn", ["churn prediction", "at risk customers"])
        skills = [covenant, recovery, churn]
        for goal in ("Fix the failing unit tests in the auth module",
                     "What is the capacity of the warehouse",
                     "Analyze the churn in our customer data and recommend a plan"):
            assert _relevant_skills_lexical(goal, skills, min_score=4.0) == []
        assert _relevant_skills_lexical(
            "Run a churn prediction on last quarter's accounts", skills, min_score=4.0) == [churn]

    def test_word_overlap_scoring(self):
        s1 = self._make_skill("a", ["web search results"])
        s2 = self._make_skill("b", ["send email"])
        out = relevant_skills("please do a web search", [s1, s2])
        assert s1 in out
        assert s2 not in out

    def test_substring_bonus_ranks_higher(self):
        s1 = self._make_skill("a", ["deploy a new service"])
        s2 = self._make_skill("b", ["deploy something"])
        out = relevant_skills("deploy a new service today", [s1, s2])
        # s1's full-phrase match beats s2's partial overlap.
        assert out[0] == s1

    def test_max_n_caps_results(self):
        skills = [self._make_skill(f"s{i}", ["test trigger"]) for i in range(10)]
        out = relevant_skills("test trigger", skills, max_n=3)
        assert len(out) == 3


class TestPurposeScopedRecall:
    @pytest.fixture(autouse=True)
    def _force_lexical(self, monkeypatch):
        monkeypatch.setattr("maverick.skill.embeddings._have_fastembed", lambda: False)

    def _skill(self, purposes=()):
        return Skill(name="s", triggers=["reconcile the general ledger"],
                     tools_needed=[], body="", path=Path("/x"), purposes=purposes)

    def test_unrestricted_skill_always_recalled(self):
        s = self._skill()
        assert s in relevant_skills("reconcile the general ledger now", [s])

    def test_purpose_scoped_hidden_without_purpose(self):
        # PBAC default: a purpose-scoped skill is NOT recalled when no purpose
        # is declared for the run.
        s = self._skill(purposes=("audit",))
        assert relevant_skills("reconcile the general ledger now", [s]) == []

    def test_purpose_scoped_recalled_within_matching_purpose(self):
        from maverick.access_policy import purpose_scope
        s = self._skill(purposes=("audit",))
        with purpose_scope("audit"):
            assert s in relevant_skills("reconcile the general ledger now", [s])

    def test_purpose_scoped_hidden_under_wrong_purpose(self):
        from maverick.access_policy import purpose_scope
        s = self._skill(purposes=("audit",))
        with purpose_scope("marketing"):
            assert relevant_skills("reconcile the general ledger now", [s]) == []


class TestSkillPurposeParse:
    def test_parse_reads_purposes_frontmatter(self, tmp_path):
        text = ("---\nname: p\ntriggers:\n  - do x\npurposes:\n  - audit\n  - finance\n"
                "---\n\n# What\n\nA body long enough to be a valid skill file.\n")
        s = Skill.parse(text, tmp_path / "p.md")
        assert s.purposes == ("audit", "finance")


def _mk(name: str) -> Skill:
    return Skill(
        name=name, triggers=["deploy service"], tools_needed=[],
        body="x", path=Path(f"/tmp/{name}.md"),
    )


def test_lexical_tie_break_is_deterministic_by_name():
    a, z = _mk("aaa"), _mk("zzz")
    # Identical triggers -> identical scores -> the tie must break by name,
    # independent of input order.
    r1 = _relevant_skills_lexical("deploy service now", [z, a], max_n=2, min_score=1)
    r2 = _relevant_skills_lexical("deploy service now", [a, z], max_n=2, min_score=1)
    assert [s.name for s in r1] == ["aaa", "zzz"]
    assert [s.name for s in r2] == ["aaa", "zzz"]
    # The max_n cut is therefore stable: top-1 is always "aaa", never order-dependent.
    top_zfirst = _relevant_skills_lexical("deploy service now", [z, a], max_n=1, min_score=1)
    top_afirst = _relevant_skills_lexical("deploy service now", [a, z], max_n=1, min_score=1)
    assert [s.name for s in top_zfirst] == ["aaa"]
    assert [s.name for s in top_afirst] == ["aaa"]
