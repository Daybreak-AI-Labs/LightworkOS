"""`maverick skills` group: bare list + stats + evict subcommands.

`skills` became a group (invoke_without_command) so the bare command still
lists, and `skills stats` / `skills evict` expose the maintenance surface.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick import skills
from maverick.cli import main
from maverick.skill import stats as skill_stats

SKILL_MD = (
    "---\n"
    "name: {name}\n"
    "triggers:\n"
    "  - do a thing\n"
    "---\n"
    "\n# What it does\n\nStuff.\n"
)


@pytest.fixture
def _skills_and_stats(tmp_path, monkeypatch):
    # The autouse home-isolation fixture points Path.home() at tmp, but
    # skill_stats.DEFAULT_PATH was bound at import; repoint it explicitly.
    monkeypatch.setattr(skill_stats, "DEFAULT_PATH", tmp_path / "stats.json")
    skills_path = skills.skills_dir()
    skills_path.mkdir(parents=True, exist_ok=True)
    (skills_path / "good.md").write_text(
        SKILL_MD.format(name="good"), encoding="utf-8",
    )
    (skills_path / "bad.md").write_text(
        SKILL_MD.format(name="bad"), encoding="utf-8",
    )
    return skills_path


def test_bare_skills_lists(_skills_and_stats):
    result = CliRunner().invoke(main, ["skills"])
    assert result.exit_code == 0
    assert "good" in result.output and "bad" in result.output


def test_skills_stats_shows_track_record(_skills_and_stats):
    for _ in range(4):
        skill_stats.record_use(["good"])
        skill_stats.record_outcome(["good"], success=True)
    result = CliRunner().invoke(main, ["skills", "stats"])
    assert result.exit_code == 0
    assert "good: uses=4 wins=4" in result.output
    assert "bad: no usage recorded" in result.output


def test_skills_evict_dry_run_lists_without_removing(_skills_and_stats):
    # 0 wins in 16 uses: the Wilson 95% upper bound (0.194) clears the 0.2
    # threshold; 6 uses would leave it near 0.39 and not convict the skill.
    for _ in range(16):
        skill_stats.record_use(["bad"])
        skill_stats.record_outcome(["bad"], success=False)
    result = CliRunner().invoke(main, ["skills", "evict"])
    assert result.exit_code == 0
    assert "candidate: bad" in result.output
    assert "dry-run" in result.output
    # Nothing deleted on a dry run.
    assert (_skills_and_stats / "bad.md").exists()


def test_skills_evict_apply_removes(_skills_and_stats):
    # 0 wins in 16 uses: the Wilson 95% upper bound (0.194) clears the 0.2
    # threshold; 6 uses would leave it near 0.39 and not convict the skill.
    for _ in range(16):
        skill_stats.record_use(["bad"])
        skill_stats.record_outcome(["bad"], success=False)
    result = CliRunner().invoke(main, ["skills", "evict", "--apply"])
    assert result.exit_code == 0
    assert "removed: bad" in result.output
    assert not (_skills_and_stats / "bad.md").exists()
    assert (_skills_and_stats / "good.md").exists()


def test_skills_evict_no_candidates(_skills_and_stats):
    result = CliRunner().invoke(main, ["skills", "evict"])
    assert result.exit_code == 0
    assert "no eviction candidates" in result.output
