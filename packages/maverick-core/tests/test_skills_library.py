"""The shipped cross-cutting + suite SKILL.md library: validates and is wired.

The agent roster shipped 1,000+ domain packs while the SKILL.md library was a
single example -- the highest-leverage gap in the library.
This pins the library (``maverick/skills_builtin/*.md``) to the same
publish-readiness bar the install/distill paths enforce
(``maverick.skills.validate_skill_file``) AND proves it is actually loaded at
runtime via ``available_skills`` (the agent recall path), with the env opt-out
honored.
"""
from __future__ import annotations

import re

import pytest
from maverick.skills import (
    available_skills,
    builtin_skills_dir,
    load_builtin_skills,
    validate_skill_file,
)

_FILES = sorted(builtin_skills_dir().glob("*.md"))


def test_skills_library_present():
    # 20 cross-cutting + 41 suite-specific skills ship with the library.
    assert len(_FILES) >= 60, f"expected >=60 skills, found {len(_FILES)} in {builtin_skills_dir()}"


@pytest.mark.parametrize("path", _FILES, ids=[p.stem for p in _FILES])
def test_skill_validates(path):
    result = validate_skill_file(path)
    assert result.ok, f"{path.name}: {result.errors}"


@pytest.mark.parametrize("path", _FILES, ids=[p.stem for p in _FILES])
def test_skill_filename_is_its_kebab_name(path):
    # The filename stem is the canonical name, so load + the index agree.
    parts = path.read_text(encoding="utf-8").split("---", 2)
    meta = parts[1] if len(parts) >= 3 else ""
    m = re.search(r"(?m)^name:\s*(\S+)", meta)
    assert m, f"{path.name}: no 'name:' in frontmatter"
    assert m.group(1) == path.stem, f"{path.name}: name {m.group(1)!r} != filename stem"


def test_builtin_skills_load_when_enabled(monkeypatch, tmp_path):
    # The autouse conftest disables builtin skills; opt back in and confirm the
    # whole library is recalled through available_skills (the agent path).
    monkeypatch.setenv("MAVERICK_BUILTIN_SKILLS", "1")
    builtin = {s.name for s in load_builtin_skills()}
    assert len(builtin) >= 60
    avail = {s.name for s in available_skills(skills_dir=tmp_path / "empty-user-dir")}
    assert builtin <= avail, "available_skills must include the shipped library when enabled"


def test_builtin_skills_excluded_when_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_BUILTIN_SKILLS", "0")
    assert available_skills(skills_dir=tmp_path / "empty-user-dir") == []


def test_the_library_is_parsed_once_and_each_caller_gets_its_own_copies(monkeypatch):
    from maverick import skills

    monkeypatch.setattr(skills, "_builtin_parsed", None)
    first = load_builtin_skills()
    assert first == skills.load_skills(builtin_skills_dir()), "the same skills as an uncached load"
    parses = []
    real = skills.Skill.parse
    monkeypatch.setattr(skills.Skill, "parse", classmethod(lambda cls, *a: parses.append(1) or real(*a)))
    first[0].triggers.append("changed by one caller")
    second = load_builtin_skills()
    assert parses == [], "the unchanged library is not read again"
    assert "changed by one caller" not in second[0].triggers and second[0] is not first[0]


def _write_skill(directory, name):
    (directory / f"{name}.md").write_text(
        f"---\nname: {name}\ntriggers:\n  - {name}\ntools_needed: []\n---\n# {name}\nDo it.\n", encoding="utf-8")


def test_a_changed_library_directory_is_read_again(monkeypatch, tmp_path):
    import os

    from maverick import skills

    monkeypatch.setattr(skills, "BUILTIN_SKILLS_DIR", tmp_path)
    monkeypatch.setattr(skills, "_builtin_parsed", None)
    _write_skill(tmp_path, "first-skill")
    assert [s.name for s in load_builtin_skills()] == ["first-skill"]
    _write_skill(tmp_path, "second-skill")
    assert sorted(s.name for s in load_builtin_skills()) == ["first-skill", "second-skill"]
    # An editor that rewrites a file in place leaves the directory's time alone.
    folder = tmp_path.stat()
    path = tmp_path / "first-skill.md"
    path.write_text(path.read_text(encoding="utf-8").replace("Do it.", "Do it again."), encoding="utf-8")
    later = path.stat().st_mtime_ns + 1_000_000_000  # a coarse clock must not hide the edit
    os.utime(path, ns=(later, later))
    os.utime(tmp_path, ns=(folder.st_atime_ns, folder.st_mtime_ns))
    assert tmp_path.stat().st_mtime_ns == folder.st_mtime_ns
    bodies = {s.name: s.body for s in load_builtin_skills()}
    assert "Do it again." in bodies["first-skill"]


def test_a_library_with_learned_entries_is_read_for_each_caller(monkeypatch, tmp_path):
    """Whether a learned skill is readable depends on whose task asks; the
    first caller's answer must never be served to the next one."""
    from maverick import skills
    from maverick.logging_config import reset_goal_context, set_goal_context
    from maverick.world_model import WorldModel, default_db_path

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    library = tmp_path / "library"
    library.mkdir(mode=0o700)
    world = WorldModel(default_db_path())
    alice_goal = world.create_goal("alice task", owner="user:alice")
    bob_goal = world.create_goal("bob task", owner="user:bob")
    alice_turn = world.create_goal("alice later task", owner="user:alice")
    world.close()
    _write_skill(library, "plain")
    (library / "learned.md").write_text(
        f"---\nname: learned\nsource: auto-distilled-v1\nsource_goal_ids: {alice_goal}\n---\nAlice's step.\n",
        encoding="utf-8")
    monkeypatch.setattr(skills, "BUILTIN_SKILLS_DIR", library)
    monkeypatch.setattr(skills, "_builtin_parsed", None)

    def names_as(goal_id):
        tokens = set_goal_context(goal_id=goal_id)
        try:
            return (sorted(s.name for s in load_builtin_skills()),
                    sorted(s.name for s in skills.load_skills(library)))
        finally:
            reset_goal_context(tokens)

    bob = names_as(bob_goal)
    alice = names_as(alice_turn)
    assert bob[0] == bob[1] and alice[0] == alice[1]
    assert "learned" in alice[0] and "learned" not in bob[0]
