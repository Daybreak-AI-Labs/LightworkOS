"""Installing a skill must not silently clobber a different skill.

Two different frontmatter names can sanitize to the same filename (e.g. "..."
and "....." both -> "skill"), and a second install that silently overwrote the
first would lose data. A colliding install is refused; a same-name re-install
(an update) still succeeds.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from maverick.skills import install_skill


def _write(tmp: Path, fname: str, name: str, body: str) -> str:
    src = tmp / fname
    src.write_text(f'---\nname: "{name}"\ntriggers:\n  - x\n---\n{body}\n')
    return str(src)


def test_colliding_different_skill_is_refused_not_clobbered(tmp_path: Path):
    skills = tmp_path / "skills"
    first = _write(tmp_path, "a.md", "...", "FIRST skill body")
    second = _write(tmp_path, "b.md", ".....", "SECOND skill body")  # also -> "skill.md"

    s1 = install_skill(first, skills_dir=skills)
    assert s1.path.name == "skill.md"
    assert "FIRST" in s1.path.read_text()

    with pytest.raises(ValueError, match="different skill already occupies"):
        install_skill(second, skills_dir=skills)
    # The first skill survived intact -- no silent clobber.
    assert "FIRST" in (skills / "skill.md").read_text()


def test_same_name_reinstall_updates(tmp_path: Path):
    skills = tmp_path / "skills"
    v1 = _write(tmp_path, "v1.md", "greety", "version one")
    install_skill(v1, skills_dir=skills)
    v2 = _write(tmp_path, "v2.md", "greety", "version two")
    s = install_skill(v2, skills_dir=skills)  # same name -> update, no error
    assert "version two" in s.path.read_text()


@pytest.mark.parametrize("dangling", [False, True])
def test_skill_install_refuses_symlink_target_without_touching_referent(
    tmp_path: Path, dangling: bool,
):
    skills = tmp_path / "skills"
    skills.mkdir()
    source = _write(tmp_path, "source.md", "greety", "new body")
    outside = tmp_path / "outside.md"
    original = '---\nname: "greety"\ntriggers:\n  - x\n---\nORIGINAL\n'
    if not dangling:
        outside.write_text(original, encoding="utf-8")
    try:
        (skills / "greety.md").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")

    with pytest.raises(ValueError, match="alias or special file"):
        install_skill(source, skills_dir=skills)
    if dangling:
        assert not outside.exists()
    else:
        assert outside.read_text(encoding="utf-8") == original


def test_skill_install_refuses_hardlinked_target(tmp_path: Path):
    skills = tmp_path / "skills"
    skills.mkdir()
    source = _write(tmp_path, "source.md", "greety", "new body")
    outside = tmp_path / "outside.md"
    original = '---\nname: "greety"\ntriggers:\n  - x\n---\nORIGINAL\n'
    outside.write_text(original, encoding="utf-8")
    try:
        os.link(outside, skills / "greety.md")
    except OSError:
        pytest.skip("hardlink creation is unavailable on this platform")

    with pytest.raises(ValueError, match="alias or special file"):
        install_skill(source, skills_dir=skills)
    assert outside.read_text(encoding="utf-8") == original
