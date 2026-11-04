"""Installing a skill without a `name` in frontmatter must be rejected.

Skill.parse falls back to path.stem when `name:` is absent; on install the
staging path is '.validating', so a nameless skill silently installed under
the bogus name 'validating'. install_skill now requires the name.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick.skills import install_skill

_NAMELESS = "---\ntriggers:\n  - x\n---\nbody only, no name\n"
_NAMED = "---\nname: greety\ntriggers:\n  - hi\n---\nbe warm\n"


def test_install_skill_rejects_missing_name(tmp_path: Path):
    src = tmp_path / "bad.md"
    src.write_text(_NAMELESS)
    with pytest.raises(ValueError, match="missing required 'name'"):
        install_skill(str(src), skills_dir=tmp_path / "skills")
    # Nothing bogus was written.
    assert not (tmp_path / "skills" / "validating.md").exists()


def test_install_skill_accepts_named(tmp_path: Path):
    src = tmp_path / "ok.md"
    src.write_text(_NAMED)
    skill = install_skill(str(src), skills_dir=tmp_path / "skills")
    assert skill.name == "greety"
    assert (tmp_path / "skills" / "greety.md").exists()
