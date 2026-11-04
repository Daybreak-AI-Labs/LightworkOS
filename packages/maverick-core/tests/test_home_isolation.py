"""The suite must never touch the invoking user's real ``~/.maverick``.

Many modules freeze ``Path.home()``-derived paths into module-level constants
at import time (``world_model.DEFAULT_DB``, ``skills.SKILLS_DIR``, ...), so
per-test ``HOME`` monkeypatches run too late to protect the real home in a
full-suite run: the first collected import bakes the real path into the
constant. The repo-root ``conftest.py`` redirects ``HOME`` before any
collection import; these tests pin that contract by checking the frozen
constants against the OS-level home (``pwd``), which env vars cannot fool.

Without it, test runs leave fake goals and phantom spend in the real
``maverick budget``, junk ``good``/``bad`` skills auto-loaded into real runs,
and test rows in the real audit log.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="pwd is POSIX-only"
)


def _real_home() -> Path:
    import pwd

    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def test_world_model_default_db_is_isolated():
    from maverick import world_model

    assert not str(world_model.DEFAULT_DB).startswith(str(_real_home())), (
        "world_model.DEFAULT_DB points into the real home -- the root "
        "conftest HOME redirect did not run before this import, so 'real "
        "WorldModel' tests would write the developer's actual world.db"
    )


def test_import_frozen_path_constants_are_isolated():
    from maverick import self_learning, skills
    from maverick.skill import stats as skill_stats

    real = str(_real_home())
    frozen = {
        "skills.SKILLS_DIR": skills.SKILLS_DIR,
        "skill_stats.DEFAULT_PATH": skill_stats.DEFAULT_PATH,
        "self_learning.LEARNED_PATH": self_learning.LEARNED_PATH,
    }
    leaked = {name: p for name, p in frozen.items() if str(p).startswith(real)}
    assert not leaked, f"import-frozen paths point into the real home: {leaked}"


def test_runtime_home_is_isolated():
    assert not str(Path.home()).startswith(str(_real_home()))
