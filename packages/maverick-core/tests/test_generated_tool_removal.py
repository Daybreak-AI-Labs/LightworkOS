"""Owned generated-tool inspection used by the reviewed removal."""
from __future__ import annotations

import os

from maverick.budget import Budget
from maverick.file_lock import private_path_is_restricted


def test_older_broad_file_keeps_one_identity_after_it_is_tightened(monkeypatch, tmp_path):
    # A tool written by an older release can be group/world readable. The
    # first inspection tightens it; the identity it reports must be the
    # tightened file's, or every first listing reads as "changed".
    from maverick import generated_tool_removal as engine
    from maverick import self_learning
    from maverick.learning_content import lineage, publish

    gen = tmp_path / "generated_tools"
    gen.mkdir()
    monkeypatch.setitem(self_learning.__dict__, "GENERATED_TOOLS_DIR", gen)
    target = gen / "older.py"
    target.write_text("# older tool\n", encoding="utf-8")
    os.chmod(target, 0o644)
    publish(target, "# older tool\n", lineage())

    def allowance():
        return Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)

    first = engine.inventory("", allowance())
    assert [row["name"] for row in first] == ["older"]
    if os.name == "nt":
        # Windows has no group/other mode bits; the tightened file gets the
        # protected owner-only DACL that ensure_private_file installs.
        assert private_path_is_restricted(target)
    else:
        assert target.stat().st_mode & 0o077 == 0
    assert engine.inspect("older", "", allowance())["binding"] == first[0]["binding"]
