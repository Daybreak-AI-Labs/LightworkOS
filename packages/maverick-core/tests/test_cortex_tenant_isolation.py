"""Cortex cross-tenant isolation -- the company brain must never surface one
tenant's memory in another's recall.

Cortex federates knowledge / skills / lessons / record / fleet. Each floors to
the active tenant differently -- the world (record) by RLS or a per-tenant
``world.db``, and knowledge / skills / lessons by their ``data_dir``-scoped
directory. This proves the guarantee end-to-end on the DEFAULT (file/directory)
deployment: content deposited as tenant A never appears in tenant B's recall
from ANY source, while A still recalls its own. Pure/offline: a temp
``MAVERICK_HOME`` so nothing touches the real home.
"""
from __future__ import annotations

import json

import pytest
from maverick import cortex
from maverick import self_harness as sh
from maverick import skills as skills_mod
from maverick.paths import reset_tenant, set_tenant

# A token that only ever exists in tenant A's stores; it must never reach B.
_MARKER = "widgetsecret"
_QUERY = "widgetsecret turbofoo guidance"


@pytest.fixture(autouse=True)
def _temp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    # Cortex + self-harness stores on their defaults (files, per-tenant dir).
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    from maverick import world_model
    world_model._tenant_worlds.clear()
    tok = set_tenant(None)
    yield
    reset_tenant(tok)
    world_model._tenant_worlds.clear()


def _seed_tenant_a():
    """Deposit a lesson, a skill and an Operating-Record goal for tenant acme,
    each carrying the secret marker, under acme's per-tenant directories."""
    tok = set_tenant("acme")
    try:
        # The lesson has a real currently unowned source in the same tenant.
        # Keep the cached tenant world open for the native recall-time check.
        from maverick.world_model import close_world_if_owned, open_world
        world = open_world()
        try:
            source_id = world.create_goal(f"{_QUERY} plan", description="acme only", owner="")
        finally:
            close_world_if_owned(world)
        sh._apply_addendum(sh.HarnessProposal(
            model_id="MODEL-X", signature="tenant recall fixture",
            addendum_line=f"alpha guidance about {_MARKER} turbofoo",
            rationale="source-bound tenant lesson", source_goal_ids=(source_id,)))
        # skills: a plain skill file dropped into acme's skills dir.
        sk = skills_mod.skills_dir()
        sk.mkdir(parents=True, exist_ok=True)
        (sk / "alpha.md").write_text(
            f"---\nname: alpha-{_MARKER}\ntriggers: [{_MARKER}, turbofoo]\n---\n"
            f"Guidance about {_MARKER} turbofoo widgets.\n",
            encoding="utf-8",
        )
    finally:
        reset_tenant(tok)


def _recall_as(tenant, **kw):
    tok = set_tenant(tenant)
    try:
        return cortex.recall(_QUERY, **kw)
    finally:
        reset_tenant(tok)


def test_no_source_leaks_tenant_a_content_to_tenant_b():
    _seed_tenant_a()
    res = _recall_as("globex")
    # Not one hit from any source may carry acme's marker.
    blob = " ".join(h.text + " " + h.citation for h in res.hits)
    assert _MARKER not in blob
    assert all(_MARKER not in json.dumps(h.meta) for h in res.hits)
    # The result is answered for globex, and every source that answered did so
    # from globex's (empty) stores -- so zero acme hits, per source.
    assert res.tenant == "globex"
    assert res.per_source.get("lessons", 0) == 0


def test_tenant_a_still_recalls_its_own_lessons_and_record():
    _seed_tenant_a()
    res = _recall_as("acme", sources=("lessons", "record"))
    hits = " ".join(h.text for h in res.hits)
    assert _MARKER in hits  # positive control: acme sees its own memory
    assert res.tenant == "acme"
    assert res.per_source["lessons"] > 0
    assert res.per_source["record"] > 0


def test_lessons_source_is_strictly_tenant_scoped():
    # Focused proof for the source whose shared-Postgres store this change
    # hardened: A deposits, B gets nothing, A gets its line.
    _seed_tenant_a()
    a = _recall_as("acme", sources=("lessons",))
    b = _recall_as("globex", sources=("lessons",))
    assert any(_MARKER in h.text for h in a.hits)
    assert b.per_source["lessons"] == 0
    assert all(_MARKER not in h.text for h in b.hits)
