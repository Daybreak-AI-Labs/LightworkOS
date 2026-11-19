"""A single-person installation learns from its owner's tasks.

Learned skills are shared by everyone in a workspace, so learning used only
ownerless tasks. Once the owner signs in, every task has an owner, and live
"Learn now" reviewed 0 of 70 finished tasks. On an installation only its
owner can sign in to, shared means the owner, so their tasks count. Any sign
of a second person turns that off again, and review and recall re-ask, so a
skill learned from the owner's tasks never reaches anyone else.
"""
from __future__ import annotations

import json

import pytest

OWNER = "owner@example.test"
OTHER = "colleague@example.test"


@pytest.fixture
def home(tmp_path, monkeypatch):
    from maverick import config

    for name in ("MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _owner(home, email=OWNER, status="ready"):
    (home / "dashboard-owner.json").write_text(json.dumps(
        {"schema": "lightwork.local-owner.v1", "status": status, "email": email}), encoding="utf-8")


def _write(home, name, data):
    (home / name).write_text(json.dumps(data), encoding="utf-8")


# -- who counts as the only person ---------------------------------------------

def test_the_ready_owner_alone_is_the_sole_person(home):
    from maverick.memory_ownership import sole_person

    assert sole_person() == ""                      # nobody set up yet
    _owner(home, status="pending")
    assert sole_person() == ""
    _owner(home)
    assert sole_person() == f"user:{OWNER}"
    # The owner's own records do not count as a second person.
    _write(home, "dashboard-passphrases.json", {"schema": "x", "accounts": {OWNER: {}}})
    _write(home, "dashboard-users.json", {f"user:{OWNER}": "admin"})
    _write(home, "dashboard-tenant-roles.json", {"local": {f"user:{OWNER}": "admin"}})
    _write(home, "dashboard-workspace-tenants.json", {"schema": "x", "selections": {OWNER: {}}})
    assert sole_person() == f"user:{OWNER}"


@pytest.mark.parametrize("name,data", [
    ("dashboard-invites.json", {"invite_1": {"email": OTHER, "created_by": OWNER}}),
    ("dashboard-passphrases.json", {"schema": "x", "accounts": {OWNER: {}, OTHER: {}}}),
    ("dashboard-users.json", {f"user:{OWNER}": "admin", f"user:{OTHER}": "operator"}),
    ("dashboard-tenant-roles.json", {"local": {f"user:{OTHER}": "viewer"}}),
    ("dashboard-workspace-tenants.json", {"schema": "x", "selections": {OTHER: {}}}),
    ("scim_users.json", {"users": [{"userName": OTHER}]}),
])
def test_any_second_person_ends_it(home, name, data):
    from maverick.memory_ownership import sole_person

    _owner(home)
    _write(home, name, data)
    assert sole_person() == ""


@pytest.mark.parametrize("env", ["MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_DASHBOARD_TOKEN"])
def test_a_sign_in_that_admits_other_people_ends_it(home, monkeypatch, env):
    from maverick.memory_ownership import sole_person

    _owner(home)
    monkeypatch.setenv(env, "1")
    assert sole_person() == ""


def test_a_configured_administrator_list_or_saved_token_ends_it(home):
    from maverick import config
    from maverick.memory_ownership import sole_person

    _owner(home)
    (home / "config.toml").write_text(f'[dashboard]\nadmins = ["{OTHER}"]\n', encoding="utf-8")
    config.reset_config_cache()
    assert sole_person() == ""
    (home / "config.toml").write_text('[dashboard]\ntoken = "shared-secret"\n', encoding="utf-8")  # pragma: allowlist secret
    config.reset_config_cache()
    assert sole_person() == ""


def test_an_unreadable_record_ends_it(home):
    from maverick.memory_ownership import sole_person

    _owner(home)
    (home / "dashboard-users.json").write_text("{not json", encoding="utf-8")
    assert sole_person() == ""
    _write(home, "dashboard-users.json", ["unexpected", "shape"])
    assert sole_person() == ""


# -- learning, review and recall -----------------------------------------------

def _owned_goals(titles, owner=f"user:{OWNER}"):
    from maverick.world_model import WorldModel, default_db_path

    world = WorldModel(default_db_path())
    ids = []
    for title in titles:
        gid = world.create_goal(title, owner=owner)
        world.set_goal_status(gid, "done", result="Done.")
        ids.append(gid)
    return world, ids


def test_learn_now_reviews_the_owners_tasks_only_while_they_are_alone(home, monkeypatch):
    from maverick import dreaming

    monkeypatch.setattr(dreaming, "settings", lambda: {"enable": True, "min_cluster": 2, "max_insights": 100})
    _owner(home)
    world, _ids = _owned_goals(["Reconcile the supplier statement for March",
                                "Reconcile the supplier statement for April"])
    paths = {"reflexion_path": home / "r.ndjson", "insights_path": home / "i.ndjson",
             "skill_store": home / "learned-skills", "skill_stats_path": home / "s.json", "audit": False}
    try:
        assert dreaming.dream_cycle(world, profiles={}, **paths).goals_replayed == 2
        _write(home, "dashboard-invites.json", {"invite_1": {"email": OTHER}})
        assert dreaming.dream_cycle(world, profiles={}, **paths).goals_replayed == 0
    finally:
        world.close()


def test_a_skill_from_the_owners_tasks_reaches_only_the_owner_while_they_are_alone(home, monkeypatch):
    from maverick import logging_config, skills
    from maverick.skill.distillation_local import save_skill

    monkeypatch.setenv("MAVERICK_DISTILL_LOCAL", "1")
    monkeypatch.setenv("MAVERICK_BUILTIN_SKILLS", "0")
    _owner(home)
    world, (source, mine) = _owned_goals(["Research competitor pricing", "Research partner pricing"])
    theirs = world.create_goal("Research supplier pricing", owner=f"user:{OTHER}")
    world.close()
    proposal_dir, installed_dir = home / "learned-skills", home / "skills"
    monkeypatch.setattr(skills, "skills_dir", lambda: installed_dir)
    save_skill({"name": "research-pricing", "triggers": ["research competitor pricing"],
                "tools_needed": ["web_search"], "summary": "Research competitor pricing and report differences",
                "source_goal_ids": [source], "n_examples": 2}, proposal_dir)

    listed = skills.learned_skill_candidates(store=proposal_dir, skills_dir=installed_dir)
    assert [item.name for item in listed] == ["research-pricing"]
    admitted = skills.admit_learned_skill("research-pricing", listed[0].fingerprint,
                                          store=proposal_dir, skills_dir=installed_dir)
    assert skills.admitted_learned_skills(skills_dir=installed_dir)[0].source_shared

    def recalled_for(goal_id):
        monkeypatch.setattr(logging_config, "current_goal_id", lambda: goal_id)
        return skills._source_readable(admitted)

    assert recalled_for(mine) is True          # the owner's next task gets it
    assert recalled_for(theirs) is False       # nobody else's does
    assert recalled_for(None) is False         # nor an ownerless task

    # A second person can now sign in: the skill goes back to private.
    _write(home, "dashboard-passphrases.json", {"schema": "x", "accounts": {OWNER: {}, OTHER: {}}})
    assert recalled_for(mine) is False
    assert not skills.admitted_learned_skills(skills_dir=installed_dir)[0].source_shared
    with pytest.raises(ValueError, match="shared task sources"):
        skills._learned_candidate("research-pricing", store=proposal_dir)
