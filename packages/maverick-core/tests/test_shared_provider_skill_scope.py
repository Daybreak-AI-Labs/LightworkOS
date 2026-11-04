"""Only explicit shared goal sources may publish tenant-wide provider skills."""
from __future__ import annotations

import hashlib

from maverick import audit, memory_ownership, skills
from maverick.blackboard import Blackboard
from maverick.logging_config import reset_goal_context, set_goal_context
from maverick.world_model import WorldModel, default_db_path

_VALID = "---\nname: repeatable-check\ntriggers:\n  - check a report\n---\n# Steps\n\n1. Check it.\n"


def test_private_goal_refused_before_provider_or_shared_directory(
    tmp_path, fake_llm,
):
    world = WorldModel(tmp_path / "world.db")
    private_id = world.create_goal("PRIVATE PAYROLL TITLE", owner="user:alice")
    target = tmp_path / "skills"
    tokens = set_goal_context(goal_id=private_id)
    try:
        assert skills.distill("PRIVATE PAYROLL TITLE", "result", Blackboard(),
                              fake_llm, skills_dir=target, source_world=world) is None
    finally:
        reset_goal_context(tokens)
        world.close()
    assert fake_llm.calls == []
    assert not target.exists()


def test_missing_goal_context_cannot_publish_shared_skill(tmp_path, fake_llm):
    target = tmp_path / "skills"
    assert skills.distill("unknown source", "result", Blackboard(), fake_llm,
                          skills_dir=target) is None
    assert fake_llm.calls == []
    assert not target.exists()


def test_shared_skill_has_source_and_prepared_audit_receipt(
    tmp_path, fake_llm, make_llm_response, monkeypatch,
):
    world = WorldModel(tmp_path / "world.db")
    shared_id = world.create_goal("shared task", owner="")
    target = tmp_path / "skills"
    skill_path = target / "repeatable-check.md"
    events = []

    def capture(kind, **payload):
        events.append((kind, payload, skill_path.exists()))
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    fake_llm.scripted = [make_llm_response(text=_VALID)]
    tokens = set_goal_context(goal_id=shared_id)
    try:
        result = skills.distill("shared task", "result", Blackboard(), fake_llm,
                                skills_dir=target, source_world=world)
    finally:
        reset_goal_context(tokens)
        world.close()

    assert result is not None and result.name == "repeatable-check"
    assert len(fake_llm.calls) == 1
    assert f"source_goal_ids: {shared_id}" in skill_path.read_text(encoding="utf-8")
    kind, receipt, existed_at_prepare = events[0]
    assert kind == audit.EventKind.SKILL_DISTILL_PREPARED
    assert receipt["goal_id"] == shared_id
    assert receipt["content_sha256"] == hashlib.sha256(skill_path.read_bytes()).hexdigest()
    assert existed_at_prepare is False


def test_scope_change_before_save_and_audit_failure_leave_no_skill(
    tmp_path, fake_llm, make_llm_response, monkeypatch,
):
    world = WorldModel(tmp_path / "world.db")
    shared_id = world.create_goal("shared task", owner="")
    target = tmp_path / "skills"
    tokens = set_goal_context(goal_id=shared_id)
    try:
        fake_llm.scripted = [make_llm_response(text=_VALID)]
        checks = 0
        real_allowed = memory_ownership.source_allowed

        def changed_scope(goal_id, owner, *, world=None):
            nonlocal checks
            checks += 1
            return checks == 1 and real_allowed(goal_id, owner, world=world)

        monkeypatch.setattr(memory_ownership, "source_allowed", changed_scope)
        assert skills.distill("shared task", "result", Blackboard(), fake_llm,
                              skills_dir=target, source_world=world) is None
        assert len(fake_llm.calls) == 1
        assert list(target.glob("*.md")) == []

        monkeypatch.setattr(memory_ownership, "source_allowed", real_allowed)
        monkeypatch.setattr(audit, "audit_event", lambda *args, **kwargs: False)
        fake_llm.scripted = [make_llm_response(text=_VALID)]
        assert skills.distill("shared task", "result", Blackboard(), fake_llm,
                              skills_dir=target, source_world=world) is None
        assert list(target.glob("*.md")) == []
    finally:
        reset_goal_context(tokens)
        world.close()


def test_automatic_distillation_cannot_replace_a_saved_skill(
    tmp_path, fake_llm, make_llm_response, monkeypatch,
):
    world = WorldModel(tmp_path / "world.db")
    shared_id = world.create_goal("shared task", owner="")
    target = tmp_path / "skills"
    target.mkdir()
    path = target / "repeatable-check.md"
    original = _VALID.replace("1. Check it.", "1. Follow the approved company procedure.")
    path.write_text(original, encoding="utf-8")
    receipts = []
    monkeypatch.setattr(audit, "audit_event", lambda *args, **kwargs: receipts.append(args) or True)
    fake_llm.scripted = [make_llm_response(text=_VALID)]
    tokens = set_goal_context(goal_id=shared_id)
    try:
        result = skills.distill("shared task", "result", Blackboard(), fake_llm,
                               skills_dir=target, source_world=world)
    finally:
        reset_goal_context(tokens)
        world.close()
    assert result is None
    assert path.read_text(encoding="utf-8") == original
    assert receipts == []


def test_automatic_distillation_cannot_shadow_a_builtin_skill(
    tmp_path, fake_llm, make_llm_response, monkeypatch,
):
    world = WorldModel(tmp_path / "world.db")
    shared_id = world.create_goal("shared task", owner="")
    target = tmp_path / "skills"
    builtin = skills.Skill.parse(_VALID, tmp_path / "builtin.md")
    monkeypatch.setattr(skills, "load_builtin_skills", lambda: [builtin])
    fake_llm.scripted = [make_llm_response(text=_VALID)]
    tokens = set_goal_context(goal_id=shared_id)
    try:
        assert skills.distill("shared task", "result", Blackboard(), fake_llm,
                              skills_dir=target, source_world=world) is None
    finally:
        reset_goal_context(tokens)
        world.close()
    assert not list(target.glob("*.md"))


def test_existing_private_provider_skill_is_retained_but_unavailable(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    world = WorldModel(default_db_path())
    private_id = world.create_goal("private payroll", owner="user:alice")
    shared_id = world.create_goal("shared checklist", owner="")
    target = skills.skills_dir()
    target.mkdir(parents=True)
    (target / "private.md").write_text(
        f"---\nname: private\nsource: auto-distilled-provider-v1\n"
        f"source_goal_ids: {private_id}\n---\nPRIVATE PAYROLL INSTRUCTION",
        encoding="utf-8",
    )
    (target / "shared.md").write_text(
        f"---\nname: shared\nsource: auto-distilled-provider-v1\n"
        f"source_goal_ids: {shared_id}\n---\nShared checklist instruction",
        encoding="utf-8",
    )
    tokens = set_goal_context(goal_id=private_id)
    try:
        assert [skill.name for skill in skills.load_skills()] == ["shared"]
        private = skills.Skill.parse((target / "private.md").read_text(encoding="utf-8"),
                                     target / "private.md")
        assert skills.render_for_prompt([private]) == ""
    finally:
        reset_goal_context(tokens)
        world.close()
    assert (target / "private.md").exists()  # reviewable legacy data, not erased
