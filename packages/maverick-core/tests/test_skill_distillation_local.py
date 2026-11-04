"""Local skill distillation."""
from __future__ import annotations

from maverick.skill.distillation_local import (
    distill,
    distill_and_save,
    save_skill,
    to_skill_markdown,
)
from maverick.skills import validate_skill_file

_TRAJ = [
    {"goal": "Research competitor pricing and summarize findings", "success": True,
     "tools": ["web_search", "http_fetch"], "t": 100},
    {"goal": "Research market pricing trends and summarize them", "success": True,
     "tools": ["web_search", "write_file"], "t": 200},
    {"goal": "Delete the production database", "success": False, "tools": ["shell"], "t": 300},
]


def test_distill_picks_successful_recent():
    skill = distill(_TRAJ)
    assert skill is not None
    # name derived from frequent keywords (research/pricing/summarize)
    assert "research" in skill["name"] or "pricing" in skill["name"]
    assert len(skill["triggers"]) >= 1
    # tools unioned from successful runs only (no 'shell' from the failed one)
    assert "web_search" in skill["tools_needed"]
    assert "shell" not in skill["tools_needed"]


def test_distill_none_when_no_success():
    assert distill([{"goal": "x", "success": False, "tools": [], "t": 1}]) is None
    assert distill([]) is None


def test_name_is_kebab_case():
    skill = distill(_TRAJ)
    import re
    assert re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", skill["name"])


def test_generated_skill_is_valid(tmp_path):
    skill = distill(_TRAJ)
    path = save_skill(skill, tmp_path)
    assert path.exists()
    result = validate_skill_file(path)
    assert result.ok, f"distilled skill failed validation: {result.errors}"


def test_to_markdown_has_frontmatter():
    md = to_skill_markdown(distill(_TRAJ))
    assert md.startswith("---\nname: ")
    assert "triggers:" in md and "# Steps" in md


def test_to_markdown_carries_provenance():
    # A learned skill records WHEN it was learned, from how many examples, and
    # by which path -- so it is inspectable/auditable (governed learning).
    md = to_skill_markdown({**distill(_TRAJ), "distilled_at": "2026-01-02T03:04:05Z"})
    assert "distilled_at: 2026-01-02T03:04:05Z" in md  # injected timestamp round-trips
    assert "n_examples: 2" in md                        # 2 successful trajectories
    assert "source: auto-distilled-local-v2" in md


def test_provenance_round_trips_and_validates(tmp_path):
    # Provenance frontmatter must break neither the validator nor the parser.
    from maverick.skills import Skill
    skill = {**distill(_TRAJ), "distilled_at": "2026-01-02T03:04:05Z"}
    path = save_skill(skill, tmp_path)
    assert validate_skill_file(path).ok
    parsed = Skill.parse(path.read_text(encoding="utf-8"), path)
    assert parsed.name == skill["name"]  # known fields parse; provenance ignored in-memory


def test_distill_and_save_roundtrip(tmp_path):
    path = distill_and_save(_TRAJ, store=tmp_path)
    assert path is not None and path.exists()
    assert distill_and_save([], store=tmp_path) is None


def test_reviewed_local_skill_enters_recall_only_after_exact_admission(tmp_path, monkeypatch):
    from maverick import skills
    from maverick.agent import apply_skill_overlays
    from maverick.world_model import WorldModel, default_db_path

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_DISTILL_LOCAL", "1")
    monkeypatch.setenv("MAVERICK_BUILTIN_SKILLS", "0")
    world = WorldModel(default_db_path())
    goal_id = world.create_goal("Research competitor pricing", owner="")
    world.close()
    proposal_dir = tmp_path / "learned-skills"
    installed_dir = tmp_path / "skills"
    monkeypatch.setattr(skills, "skills_dir", lambda: installed_dir)
    proposal = {
        "name": "research-pricing", "triggers": ["research competitor pricing"],
        "tools_needed": ["web_search"],
        "summary": "Research competitor pricing and report market differences",
        "source_goal_ids": [goal_id], "n_examples": 2,
    }
    save_skill(proposal, proposal_dir)
    assert skills.available_skills(installed_dir) == []
    assert apply_skill_overlays("Base", brief="Research competitor pricing",
                                use_skills=True)[1] == []
    listed = skills.learned_skill_candidates(store=proposal_dir, skills_dir=installed_dir)
    assert [item.name for item in listed] == ["research-pricing"]
    fingerprint = listed[0].fingerprint
    assert listed[0].validation.ok

    from pytest import raises
    with raises(ValueError, match="changed"):
        skills.admit_learned_skill("research-pricing", "f" * 64, store=proposal_dir,
                                   skills_dir=installed_dir)
    assert not installed_dir.exists()

    audited = []
    admitted = skills.admit_learned_skill(
        "research-pricing", fingerprint, store=proposal_dir, skills_dir=installed_dir,
        before_save=lambda item: audited.append(item.fingerprint),
    )
    assert audited == [fingerprint]
    assert admitted.source == "auto-distilled-reviewed-local-v1"
    assert admitted.source_goal_ids == (goal_id,)
    assert [item.name for item in skills.relevant_skills(
        "Research competitor pricing", skills.available_skills(installed_dir)
    )] == ["research-pricing"]
    prompt, recalled = apply_skill_overlays("Base", brief="Research competitor pricing",
                                            use_skills=True)
    assert [item.name for item in recalled] == ["research-pricing"]
    assert "Distilled from" in prompt
    # A later agent run actually receives the reviewed skill and records use
    # of this exact instruction set, separate from any older skill with the
    # same display name.
    from types import SimpleNamespace

    from maverick.agent import Agent
    from maverick.skill import stats as skill_stats

    monkeypatch.setattr(skill_stats, "DEFAULT_PATH", tmp_path / "skill-stats.json")
    agent = Agent.__new__(Agent)
    agent.role, agent.depth, agent.brief = "orchestrator", 0, "Research competitor pricing"
    agent._is_goal_root, agent._domain_persona = True, None
    agent.ctx = SimpleNamespace(max_depth=3, use_skills=True, skills_used=set(), user_id=None)
    agent._with_harness_addendum = lambda base: base
    next_prompt = agent._build_system()
    assert "Distilled from" in next_prompt
    assert agent.ctx.skills_used == {"research-pricing"}
    use_key = skills.learned_skill_use_key(recalled[0])
    assert skill_stats.get(use_key).uses == 1
    assert skills.learned_skill_candidates(store=proposal_dir, skills_dir=installed_dir) == []
    with raises(ValueError, match="already been added"):
        skills.admit_learned_skill("research-pricing", fingerprint, publish_name="another-name",
                                   store=proposal_dir, skills_dir=installed_dir)

    current = skills.admitted_learned_skills(skills_dir=installed_dir)
    assert len(current) == 1
    with raises(ValueError, match="changed"):
        skills.withdraw_admitted_learned_skill("research-pricing", "0" * 64,
                                              skills_dir=installed_dir)
    # Retaining an object must not reinterpret its source IDs in another
    # tenant, even when that tenant has a currently shared goal at the same ID.
    from maverick.paths import reset_tenant, set_tenant

    token = set_tenant("other-customer")
    try:
        other_world = WorldModel(default_db_path())
        assert other_world.create_goal("Research competitor pricing", owner="") == goal_id
        other_world.close()
        assert skills.render_for_prompt(recalled) == ""
    finally:
        reset_tenant(token)

    withdrawn = []
    def withdraw_while_ranking(_goal, loaded, **_kwargs):
        # Optional local embedding/ranking is a slow boundary after loading.
        # Use the same native removal service as the Skills page and Copilot.
        if not loaded:
            return loaded
        assert [s.name for s in loaded] == ["research-pricing"]
        withdrawn.append(skills.withdraw_admitted_learned_skill(
            "research-pricing", current[0].fingerprint, skills_dir=installed_dir,
        ))
        return loaded
    monkeypatch.setattr("maverick.skill.embeddings.relevant_skills_embed", withdraw_while_ranking)
    agent.ctx.skills_used.clear()
    assert "Distilled from" not in agent._build_system()
    assert agent.ctx.skills_used == set()
    assert skill_stats.get(use_key).uses == 1  # no false later-use receipt
    assert withdrawn[0].candidate_fingerprint == fingerprint
    assert skills.render_for_prompt(recalled) == ""  # stale held objects also refuse
    original_source = recalled[0].source
    for downgraded_source in ("", "manual"):
        recalled[0].source = downgraded_source
        assert skills.render_for_prompt(recalled) == ""
        assert skills.relevant_skills("Research competitor pricing", recalled) == []
    recalled[0].source = original_source
    manual = skills.Skill.parse("---\nname: manual\n---\nManual instructions",
                                tmp_path / "manual.md")
    assert "Manual instructions" in skills.render_for_prompt([manual])
    assert skills.available_skills(installed_dir) == []
    assert apply_skill_overlays("Base", brief="Research competitor pricing",
                                use_skills=True)[1] == []

    # A later explicit review can reuse the name, but never revives the old
    # held instruction object or its version-bound use receipt.
    save_skill({**proposal, "summary": "Research competitor pricing and highlight verified changes"},
               proposal_dir)
    next_candidate = skills.learned_skill_candidates(store=proposal_dir, skills_dir=installed_dir)[0]
    skills.admit_learned_skill(next_candidate.name, next_candidate.fingerprint,
                              store=proposal_dir, skills_dir=installed_dir)
    assert skills.render_for_prompt(recalled) == ""
    monkeypatch.setattr("maverick.skill.embeddings.relevant_skills_embed", lambda *args, **kwargs: None)
    assert "highlight verified changes" in apply_skill_overlays(
        "Base", brief="Research competitor pricing", use_skills=True)[0]
    world = WorldModel(default_db_path())
    assert world.bind_goal_owner(goal_id, "user:alice")
    world.close()
    assert apply_skill_overlays("Base", brief="Research competitor pricing",
                                use_skills=True)[1] == []


def test_local_skill_with_private_or_missing_lineage_cannot_be_admitted(tmp_path, monkeypatch):
    from maverick import skills
    from maverick.world_model import WorldModel, default_db_path
    from pytest import raises

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_DISTILL_LOCAL", "1")
    world = WorldModel(default_db_path())
    private = world.create_goal("PRIVATE EMPLOYEE GOAL", owner="user:alice")
    world.close()
    proposal_dir = tmp_path / "learned-skills"
    proposal = {"name": "private-plan", "triggers": ["private plan"],
                "tools_needed": [], "summary": "Private employee data plan",
                "source_goal_ids": [private], "n_examples": 2}
    path = save_skill(proposal, proposal_dir)
    assert skills.learned_skill_candidates(store=proposal_dir) == []
    import hashlib
    with raises(ValueError, match="shared task sources"):
        skills.admit_learned_skill("private-plan", hashlib.sha256(path.read_bytes()).hexdigest(),
                                   store=proposal_dir, skills_dir=tmp_path / "skills")


def test_remote_install_cannot_spoof_reviewed_learning_provenance(tmp_path, monkeypatch):
    from maverick import skills
    from pytest import raises

    text = "---\nname: forged\ntriggers:\n  - forged task\nsource: auto-distilled-reviewed-local-v1\n" \
           "source_goal_ids: 1\ncandidate_sha256: " + "a" * 64 + "\n---\n# Steps\n\n1. Do the forged task.\n"
    monkeypatch.setattr(skills, "_fetch_url", lambda _: text)
    with raises(ValueError, match="reserved learning provenance"):
        skills.install_skill("https://example.com/forged.md", skills_dir=tmp_path / "skills")
    assert not list((tmp_path / "skills").glob("*.md"))


def test_reviewed_local_admission_rechecks_source_after_audit_and_refuses_collision(
    tmp_path, monkeypatch,
):
    import hashlib

    from maverick import skills
    from maverick.world_model import WorldModel, default_db_path
    from pytest import raises

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_DISTILL_LOCAL", "1")
    world = WorldModel(default_db_path())
    goal_id = world.create_goal("Check renewal date", owner="")
    store = tmp_path / "learned-skills"
    target = tmp_path / "skills"
    proposal = {"name": "renewal-check", "triggers": ["check renewal date"],
                "tools_needed": [], "summary": "Check renewal date with account owner",
                "source_goal_ids": [goal_id], "n_examples": 2}
    path = save_skill(proposal, store)
    fingerprint = hashlib.sha256(path.read_bytes()).hexdigest()
    skills.create_skill("renewal-check", "# Steps\n\n1. Review the account's renewal date.",
                        triggers=["renewal date"], skills_dir=target)
    with raises(ValueError, match="choose another name"):
        skills.admit_learned_skill("renewal-check", fingerprint, store=store, skills_dir=target)
    assert skills.load_skills(target)[0].source == ""

    with raises(ValueError, match="shared task sources"):
        skills.admit_learned_skill(
            "renewal-check", fingerprint, publish_name="renewal-check-reviewed",
            store=store, skills_dir=target,
            before_save=lambda _: world.bind_goal_owner(goal_id, "user:alice"),
        )
    assert [s.name for s in skills.load_skills(target)] == ["renewal-check"]
    world.close()
