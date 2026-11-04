"""Skills, add-ons, templates, tool servers and connectors: the buttons that
replace ``maverick skill install`` / ``skills stats`` / ``skills evict`` /
``plugin verify|lock|reload|stats|new`` / ``template ratings-export`` /
``mcp-registry add`` / ``connectors list|simulate|plan``.

Each route: permission refusal, the kernel function doing the work, the
confirmation a destructive change needs, the activity-record row, bounded
input, and plain wording on the pages."""
from __future__ import annotations

import io
import json
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
SKILL = """---
name: weekly-status
triggers:
  - weekly status
tools_needed:
  - http_fetch
---
# Steps

1. Gather the week's finished tasks and summarise them in five bullet points.
"""


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_CONFIG", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT",
                 "MAVERICK_ALLOW_SKILL_INSTALL", "MAVERICK_GOVERNED_CONNECTORS",
                 "MAVERICK_CONNECTIONS", "LIGHTWORK_CONNECTIONS"):
        monkeypatch.delenv(name, raising=False)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    from maverick.skill import stats as skill_stats
    monkeypatch.setattr(skill_stats, "DEFAULT_PATH", tmp_path / "skill_stats.json")
    import maverick.skills as skills_mod
    monkeypatch.setattr(skills_mod, "skills_dir", lambda: tmp_path / "skills")
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()
    try:
        yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    finally:
        config.reset_config_cache()
        audit_writer._default = None
        audit_writer._defaults.clear()
        dash_app._world_cache.clear()


def _as(monkeypatch, role: str, who: str | None = None) -> None:
    from maverick_dashboard import auth, rbac
    who = who or f"user:{role}1"
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _audit(monkeypatch) -> list[dict]:
    from maverick.audit import writer
    seen: list[dict] = []
    real = writer.audit_event

    def spy(kind, **payload):
        seen.append(payload)
        return real(kind, **payload)
    monkeypatch.setattr(writer, "audit_event", spy)
    import maverick.audit as audit_pkg
    monkeypatch.setattr(audit_pkg, "audit_event", spy)
    return seen


def _verbs(seen) -> list[str]:
    return [p.get("verb") for p in seen if p.get("verb")]


def _skill_change(client, name, action, fingerprint, *, publish_name="", confirm=True):
    """Review, then add or remove a suggested skill the way the Skills page does."""
    base = "/api/v1/skills/learned-candidates/" + name
    context = client.get("/api/v1/skills/learned-candidates").json()["context"]
    review = client.post(base + "/review", json={"action": action, "fingerprint": fingerprint,
                                                 "publish_name": publish_name, "context": context})
    if review.status_code != 200:
        return review
    body = {"fingerprint": fingerprint, "confirm": confirm, "review_token": review.json()["token"]}
    if action == "admit" and publish_name:
        body["publish_name"] = publish_name
    return client.post(base + "/" + action, json=body)


def _plain(text: str) -> None:
    from test_support.plain_language import developer_terms
    assert developer_terms(f"<main>{text}</main>") == [], text


def test_suggested_skill_requires_shared_source_review_and_audited_admission(
    client, monkeypatch, tmp_path,
):
    from maverick import skills, world_model
    from maverick.skill.distillation_local import save_skill

    monkeypatch.setenv("MAVERICK_DISTILL_LOCAL", "1")
    world = world_model.WorldModel(world_model.default_db_path())
    shared = world.create_goal("Check customer renewal timing", owner="")
    private = world.create_goal("PRIVATE PAYROLL", owner="user:alice")
    world.close()
    store = tmp_path / "home" / "learned-skills"
    for name, goal_id in (("renewal-timing", shared), ("private-payroll", private)):
        save_skill({"name": name, "triggers": ["check customer renewal timing"],
                    "tools_needed": [], "summary": "Check customer renewal timing and report it",
                    "n_examples": 2, "source_goal_ids": [goal_id]}, store)

    seen = _audit(monkeypatch)
    listing = client.get("/api/v1/skills/learned-candidates")
    assert listing.status_code == 200, listing.text
    data = listing.json()
    assert [row["name"] for row in data["suggestions"]] == ["renewal-timing"]
    row = data["suggestions"][0]
    assert "Check customer renewal timing" in row["instructions"]
    assert row["source_tasks"] == [shared]
    assert "private-payroll" not in listing.text
    # A private source cannot even be reviewed.
    assert _skill_change(client, "private-payroll", "admit", "a" * 64).status_code == 409
    assert _skill_change(client, "renewal-timing", "admit", row["fingerprint"], confirm=False).status_code == 422
    assert _skill_change(client, "renewal-timing", "admit", "b" * 64).status_code == 409
    assert skills.load_skills() == []

    added = _skill_change(client, "renewal-timing", "admit", row["fingerprint"], publish_name="renewal-timing")
    assert added.status_code == 201, added.text
    assert added.json()["name"] == "renewal-timing" and added.json()["confirmed"] is True
    assert "learned_skill_admit" in _verbs(seen)
    assert [skill.name for skill in skills.load_skills()] == ["renewal-timing"]
    after = client.get("/api/v1/skills/learned-candidates").json()
    assert after["suggestions"] == []
    assert [saved["name"] for saved in after["added"]] == ["renewal-timing"]
    assert after["added"][0]["recall_ready"] is True
    assert after["added"][0]["uses"] == 0
    from maverick.skill import stats as skill_stats
    skill_stats.record_use([skills.learned_skill_use_key(skills.load_skills()[0])])
    used = client.get("/api/v1/skills/learned-candidates").json()["added"][0]
    assert used["uses"] == 1
    monkeypatch.setenv("MAVERICK_USE_SKILLS", "0")
    paused = client.get("/api/v1/skills/learned-candidates").json()["added"][0]
    assert paused["recall_ready"] is False
    assert "turned off" in paused["status"]
    monkeypatch.delenv("MAVERICK_USE_SKILLS")
    fp = after["added"][0]["fingerprint"]
    assert _skill_change(client, "renewal-timing", "withdraw", "0" * 64).status_code == 409
    removed = _skill_change(client, "renewal-timing", "withdraw", fp)
    assert removed.status_code == 200 and removed.json()["confirmed"] is True, removed.text
    assert "learned_skill_withdraw" in _verbs(seen)
    assert skills.load_skills() == []


def test_suggested_skill_admission_refuses_disabled_learning_and_audit_failure(
    client, monkeypatch, tmp_path,
):
    from maverick import world_model
    from maverick.skill.distillation_local import save_skill

    monkeypatch.setenv("MAVERICK_DISTILL_LOCAL", "1")
    world = world_model.WorldModel(world_model.default_db_path())
    shared = world.create_goal("Review customer renewal", owner="")
    world.close()
    save_skill({"name": "renewal-review", "triggers": ["review customer renewal"],
                "tools_needed": [], "summary": "Review customer renewal and report outcome",
                "n_examples": 2, "source_goal_ids": [shared]},
               tmp_path / "home" / "learned-skills")
    row = client.get("/api/v1/skills/learned-candidates").json()["suggestions"][0]
    from maverick import audit

    monkeypatch.setattr(audit, "audit_event", lambda *args, **kwargs: False)
    refused = _skill_change(client, "renewal-review", "admit", row["fingerprint"])
    assert refused.status_code == 503
    assert client.get("/api/v1/skills").json() == []
    monkeypatch.setenv("MAVERICK_DISTILL_LOCAL", "0")
    # With learning off the suggestion cannot even be reviewed for adding.
    assert _skill_change(client, "renewal-review", "admit", row["fingerprint"]).status_code == 409
    data = client.get("/api/v1/skills/learned-candidates").json()
    assert data["can_add"] is False and data["suggestions"]


def test_admitted_suggestion_remains_visible_and_withdrawable_after_source_becomes_private(
    client, monkeypatch, tmp_path,
):
    from maverick import skills, world_model
    from maverick.skill.distillation_local import save_skill

    monkeypatch.setenv("MAVERICK_DISTILL_LOCAL", "1")
    world = world_model.WorldModel(world_model.default_db_path())
    source = world.create_goal("Review renewal schedule", owner="")
    save_skill({"name": "renewal-schedule", "triggers": ["review renewal schedule"],
                "tools_needed": [], "summary": "Review renewal schedule and report it",
                "n_examples": 2, "source_goal_ids": [source]},
               tmp_path / "home" / "learned-skills")
    proposal = client.get("/api/v1/skills/learned-candidates").json()["suggestions"][0]
    assert _skill_change(client, "renewal-schedule", "admit", proposal["fingerprint"]).status_code == 201
    assert world.bind_goal_owner(source, "user:alice")
    world.close()

    assert skills.load_skills() == []
    current = client.get("/api/v1/skills/learned-candidates")
    assert current.status_code == 200, current.text
    assert current.json()["suggestions"] == []
    paused = current.json()["added"][0]
    assert paused["name"] == "renewal-schedule"
    assert paused["source_shared"] is False
    assert "Paused" in paused["status"]

    removed = _skill_change(client, "renewal-schedule", "withdraw", paused["fingerprint"])
    assert removed.status_code == 200 and removed.json()["confirmed"] is True, removed.text
    assert client.get("/api/v1/skills/learned-candidates").json()["added"] == []


def test_suggested_skill_last_write_rechecks_administrator_permission(
    client, monkeypatch, tmp_path,
):
    from maverick import file_lock, skills, world_model
    from maverick.skill.distillation_local import save_skill
    from maverick_dashboard import tools_ops_api as native

    monkeypatch.setenv("MAVERICK_DISTILL_LOCAL", "1")
    world = world_model.WorldModel(world_model.default_db_path())
    source = world.create_goal("Review renewal schedule", owner="")
    world.close()
    save_skill({"name": "renewal-schedule", "triggers": ["review renewal schedule"],
                "tools_needed": [], "summary": "Review renewal schedule and report it",
                "n_examples": 2, "source_goal_ids": [source]},
               tmp_path / "home" / "learned-skills")
    proposal = client.get("/api/v1/skills/learned-candidates").json()["suggestions"][0]
    state = {"admin": True, "demote_on_lock": True}
    original_permission = native.require_permission
    original_lock = file_lock.cross_process_lock

    def permission(request, grant):
        if grant == "admin" and not state["admin"]:
            raise HTTPException(403, "administrator permission was removed")
        return original_permission(request, grant)

    @contextmanager
    def lock_and_demote(target, **kwargs):
        with original_lock(target, **kwargs):
            if state["demote_on_lock"] and Path(target).name == "renewal-schedule.md":
                state["admin"] = False
            yield

    from maverick_dashboard import learned_skill_changes
    monkeypatch.setattr(native, "require_permission", permission)
    monkeypatch.setattr(learned_skill_changes, "require_permission", permission)
    monkeypatch.setattr(file_lock, "cross_process_lock", lock_and_demote)
    refused = _skill_change(client, "renewal-schedule", "admit", proposal["fingerprint"])
    assert refused.status_code == 403
    assert skills.load_skills() == []

    state.update(admin=True, demote_on_lock=False)
    assert _skill_change(client, "renewal-schedule", "admit", proposal["fingerprint"]).status_code == 201
    current = client.get("/api/v1/skills/learned-candidates").json()["added"][0]
    state.update(admin=True, demote_on_lock=True)
    refused = _skill_change(client, "renewal-schedule", "withdraw", current["fingerprint"])
    assert refused.status_code == 403
    assert [item.name for item in skills.load_skills()] == ["renewal-schedule"]


def test_suggested_skill_audit_never_claims_success_before_file_change(
    client, monkeypatch, tmp_path,
):
    from maverick import file_lock, world_model
    from maverick.skill.distillation_local import save_skill

    monkeypatch.setenv("MAVERICK_DISTILL_LOCAL", "1")
    world = world_model.WorldModel(world_model.default_db_path())
    source = world.create_goal("Review renewal schedule", owner="")
    world.close()
    save_skill({"name": "renewal-schedule", "triggers": ["review renewal schedule"],
                "tools_needed": [], "summary": "Review renewal schedule and report it",
                "n_examples": 2, "source_goal_ids": [source]},
               tmp_path / "home" / "learned-skills")
    proposal = client.get("/api/v1/skills/learned-candidates").json()["suggestions"][0]
    seen = _audit(monkeypatch)
    original_write = file_lock.atomic_write_text

    def disk_full(path, text, **kwargs):
        if Path(path).name == "renewal-schedule.md" and Path(path).parent.name == "skills":
            raise OSError("simulated disk full")
        return original_write(path, text, **kwargs)

    monkeypatch.setattr(file_lock, "atomic_write_text", disk_full)
    failed = _skill_change(client, "renewal-schedule", "admit", proposal["fingerprint"])
    # The reserved original stays unconfirmed: no success is claimed and the
    # change is not repeated.
    assert failed.json()["confirmed"] is False and "unconfirmed" in failed.json()["message"]
    events = [row for row in seen if row.get("verb") == "learned_skill_admit"]
    assert [row["phase"] for row in events] == ["prepared"]
    assert all(row.get("ok") is not True for row in events)
    assert not (tmp_path / "skills" / "renewal-schedule.md").exists()

    monkeypatch.setattr(file_lock, "atomic_write_text", original_write)
    added = _skill_change(client, "renewal-schedule", "admit", proposal["fingerprint"])
    assert added.status_code == 201 and added.json()["confirmed"] is True
    events = [row for row in seen if row.get("verb") == "learned_skill_admit"]
    assert [row["phase"] for row in events] == ["prepared", "prepared"]

    saved = client.get("/api/v1/skills/learned-candidates").json()["added"][0]
    original_unlink = Path.unlink

    def refuse_delete(path, *args, **kwargs):
        if path.name == "renewal-schedule.md" and path.parent.name == "skills":
            raise OSError("simulated delete failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse_delete)
    failed = _skill_change(client, "renewal-schedule", "withdraw", saved["fingerprint"])
    assert failed.json()["confirmed"] is False and "unconfirmed" in failed.json()["message"]
    events = [row for row in seen if row.get("verb") == "learned_skill_withdraw"]
    assert [row["phase"] for row in events] == ["prepared"]
    assert all(row.get("ok") is not True for row in events)
    assert (tmp_path / "skills" / "renewal-schedule.md").exists()

    monkeypatch.setattr(Path, "unlink", original_unlink)
    removed = _skill_change(client, "renewal-schedule", "withdraw", saved["fingerprint"])
    assert removed.status_code == 200 and removed.json()["confirmed"] is True
    assert not (tmp_path / "skills" / "renewal-schedule.md").exists()


def test_suggested_skill_completed_audit_failure_reports_changed_state(
    client, monkeypatch, tmp_path,
):
    from maverick import audit, skills, world_model
    from maverick.skill.distillation_local import save_skill

    monkeypatch.setenv("MAVERICK_DISTILL_LOCAL", "1")
    world = world_model.WorldModel(world_model.default_db_path())
    source = world.create_goal("Review renewal schedule", owner="")
    world.close()
    save_skill({"name": "renewal-schedule", "triggers": ["review renewal schedule"],
                "tools_needed": [], "summary": "Review renewal schedule and report it",
                "n_examples": 2, "source_goal_ids": [source]},
               tmp_path / "home" / "learned-skills")
    proposal = client.get("/api/v1/skills/learned-candidates").json()["suggestions"][0]
    original_record = audit.record

    def lose_completion(kind, **payload):
        if payload.get("action") == "skills.reviewed_change.completed":
            return False
        return original_record(kind, **payload)

    monkeypatch.setattr(audit, "record", lose_completion)
    result = _skill_change(client, "renewal-schedule", "admit", proposal["fingerprint"])
    # The skill changed, but its completion record was lost: the original is
    # reported as unconfirmed and the installed skill is named separately.
    assert result.json()["confirmed"] is False
    assert result.json()["current"] == "This saved version is still installed."
    assert [item.name for item in skills.load_skills()] == ["renewal-schedule"]
    assert client.get("/api/v1/skills/learned-candidates").json()["added"][0]["name"] == "renewal-schedule"


# ---- skills: add from a web address after a check ----------------------------

def _serve_skill(monkeypatch, text=SKILL):
    """Stand in for the network under the kernel's guarded fetch."""
    import maverick.skills as skills_mod
    fetched: list[str] = []

    def fetch(url):
        fetched.append(url)
        return text.encode()
    monkeypatch.setattr(skills_mod, "_fetch_url_bytes", fetch)
    return fetched


def test_skill_check_shows_what_it_does_without_installing(client, monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    fetched = _serve_skill(monkeypatch)
    r = client.post("/api/v1/skills/source-preview", json={"source": "gh:acme/skills:weekly/SKILL.md"})
    assert r.status_code == 200, r.text
    p = r.json()
    assert fetched == ["https://raw.githubusercontent.com/acme/skills/main/weekly/SKILL.md"]
    assert p["name"] == "weekly-status" and p["triggers"] == ["weekly status"] and p["tools"] == ["http_fetch"]
    assert p["ok"] is True and p["problems"] == [] and len(p["fingerprint"]) == 64
    assert p["adding_allowed"] is True and p["can_add"] is True
    assert not (tmp_path / "skills").exists() or not list((tmp_path / "skills").glob("*.md"))


def test_skill_check_explains_problems_plainly_and_refuses_bad_addresses(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    _serve_skill(monkeypatch, "---\nname: Bad Name\n---\nshort\n")
    p = client.post("/api/v1/skills/source-preview", json={"source": "https://example.com/s.md"}).json()
    assert p["ok"] is False
    assert "It does not say when agents should use it." in p["problems"]
    for line in p["problems"] + p["suggestions"]:
        _plain(line)
    assert p["technical"]  # the linter's own words stay in the details
    for bad in ("http://example.com/s.md", "/etc/passwd", "file:///etc/passwd", "gh:not a project"):
        r = client.post("/api/v1/skills/source-preview", json={"source": bad})
        assert r.status_code == 422, bad
    assert client.post("/api/v1/skills/source-preview", json={"source": "x" * 2001}).status_code == 422


@pytest.mark.parametrize("source", ["https://127.0.0.1/s.md", "https://169.254.169.254/latest/s.md",
                                    "https://[::1]/s.md", "https://100.100.100.200/s.md"])
def test_skill_check_refuses_internal_addresses(client, monkeypatch, source):
    # The real guarded fetch refuses these before connecting; the page says why.
    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    r = client.post("/api/v1/skills/source-preview", json={"source": source})
    assert r.status_code == 422 and "inside its own network" in r.json()["detail"], r.text


def test_skill_check_is_refused_without_fetching_when_adding_is_off(client, monkeypatch):
    fetched = _serve_skill(monkeypatch)
    r = client.post("/api/v1/skills/source-preview", json={"source": "https://example.com/s.md"})
    assert r.status_code == 403
    assert "turned off" in r.json()["detail"]
    _plain(r.json()["detail"])
    assert fetched == []  # nothing was read from the network


def test_skill_add_needs_admin_the_switch_and_a_confirmation(client, monkeypatch, tmp_path):
    _serve_skill(monkeypatch)
    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    fp = client.post("/api/v1/skills/source-preview", json={"source": "https://example.com/s.md"}).json()["fingerprint"]
    body = {"source": "https://example.com/s.md", "fingerprint": fp, "confirm": True}
    monkeypatch.delenv("MAVERICK_ALLOW_SKILL_INSTALL")
    assert client.post("/api/v1/skills/source-install", json=body).status_code == 403  # switched off
    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    assert client.post("/api/v1/skills/source-install", json={**body, "confirm": False}).status_code == 422
    seen = _audit(monkeypatch)
    r = client.post("/api/v1/skills/source-install", json=body)
    assert r.status_code == 201, r.text
    assert r.json()["name"] == "weekly-status"
    assert (tmp_path / "skills" / "weekly-status.md").exists()
    assert "skill_install" in _verbs(seen)
    _as(monkeypatch, "operator")
    assert client.post("/api/v1/skills/source-preview", json={"source": "https://example.com/s.md"}).status_code == 403
    assert client.post("/api/v1/skills/source-install", json=body).status_code == 403


def test_skill_that_changed_after_the_check_is_not_added(client, monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    _serve_skill(monkeypatch)
    fp = client.post("/api/v1/skills/source-preview", json={"source": "https://example.com/s.md"}).json()["fingerprint"]
    _serve_skill(monkeypatch, SKILL.replace("five bullet points", "ten bullet points"))
    r = client.post("/api/v1/skills/source-install",
                    json={"source": "https://example.com/s.md", "fingerprint": fp, "confirm": True})
    assert r.status_code == 409 and "changed after you checked" in r.json()["detail"]
    assert not (tmp_path / "skills" / "weekly-status.md").exists()


def test_skill_add_keeps_web_address_passwords_out_of_the_activity_record(client, monkeypatch, tmp_path):
    """A private link carries its password (``user:pass@`` or ``?token=``);
    the activity record keeps where the skill came from, never that password."""
    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    fetched = _serve_skill(monkeypatch)
    source = ("https://alice:hunter2-secret@raw.example.com/acme/skills/SKILL.md"  # pragma: allowlist secret
              "?token=GHSAT0AAAAAAsecretvalue#frag")
    fp = client.post("/api/v1/skills/source-preview", json={"source": source}).json()["fingerprint"]
    seen = _audit(monkeypatch)
    r = client.post("/api/v1/skills/source-install",
                    json={"source": source, "fingerprint": fp, "confirm": True})
    assert r.status_code == 201, r.text
    assert fetched[-1] == source  # the fetch itself still uses the full link
    row = next(p for p in seen if p.get("verb") == "skill_install")
    assert row["source"] == "https://raw.example.com/acme/skills/SKILL.md"
    written = "".join(f.read_text(errors="replace") for f in (tmp_path / "home").rglob("*")
                      if f.is_file() and "audit" in str(f))
    assert "skill_install" in written
    for secret in ("hunter2-secret", "GHSAT0AAAAAAsecretvalue", "alice"):
        assert secret not in written


# ---- skills: track record and tidying up -------------------------------------

def _install_skill(tmp_path, name):
    from maverick.skills import build_skill_md
    folder = tmp_path / "skills"
    folder.mkdir(exist_ok=True, mode=0o700)
    (folder / f"{name}.md").write_text(build_skill_md(name, ["x"], [], "Do the thing carefully, step by step."))


def test_skill_track_record_uses_the_kernel_numbers(client, tmp_path):
    from maverick.skill import stats as skill_stats
    _install_skill(tmp_path, "helpful")
    _install_skill(tmp_path, "unused")
    skill_stats.record_use(["helpful"] * 1)
    skill_stats.record_outcome(["helpful"], success=True)
    rows = {r["name"]: r for r in client.get("/api/v1/skills/usage").json()["skills"]}
    assert rows["helpful"]["uses"] == 1 and rows["helpful"]["wins"] == 1 and rows["helpful"]["win_rate"] == 1.0
    assert rows["unused"]["uses"] == 0 and rows["unused"]["win_rate"] is None
    assert rows["helpful"] == skill_stats.usage_rows(["helpful"])[0]


def test_tidying_lists_then_removes_only_confirmed_candidates(client, monkeypatch, tmp_path):
    from maverick.skill import stats as skill_stats
    for name in ("dud", "good"):
        _install_skill(tmp_path, name)
    for _ in range(20):
        skill_stats.record_use(["dud", "good"])
        skill_stats.record_outcome(["dud"], success=False)
        skill_stats.record_outcome(["good"], success=True)
    preview = client.post("/api/v1/skills/tidy-preview", json={"min_uses": 5, "max_success": 0.2})
    assert [r["name"] for r in preview.json()["skills"]] == ["dud"]
    body = {"min_uses": 5, "max_success": 0.2, "names": ["dud", "good"]}
    assert client.post("/api/v1/skills/tidy", json=body).status_code == 422  # not confirmed
    assert (tmp_path / "skills" / "dud.md").exists()
    seen = _audit(monkeypatch)
    out = client.post("/api/v1/skills/tidy", json={**body, "confirm": True}).json()
    assert out == {"removed": ["dud"], "skipped": 1}  # "good" never matched the rule
    assert not (tmp_path / "skills" / "dud.md").exists() and (tmp_path / "skills" / "good.md").exists()
    assert "skills_evict" in _verbs(seen)
    # Only the listed choices, and a bounded list of names.
    assert client.post("/api/v1/skills/tidy-preview", json={"min_uses": 1, "max_success": 0.2}).status_code == 422
    assert client.post("/api/v1/skills/tidy", json={**body, "names": ["x"] * 201, "confirm": True}).status_code == 422
    _as(monkeypatch, "operator")
    assert client.post("/api/v1/skills/tidy-preview", json={"min_uses": 5, "max_success": 0.2}).status_code == 403
    assert client.post("/api/v1/skills/tidy", json={**body, "confirm": True}).status_code == 403


# ---- add-ons: versions, pinning, reload, usage, starter ----------------------

@pytest.fixture
def addons(monkeypatch):
    from maverick import plugin_lock
    installed = {"acme-tools": "1.0.0"}
    monkeypatch.setattr(plugin_lock, "_active_plugin_dists", lambda: dict(installed))
    monkeypatch.setattr(plugin_lock, "_dist_content_hash", lambda name: None)
    return installed


def test_versions_list_every_addon_and_pinning_needs_confirmation(client, monkeypatch, addons):
    v = client.get("/api/v1/plugins/versions").json()
    assert v["pinned"] is False and [a["state"] for a in v["addons"]] == ["unpinned"]
    _plain(v["summary"])
    assert client.post("/api/v1/plugins/versions/pin", json={}).status_code == 422
    seen = _audit(monkeypatch)
    pinned = client.post("/api/v1/plugins/versions/pin", json={"confirm": True}).json()
    assert pinned["pinned"] == 1 and pinned["ok"] is True
    assert pinned["addons"] == [{"name": "acme-tools", "approved": "1.0.0", "installed": "1.0.0",
                                 "state": "match", "label": "Matches the approved version"}]
    assert "plugin_lock" in _verbs(seen)
    addons["acme-tools"] = "2.0.0"
    addons["new-addon"] = "0.1"
    v = client.get("/api/v1/plugins/versions").json()
    assert {a["name"]: a["state"] for a in v["addons"]} == {"acme-tools": "drifted", "new-addon": "unpinned"}
    assert v["ok"] is False and "2 add-ons differ" in v["summary"]


def test_reload_is_confirmed_recorded_and_limited_to_installed_addons(client, monkeypatch, addons):
    from maverick import plugins
    calls = []
    monkeypatch.setattr(plugins, "reload_plugin", lambda name: calls.append(name) or ["acme_tools", "acme_tools.x"])
    assert client.post("/api/v1/plugins/reload", json={"addon": "acme-tools"}).status_code == 422
    assert client.post("/api/v1/plugins/reload", json={"addon": "other", "confirm": True}).status_code == 404
    seen = _audit(monkeypatch)
    r = client.post("/api/v1/plugins/reload", json={"addon": "acme-tools", "confirm": True})
    assert r.json()["reloaded_parts"] == 2 and calls == ["acme-tools"]
    assert "plugin_reload" in _verbs(seen)
    monkeypatch.setattr(plugins, "reload_plugin", lambda name: [])
    assert client.post("/api/v1/plugins/reload", json={"addon": "acme-tools", "confirm": True}).status_code == 409


def test_addon_usage_reads_the_local_tally(client, monkeypatch, tmp_path):
    from maverick import plugin_telemetry
    monkeypatch.setattr(plugin_telemetry, "telemetry_path", lambda: tmp_path / "tele.json")
    plugin_telemetry.record("forecast", "acme-tools", path=tmp_path / "tele.json")
    plugin_telemetry.record("forecast", "acme-tools", path=tmp_path / "tele.json")
    data = client.get("/api/v1/plugins/usage").json()
    assert data["counting"] is False
    assert data["tools"][0]["tool"] == "forecast" and data["tools"][0]["calls"] == 2


def test_starter_plugin_downloads_and_writes_nothing_on_the_server(client, tmp_path):
    r = client.post("/api/v1/plugins/starter", json={"name": "Weather Tools", "kind": "tool"})
    assert r.status_code == 200, r.text
    assert 'filename="weather-tools-starter.zip"' in r.headers["content-disposition"]
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert any(n.endswith("pyproject.toml") for n in names) and all(n.startswith("weather-tools/") for n in names)
    assert client.post("/api/v1/plugins/starter", json={"name": "x", "kind": "tool"}).status_code == 422
    assert client.post("/api/v1/plugins/starter", json={"name": "ok-name", "kind": "virus"}).status_code == 422


def test_operator_is_refused_every_installation_route(client, monkeypatch, addons):
    _as(monkeypatch, "operator")
    for method, path, body in (
        ("get", "/api/v1/plugins/versions", None), ("post", "/api/v1/plugins/versions/pin", {"confirm": True}),
        ("get", "/api/v1/plugins/usage", None), ("get", "/api/v1/templates/ratings-export", None),
        ("post", "/api/v1/mcp-registry/preview", {"name": "x"}), ("get", "/api/v1/governed-connectors", None),
    ):
        r = getattr(client, method)(path, **({"json": body} if body is not None else {}))
        assert r.status_code == 403, path


# ---- templates: ratings download ----------------------------------------------

def test_ratings_download_is_the_kernel_export(client):
    from maverick.marketplace.ratings import RatingsLedger
    RatingsLedger().rate("templates", "weekly-report", 4, "nice")
    r = client.get("/api/v1/templates/ratings-export")
    assert r.status_code == 200
    assert 'filename="Lightwork-template-ratings.json"' in r.headers["content-disposition"]
    assert json.loads(r.content) == {"templates": {"weekly-report": 4}}  # comments stay local


# ---- tool servers: look before adding -------------------------------------------

def _registry(monkeypatch, spec):
    # Exercise preview/probe mechanics with an explicitly supplied trusted spec;
    # the real registry boundary is tested separately below.
    from maverick import mcp_registry
    from maverick.mcp_client import MCPServerSpec
    def trusted_spec(name, **_kwargs):
        if name != "weather":
            raise ValueError("unknown server")
        return MCPServerSpec.from_config(name, spec)
    monkeypatch.setattr(mcp_registry, "install_mcp_from_registry", trusted_spec)


def test_unauthenticated_registry_entry_cannot_be_previewed_probed_or_added(client, monkeypatch):
    from maverick import catalog, mcp_registry
    entry = catalog.CatalogEntry(name="weather", version="1", kind="mcp", summary="Weather",
                                 source="", sha256="", spec={"url": "https://mcp.example.com/"})
    monkeypatch.setattr(mcp_registry, "resolve_mcp", lambda *_a, **_k: entry)
    monkeypatch.setattr(mcp_registry, "add_mcp_server_to_config",
                        lambda *_a, **_k: pytest.fail("configuration changed"))
    for path, body in (
        ("/api/v1/mcp-registry/preview", {"name": "weather"}),
        ("/api/v1/mcp-registry/tools", {"name": "weather", "fingerprint": "a" * 64, "confirm": True}),
        ("/api/v1/mcp-registry/add", {"name": "weather"}),
    ):
        assert client.post(path, json=body).status_code == 409


def test_registry_preview_shows_the_exact_program_and_address(client, monkeypatch):
    _registry(monkeypatch, {"command": "/opt/mcp/weather-server", "args": ["--units", "metric"],
                            "env": {"WEATHER_KEY": "k"}, "pin_sha256": "a" * 64})
    p = client.post("/api/v1/mcp-registry/preview", json={"name": "weather"}).json()
    assert p["online"] is False and p["program"] == "/opt/mcp/weather-server"
    assert p["arguments"] == ["--units", "metric"] and p["settings"] == ["WEATHER_KEY"]
    assert p["program_checked"] is True and len(p["fingerprint"]) == 64
    assert p["gets_every_server_setting"] is False
    _registry(monkeypatch, {"command": "/opt/mcp/weather-server", "inherit_env": True,
                            "pin_sha256": "a" * 64})
    p = client.post("/api/v1/mcp-registry/preview", json={"name": "weather"}).json()
    assert p["gets_every_server_setting"] is True  # the person sees it before adding
    _registry(monkeypatch, {"url": "https://mcp.example.com/weather"})
    p = client.post("/api/v1/mcp-registry/preview", json={"name": "weather"}).json()
    assert p["online"] is True and p["address"] == "https://mcp.example.com/weather"
    r = client.post("/api/v1/mcp-registry/preview", json={"name": "gone"})
    assert r.status_code == 409
    _plain(r.json()["detail"])


def _resolve_to(monkeypatch, ip):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))])


def test_registry_tools_are_asked_only_on_confirmation(client, monkeypatch):
    _resolve_to(monkeypatch, "93.184.216.34")
    _registry(monkeypatch, {"url": "https://mcp.example.com/weather"})
    fp = client.post("/api/v1/mcp-registry/preview", json={"name": "weather"}).json()["fingerprint"]
    import maverick.mcp_client as mcp_client
    started = []

    class FakeClient:
        def __init__(self, spec, timeout, **kwargs):
            self.tools = [{"name": "forecast", "description": "Tomorrow's weather"}]

        async def start(self):
            started.append(True)

        async def stop(self):
            pass
    monkeypatch.setattr(mcp_client, "StreamableHttpMCPClient", FakeClient)
    assert client.post("/api/v1/mcp-registry/tools", json={"name": "weather", "fingerprint": fp}).status_code == 422
    assert client.post("/api/v1/mcp-registry/tools",
                       json={"name": "weather", "fingerprint": "b" * 64, "confirm": True}).status_code == 409
    assert started == []
    seen = _audit(monkeypatch)
    r = client.post("/api/v1/mcp-registry/tools", json={"name": "weather", "fingerprint": fp, "confirm": True})
    assert r.json() == {"tools": [{"name": "forecast", "description": "Tomorrow's weather"}]}
    assert started == [True] and "mcp_registry_probe" in _verbs(seen)
    # Adding refuses a server whose details changed after the look.
    r = client.post("/api/v1/mcp-registry/add", json={"name": "weather", "fingerprint": "c" * 64})
    assert r.status_code == 409
    assert client.post("/api/v1/mcp-registry/add", json={"name": "weather", "fingerprint": fp}).json() == {"added": "weather"}



@pytest.mark.parametrize("url, ip", [("http://169.254.169.254/latest/meta-data/", "169.254.169.254"),
                                     ("https://mcp.internal.test/weather", "10.0.0.5"),
                                     ("https://aliyun.test/", "100.100.100.200"),
                                     ("http://[::1]:8080/mcp", "::1")])
def test_registry_tools_refuse_an_online_server_inside_the_network(client, monkeypatch, url, ip):
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    _resolve_to(monkeypatch, ip)
    _registry(monkeypatch, {"url": url})
    fp = client.post("/api/v1/mcp-registry/preview", json={"name": "weather"}).json()["fingerprint"]
    import maverick.mcp_client as mcp_client
    started = []

    class FakeClient:
        def __init__(self, spec, timeout, **kwargs):
            self.tools = []

        async def start(self):
            started.append(True)

        async def stop(self):
            pass
    monkeypatch.setattr(mcp_client, "StreamableHttpMCPClient", FakeClient)
    r = client.post("/api/v1/mcp-registry/tools", json={"name": "weather", "fingerprint": fp, "confirm": True})
    assert r.status_code == 422 and "inside" in r.json()["detail"], r.text
    _plain(r.json()["detail"])
    assert started == []  # never contacted
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")  # the same escape hatch as every fetch
    r = client.post("/api/v1/mcp-registry/tools", json={"name": "weather", "fingerprint": fp, "confirm": True})
    assert r.status_code == 200 and started == [True]



def test_registry_tools_connect_to_the_address_that_was_checked(client, monkeypatch):
    """DNS that answers a public address for the check and an internal one
    afterwards must not move the connection inside the network."""
    import json as _json
    import socket

    import httpx
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    answers = iter(["93.184.216.34"])

    def rebinding(host, *a, **k):
        ip = next(answers, "10.0.0.5")  # first lookup public, every later one internal
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    connected: list[tuple[str, str, str]] = []

    class Wire(httpx.AsyncBaseTransport):
        """Stands in for the network: records where each request would go."""

        async def handle_async_request(self, request):
            host = request.url.host
            try:
                ipaddress.ip_address(host)
            except ValueError:  # a name: the connection layer would look it up again
                host = socket.getaddrinfo(host, None)[0][4][0]
            connected.append((host, request.headers.get("host", ""),
                              str(request.extensions.get("sni_hostname", ""))))
            body = _json.loads(request.content or b"{}")
            if "id" not in body:
                return httpx.Response(202, request=request)
            result = ({"protocolVersion": "2025-11-25", "capabilities": {}} if body["method"] == "initialize"
                      else {"tools": [{"name": "forecast", "description": "Tomorrow's weather",
                                  "inputSchema": {"type": "object"}}]})
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result},
                                  request=request)
    import ipaddress
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda *a, **k: Wire())
    monkeypatch.setattr(httpx._client, "AsyncHTTPTransport", lambda *a, **k: Wire())
    _registry(monkeypatch, {"url": "https://mcp.example.com/weather"})
    fp = client.post("/api/v1/mcp-registry/preview", json={"name": "weather"}).json()["fingerprint"]
    r = client.post("/api/v1/mcp-registry/tools", json={"name": "weather", "fingerprint": fp, "confirm": True})
    assert r.status_code == 200, r.text
    assert r.json()["tools"][0]["name"] == "forecast"
    assert connected and {c[0] for c in connected} == {"93.184.216.34"}  # never 10.0.0.5
    assert all(c[1] == "mcp.example.com" and c[2] == "mcp.example.com" for c in connected)


# ---- governed connectors: list and preview a change ----------------------------

def _connectors_on(monkeypatch, restore=True):
    from maverick import config
    monkeypatch.setattr(config, "get_governed_connectors", lambda: {
        "enable": True, "connectors": ["salesforce"], "restore_points": restore})
    monkeypatch.delenv("SALESFORCE_INSTANCE_URL", raising=False)


def test_connectors_list_matches_the_kernel_rows(client, monkeypatch):
    assert client.get("/api/v1/governed-connectors").json()["enabled"] is False
    _connectors_on(monkeypatch)
    data = client.get("/api/v1/governed-connectors").json()
    assert data["enabled"] is True
    assert data["connectors"] == [{"name": "salesforce", "change_risk": "High", "needs_approval": True,
                                   "can_address_records": True}]


def test_change_preview_simulates_and_plans_without_changing_anything(client, monkeypatch):
    _connectors_on(monkeypatch)
    from maverick import governed_rest
    wrote = []
    monkeypatch.setattr(governed_rest.RestConnector, "write", lambda self, params: wrote.append(params) or "ok")
    body = {"connector": "salesforce", "change": "update", "record_type": "Opportunity",
            "record_id": "006000000000001AAA", "fields": [{"name": "Amount", "value": "120000", "kind": "number"}]}
    r = client.post("/api/v1/governed-connectors/preview", json=body)
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["summary"] == "Lightwork would change Amount on the Opportunity record 006000000000001AAA in Salesforce."
    assert p["risk"] == "High" and p["needs_approval"] is True and p["changed_anything"] is False
    assert "would PATCH salesforce/services/data/v60.0/sobjects/Opportunity/006000000000001AAA" in p["technical"][0]["text"]
    planned = client.post("/api/v1/governed-connectors/preview", json={**body, "read_current_values": True}).json()
    assert planned["read_current_values"] is True and planned["can_undo"] is False  # no credentials here
    assert wrote == []
    # Bounded, typed input.
    for bad in ({**body, "record_id": ""}, {**body, "change": "create"}, {**body, "record_id": "../../x"},
                {**body, "fields": [{"name": "a b", "value": "1"}]}, {**body, "fields": []},
                {**body, "fields": [{"name": "Amount", "value": "lots", "kind": "number"}]},
                {**body, "fields": [{"name": f"F{i}", "value": "1"} for i in range(51)]}):
        assert client.post("/api/v1/governed-connectors/preview", json=bad).status_code == 422, bad
    assert client.post("/api/v1/governed-connectors/preview", json={**body, "connector": "servicenow"}).status_code == 404


# ---- pages ------------------------------------------------------------------

@pytest.mark.parametrize("path, words", [
    ("/skills", ("Check this skill", "How your skills are doing", "Find skills that rarely help")),
    ("/plugins", ("Approved versions", "Pin current versions", "How often add-on tools are used",
                  "Download starter plugin")),
    ("/mcp", ("Find more tool servers", "exactly what it starts or connects to")),
    ("/connections", ("Systems Lightwork may change", "Preview this change")),
    ("/templates", ("Share your ratings", "Download ratings")),
])
def test_pages_carry_the_new_controls_in_plain_words(client, monkeypatch, path, words):
    from test_support.plain_language import developer_terms, visible_text
    if path == "/connections":
        # The page correctly shows setup guidance when connections are off.
        # Exercise the enabled admin journey for the controls asserted below.
        monkeypatch.setenv("MAVERICK_CONNECTIONS", "1")
        _connectors_on(monkeypatch)
        assert client.get("/api/v1/governed-connectors").json()["enabled"] is True
    page = client.get(path)
    assert page.status_code == 200
    text = visible_text(page.text)
    if path == "/connections":
        assert "Connections is turned off." not in text
    for word in words:
        assert word in text, (path, word)
    html = page.text
    if path == "/templates":  # built-in templates carry their own technical details
        start = html.index('id="to-ratings"')
        html = "<main>" + html[start:html.index("</section>", start)] + "</main>"
    assert developer_terms(html) == [], path
    assert "maverick " not in text


def test_page_scripts_are_served():
    from maverick_dashboard.app import app
    c = TestClient(app, base_url="http://127.0.0.1")
    for name in ("lightwork-tool-ops.js", "lightwork-insight-ops.js", "lightwork-code-sandbox.js"):
        r = c.get("/static/" + name)
        assert r.status_code == 200 and "javascript" in r.headers["content-type"], name
