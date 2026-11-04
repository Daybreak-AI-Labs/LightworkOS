"""Learned page: suggested instruction changes and self-coaching read-outs.
Reads need view (or audit for the activity log and hold-out check); every
change needs a global administrator and runs the CLI's kernel function."""
from __future__ import annotations

import os
import re

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
API = "/api/v1/learning-loop"
_BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
    r"idempoten\w*|harness|refinement|corpus|holdout|efficacy|canary)\b|/api/v1|HTTP \d{3}|maverick ",
    re.IGNORECASE,
)


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_HARNESS_REFINE"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


def _configure(body: str) -> None:
    from maverick import config
    with open(os.environ["MAVERICK_CONFIG"], "w", encoding="utf-8") as fh:
        fh.write(body + "\n")
    config.reset_config_cache()


def _as(monkeypatch, role: str, who: str = "user:someone"):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _decision(client, proposal, action):
    preview = client.get(f"/api/v1/learning-ops/refinements/{proposal}/preview").json()
    return client.post(API + f"/refinements/{proposal}/{action}",
                       json={"revision": preview["revision"], "confirm": True})


SUGGESTION = {
    "target": "prompt",
    "title": "Check quote approval",
    "failure": "The agent emailed the customer before the quote was approved.",
    "change": "Confirm the quote is approved before contacting the customer.",
    "rationale": "Three blocked tasks in a row carried an unapproved quote.",
}


def test_every_change_needs_a_global_admin(client, monkeypatch):
    _as(monkeypatch, "operator")
    for path, body in (
        ("/refinements", SUGGESTION),
        ("/refinements/0123456789abcdef/apply", {"revision": "a" * 64, "confirm": True}),  # pragma: allowlist secret
        ("/refinements/0123456789abcdef/revert", {"revision": "a" * 64, "confirm": True}),
        ("/run", {"scope": "main"}),
        ("/corpus-quality", {}),
        ("/lessons/withdraw", {"model_id": "M", "token": "a" * 64,
                               "reason": "Current policy changed.", "confirm": True}),
    ):
        assert client.post(API + path, json=body).status_code == 403, path


def test_reads_need_view_and_audit_reads_need_audit(client, monkeypatch):
    _as(monkeypatch, "viewer")
    assert client.get(API + "/refinements").status_code == 200
    assert client.get(API + "/models").status_code == 200
    assert client.get(API + "/conflicts").status_code == 200
    for path in ("/log", "/holdout", "/preview"):
        assert client.get(API + path).status_code == 403, path
    _as(monkeypatch, "auditor", "user:auditor")
    assert client.get(API + "/log").status_code == 200
    assert client.get(API + "/holdout").json() == {"configured": False}


def test_suggest_approve_apply_and_undo_through_the_kernel(client):
    from maverick import harness_refine
    from maverick.world_model import open_world

    off = client.get(API + "/refinements").json()
    assert off["enabled"] is False and off["proposals"] == []
    refused = client.post(API + "/refinements", json=SUGGESTION)
    assert refused.status_code == 409 and "turned off" in refused.json()["detail"]

    _configure("[harness_refine]\nenable = true")
    made = client.post(API + "/refinements", json=SUGGESTION).json()
    assert made["needs_approval"] is True
    proposal = made["proposal"]
    assert proposal["title"] == "Check quote approval"
    assert proposal["target"] == "Standing instructions"
    listed = client.get(API + "/refinements").json()["proposals"][0]
    assert listed["approval"] == "Waiting for approval"
    assert listed["can_apply"] is False

    early = _decision(client, proposal["id"], "apply")
    assert early.status_code == 409 and "waiting for approval" in early.json()["detail"]
    assert harness_refine.refinements() == []

    approval_id = harness_refine.list_proposals()[0]["approval_id"]
    world = open_world()
    world.decide_approval(approval_id, "approved", decided_by="security@corp.test")
    assert client.get(API + "/refinements").json()["proposals"][0]["can_apply"] is True

    applied = _decision(client, proposal["id"], "apply")
    assert applied.status_code == 200, applied.text
    live = client.get(API + "/refinements").json()
    assert live["in_force"][0]["change"] == SUGGESTION["change"]
    assert live["proposals"][0]["can_revert"] is True

    assert _decision(client, proposal["id"], "revert").json() == {"reverted": True}
    assert harness_refine.refinements() == []
    again = _decision(client, proposal["id"], "revert")
    assert again.status_code == 409


def test_refinements_are_workspace_scoped(client, monkeypatch):
    _configure("[harness_refine]\nenable = true\nrequire_approval = false")
    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    assert client.post(API + "/refinements", json=SUGGESTION).status_code == 200
    assert len(client.get(API + "/refinements").json()["proposals"]) == 1
    monkeypatch.setenv("MAVERICK_TENANT", "beta")
    assert client.get(API + "/refinements").json()["proposals"] == []


def test_suggestion_text_is_screened_and_ids_are_checked(client):
    _configure("[harness_refine]\nenable = true")
    bad = dict(SUGGESTION, title="!!!")
    r = client.post(API + "/refinements", json=bad)
    assert r.status_code == 422
    assert client.post(API + "/refinements/../etc/apply").status_code in (404, 405)
    assert client.post(API + "/refinements/not-an-id/apply").status_code == 404


def test_read_outs_use_offered_models_only(client, monkeypatch):
    from maverick import self_harness as sh
    store = os.path.join(os.environ["HOME"], "addenda.json")
    from pathlib import Path
    monkeypatch.setattr(sh, "_store_path", lambda: Path(store))
    sh._write_addenda({"claude-x": "Operating guidance learned for this model:\n"
                                   "- always cite the source\n- never cite the source"}, Path(store))
    meta = {}
    for line in ("always cite the source", "never cite the source"):
        sh._upsert_line_meta(meta, "claude-x", line, {"source_goal_ids": [0]}, now=1)
    sh._write_line_meta(meta, Path(store))
    models = client.get(API + "/models").json()["models"]
    assert "claude-x" in [m["value"] for m in models]
    eff = client.get(API + "/efficacy", params={"model_id": "claude-x"}).json()
    assert [row["text"] for row in eff["lessons"]] == ["always cite the source", "never cite the source"]
    assert client.get(API + "/efficacy", params={"model_id": "made-up"}).status_code == 422


def test_exact_lesson_withdrawal_requires_current_review_and_leaves_other_scope(client, monkeypatch):
    from pathlib import Path

    from maverick import self_harness as sh
    store = Path(os.environ["HOME"]) / "addenda.json"
    monkeypatch.setattr(sh, "_store_path", lambda: store)
    line = "Check the source before answering."
    scoped = sh._scoped_key("M", "domain=finance")
    sh._write_addenda({"M": sh._ADDENDUM_HEADER + "\n- " + line,
                       scoped: sh._ADDENDUM_HEADER + "\n- " + line}, store)
    meta = {}
    for key in ("M", scoped):
        sh._upsert_line_meta(meta, key, line, {"source_goal_ids": [0]}, now=1)
    sh._write_line_meta(meta, store)
    rows = client.get(API + "/efficacy", params={"model_id": "M"}).json()["lessons"]
    assert len(rows) == 2
    selected = next(row for row in rows if row["scope_label"] == "Department: finance")
    body = {"model_id": "M", "token": selected["token"],
            "reason": "This department changed its policy.", "confirm": True}
    assert client.post(API + "/lessons/withdraw", json=dict(body, reason="short")).status_code == 422
    removed = client.post(API + "/lessons/withdraw", json=body)
    assert removed.status_code == 200, removed.text
    assert removed.json()["removed"] is True
    current = client.get(API + "/efficacy", params={"model_id": "M"}).json()["lessons"]
    assert len(current) == 1 and current[0]["scope_label"] == "All work"
    assert client.post(API + "/lessons/withdraw", json=body).status_code == 409


def test_lesson_withdrawal_refuses_when_learning_audit_unavailable(client, monkeypatch):
    from pathlib import Path

    from maverick import self_harness as sh
    from maverick_dashboard import learning_loop_api as native
    store = Path(os.environ["HOME"]) / "addenda.json"
    monkeypatch.setattr(sh, "_store_path", lambda: store)
    sh._write_addenda({"M": sh._ADDENDUM_HEADER + "\n- Check totals"}, store)
    meta = {}
    sh._upsert_line_meta(meta, "M", "Check totals", {"source_goal_ids": [0]}, now=1)
    sh._write_line_meta(meta, store)
    token = client.get(API + "/efficacy", params={"model_id": "M"}).json()["lessons"][0]["token"]
    def refuse(*_args, **_kwargs):
        raise HTTPException(503, "The activity log refused this change.")
    from fastapi import HTTPException
    monkeypatch.setattr(native, "_audit", refuse)
    response = client.post(API + "/lessons/withdraw", json={
        "model_id": "M", "token": token, "reason": "It conflicts with current policy.", "confirm": True})
    assert response.status_code == 503
    assert len(sh.line_efficacy("M")) == 1


def test_copilot_reviews_and_withdraws_the_same_current_lesson(client, monkeypatch):
    from pathlib import Path

    from cryptography.fernet import Fernet
    from maverick import self_harness as sh
    from maverick_dashboard import product_operations as ops
    from maverick_dashboard import product_operations_learning_lessons as lessons

    store = Path(os.environ["HOME"]) / "addenda.json"
    monkeypatch.setattr(sh, "_store_path", lambda: store)
    sh._write_addenda({"M": sh._ADDENDUM_HEADER + "\n- Check totals"}, store)
    meta = {}
    sh._upsert_line_meta(meta, "M", "Check totals", {"source_goal_ids": [0]}, now=1)
    sh._write_line_meta(meta, store)

    codec = Fernet(Fernet.generate_key())
    monkeypatch.setattr(ops, "_gate", lambda _request: None)
    monkeypatch.setattr(ops, "_context", lambda _request: "c" * 64)
    monkeypatch.setattr(ops, "enabled_families", lambda: {"learning"})
    monkeypatch.setattr(ops, "adapters", lambda: {entry.id: entry for entry in lessons.entries()})
    monkeypatch.setattr(ops.crypto_at_rest, "seal_to_str", lambda value: "sealed:" + codec.encrypt(value.encode()).decode())
    monkeypatch.setattr(ops.crypto_at_rest, "is_sealed_str", lambda value: value.startswith("sealed:"))
    monkeypatch.setattr(ops.crypto_at_rest, "unseal_from_str", lambda value: codec.decrypt(value[7:].encode()).decode())

    base = "/api/v1/copilot/product-operations"
    selection = {"kind": "learning_model", "id": "M"}
    catalog = client.post(base + "/catalog", json={"page": "/learned", "selection": selection}).json()
    by_id = {item["id"]: item for item in catalog["operations"]}
    assert set(by_id) == {"learning.lesson_results", "learning.withdraw_lesson"}
    read = client.post(base + "/prepare", json={"page": "/learned", "selection": selection,
        "operation": "learning.lesson_results", "context": catalog["context"],
        "revision": by_id["learning.lesson_results"]["revision"], "arguments": {}})
    assert read.status_code == 200 and read.json()["read_only"]
    assert read.json()["details"]["lessons"][0]["text"] == "Check totals"

    choice = by_id["learning.withdraw_lesson"]["fields"][0]["choices"][0]["value"]
    review = client.post(base + "/prepare", json={"page": "/learned", "selection": selection,
        "operation": "learning.withdraw_lesson", "context": catalog["context"],
        "revision": by_id["learning.withdraw_lesson"]["revision"],
        "arguments": {"lesson": choice, "reason": "The policy changed and this is wrong."}})
    assert review.status_code == 200, review.text
    assert "Check totals" in str(review.json()["changes"])
    assert client.post(base + "/execute", json={"token": review.json()["token"],
        "confirmed": False}).status_code == 400
    done = client.post(base + "/execute", json={"token": review.json()["token"],
        "confirmed": True})
    assert done.status_code == 200, done.text
    assert done.json()["status"] == "confirmed"
    assert sh.line_efficacy("M") == []
    assert client.post(base + "/execute", json={"token": review.json()["token"],
        "confirmed": True}).status_code == 409


def _finished(client, started, timeout: float = 15.0) -> dict:
    import time
    job = started.json()["job"]
    deadline = time.time() + timeout
    while job["state"] in ("admitted", "running", "stopping"):  # an admitted job has not started yet
        assert time.time() < deadline, job
        time.sleep(0.05)
        job = client.get(f"/api/v1/learning-ops/jobs/{job['id']}").json()["job"]
    return job


def test_copilot_activates_and_restores_exact_instructions_without_replaying(client, monkeypatch):
    from cryptography.fernet import Fernet
    from maverick import harness_refine
    from maverick_dashboard import product_operations as ops
    from maverick_dashboard import product_operations_learning_program as program

    _configure("[harness_refine]\nenable = true\nrequire_approval = false")
    proposal = client.post(API + "/refinements", json=SUGGESTION).json()["proposal"]["id"]
    codec = Fernet(Fernet.generate_key())
    monkeypatch.setattr(ops, "_gate", lambda _request: None)
    monkeypatch.setattr(ops, "_context", lambda _request: "c" * 64)
    monkeypatch.setattr(ops, "enabled_families", lambda: {"learning"})
    monkeypatch.setattr(ops, "adapters", lambda: {entry.id: entry for entry in program.entries()})
    monkeypatch.setattr(ops.crypto_at_rest, "seal_to_str", lambda value: "sealed:" + codec.encrypt(value.encode()).decode())
    monkeypatch.setattr(ops.crypto_at_rest, "is_sealed_str", lambda value: value.startswith("sealed:"))
    monkeypatch.setattr(ops.crypto_at_rest, "unseal_from_str", lambda value: codec.decrypt(value[7:].encode()).decode())
    base = "/api/v1/copilot/product-operations"

    def prepare(identifier):
        catalog = client.post(base + "/catalog", json={"page": "/learned", "selection": {}}).json()
        operation = next(item for item in catalog["operations"] if item["id"] == identifier)
        assert operation["available"]
        review = client.post(base + "/prepare", json={"page": "/learned", "selection": {},
            "operation": identifier, "context": catalog["context"], "revision": operation["revision"],
            "arguments": {"proposal": proposal}})
        assert review.status_code == 200, review.text
        return review.json()

    apply_review = prepare("learning.instructions_apply")
    assert SUGGESTION["change"] in str(apply_review["changes"])
    assert client.post(base + "/execute", json={"token": apply_review["token"], "confirmed": False}).status_code == 400
    first = client.post(base + "/execute", json={"token": apply_review["token"], "confirmed": True})
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "confirmed"
    replay = client.post(base + "/execute", json={"token": apply_review["token"], "confirmed": True})
    assert replay.json()["status"] == "replayed"
    assert len(harness_refine.refinements()) == 1

    undo_review = prepare("learning.instructions_restore")
    assert undo_review["changes"][0]["after"] == "Removed"
    restored = client.post(base + "/execute", json={"token": undo_review["token"], "confirmed": True})
    assert restored.status_code == 200, restored.text
    assert harness_refine.refinements() == []
    assert client.post(base + "/execute", json={"token": undo_review["token"], "confirmed": True}).json()["status"] == "replayed"
    # The old apply review reads its original receipt; it is never applied again.
    stale = client.post(base + "/execute", json={"token": apply_review["token"], "confirmed": True})
    assert stale.status_code == 200 and stale.json()["status"] == "replayed"
    assert harness_refine.refinements() == []


def _pass(client, **choices):
    """Review and start a learning pass the way the Learned page does.

    Returns the refusal, or the pass's finished task once its admitted job ends.
    """
    import time
    current = client.get(API + "/passes/current")
    if current.status_code != 200:
        return current
    review = client.post(API + "/passes/review", json={
        "context": current.json()["context"], "revision": current.json()["revision"], **choices})
    if review.status_code != 200:
        return review
    started = client.post(API + "/passes/start", json={"token": review.json()["token"], "confirm": True})
    assert started.status_code == 200, started.text
    original = API + "/passes/requests/" + review.json()["operation"]
    deadline = time.time() + 15
    body = started.json()
    while not body.get("job") or body["job"]["state"] in ("admitted", "running", "stopping"):
        assert time.time() < deadline, body
        time.sleep(0.05)
        body = client.get(original).json()
    return body


def _main_model():
    from maverick.llm import model_for_role
    return model_for_role("orchestrator")


def test_run_now_respects_the_switch_and_the_learning_stop(client, monkeypatch):
    from maverick import learning_guard, self_harness
    from maverick import self_improvement_runner as runner
    _configure("[self_harness]\nenable = false")
    r = _pass(client, scope="main")
    assert r.status_code == 409 and "Self-coaching is off" in r.json()["detail"]

    _configure("[self_harness]\nenable = true")
    report = self_harness.SelfHarnessReport(model_id="claude-x", mined=2, proposed=1, validated=1,
                                            promoted=1, applied_lines=["check totals"])
    seen: list[dict] = []
    monkeypatch.setattr(runner, "run_self_harness_cycle", lambda *a, **kw: seen.append(kw) or (report, 3))
    from maverick_dashboard import learning_jobs
    done = _pass(client, scope="main")
    assert done["job"]["state"] == "done", done
    job = next(job for job in learning_jobs._jobs.values() if job.kind == "self_harness_run")
    assert job.cancellable is True  # a reviewed pass can be stopped between models
    out = done["result"]
    assert out["reports"][0]["Adopted"] == 1 and out["reports"][0]["Retired"] == 3
    assert (seen[-1]["model_id"], seen[-1]["retire"], seen[-1]["canary"], seen[-1]["evaluation_system"]) == (
        _main_model(), True, None, None)

    def halted(job, phase):
        raise learning_guard.Halted("stop", "operator")
    monkeypatch.setattr(learning_guard, "check_learning_halt", halted)
    stopped = _pass(client, scope="main")
    assert stopped.status_code == 409 and "stopped" in stopped.json()["detail"]


def test_run_now_passes_trial_retire_and_the_deployed_instructions(client, monkeypatch):
    from maverick import self_harness
    from maverick import self_improvement_runner as runner
    _configure("[self_harness]\nenable = true")
    report = self_harness.SelfHarnessReport(model_id="claude-x")
    seen: list[dict] = []
    monkeypatch.setattr(runner, "run_self_harness_cycle", lambda *a, **kw: seen.append(kw) or (report, 0))
    body = {"scope": "main", "trial": True, "retire": False, "instructions": "You are a careful agent."}
    _pass(client, **body)
    assert (seen[-1]["retire"], seen[-1]["canary"], seen[-1]["evaluation_system"]) == (
        False, True, "You are a careful agent.")
    for bad in ("   ", "a\x00b", "x" * (1024 * 1024 + 1)):
        r = _pass(client, **dict(body, instructions=bad))
        assert r.status_code in (413, 422), bad[:5]

    seen.clear()
    done = _pass(client, scope="all")
    assert len(done["result"]["reports"]) == len(runner.harness_fleet_models()) == len(seen)
    assert all(call["canary"] is None and call["retire"] is True for call in seen)


def test_run_for_the_chosen_model_and_preview_threshold(client, monkeypatch):
    from maverick import self_harness
    from maverick import self_improvement_runner as runner
    _configure("[self_harness]\nenable = true")
    seen: list[dict] = []
    monkeypatch.setattr(runner, "run_self_harness_cycle",
                        lambda *a, **kw: seen.append(kw) or (self_harness.SelfHarnessReport(model_id="claude-x"), 0))
    assert _pass(client, scope="chosen").status_code == 409
    assert _pass(client, scope="chosen", model_id="made-up").status_code == 409
    chosen = runner.harness_fleet_models()[-1]
    _pass(client, scope="chosen", model_id=chosen)
    assert seen[-1]["model_id"] == chosen
    assert client.get(API + "/preview", params={"min_support": 5}).status_code == 200
    assert client.get(API + "/preview", params={"min_support": 4}).status_code == 422


def test_test_case_check_runs_in_the_background_and_removal_needs_confirmation(client, monkeypatch, tmp_path):
    from maverick import self_harness_eval as ev
    from maverick import self_improvement_runner as runner
    _configure(f'[self_harness]\nenable = true\neval_corpus = "{(tmp_path / "c.json").as_posix()}"')
    monkeypatch.setattr(runner, "run_corpus_quality", lambda **kw: [
        {"goal": "easy task", "discriminative": False, "baseline_rate": 1.0, "age_days": None},
        {"goal": "hard task", "discriminative": True, "baseline_rate": 0.5, "age_days": 3.0}])
    removed: list = []
    monkeypatch.setattr(ev, "retire_corpus_cases", lambda path, key, goals: removed.append((key, goals)) or len(goals))
    # Checking runs from Check saved learning questions on Learned, after a
    # complete review; checking never removes a question. A check-and-delete
    # shortcut refuses every form.
    for body in ({}, {"remove_weak": True}, {"remove_weak": True, "confirm": True}):
        refused = client.post(API + "/corpus-quality", json=body)
        assert refused.status_code == 409
        assert "Checking never removes a question" in refused.json()["detail"]
    assert removed == []


def test_learned_page_shows_the_new_sections_in_plain_words(client):
    page = client.get("/learned").text
    assert 'id="llp-root"' in page and 'data-admin="1"' in page
    assert 'id="llp-propose"' in page and 'id="lp-review"' in page
    assert "/static/lightwork-learning-loop.js" in page
    own = page.split('id="llp-root"', 1)[1].split(">", 1)[1].split("<style>", 1)[0]
    visible = re.sub(r"<script[\s\S]*?</script>|<[^>]+>", " ", own)
    assert "Suggested instruction changes" in visible
    assert not _BANNED.search(visible), visible


def test_learned_page_hides_controls_from_non_admins(client, monkeypatch):
    _as(monkeypatch, "viewer")
    page = client.get("/learned").text
    assert 'id="llp-root"' in page and 'data-admin="0"' in page
    assert 'id="llp-propose"' not in page and 'id="llp-run"' not in page


def test_learning_loop_script_is_served(client):
    r = client.get("/static/lightwork-learning-loop.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]
    assert "window.confirm(" not in r.text and "mvConfirm" in r.text
