"""Learning-page and Learned-page buttons for learning systems that were
terminal-only: permission refusals, the kernel function underneath, confirm
and size limits, one activity-record row per change, background jobs with
status and stop, and plain-language pages."""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from test_support.settings_pages import every_group

ORIGIN = {"Origin": "http://127.0.0.1"}
LO = "/api/v1/learning-ops"
TO = "/api/v1/training-ops"
_BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|jsonl|revision|"
    r"idempoten\w*|harness|refinement|corpus|holdout|efficacy|canary|codebook|codec|klear|"
    r"trajectory|dgm|flywheel_turn)\b|/api/v1|HTTP \d{3}|maverick |\[\w+\]",
    re.IGNORECASE,
)


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import learning_jobs
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_SELF_HARNESS",
                 "MAVERICK_DATA_ENGINE", "MAVERICK_FACTORY_LEARNING", "MAVERICK_HARNESS_REFINE"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    learning_jobs.clear_for_tests()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    learning_jobs.clear_for_tests()
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit
    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True
    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


def _configure(body: str) -> None:
    from maverick import config
    with open(os.environ["MAVERICK_CONFIG"], "w", encoding="utf-8") as fh:
        fh.write(body + "\n")
    config.reset_config_cache()


def _as(monkeypatch, role: str, who: str = "user:someone"):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


@pytest.mark.parametrize("role", ["viewer", "operator"])
@pytest.mark.parametrize("action", ["compare", "adopt", "restore"])
def test_factory_review_checks_authority_before_nested_values(client, monkeypatch, role, action):
    _as(monkeypatch, role)
    response = client.post(f"{LO}/factory/review", json={"action": action, "values": {}})
    assert response.status_code == 403


@pytest.mark.parametrize("action,values", [
    ("compare", {}), ("restore", {}), ("adopt", {}),
    ("adopt", {"operation": 4}), ("adopt", {"operation": "a" * 32, "extra": True}),
])
def test_factory_review_invalid_nested_values_return_422(client, monkeypatch, action, values):
    _as(monkeypatch, "admin")
    response = client.post(f"{LO}/factory/review", json={"action": action, "values": values})
    assert response.status_code == 422


def test_factory_review_authenticates_before_parsing_json(client, monkeypatch):
    _as(monkeypatch, "viewer")
    assert client.post(f"{LO}/factory/review", content="{", headers={"Content-Type": "application/json"}).status_code == 403
    _as(monkeypatch, "admin")
    assert client.post(f"{LO}/factory/review", content="{", headers={"Content-Type": "application/json"}).status_code == 422
    assert client.post(f"{LO}/factory/review", content='{"action":"adopt","values":{}}',
                       headers={"Content-Type": "text/plain"}).status_code == 422
    operation = client.get("/openapi.json").json()["paths"][f"{LO}/factory/review"]["post"]
    assert operation["requestBody"]["content"]["application/json"]["schema"]["required"] == ["action", "values"]


def _wait(client, started, timeout: float = 15.0) -> dict:
    job = started.json()["job"] if hasattr(started, "json") else started
    deadline = time.time() + timeout
    while job["state"] in ("admitted", "running", "stopping"):  # an admitted job has not started yet
        assert time.time() < deadline, job
        time.sleep(0.05)
        job = client.get(f"{LO}/jobs/{job['id']}").json()["job"]
    return job


def _original_job(client, path: str, timeout: float = 15.0) -> dict:
    """Read a reviewed request's original until its admitted job is named."""
    deadline = time.time() + timeout
    result = client.get(path).json()
    while "job_id" not in result:
        assert time.time() < deadline, result
        time.sleep(0.05)
        result = client.get(path).json()
    return result


def _visible(page: str, marker: str) -> str:
    own = page.split(marker, 1)[1]
    own = re.sub(r"<style[\s\S]*?</style>|<script[\s\S]*?</script>", " ", own)
    return re.sub(r"<[^>]+>", " ", own)


# ---- permissions ---------------------------------------------------------------

ADMIN_ONLY = (
    ("post", f"{LO}/self-harness/clash-check", {}),
    ("post", f"{LO}/self-harness/transfer", {"source": "m"}),
    ("post", f"{LO}/self-harness/test-cases/harvest", {"mode": "propose"}),
    ("get", f"{LO}/self-harness/test-cases/export", None),
    ("get", f"{LO}/self-harness/plan", None),
    ("post", f"{LO}/self-harness/hold-out/set-up", {"confirm": True}),
    ("get", f"{LO}/refinements/0123456789abcdef/preview", None),  # pragma: allowlist secret
    ("post", f"{LO}/flywheel/review", {"context": "0" * 64, "revision": "0" * 64}),
    ("post", f"{LO}/flywheel/turn", {"token": "sealed-review", "confirmed": True}),
    ("get", f"{LO}/factory/preview", None),
    ("get", f"{LO}/self-modify", None),
    ("get", f"{LO}/self-modify/results", None),
    ("post", f"{LO}/self-modify/review", {"objective": "make summaries faster", "context": "0" * 64, "revision": "0" * 64}),
    ("post", f"{LO}/self-modify/run", {"objective": "make summaries faster", "context": "0" * 64,
                                       "revision": "0" * 64, "token": "sealed-review", "confirm": True}),
    ("post", f"{TO}/reward-models/train", {}),
    ("post", f"{TO}/codec/shorthand/learn", {}),
    ("post", f"{TO}/codec/token-codes/learn", {}),
    ("post", f"{TO}/codec/measure", {}),
)


def test_every_learning_operation_needs_a_global_admin(client, monkeypatch):
    _as(monkeypatch, "operator")
    for method, path, body in ADMIN_ONLY:
        kwargs = {"json": body} if body is not None else {}
        assert getattr(client, method)(path, **kwargs).status_code == 403, path
    for path in (f"{LO}/self-harness/test-cases/import?confirm=true", f"{LO}/self-harness/test-cases/import/preview",
                 f"{LO}/factory/promote?confirm=true", f"{TO}/model-improvement/score?task_set=x",
                 f"{TO}/reward-models/rm-20260101-000000/score"):
        assert client.post(path, content=b"{}").status_code == 403, path
    assert client.get(f"{TO}/reward-models/rm-20260101-000000/download").status_code == 403


def test_a_workspace_admin_is_not_a_global_admin(client, monkeypatch):
    from maverick_dashboard import auth
    _as(monkeypatch, "operator", "user:wsadmin")
    monkeypatch.setattr(auth, "has_permission", lambda request, perm: True)
    assert client.post(f"{LO}/flywheel/turn", json={"token": "sealed-review", "confirmed": True}).status_code == 403
    assert client.post(f"{LO}/self-modify/run", json={"objective": "make it faster please",
                                                       "context": "0" * 64, "revision": "0" * 64, "token": "sealed-review",
                                                       "confirm": True}).status_code == 403


def test_reads_on_the_learning_page_need_view(client, monkeypatch):
    _as(monkeypatch, "viewer")
    for path in (f"{TO}/reward-models", f"{TO}/codec", f"{LO}/donations", f"{LO}/jobs"):
        assert client.get(path).status_code == 200, path
    assert client.post(f"{LO}/donations/clear", json={"confirm": True}).status_code == 403
    # Model choices are read only by those the Learning page itself admits
    # (installation administrators); a viewer is refused, an administrator reads.
    assert client.get(f"{TO}/model-improvement").status_code == 403
    _as(monkeypatch, "admin")
    assert client.get(f"{TO}/model-improvement").status_code == 200


# ---- background jobs -------------------------------------------------------------

def test_jobs_are_hidden_from_people_who_cannot_start_them(client, monkeypatch):
    from maverick_dashboard import learning_jobs
    gate = threading.Event()
    job = learning_jobs.start("probe", "Probe", lambda j: gate.wait(5) and {"ok": True}, started_by="user:ada")
    assert client.get(f"{LO}/jobs/{job.id}").json()["job"]["state"] == "running"
    _as(monkeypatch, "viewer")
    assert client.get(f"{LO}/jobs/{job.id}").status_code == 404
    assert client.get(f"{LO}/jobs").json()["jobs"] == []
    gate.set()


def test_the_same_job_cannot_run_twice_and_stopping_is_cooperative(client, audit_rows):
    from maverick_dashboard import learning_jobs

    def loop(job):
        while not job.cancelled:
            time.sleep(0.01)
        return {"stopped_cleanly": True}
    job = learning_jobs.start("loop", "Loop", loop, started_by="user:ada", cancellable=True)
    with pytest.raises(learning_jobs.JobRefused):
        learning_jobs.start("loop", "Loop", loop, started_by="user:ada")
    stop = client.post(f"{LO}/jobs/{job.id}/stop", json={})
    assert stop.status_code == 200
    done = _wait(client, stop)
    assert done["state"] == "stopped" and done["result"] == {"stopped_cleanly": True}
    assert [r["action"] for r in audit_rows] == ["job_stop"]
    again = client.post(f"{LO}/jobs/{job.id}/stop", json={})
    assert again.status_code == 409


def test_a_job_that_cannot_stop_refuses_the_stop_button(client):
    from maverick_dashboard import learning_jobs
    gate = threading.Event()
    job = learning_jobs.start("fixed", "Fixed", lambda j: gate.wait(5) and {}, started_by="user:ada")
    r = client.post(f"{LO}/jobs/{job.id}/stop", json={})
    assert r.status_code == 409 and "cannot be stopped" in r.json()["detail"]
    gate.set()


@pytest.mark.parametrize("elapsed", [0.0, 0.0001, 12.0])
@pytest.mark.parametrize("cap", [None, 0.0001, 3600.0])
def test_stop_budget_only_tightens_the_wall_clock(monkeypatch, elapsed, cap):
    from maverick.budget import Budget, BudgetExceeded
    from maverick_dashboard.learning_jobs import stop_budget
    budget = Budget(max_wall_seconds=cap)
    monkeypatch.setattr(Budget, "elapsed", lambda self: elapsed)
    stop_budget(budget)()
    assert budget.max_wall_seconds == (elapsed if cap is None else min(cap, elapsed))
    with pytest.raises(BudgetExceeded):
        budget.check()


def test_failures_become_one_plain_sentence(client):
    from maverick.learning_guard import Halted
    from maverick_dashboard import learning_jobs
    from maverick_dashboard.learning_ops_api import job_problem

    def halted(job):
        raise Halted("stop", "operator")
    job = learning_jobs.start("halted", "Halted", halted, started_by="u", problem=job_problem)
    done = _wait(client, job.view())
    assert done["state"] == "failed" and "Learning is stopped" in done["problem"]

    def broken(job):
        raise RuntimeError("secret internals /etc/passwd")
    job = learning_jobs.start("broken", "Broken", broken, started_by="u", problem=job_problem)
    done = _wait(client, job.view())
    assert done["problem"] == "This task stopped because of a problem. Work completed before the failure may remain. Read its current result before deciding what to do next; do not repeat it automatically."


# ---- improvement flywheel ------------------------------------------------------------

def _flywheel_review(client):
    """A cycle starts only from a complete current review (sealed token)."""
    current = client.get(f"{LO}/flywheel").json()
    return current, client.post(f"{LO}/flywheel/review", json={
        "context": current["context"], "revision": current.get("revision") or "0" * 64})


def test_flywheel_needs_its_switch_and_respects_the_learning_stop(client, monkeypatch):
    from maverick import data_engine, learning_guard
    monkeypatch.setattr(data_engine, "enabled", lambda: False)
    current, r = _flywheel_review(client)
    assert current["ready"] is False and "improvement flywheel" in current["problem"]
    assert r.status_code == 409 and "improvement flywheel" in r.json()["detail"]
    monkeypatch.setattr(data_engine, "enabled", lambda: True)

    def halted(job, phase):
        raise learning_guard.Halted("stop", "operator")
    monkeypatch.setattr(learning_guard, "check_learning_halt", halted)
    _current, r = _flywheel_review(client)
    assert r.status_code == 409 and "stopped" in r.json()["detail"]


def test_flywheel_turn_runs_the_kernel_and_is_recorded_first(client, monkeypatch, audit_rows):
    from maverick import data_engine, flywheel
    monkeypatch.setattr(data_engine, "enabled", lambda: True)
    seen: list[int] = []

    def turn():
        seen.append(len(audit_rows))
        return SimpleNamespace(acted=True, n_episodes=12,
                               guardrails=[SimpleNamespace(action="send_invoice_unchecked")],
                               memories=[SimpleNamespace(action="check_totals")],
                               hypotheses=[SimpleNamespace(baseline_action="retry", candidate_action="ask_owner")])
    monkeypatch.setattr(flywheel, "run_once", lambda steps, **_kwargs: turn())
    current, review = _flywheel_review(client)
    assert current["ready"] is True, current
    assert review.status_code == 200, review.text
    started = client.post(f"{LO}/flywheel/turn", json={"token": review.json()["token"], "confirmed": True})
    assert started.status_code == 200, started.text
    original, deadline = started.json(), time.time() + 15
    while "task_href" not in original:  # the worker names its task once admitted
        assert time.time() < deadline, original
        time.sleep(0.05)
        original = client.get(f"{LO}/flywheel/original/{review.json()['operation']}").json()
    job_id = original["task_href"].split("learning_task=", 1)[1].split("#", 1)[0]
    done = _wait(client, client.get(f"{LO}/jobs/{job_id}").json()["job"])
    assert done["state"] == "done", done
    assert done["result"]["complete"] is True
    assert done["result"]["counts"] == {"avoid": 1, "habits": 1, "ideas": 1}
    # The activity record row is written before the kernel turns.
    assert [r["action"] for r in audit_rows] == ["flywheel_turn"] and seen == [1]


def test_flywheel_turn_accepts_only_a_sealed_review_with_complete_material(client, monkeypatch, audit_rows):
    from maverick import crypto_at_rest, data_engine, flywheel
    monkeypatch.setattr(data_engine, "enabled", lambda: True)
    ran: list[int] = []
    monkeypatch.setattr(flywheel, "run_once", lambda steps, **_kwargs: ran.append(1))
    _current, review = _flywheel_review(client)
    assert review.status_code == 200, review.text
    sealed = review.json()["token"]
    assert crypto_at_rest.is_sealed_str(sealed)
    turn = f"{LO}/flywheel/turn"

    # A hand-written plain-JSON review is not a review this server produced.
    plain = crypto_at_rest.unseal_from_str(sealed)
    assert json.loads(plain)["purpose"] == "lightwork.flywheel.v1"
    forged = client.post(turn, json={"token": plain, "confirmed": True})
    assert forged.status_code == 409 and "unavailable" in forged.json()["detail"], forged.text

    # Sealed material that lacks part of the review is refused cleanly, not as a server error.
    material = json.loads(plain)
    for broken in ({key: value for key, value in material.items() if key != "prepared"},
                   {key: value for key, value in material.items() if key != "operation"},
                   {**material, "prepared": "not an object"}, [material]):
        token = crypto_at_rest.seal_to_str(json.dumps(broken))
        refused = client.post(turn, json={"token": token, "confirmed": True})
        assert refused.status_code == 409 and "unavailable" in refused.json()["detail"], (broken, refused.text)
    # So is a sealed review whose protected contents were altered.
    altered = sealed[:-4] + ("AAAA" if not sealed.endswith("AAAA") else "BBBB")
    tampered = client.post(turn, json={"token": altered, "confirmed": True})
    assert tampered.status_code == 409 and "unavailable" in tampered.json()["detail"], tampered.text
    assert ran == [] and audit_rows == []


# ---- self-coaching extras ----------------------------------------------------------------

def _harness(monkeypatch, tmp_path, *, corpus: bool = True, ledger: str = ""):
    from maverick import self_harness
    body = "[self_harness]\nenable = true\n"
    if corpus:
        body += f'eval_corpus = "{(tmp_path / "corpus.json").as_posix()}"\n'
    if ledger:
        body += f'holdout_ledger = "{ledger}"\n'
    _configure(body)
    store = tmp_path / "addenda.json"
    monkeypatch.setattr(self_harness, "_store_path", lambda: store)
    self_harness._write_addenda({"claude-x": "Operating guidance learned for this model:\n"
                                             "- always cite the source\n- never cite the source"}, store)
    meta = {}
    for line in ("always cite the source", "never cite the source"):
        self_harness._upsert_line_meta(meta, "claude-x", line, {"source_goal_ids": [0]}, now=1)
    self_harness._write_line_meta(meta, store)


def test_clash_check_asks_the_checker_model_within_a_spending_limit(client, monkeypatch, tmp_path, audit_rows):
    from maverick import llm, self_harness
    _harness(monkeypatch, tmp_path)
    roles: list[str] = []
    budgets: list = []
    monkeypatch.setattr(llm, "model_for_role", lambda role: roles.append(role) or "checker-model")
    monkeypatch.setattr(llm, "LLM", lambda model: SimpleNamespace(model=model))

    def classifier(judge, *, budget=None, **_kw):
        budgets.append(budget)
        return lambda a, b: True
    monkeypatch.setattr(self_harness, "llm_conflict_classifier", classifier)
    from maverick_dashboard import learning_jobs
    context = client.get(f"{LO}/self-harness/clash-check").json()["context"]
    review = client.post(f"{LO}/self-harness/clash-check/review", json={"model_id": "claude-x", "context": context})
    assert review.status_code == 200, review.text
    started = client.post(f"{LO}/self-harness/clash-check", json={
        "context": context, "token": review.json()["token"], "confirmed": True})
    assert started.status_code == 200, started.text
    original = f"{LO}/self-harness/clash-check/requests/{review.json()['operation']}"
    result = _original_job(client, original)
    assert learning_jobs.get(result["job_id"]).cancellable is True
    done = _wait(client, client.get(f"{LO}/jobs/{result['job_id']}").json()["job"])
    assert done["state"] == "done", done
    assert "verifier" in roles and budgets and budgets[0] is not None
    result = client.get(original).json()
    assert result["pairs"][0]["first"] == "always cite the source"
    assert [r.get("action") for r in audit_rows].count("self_harness_semantic_conflicts") == 1
    assert client.post(f"{LO}/self-harness/clash-check/review",
                       json={"model_id": "made-up", "context": context}).status_code == 422


def test_transfer_needs_the_switch_and_test_cases(client, monkeypatch, tmp_path, audit_rows):
    from maverick import self_improvement_runner as runner
    calls: list = []
    monkeypatch.setattr(runner, "run_self_harness_transfer", lambda *a, **k: calls.append((a, k)))
    _configure("[self_harness]\nenable = false")
    current = client.get("/api/v1/learning-transfers/current").json()
    assert current["available"] is False and "Self-coaching is off" in current["problem"]
    _harness(monkeypatch, tmp_path)
    monkeypatch.setattr(runner, "harness_fleet_models", lambda: ["claude-x", "worker-y"])
    # Lesson tests start only from the complete reviewed lesson test on Learned
    # (current lessons, questions, standing instructions and spending); the
    # old one-click start refuses before anything runs or is recorded.
    r = client.post(f"{LO}/self-harness/transfer", json={"source": "claude-x", "retry_judged": True})
    assert r.status_code == 409 and "Test lessons on another model" in r.json()["detail"]
    assert calls == [] and audit_rows == []


def test_test_cases_find_download_preview_and_add(client, monkeypatch, tmp_path, audit_rows):
    from maverick import self_improvement_runner as runner
    r = client.post(f"{LO}/self-harness/test-cases/harvest", json={"mode": "propose"})
    assert r.status_code == 409 and "not set up" in r.json()["detail"]
    _harness(monkeypatch, tmp_path)
    (tmp_path / "corpus.json").write_text(json.dumps({"claude-x": [{"goal": "old", "expected": "x"}]}))
    modes: list[str] = []
    monkeypatch.setattr(runner, "run_corpus_harvest",
                        lambda world, *, mode, raise_errors: modes.append(mode) or 3)
    assert client.post(f"{LO}/self-harness/test-cases/harvest", json={"mode": "auto"}).json() == {
        "found": 3, "mode": "auto"}
    assert modes == ["auto"]

    down = client.get(f"{LO}/self-harness/test-cases/export")
    assert down.status_code == 200 and "attachment" in down.headers["content-disposition"]
    assert json.loads(down.text) == {"claude-x": [{"goal": "old", "expected": "x"}]}

    upload = json.dumps({"claude-x": [{"goal": "old", "expected": "x"}, {"goal": "new", "expected": "y"}]}).encode()
    pv = client.post(f"{LO}/self-harness/test-cases/import/preview", content=upload).json()
    assert pv["added"] == 1 and pv["keys"][0]["now"] == 1 and pv["keys"][0]["after"] == 2
    assert json.loads((tmp_path / "corpus.json").read_text())["claude-x"][-1]["goal"] == "old"
    review = {"X-Lightwork-Import-Review": pv["token"]}
    # Importing needs both the sealed review of this exact file and an explicit confirmation.
    assert client.post(f"{LO}/self-harness/test-cases/import", content=upload).status_code == 409
    assert client.post(f"{LO}/self-harness/test-cases/import?confirm=true", content=upload).status_code == 409
    assert client.post(f"{LO}/self-harness/test-cases/import", content=upload, headers=review).status_code == 409
    assert client.post(f"{LO}/self-harness/test-cases/import?confirm=true", content=b"[1, 2]",
                       headers=review).status_code == 422
    assert client.post(f"{LO}/self-harness/test-cases/import/preview",
                       content=b"{" + b" " * (6 * 1024 * 1024) + b"}").status_code == 413
    assert json.loads((tmp_path / "corpus.json").read_text())["claude-x"][-1]["goal"] == "old"
    added = client.post(f"{LO}/self-harness/test-cases/import?confirm=true", content=upload, headers=review).json()
    assert (added["confirmed"], added["cases"], added["replaced"], added["operation"]) == (True, 1, False, pv["operation"])
    assert [c["goal"] for c in json.loads((tmp_path / "corpus.json").read_text())["claude-x"]] == ["old", "new"]
    assert [r["action"] for r in audit_rows] == [
        "self_harness_corpus_harvest", "self_harness_corpus_export", "self_harness_corpus_import"]


HOLD_OUT = "/api/v1/learning-holdout-setup"


def _hold_out(client, action: str = "initialize", *, step: str = "save"):
    """Review and save one hold-out setup step the way the Learned page does."""
    current = client.get(HOLD_OUT).json()
    review = client.post(f"{HOLD_OUT}/review", json={
        "action": action, "context": current["context"], "revision": current["revision"]})
    if review.status_code != 200 or step == "review":
        return review
    return client.post(f"{HOLD_OUT}/save", json={"token": review.json()["token"], "confirmed": True})


def test_hold_out_record_is_set_up_once_and_never_replaced(client, monkeypatch, tmp_path, audit_rows):
    r = _hold_out(client)
    assert r.status_code == 409 and "Choose the managed location first" in r.json()["detail"]
    # The record must sit inside Lightwork's managed data, as its setting requires.
    ledger = Path(_data_file("ledger.db")).as_posix()
    _harness(monkeypatch, tmp_path, ledger=ledger)
    review = _hold_out(client, step="review")
    assert review.status_code == 200, review.text
    assert client.post(f"{HOLD_OUT}/save", json={"token": review.json()["token"]}).status_code == 422
    made = client.post(f"{HOLD_OUT}/save", json={"token": review.json()["token"], "confirmed": True})
    assert made.status_code == 200 and made.json()["confirmed"] is True and made.json()["ready"] is True
    assert Path(ledger).exists()
    again = _hold_out(client)
    assert again.status_code == 409 and "never initialized again" in again.json()["detail"]
    assert [r["action"] for r in audit_rows if "action" in r and r["action"].startswith("self_harness")] == [
        "self_harness_holdout_initialize"]
    plan = client.get(f"{LO}/self-harness/plan").json()
    assert plan["hold_out"] == {"set_up": True, "exists": True}


def test_refinement_preview_shows_before_and_after(client):
    from maverick import harness_refine
    from maverick.world_model import open_world
    _configure("[harness_refine]\nenable = true")
    change = {"target": "prompt", "title": "Check quote approval", "failure": "Emailed early",
              "change": "Confirm the quote first.", "rationale": "Three blocked tasks."}
    pid = client.post("/api/v1/learning-loop/refinements", json=change).json()["proposal"]["id"]
    pv = client.get(f"{LO}/refinements/{pid}/preview").json()
    assert pv["now"] == "" and pv["after"] == "Confirm the quote first." and pv["undo_also_removes"] == []
    approval = harness_refine.list_proposals()[0]["approval_id"]
    open_world().decide_approval(approval, "approved", decided_by="security@corp.test")
    assert client.post(f"/api/v1/learning-loop/refinements/{pid}/apply",
                       json={"revision": pv["revision"], "confirm": True}).status_code == 200
    second = dict(change, change="Confirm the quote and the date first.")
    pid2 = client.post("/api/v1/learning-loop/refinements", json=second).json()["proposal"]["id"]
    assert client.get(f"{LO}/refinements/{pid2}/preview").json()["now"] == "Confirm the quote first."
    assert client.get(f"{LO}/refinements/ffffffffffffffff/preview").status_code == 404
    assert client.get(f"{LO}/refinements/not-an-id/preview").status_code == 404


# ---- improving how new agents are built -----------------------------------------------

def test_factory_learning_preview_and_adopt_with_evidence(client, monkeypatch, audit_rows):
    from maverick import factory_learning
    monkeypatch.setattr(factory_learning, "enabled", lambda: False)
    assert client.get(f"{LO}/factory/preview").status_code == 409
    monkeypatch.setattr(factory_learning, "enabled", lambda: True)
    monkeypatch.setattr(factory_learning, "mine_corrections", lambda min_support: [
        SimpleNamespace(guidance="Always add a deny list.", support=min_support, scope="provisioning")])
    pv = client.get(f"{LO}/factory/preview?min_support=5").json()
    assert pv["corrections"] == [{"guidance": "Always add a deny list.", "seen_in": 5, "area": "provisioning"}]
    assert client.get(f"{LO}/factory/preview?min_support=4").status_code == 422
    # Adoption now goes through Improve how new agents are built (one
    # suggestion, a complete comparison, then a separate Adopt review). The old
    # bulk shortcut refuses, even with evidence and a confirmation, and adopts nothing.
    monkeypatch.setattr(factory_learning, "load_measured_evidence", lambda path: "scorer")

    def adopt(**_kwargs):
        raise AssertionError("the retired shortcut must not adopt guidance")
    monkeypatch.setattr(factory_learning, "review_and_promote", adopt)
    for query, body in (("", b"{}"), ("?confirm=true", b'{"version": 2}')):
        refused = client.post(f"{LO}/factory/promote{query}", content=body)
        assert refused.status_code == 409
        assert "review a complete comparison" in refused.json()["detail"]
    assert audit_rows == []


# ---- practising changes to its own code -----------------------------------------------------

def test_self_modify_status_is_plain_and_run_needs_confirmation(client, audit_rows):
    status = client.get(f"{LO}/self-modify").json()
    assert status["state"] == "off" and isinstance(status["areas"], int)
    for sentence in status["blockers"]:
        assert "_" not in sentence and "[" not in sentence
    assert client.get(f"{LO}/self-modify/results").json() == {"results": []}
    r = client.post(f"{LO}/self-modify/run", json={"objective": "make summaries faster"})
    assert r.status_code == 422
    assert client.post(f"{LO}/self-modify/run", json={"objective": "short", "confirm": True}).status_code == 422
    assert client.post(f"{LO}/self-modify/run", json={"objective": "make summaries faster", "cycles": 50,
                                                      "confirm": True}).status_code == 422
    assert audit_rows == []


def _practice(client, objective="make summaries faster", cycles=1):
    """Start practice the way the page does: review the exact objective first."""
    current = client.get(f"{LO}/self-modify").json()
    body = {"objective": objective, "cycles": cycles, "context": current["context"], "revision": current["revision"]}
    review = client.post(f"{LO}/self-modify/review", json=body)
    assert review.status_code == 200, review.text
    return client.post(f"{LO}/self-modify/run", json={**body, "token": review.json()["token"], "confirm": True})


def test_self_modify_run_uses_the_kernel_budget_and_shows_its_refusal(client, monkeypatch, audit_rows):
    from maverick import self_modify_runner
    seen: dict = {}

    def run(*, cycles, objective, budget):
        seen.update(cycles=cycles, objective=objective, budget=budget)
        return self_modify_runner.RunSummary(False, reason="self-modification disabled ([self_modify] enable)")
    monkeypatch.setattr(self_modify_runner, "run", run)
    done = _wait(client, _practice(client, "  make   summaries faster  ", cycles=2))
    assert seen["cycles"] == 2 and seen["objective"] == "make summaries faster"
    assert seen["budget"] is not None
    assert done["result"]["ran"] is False and done["result"]["problem"] == (
        "Turn on the experiment under “Experimental: let Lightwork try improving its own code” "
        "on the Learning page first.")
    assert [r["action"] for r in audit_rows] == ["self_modify_run"]


def test_an_exhausted_organisation_allowance_refuses_before_anything_starts(client, monkeypatch, audit_rows):
    from maverick import budget as budget_mod
    from maverick.budget import Budget

    def refused(*, task_class=None, **kw):
        b = Budget(max_dollars=1.0)
        b._tenant_refusal = "organisation allowance exhausted"
        return b
    monkeypatch.setattr(budget_mod, "budget_from_config", refused)
    r = _practice(client)
    assert r.status_code == 409 and "allowance is used up" in r.json()["detail"]
    assert audit_rows == []


def test_stopping_self_modify_tightens_its_own_budget(client, monkeypatch):
    from maverick import self_modify_runner
    from maverick.budget import BudgetExceeded

    def run(*, cycles, objective, budget):
        while True:
            try:
                budget.check()
            except BudgetExceeded:
                return self_modify_runner.RunSummary(True)
            time.sleep(0.01)
    monkeypatch.setattr(self_modify_runner, "run", run)
    started = _practice(client)
    job = started.json()["job"]
    deadline = time.time() + 15
    while job["state"] == "admitted":  # the stop button appears once it runs
        assert time.time() < deadline, job
        time.sleep(0.05)
        job = client.get(f"{LO}/jobs/{job['id']}").json()["job"]
    assert job["can_stop"] is True
    # A learning task is stopped through its reviewed stop on the Learned page.
    current = client.get(f"{LO}/job-history/{job['id']}").json()
    stop = client.post(f"{LO}/job-history/{job['id']}/stop", json={
        "context": current["context"], "revision": current["revision"],
        "operation": uuid.uuid4().hex, "confirm": True})
    assert stop.status_code == 200 and stop.json()["receipt"]["confirmed"] is True, stop.text
    done = _wait(client, started)
    assert done["state"] == "stopped" and done["result"]["ran"] is True


# ---- task outlines waiting to be shared ----------------------------------------------------------

def test_waiting_outlines_are_listed_and_cleared_with_confirmation(client, audit_rows):
    from maverick.paths import data_dir
    outbox = data_dir("outbox")
    outbox.mkdir(parents=True, exist_ok=True)
    (outbox / "trj_1.json").write_text("{}")
    (outbox / "trj_2.json").write_text("{}")
    status = client.get(f"{LO}/donations").json()
    assert status["waiting"] == 2 and status["can_clear"] is True
    assert client.post(f"{LO}/donations/clear", json={}).status_code == 422
    assert client.post(f"{LO}/donations/clear", json={"confirm": True}).json() == {"cleared": 2}
    assert list(outbox.glob("*.json")) == []
    assert [r["action"] for r in audit_rows] == ["donations_clear"]
    assert client.post(f"{LO}/donations/clear", json={"confirm": True}).json() == {"cleared": 0}


# ---- model planning, reward model, shorthand ---------------------------------------------------

def test_model_planning_reads_and_scores_through_the_kernel(client):
    from maverick.training.environments import list_environment_ids, load_environment
    status = client.get(f"{TO}/model-improvement").json()
    assert status["task_sets"] and status["choices"]["roles"]
    role = status["choices"]["roles"][0]["value"]
    models = client.get(f"{TO}/model-improvement/models", params={
        "role": role, "memory_gib": 32, "context_tokens": 16384, "concurrency": 1}).json()
    assert models["planning_only"] is True and "fits" in models["models"][0]
    assert client.get(f"{TO}/model-improvement/models", params={"role": role, "memory_gib": 33}).status_code == 422
    env_id = list_environment_ids()[0]
    pack = load_environment(env_id)
    case = pack.split("holdout")[0]
    upload = json.dumps({case.case_id: "not the answer"}).encode()
    assert client.post(f"{TO}/model-improvement/score?task_set=nope", content=upload).status_code == 422
    dup = b'{"a": 1, "a": 2}'
    assert client.post(f"{TO}/model-improvement/score?task_set={env_id}", content=dup).status_code == 422
    done = _wait(client, client.post(f"{TO}/model-improvement/score?task_set={env_id}", content=upload))
    assert done["state"] == "done", done
    assert done["result"]["questions"] >= 1 and done["result"]["unanswered"] >= 0


def _outlines() -> bytes:
    rows = []
    for i, reward in enumerate((1.0, 0.0, 0.9, 0.1)):
        rows.append({"id": f"r{i}", "task_family": "fam", "outcome": "success" if reward > 0.5 else "failure",
                     "terminal_reward": reward,
                     "messages": [{"role": "assistant", "type": "tool_call", "name": "t", "error": i % 2 == 1}] * (i + 1),
                     "rewards": []})
    return "\n".join(json.dumps(r) for r in rows).encode()


def test_reward_model_trains_keeps_scores_and_downloads(client, audit_rows):
    empty = _wait(client, client.post(f"{TO}/reward-models/train?source=outbox", json={}))
    assert empty["result"] == {"trained": False, "why": "There are no task outlines to learn from yet."}
    done = _wait(client, client.post(f"{TO}/reward-models/train?source=file&epochs=100", content=_outlines()))
    assert done["state"] == "done" and done["result"]["trained"] is True, done
    name = done["result"]["name"]
    listed = client.get(f"{TO}/reward-models").json()["models"]
    assert listed[0]["name"] == name
    scored = _wait(client, client.post(f"{TO}/reward-models/{name}/score?source=file", content=_outlines()))
    assert scored["result"]["scored"] == 4
    assert client.post(f"{TO}/reward-models/rm-19990101-000000/score?source=file",
                       content=_outlines()).status_code == 404
    down = client.get(f"{TO}/reward-models/{name}/download")
    assert down.status_code == 200 and json.loads(down.text)["type"] == "bradley_terry_linear"
    assert client.post(f"{TO}/reward-models/train?epochs=7", json={}).status_code == 422
    assert [r["action"] for r in audit_rows] == ["reward_model_train", "reward_model_train", "reward_model_download"]


def test_shorthand_learns_and_measures_from_recorded_messages(client, monkeypatch, audit_rows):
    from maverick import codec_probe
    from maverick_dashboard import training_ops_api
    msgs = ["please check the quarterly totals before sending"] * 6 + ["the quarterly totals look fine"] * 4
    monkeypatch.setattr(training_ops_api, "_messages", lambda how_many: msgs)
    monkeypatch.setattr(codec_probe, "resolve_counter", lambda **kw: (lambda text: max(1, len(str(text)) // 4)))
    view = client.get(f"{TO}/codec").json()
    assert view["exact_count_available"] is False
    learned = _wait(client, client.post(f"{TO}/codec/shorthand/learn", json={"how_many": 500}))
    assert learned["result"]["messages"] == 10
    measured = _wait(client, client.post(f"{TO}/codec/measure", json={"how_many": 500}))
    assert measured["result"]["measured"] is True and "tokens_saved_pct" in measured["result"]
    tokens = _wait(client, client.post(f"{TO}/codec/token-codes/learn", json={"how_many": 500}))
    assert tokens["state"] == "done"
    exact = client.post(f"{TO}/codec/measure", json={"how_many": 500, "exact": True})
    assert exact.status_code == 409 and "free estimate" in exact.json()["detail"]
    assert client.post(f"{TO}/codec/measure", json={"how_many": 17}).status_code == 422
    assert [r["action"] for r in audit_rows] == ["codebook_learn", "codec_learn"]


# ---- pages ------------------------------------------------------------------------------------

def test_learning_page_has_a_control_next_to_each_system(client):
    page = client.get("/learning").text
    assert 'id="lo-root"' in page and 'data-admin="1"' in page
    for control in ("lo-fw-run", "lo-fa-preview", "lo-fa-adopt", "lo-sm-run", "lo-mi-find", "lo-mi-score",
                    "lo-rm-train", "lo-rm-score", "lo-cd-learn", "lo-cd-tokens", "lo-cd-measure", "lo-jobs"):
        assert f'id="{control}"' in page, control
    assert "/static/lightwork-learning-ops.js" in page and "/static/lightwork-ops-jobs.js" in page
    visible = _visible(page, 'id="lo-root"').split("Run learning now", 1)[0]
    assert "Improvement flywheel" in visible and "Learn how to rank work" in visible
    assert not _BANNED.search(visible), _BANNED.search(visible)


def test_learning_page_stays_closed_to_non_admins(client, monkeypatch):
    _as(monkeypatch, "operator")
    assert client.get("/learning").status_code == 403


def test_learned_page_has_the_extra_self_coaching_tools(client, monkeypatch):
    page = client.get("/learned").text
    for control in ("lpo-clash-run", "lt-review", "lpo-harvest", "lpo-export", "lpo-import-check",
                    "lp-trial", "lp-instructions", "lqc-load"):
        assert f'id="{control}"' in page, control
    visible = _visible(page, 'id="lpo-root"')
    assert "Check lessons for clashes by meaning" in visible
    assert not _BANNED.search(visible), _BANNED.search(visible)
    _as(monkeypatch, "viewer")
    assert 'id="lpo-root"' not in client.get("/learned").text


def test_page_scripts_are_served_and_use_the_shared_confirm(client):
    for name in ("lightwork-ops-jobs.js", "lightwork-learning-ops.js", "lightwork-learned-ops.js",
                 "lightwork-workforce-ops.js"):
        r = client.get(f"/static/{name}")
        assert r.status_code == 200 and "javascript" in r.headers["content-type"], name
        assert "window.confirm(" not in r.text and "alert(" not in r.text
        assert "String(err" not in r.text and "'HTTP '" not in r.text


# ---- every "go here" in a message is a real place, and saving there works ---------

def _save_setting(client, changes):
    return client.post("/api/v1/settings/catalog", json={"changes": changes, "confirm": True, "expected_revision": client.get("/api/v1/settings/catalog").json()["revision"]})


def _data_file(name: str) -> str:
    from maverick.paths import maverick_home
    folder = maverick_home() / "learning"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    return str(folder / name)


def test_every_destination_named_in_a_message_exists(client):
    import html

    from maverick_dashboard import learning_ops_api as ops
    from maverick_dashboard import settings_catalog as catalog
    page = html.unescape(every_group(client))
    for setting_id in ("self_harness.eval_corpus", "self_harness.holdout_ledger", "harness_refine.enable",
                       "self_modify.editable_paths", "self_modify.eval_tests"):
        s = catalog.BY_ID[setting_id]
        place = ops.setting_place(setting_id)
        assert place.startswith("All settings, " + s.group) and f"“{s.label}”" in place
        assert s.label in page and s.group in page and (not s.subgroup or s.subgroup in page), setting_id
    switches = {sw["label"] for sw in client.get("/api/v1/features/switches").json()["switches"]}
    for section in ("self_harness", "fleet_memory"):
        label = ops.switch_place(section).split("”")[0].lstrip("“")
        assert label in switches, section
    learning = html.unescape(client.get("/learning").text)
    assert "Turn each part of learning on or off" in learning and "Learning systems" in learning
    for key in ("self_improvement", "data_engine", "factory_learning"):
        label = ops.part_place(key).split("”")[0].lstrip("“")
        assert label in learning, key
    assert ops._DGM_SECTION in (Path(__file__).parents[1] / "maverick_dashboard/templates/learning.html").read_text(encoding="utf-8")


def test_test_case_location_is_checked_on_the_server_and_then_used(client):
    from maverick.paths import maverick_home
    plan = client.get(f"{LO}/self-harness/plan").json()
    assert plan["test_cases_set_up"] is False and "“Test cases for improvements”" in plan["places"]["test_cases"]
    outside = _save_setting(client, [{"id": "self_harness.eval_corpus", "value": str(maverick_home().parent / "outside-test-cases.json")}])
    assert outside.status_code == 400 and "data folder" in outside.json()["message"]
    no_folder = _save_setting(client, [{"id": "self_harness.eval_corpus",
                                        "value": str(maverick_home() / "missing" / "c.json")}])
    assert no_folder.status_code == 400 and "folder for that file was not found" in no_folder.json()["message"]
    target = _data_file("test-cases.json")
    check = client.post("/api/v1/settings/catalog/test", json={"id": "self_harness.eval_corpus", "value": target})
    assert check.json() == {"ok": True, "message": (
        "The folder was found. Lightwork will create this file there when it first needs it.")}
    assert _save_setting(client, [{"id": "self_harness.eval_corpus", "value": target}]).status_code == 200
    assert client.get(f"{LO}/self-harness/plan").json()["test_cases_set_up"] is True
    upload = json.dumps({"claude-x": [{"goal": "new", "expected": "y"}]}).encode()
    token = client.post(f"{LO}/self-harness/test-cases/import/preview", content=upload).json()["token"]
    added = client.post(f"{LO}/self-harness/test-cases/import?confirm=true", content=upload,
                        headers={"X-Lightwork-Import-Review": token}).json()
    assert added["confirmed"] is True and added["cases"] == 1
    assert json.loads(Path(target).read_text())["claude-x"][0]["goal"] == "new"


def test_hold_out_location_saved_in_all_settings_is_where_the_record_is_set_up(client):
    refused = _hold_out(client)
    assert refused.status_code == 409 and "Choose the managed location first" in refused.json()["detail"]
    target = _data_file("hold-out.db")
    assert _save_setting(client, [{"id": "self_harness.holdout_ledger", "value": target}]).status_code == 200
    made = _hold_out(client)
    assert made.status_code == 200 and made.json()["confirmed"] is True and Path(target).is_file()
    again = _save_setting(client, [{"id": "self_harness.holdout_ledger", "value": target}])
    assert again.status_code == 200  # an existing record is a valid location too
    verified = client.get("/api/v1/learning-loop/holdout").json()
    assert verified["configured"] is True and verified["verified"] is True


def test_self_modify_files_and_tests_saved_in_all_settings_clear_its_blockers(client):
    from maverick import config, self_modify
    from maverick import self_modify_runner as runner
    before = client.get(f"{LO}/self-modify").json()["blockers"]
    assert any("All settings, Memory & learning, Research experiments, “Files code experiments may change”"
               in b for b in before), before
    assert any("“Tests each code experiment must pass”" in b for b in before), before
    tests = ["tests/test_a.py::test_one", "tests/test_b.py::test_two"]
    r = _save_setting(client, [{"id": "self_modify.editable_paths", "value": ["packages/example/*.py"]},
                               {"id": "self_modify.eval_tests", "value": tests}])
    assert r.status_code == 200, r.text
    config.reset_config_cache()
    assert runner._self_modify_config()["eval_tests"] == tests
    assert self_modify.default_surface().editable_globs == ("packages/example/*.py",)
    codes = {b["code"] for b in self_modify.production_status()["blockers"]}
    assert "editable_surface_missing" not in codes and "challenge_corpus_missing" not in codes
    after = client.get(f"{LO}/self-modify").json()["blockers"]
    assert not any("Files code experiments" in b or "Tests each code experiment" in b for b in after)


def test_fleet_memory_is_switched_on_where_the_message_says(client):
    from maverick_dashboard.learning_ops_api import switch_place
    body = {"vendor": "custom", "name": "billing-bot"}
    off = client.post("/api/v1/workforce-ops/outside-agents", json=body)
    assert off.status_code == 409
    assert off.json()["detail"] == f"Turn on {switch_place('fleet_memory')} first."
    assert "“Fleet memory” under Learning systems on the Learning page" in off.json()["detail"]
    on = client.post("/api/v1/features/switches", json={"section": "fleet_memory", "enabled": True})
    assert on.status_code == 200, on.text
    assert client.post("/api/v1/workforce-ops/outside-agents", json=body).json()["added"] is True
