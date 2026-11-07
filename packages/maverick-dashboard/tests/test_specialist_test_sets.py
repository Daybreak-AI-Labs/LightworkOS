"""Customer-owned answer checks use current specialist instructions and real run receipts."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

API = "/api/v1/workforce-ops/test-suite"


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
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    config.reset_config_cache()
    dash_app._world_cache.clear()
    learning_jobs.clear_for_tests()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), tmp_path
    learning_jobs.clear_for_tests()
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: rows.append(payload) or True)
    return rows


def _case(specialist="finance_ap", **extra):
    row = {"specialist": specialist,
           "task": "Two invoices have the same purchase order. What would you do?",
           "includes": ["duplicate"], "excludes": ["payment sent"],
           "refusal": False, "citation": False}
    row.update(extra)
    return row


def _wait(client, response):
    assert response.status_code == 200, response.text
    job = response.json()["job"]
    deadline = time.time() + 15
    while job["state"] in {"admitted", "running", "stopping"}:  # an admitted job has not started yet
        assert time.time() < deadline, job
        time.sleep(.05)
        job = client.get("/api/v1/learning-ops/jobs/" + job["id"]).json()["job"]
    return job


def _revisions(app, specialist="finance_ap"):
    rows = app.get(API + "/customer", params={"specialist": specialist}).json()["cases"]
    return {row["id"]: row["revision"] for row in rows}


def test_cases_are_saved_scoped_editable_and_revision_guarded(client, monkeypatch, audit_rows):
    app, _tmp = client
    from maverick_dashboard import auth, rbac

    who = "user:worker"
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)
    rbac.set_role(who, "operator")
    assert app.post(API + "/customer", json=_case()).status_code == 403
    rbac.set_role(who, "admin")
    assert app.post(API + "/customer", json=_case(includes=[], excludes=[])).status_code == 422
    created = app.post(API + "/customer", json=_case())
    assert created.status_code == 200, created.text
    row = created.json()["case"]
    listed = app.get(API + "/customer", params={"specialist": "finance_ap"}).json()
    assert listed["cases"] == [row] and listed["live_enabled"] is False
    assert app.get(API + "/customer", params={"specialist": "not_real"}).status_code == 404
    update = _case(identity=row["id"], expected_revision=1)
    update["task"] = "Two invoices are identical. Should either be paid?"
    changed = app.post(API + "/customer", json=update).json()["case"]
    assert changed["revision"] == 2
    assert app.post(API + "/customer", json=update).status_code == 409
    assert app.post(API + "/customer/remove", json={"specialist": "finance_ap", "identity": row["id"],
                                                    "expected_revision": 1}).status_code == 409
    removed = app.post(API + "/customer/remove", json={"specialist": "finance_ap", "identity": row["id"],
                                                      "expected_revision": 2})
    assert removed.json() == {"removed": True}
    assert app.get(API + "/customer", params={"specialist": "finance_ap"}).json()["cases"] == []
    assert [x["verb"] for x in audit_rows if x.get("verb", "").startswith("specialist_test_")] == [
        "specialist_test_save", "specialist_test_save", "specialist_test_save",
        "specialist_test_remove", "specialist_test_remove"]


def test_live_batch_uses_current_instructions_no_tools_and_durable_results(client, monkeypatch, audit_rows):
    app, tmp = client
    from maverick import config, llm

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n", encoding="utf-8")
    config.reset_config_cache()
    one = app.post(API + "/customer", json=_case()).json()["case"]
    two = app.post(API + "/customer", json=_case(task="Another invoice could be duplicate. What next?"))
    assert two.status_code == 200
    calls = []

    def answer(self, system, messages, **kwargs):
        calls.append((system, messages, kwargs))
        assert kwargs["tools"] is None and kwargs["max_physical_attempts"] == 1
        assert kwargs["_no_failover"] is True and kwargs["max_tokens"] == 128
        assert kwargs["budget"].max_dollars <= .25
        kwargs["dispatch_guard"]()
        return llm.LLMResponse(text="This is a duplicate; no payment sent.", thinking=None,
                               tool_calls=[], stop_reason="end_turn")

    monkeypatch.setattr(llm.LLM, "complete", answer)
    request_id = "d" * 32
    job = _wait(app, app.post(API + "/customer/run", json={"specialist": "finance_ap",
                                                        "operation_id": request_id,
                                                        "case_revisions": _revisions(app)}))
    assert job["state"] == "done", job
    run = job["result"]["run"]
    assert len(calls) == 2 and all("No tools, files" in system for system, _, _ in calls)
    assert run["total"] == 2 and run["passed"] == 0
    assert all(r["checks"]["includes"] == 1 and r["checks"]["excludes"] == 0 for r in run["results"])
    assert run["case_revisions"][0] == {"id": one["id"], "revision": 1}
    history = app.get(API + "/customer", params={"specialist": "finance_ap"}).json()["runs"]
    assert history[0]["id"] == run["id"] and history[0]["results"] == run["results"]
    original = app.get(API + "/customer/run/" + request_id)
    assert original.status_code == 200 and original.json()["run"]["id"] == run["id"]
    replay = app.post(API + "/customer/run", json={"specialist": "finance_ap",
                                                 "operation_id": request_id,
                                                 "case_revisions": _revisions(app)})
    assert replay.json()["replayed"] is True and len(calls) == 2
    assert audit_rows[-1]["verb"] == "specialist_test_run"
    assert "task" not in audit_rows[-1]


def test_failed_provider_call_is_unknown_and_never_replayed(client, monkeypatch):
    app, tmp = client
    from maverick import config, llm

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n", encoding="utf-8")
    config.reset_config_cache()
    app.post(API + "/customer", json=_case())
    attempts = []

    def fail(self, *args, **kwargs):
        attempts.append(True)
        raise TimeoutError("provider response uncertain")

    monkeypatch.setattr(llm.LLM, "complete", fail)
    job = _wait(app, app.post(API + "/customer/run", json={"specialist": "finance_ap",
                                                        "operation_id": "e" * 32,
                                                        "case_revisions": _revisions(app)}))
    run = job["result"]["run"]
    assert attempts == [True]
    assert run["state"] == "unknown" and run["passed"] == 0
    assert "may have been billed" in run["message"]
    readback = app.get(API + "/customer/run/" + "e" * 32).json()["run"]
    assert readback["state"] == "unknown"
    replay = app.post(API + "/customer/run", json={"specialist": "finance_ap", "operation_id": "e" * 32,
                                                 "case_revisions": _revisions(app)})
    assert replay.json()["replayed"] and attempts == [True]


def test_large_saved_set_runs_only_the_selected_cases(client, monkeypatch):
    app, tmp = client
    from maverick import config, llm

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n", encoding="utf-8")
    config.reset_config_cache()
    ids = []
    for n in range(6):
        row = app.post(API + "/customer", json=_case(task=f"Invoice example {n}: what should be checked first?"))
        assert row.status_code == 200, row.text
        ids.append(row.json()["case"]["id"])
    assert app.post(API + "/customer/run", json={"specialist": "finance_ap",
                                                    "operation_id": "f" * 32,
                                                    "case_revisions": dict(list(_revisions(app).items())[:5])}).status_code == 409
    calls = []

    def answer(self, system, messages, **kwargs):
        calls.append(messages[0]["content"])
        return llm.LLMResponse(text="Check for duplicate before approval.", thinking=None,
                               tool_calls=[], stop_reason="end_turn")

    monkeypatch.setattr(llm.LLM, "complete", answer)
    stale = app.post(API + "/customer/run", json={"specialist": "finance_ap",
                                                   "operation_id": "a" * 32, "case_ids": ids[1:3],
                                                   "case_revisions": {ids[1]: 1, ids[2]: 2}})
    assert stale.status_code == 409 and calls == []
    job = _wait(app, app.post(API + "/customer/run", json={"specialist": "finance_ap",
                                                        "operation_id": "a" * 32, "case_ids": ids[1:3],
                                                        "case_revisions": {ids[1]: 1, ids[2]: 1}}))
    assert job["result"]["run"]["total"] == 2
    assert calls == ["Invoice example 1: what should be checked first?",
                     "Invoice example 2: what should be checked first?"]


def test_copilot_reads_creates_and_starts_only_one_reviewed_run(client, monkeypatch, audit_rows):
    _app, tmp = client
    from maverick import config
    from maverick_dashboard import auth
    from maverick_dashboard import product_operations as ops
    from maverick_dashboard import product_operations_specialist_tests as actions
    from maverick_dashboard import specialist_test_sets as saved
    from starlette.requests import Request

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n", encoding="utf-8")
    config.reset_config_cache()
    # Load the whole Copilot registry before stubbing the gate. adapters()
    # imports every adapter module, and a module first imported while the stub
    # is in place keeps it through `from .auth import require_permission` after
    # monkeypatch restores auth (viewpoints_requests then let a viewer operate).
    assert {"specialists.tests.read", "specialists.tests.create", "specialists.tests.run"} <= set(ops.adapters())
    monkeypatch.setattr(actions, "context_for", lambda request: "current-workspace")
    monkeypatch.setattr(auth, "require_permission", lambda request, permission: None)
    request = Request({"type": "http", "method": "POST", "path": "/workforce",
                       "headers": [(b"host", b"127.0.0.1")]})
    args = {"specialist": "finance_ap", "task": "Two invoices have the same amount. What should happen?",
            "must_mention": "duplicate", "must_never_say": "payment sent",
            "must_refuse": "no", "must_cite": "no"}
    review = actions.create_prepare(request, {}, args)
    assert "Nothing is sent" in review.summary
    created = actions.create_execute(request, {}, args, review.native, "b" * 32)
    replay = actions.create_recover(request, {}, args, review.native, "b" * 32)
    assert created.status == "confirmed" and replay.status == "replayed"
    assert len(saved.cases_for("finance_ap")) == 1
    read = actions.read_prepare(request, {}, {"specialist": "finance_ap"})
    assert len(read.native["cases"]) == 1 and "duplicate" in read.native["cases"][0]["must_mention"]
    run_args = {"specialist": "finance_ap", "checks": [created.details["test"]["id"]]}
    run_review = actions.run_prepare(request, {}, run_args)
    calls = []

    def started(_request, specialist, *, operation_id, case_ids, case_revisions):
        calls.append((specialist, operation_id))
        assert case_ids == run_args["checks"] and case_revisions == {case_ids[0]: 1}
        saved.begin_run(specialist, run_review.native["model"], run_review.native["instructions"],
                        saved.snapshot(specialist, case_ids), "user:reviewer", identity=operation_id)
        return {"job": {"id": "job-1", "state": "running"}}

    monkeypatch.setattr(actions.native, "_start_customer_test_job", started)
    first = actions.run_execute(request, {}, run_args, run_review.native, "c" * 32)
    found = actions.run_recover(request, {}, run_args, run_review.native, "c" * 32)
    assert first.status == "queued" and found.status == "replayed"
    assert calls == [("finance_ap", "c" * 32)]
    assert [row["verb"] for row in audit_rows if row.get("verb") == "specialist_test_save"] == ["specialist_test_save"]


def test_copilot_named_subset_runs_native_bounded_worker_and_recovers_exact_receipt(client, monkeypatch, audit_rows):
    app, tmp = client
    from cryptography.fernet import Fernet
    from maverick import config, llm
    from maverick_dashboard import auth, rbac
    from maverick_dashboard import product_operations as ops
    from maverick_dashboard import product_operations_specialist_tests as actions
    from maverick_dashboard import specialist_test_sets as saved

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n"
                                    "[features]\ncopilot_operations = true\n"
                                    '[copilot]\noperation_families = ["models"]\n', encoding="utf-8")
    config.reset_config_cache()
    actor = {"name": "user:reviewer"}
    monkeypatch.setattr(auth, "caller_principal", lambda request: actor["name"])
    rbac.set_role(actor["name"], "admin")
    monkeypatch.setattr(ops, "adapters", lambda: {entry.id: entry for entry in actions.entries()})
    codec = Fernet(Fernet.generate_key())
    monkeypatch.setattr(ops.crypto_at_rest, "seal_to_str", lambda value: "sealed:" + codec.encrypt(value.encode()).decode())
    monkeypatch.setattr(ops.crypto_at_rest, "is_sealed_str", lambda value: value.startswith("sealed:"))
    monkeypatch.setattr(ops.crypto_at_rest, "unseal_from_str", lambda value: codec.decrypt(value[7:].encode()).decode())
    rows = [saved.save_case("finance_ap", {"task": f"Invoice question {index}: what should we check?",
            "includes": ["duplicate"], "excludes": [], "refusal": False, "citation": False}) for index in range(20)]
    calls = []

    def answer(self, system, messages, **kwargs):
        calls.append(messages[0]["content"])
        assert kwargs["budget"].max_dollars <= .25 and kwargs["tools"] is None
        assert kwargs["max_physical_attempts"] == 1 and kwargs["_no_failover"] is True
        kwargs["dispatch_guard"]()
        return llm.LLMResponse(text="Check for duplicate before approval.", thinking=None,
                               tool_calls=[], stop_reason="end_turn")

    monkeypatch.setattr(llm.LLM, "complete", answer)
    base = "/api/v1/copilot/product-operations"
    selected = [rows[index]["id"] for index in (3, 7, 12)]

    def prepare(checks):
        catalog = app.post(base + "/catalog", json={"page": "/workforce"}).json()
        item = next(row for row in catalog["operations"] if row["id"] == "specialists.tests.run")
        assert item["available"], item
        assert item["fields"][0]["kind"] == "select"
        questions = item["fields"][1]
        assert questions["kind"] == "multiselect" and questions["depends_on"] == "specialist"
        assert [choice["label"] for choice in questions["choices_by"]["finance_ap"]] == [row["task"] for row in rows]
        assert questions["value"] == []
        return app.post(base + "/prepare", json={"page": "/workforce", "operation": item["id"],
            "context": catalog["context"], "revision": item["revision"],
            "arguments": {"specialist": "finance_ap", "checks": checks}})

    assert prepare([row["id"] for row in rows[:6]]).status_code == 422
    assert prepare([selected[0], selected[0]]).status_code == 409
    assert prepare(["e" * 32]).status_code == 409
    review = prepare(selected)
    assert review.status_code == 200, review.text
    assert review.json()["changes"][1]["after"] == "; ".join(rows[index]["task"] for index in (3, 7, 12))
    payload = {"token": review.json()["token"], "confirmed": True}
    assert calls == []
    assert app.post(base + "/execute", json={**payload, "confirmed": False}).status_code == 400
    # A different administrator cannot spend from another actor's sealed review.
    actor["name"] = "user:other-reviewer"
    rbac.set_role(actor["name"], "admin")
    assert app.post(base + "/execute", json=payload).status_code == 409 and calls == []
    actor["name"] = "user:reviewer"
    # Exact selected versions are rechecked before the native spending admission.
    rows[7] = saved.save_case("finance_ap", {key: rows[7][key] for key in (
        "task", "includes", "excludes", "refusal", "citation")}, identity=rows[7]["id"], expected_revision=1)
    assert app.post(base + "/execute", json=payload).status_code == 409 and calls == []
    review = prepare(selected)
    assert review.status_code == 200, review.text
    payload["token"] = review.json()["token"]
    started = app.post(base + "/execute", json=payload)
    assert started.status_code == 200, started.text
    assert started.json()["status"] == "queued"
    operation = started.json()["operation_id"]
    deadline = time.time() + 15
    while saved.run_by_id(operation)["state"] in {"prepared", "running"}:
        assert time.time() < deadline
        time.sleep(.05)
    receipt = saved.run_by_id(operation)
    assert receipt["state"] == "done" and receipt["total"] == 3 and receipt["actor"] == "user:reviewer"
    assert receipt["case_revisions"] == [{"id": rows[index]["id"], "revision": rows[index]["revision"]}
                                         for index in (3, 7, 12)]
    assert calls == [rows[index]["task"] for index in (3, 7, 12)]
    # Changing current checks never turns recovery into another paid request.
    saved.delete_case("finance_ap", rows[3]["id"], 1)
    recovered = app.post(base + "/execute", json=payload)
    assert recovered.status_code == 200 and recovered.json()["status"] == "replayed"
    assert len(calls) == 3 and recovered.json()["details"]["answers_checked"] == 3
    assert recovered.json()["details"]["questions"] == "; ".join(rows[index]["task"] for index in (3, 7, 12))
    assert "case_revisions" not in str(recovered.json()["details"]) and operation not in str(recovered.json()["details"])


@pytest.mark.parametrize("uncertain", [False, True])
def test_instruction_comparison_freezes_both_versions_recovers_and_marks_stale(client, monkeypatch, audit_rows, uncertain):
    app, tmp = client
    from maverick import config, llm
    from maverick_dashboard import auth, rbac
    from maverick_dashboard import specialist_test_sets as saved

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n", encoding="utf-8")
    config.reset_config_cache()
    actor = {"name":"user:reviewer"}
    monkeypatch.setattr(auth, "caller_principal", lambda request:actor["name"])
    rbac.set_role(actor["name"], "admin")
    row = app.post(API + "/customer", json=_case()).json()["case"]
    current = app.get(API + "/customer", params={"specialist":"finance_ap"}).json()
    calls = []

    def answer(self, system, messages, **kwargs):
        kwargs["dispatch_guard"]()
        assert kwargs["tools"] is None and kwargs["max_physical_attempts"] == 1 and kwargs["_no_failover"] is True
        assert kwargs["max_tokens"] == 64 and kwargs["budget"].max_dollars <= .25
        calls.append(system)
        kwargs["budget"].dollars += .001  # explicitly synthetic provider charge
        kwargs["budget"].check()
        if uncertain and len(calls) == 2:
            raise TimeoutError("Synthetic provider outcome unknown")
        return llm.LLMResponse(text="Check the duplicate before approval.", thinking=None, tool_calls=[], stop_reason="end_turn")

    monkeypatch.setattr(llm.LLM, "complete", answer)
    body = {"specialist":"finance_ap", "operation_id":"1"*32, "case_ids":[row["id"]],
            "case_revisions":{row["id"]:1}, "proposed_instructions":"Proposed: require duplicate review before invoice approval.",
            "baseline_revision":current["baseline_revision"], "expected_context":current["context"]}
    assert app.post(API + "/customer/compare", json={**body, "baseline_revision":"0"*64}).status_code == 409
    assert app.post(API + "/customer/compare", json={**body, "expected_context":"0"*64}).status_code == 409
    assert calls == []
    job = _wait(app, app.post(API + "/customer/compare", json=body))
    result = job["result"]["run"]
    assert result["state"] == ("unknown" if uncertain else "done") and len(calls) == 2
    assert result["comparison"]["current_instructions"] == current["current_instructions"]
    assert result["comparison"]["proposed_instructions"] == body["proposed_instructions"]
    assert result["instruction_hash"] == body["baseline_revision"]
    assert result["spent_dollars"] == .002
    assert [answer["variant"] for answer in result["results"]] == (["current"] if uncertain else ["current", "proposed"])
    assert all(answer["spent_dollars"] == .001 for answer in result["results"])
    assert app.post(API + "/customer/compare", json=body).json()["replayed"] is True and len(calls) == 2
    assert app.post(API + "/customer/compare", json={**body, "proposed_instructions":"A different proposal should not replay."}).status_code == 409
    saved.save_case("finance_ap", {**_case(), "task":"Updated invoice question for this saved check?"}, identity=row["id"], expected_revision=1)
    historical = app.get(API + "/customer/run/" + body["operation_id"]).json()["run"]
    assert historical["baseline_current"] is True and historical["questions_current"] is False
    assert app.post(API + "/customer/compare", json=body).json()["replayed"] is True and len(calls) == 2
    assert app.post(API + "/customer/compare", json={**body, "operation_id":"2"*32}).status_code == 409
    assert app.get(API + "/customer", params={"specialist":"finance_ap"}).json()["baseline_revision"] == body["baseline_revision"]
    actor["name"] = "user:other-reviewer"
    rbac.set_role(actor["name"], "admin")
    assert app.get(API + "/customer/run/" + body["operation_id"]).status_code == 403
    assert app.post(API + "/customer/compare", json=body).status_code == 409 and len(calls) == 2


def test_saved_checks_stop_at_twenty_by_default_and_a_raised_limit_admits_more(client):
    app, tmp = client
    from maverick import config

    for index in range(20):
        row = app.post(API + "/customer", json=_case(task=f"Invoice number {index} might be a duplicate?"))
        assert row.status_code == 200, row.text
    full = app.post(API + "/customer", json=_case(task="One more invoice that might be a duplicate?"))
    assert full.status_code == 409 and "list is full" in full.json()["detail"]
    assert app.get(API + "/customer", params={"specialist": "finance_ap"}).json()["max_checks"] == 20

    (tmp / "config.toml").write_text("[agent_tests]\nmax_cases_per_specialist = 25\n", encoding="utf-8")
    config.reset_config_cache()
    for index in range(20, 25):
        row = app.post(API + "/customer", json=_case(task=f"Invoice number {index} might be a duplicate?"))
        assert row.status_code == 200, row.text
    assert app.post(API + "/customer", json=_case(task="A twenty-sixth invoice question?")).status_code == 409
    listed = app.get(API + "/customer", params={"specialist": "finance_ap"}).json()
    assert len(listed["cases"]) == 25 and listed["max_checks"] == 25


def test_one_run_checks_no_more_than_the_limit_and_keeps_stored_checks_readable(client):
    app, tmp = client
    from maverick import config
    from maverick_dashboard import specialist_test_sets as saved

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n[agent_tests]\nmax_cases_per_specialist = 21\n",
                                    encoding="utf-8")
    config.reset_config_cache()
    for index in range(21):
        row = app.post(API + "/customer", json=_case(task=f"Invoice number {index} might be a duplicate?"))
        assert row.status_code == 200, row.text
    revisions = _revisions(app)
    # Back at the default of 20, the twenty-one stored checks are still listed and can be run in parts.
    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n", encoding="utf-8")
    config.reset_config_cache()
    assert len(app.get(API + "/customer", params={"specialist": "finance_ap"}).json()["cases"]) == 21
    refused = app.post(API + "/customer/run", json={"specialist": "finance_ap", "operation_id": "a" * 32,
                                                    "case_revisions": revisions})
    assert refused.status_code == 409 and "at most 20" in refused.json()["detail"]
    ids = list(revisions)
    assert len(saved.snapshot("finance_ap", ids[:3])) == 3
    with pytest.raises(ValueError, match="at most 20"):
        saved.snapshot("finance_ap")


def test_the_whole_store_limit_grows_with_the_per_specialist_limit(tmp_path, monkeypatch):
    from maverick import config
    from maverick_dashboard import specialist_test_sets as saved

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    try:
        assert saved._max_all_cases() == 1000
        (tmp_path / "config.toml").write_text("[agent_tests]\nmax_cases_per_specialist = 200\n", encoding="utf-8")
        config.reset_config_cache()
        assert saved._max_all_cases() == 10000
    finally:
        config.reset_config_cache()


def test_a_must_not_contain_check_fails_an_answer_that_says_the_forbidden_phrase():
    from maverick_dashboard import specialist_test_sets as saved

    case = {"id": "c" * 32, "specialist": "finance_ap", "task": "Two invoices have the same amount?",
            "includes": ["duplicate"], "excludes": ["payment sent"], "refusal": False, "citation": False}
    said = saved.grade(case, "This is a duplicate, so the payment sent today.")
    held = saved.grade(case, "This is a duplicate; hold it for review.")
    assert said["passed"] is False and said["checks"]["excludes"] == 0.0
    assert held["passed"] is True and held["checks"]["excludes"] == 1.0
