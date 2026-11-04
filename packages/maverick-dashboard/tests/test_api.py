"""REST API endpoint tests."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

# Same-origin default: mutating /api/v1 requests in no-token (loopback) mode
# must carry a matching Origin, the CSRF contract the dashboard enforces
# centrally (see app.py bearer_auth). These functional tests simulate a
# legitimate same-origin caller; the missing/forged-Origin cases are covered
# by test_security.py. GET/HEAD/OPTIONS skip the check, so this is a no-op for
# read tests.
client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_world(tmp_path, monkeypatch):
    import maverick.runner as runner_mod
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    # Route-shape changes must never turn a stale admission mock into paid work.
    # Individual dispatch contract tests replace this safe default explicitly.
    monkeypatch.setattr(runner_mod, "run_goal_in_thread", lambda *a, **kw: None)
    yield


class TestGoals:
    def test_openapi_documents_idempotency_and_pagination_headers(self):
        operations = app.openapi()["paths"]["/api/v1/goals"]
        create_headers = operations["post"]["responses"]["201"]["headers"]
        assert set(create_headers) == {"Location", "Idempotency-Replayed"}
        list_headers = operations["get"]["responses"]["200"]["headers"]
        assert set(list_headers) == {
            "Pagination-Limit",
            "Pagination-Offset",
            "Pagination-Has-More",
            "Pagination-Next-Offset",
            "Pagination-Next-Before-Id",
        }

    def test_create_requires_api_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        resp = client.post("/api/v1/goals", json={"title": "hi"})
        assert resp.status_code == 400
        assert "ANTHROPIC_API_KEY" in resp.json()["detail"]

    def test_create_returns_pending(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        # Patch the shared runner so we don't actually call Anthropic.
        # The new signature is (goal_id, max_dollars, max_wall_seconds, max_depth).
        import maverick.runner as runner_mod
        called = []

        def fake_run(
            goal_id, max_dollars=2.0, max_wall_seconds=1800.0, max_depth=3, **_kwargs,
        ):
            # The endpoint also threads channel/user_id/capability/
            # concurrency_principal/allowed_suites; this double only asserts
            # the budget knobs, so swallow the rest instead of going stale on
            # every new dispatch kwarg.
            called.append((goal_id, max_dollars, max_wall_seconds, max_depth))
        monkeypatch.setattr(runner_mod, "run_goal_in_thread", fake_run)
        resp = client.post("/api/v1/goals", json={
            "title": "test goal", "description": "x", "max_dollars": 1.0,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "pending"
        assert data["title"] == "test goal"
        assert resp.headers["location"] == f"/api/v1/goals/{data['id']}"
        assert resp.headers["idempotency-replayed"] == "false"
        assert len(called) == 1
        assert called[0][0] == data["id"]
        # Verify payload's max_dollars propagated.
        assert called[0][1] == 1.0

    def test_create_uses_installed_dispatcher_not_local_execution(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        import maverick.runner as runner_mod

        submitted = []

        class FakeDispatcher:
            def submit(self, goal_id, **kwargs):
                submitted.append((goal_id, kwargs))
                return "queued"

        monkeypatch.setattr(runner_mod, "_dispatcher", FakeDispatcher())
        monkeypatch.setattr(
            runner_mod,
            "run_goal_in_thread",
            lambda *a, **k: pytest.fail("dashboard bypassed installed dispatcher"),
        )

        resp = client.post("/api/v1/goals", json={"title": "dispatch me"})

        assert resp.status_code == 201
        assert submitted == [
            (
                resp.json()["id"],
                {
                    "max_dollars": 2.0,
                    "max_wall_seconds": 1800.0,
                    "max_depth": 3,
                    "channel": None,
                    "user_id": None,
                    "conversation_id": None,
                    "capability": None,
                    "concurrency_principal": None,
                    "allowed_suites": None,
                },
            )
        ]

    def test_create_preserves_explicit_empty_suite_snapshot(self, monkeypatch):
        """An explicit empty grant must not widen to unrestricted in dispatch."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        import maverick.runner as runner_mod
        from maverick_dashboard import api as api_mod

        submitted = []

        class FakeDispatcher:
            def submit(self, goal_id, **kwargs):
                submitted.append((goal_id, kwargs))
                return "queued"

        monkeypatch.setattr(api_mod, "caller_suites", lambda _request: frozenset())
        monkeypatch.setattr(runner_mod, "_dispatcher", FakeDispatcher())

        resp = client.post("/api/v1/goals", json={"title": "no-suite goal"})

        assert resp.status_code == 201
        assert submitted[0][1]["allowed_suites"] == frozenset()
        assert submitted[0][1]["allowed_suites"] is not None


    def test_idempotency_key_dedups_create(self, monkeypatch):
        # A retried POST carrying the same Idempotency-Key must return the
        # ORIGINAL goal and dispatch only one run (no double-create/double-bill).
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        import maverick.runner as runner_mod
        called = []
        monkeypatch.setattr(
            runner_mod, "run_goal_in_thread",
            lambda goal_id, *a, **k: called.append(goal_id),
        )
        headers = {"Idempotency-Key": "abc-123"}
        r1 = client.post("/api/v1/goals", json={"title": "idem goal"}, headers=headers)
        r2 = client.post("/api/v1/goals", json={"title": "idem goal"}, headers=headers)
        assert r1.status_code == 201 and r2.status_code == 201
        assert r1.json()["id"] == r2.json()["id"]   # same goal returned
        assert len(called) == 1                      # only one run dispatched
        assert r1.headers["idempotency-replayed"] == "false"
        assert r2.headers["idempotency-replayed"] == "true"
        assert r2.headers["location"] == f"/api/v1/goals/{r1.json()['id']}"

    def test_distinct_idempotency_keys_create_distinct_goals(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        import maverick.runner as runner_mod
        monkeypatch.setattr(runner_mod, "run_goal_in_thread", lambda *a, **k: None)
        r1 = client.post("/api/v1/goals", json={"title": "g"}, headers={"Idempotency-Key": "k1"})
        r2 = client.post("/api/v1/goals", json={"title": "g"}, headers={"Idempotency-Key": "k2"})
        assert r1.json()["id"] != r2.json()["id"]

    def test_legacy_idempotency_is_readable_but_cannot_authorize_new_dispatch(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        from maverick_dashboard import api as api_mod

        world = api_mod._world()
        winner_id = world.create_goal("winner", "")
        world.mark_message_processed("idempotency:api:goals", ":same-key", goal_id=winner_id)
        monkeypatch.setattr(api_mod, "_world", lambda: world)

        response = client.post(
            "/api/v1/goals",
            json={"title": "racing request"},
            headers={"Idempotency-Key": "same-key"},
        )

        assert response.status_code == 409
        recovered = client.get("/api/v1/goal-submissions/receipt", headers={"Idempotency-Key": "same-key"})
        assert recovered.status_code == 200
        assert recovered.json()["goal"]["id"] == winner_id
        assert recovered.json()["submission_state"] == "legacy_unverified"
        assert len(world.list_goals()) == 1

    def test_create_rejects_invalid_template_name(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        resp = client.post("/api/v1/goals", json={
            "title": "test goal",
            "template": "../escape_secret",
        })
        assert resp.status_code == 400
        assert "invalid template name" in resp.json()["detail"]

    def test_create_unknown_template_404_does_not_leak_path(self, monkeypatch):
        # A valid-named but non-existent template -> 404 that reflects the
        # caller's name, never the absolute on-disk template path.
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        resp = client.post("/api/v1/goals", json={
            "title": "t", "template": "no_such_template_xyz",
        })
        assert resp.status_code == 404
        detail = resp.json()["detail"]
        assert "no_such_template_xyz" in detail   # reflects the request
        assert "/" not in detail                  # no filesystem path leaked
        assert ".maverick" not in detail

    @pytest.mark.parametrize("ceiling,expected", [(None, 100.0), (25.0, 25.0), (0.0, 0.0)])
    def test_create_applies_only_configured_max_dollars(self, monkeypatch, tmp_path, ceiling, expected):
        """An explicit deployment ceiling constrains a caller's requested cap."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        import maverick.runner as runner_mod
        called = []
        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        if ceiling is not None:
            (tmp_path / "config.toml").write_text(
                f"[budget]\nmax_dollars = {ceiling}\n", encoding="utf-8",
            )
        monkeypatch.setattr(runner_mod, "run_goal_in_thread", lambda *a, **kw: called.append((a, kw)))
        resp = client.post("/api/v1/goals", json={
            "title": "big spend", "max_dollars": 10_000.0,
        })
        assert resp.status_code == 201
        assert len(called) == 1
        assert called[0][1]["max_dollars"] == expected
        assert resp.json()["limits"]["max_dollars"] == expected

    def test_legacy_no_limit_config_stays_unchanged_but_rest_has_safe_defaults(
            self, monkeypatch, tmp_path):
        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        (tmp_path / "config.toml").write_text(
            "[budget]\ntask_limits_enabled = false\n", encoding="utf-8",
        )
        from maverick import runner as runner_mod

        called = []
        monkeypatch.setattr(runner_mod, "run_goal_in_thread", lambda *a, **kw: called.append(kw))

        response = client.post("/api/v1/goals", json={"title": "legacy bounded REST"})

        assert response.status_code == 201, response.text
        assert response.json()["limits"] == {
            "max_dollars": 2.0, "max_wall_seconds": 1800.0, "max_depth": 3,
        }
        assert called[0]["max_dollars"] == 2.0
        assert called[0]["max_wall_seconds"] == 1800.0
        assert runner_mod.configured_max_dollars() is None
        assert runner_mod.configured_max_wall_seconds() is None

    def test_explicit_rest_limits_are_bounded_and_reconciled(
            self, monkeypatch, tmp_path):
        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        from maverick import runner as runner_mod

        called = []
        monkeypatch.setattr(runner_mod, "run_goal_in_thread", lambda *a, **kw: called.append(kw))
        headers = {"Idempotency-Key": "bounded-rest-goal"}
        payload = {"title": "large request", "max_dollars": 1000,
                   "max_wall_seconds": 1000000}

        first = client.post("/api/v1/goals", json=payload, headers=headers)
        replay = client.post("/api/v1/goals", json=payload, headers=headers)
        receipt = client.get("/api/v1/goal-submissions/receipt", headers=headers)

        expected = {"max_dollars": 100.0, "max_wall_seconds": 86400.0,
                    "max_depth": 3}
        assert first.status_code == replay.status_code == 201
        assert first.json()["limits"] == replay.json()["limits"] == expected
        assert receipt.status_code == 200 and receipt.json()["limits"] == expected
        assert len(called) == 1
        assert called[0]["max_dollars"] == 100.0
        assert called[0]["max_wall_seconds"] == 86400.0

    def test_create_without_limits_dispatches_finite_fresh_install_caps(self, monkeypatch, tmp_path):
        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        monkeypatch.delenv("MAVERICK_BUDGET_DOLLARS", raising=False)
        import maverick.runner as runner_mod

        called = []
        monkeypatch.setattr(runner_mod, "run_goal_in_thread", lambda *a, **kw: called.append((a, kw)))
        resp = client.post("/api/v1/goals", json={"title": "bounded goal"})
        assert resp.status_code == 201, resp.text
        assert len(called) == 1
        assert called[0][1]["max_dollars"] == 2.0
        assert called[0][1]["max_wall_seconds"] == 1800.0

    def test_create_rejects_oversized_description(self, monkeypatch):
        """An unbounded description is a cost/DB-bloat amplification vector;
        the bound rejects it with 422 rather than silently storing it."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        resp = client.post("/api/v1/goals", json={
            "title": "ok", "description": "x" * 16_001,
        })
        assert resp.status_code == 422

    def test_list_returns_array(self):
        resp = client.get("/api/v1/goals")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_pagination_metadata_is_backward_compatible(self):
        from maverick_dashboard.app import _world

        world = _world()
        for index in range(3):
            world.create_goal(f"goal-{index}", "")

        first = client.get("/api/v1/goals?limit=2&offset=0")
        assert first.status_code == 200
        assert len(first.json()) == 2
        assert first.headers["pagination-limit"] == "2"
        assert first.headers["pagination-offset"] == "0"
        assert first.headers["pagination-has-more"] == "true"
        assert first.headers["pagination-next-offset"] == "2"

        last = client.get("/api/v1/goals?limit=2&offset=2")
        assert last.status_code == 200
        assert len(last.json()) == 1
        assert last.headers["pagination-has-more"] == "false"
        assert "pagination-next-offset" not in last.headers

    def test_get_unknown_404(self):
        resp = client.get("/api/v1/goals/999999")
        assert resp.status_code == 404

    def test_events_for_unknown_404(self):
        resp = client.get("/api/v1/goals/999999/events")
        assert resp.status_code == 404


class TestAnswer:
    """POST /api/v1/goals/{id}/answer takes a JSON body."""

    def test_answer_unknown_question_404(self, tmp_path, monkeypatch):
        from maverick import world_model
        monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
        w = world_model.WorldModel(tmp_path / "world.db")
        gid = w.create_goal("test", "")
        resp = client.post(
            f"/api/v1/goals/{gid}/answer",
            json={"question_id": 9999, "answer": "x"},
        )
        assert resp.status_code == 404

    def test_answer_missing_body_422(self, tmp_path, monkeypatch):
        from maverick import world_model
        monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
        w = world_model.WorldModel(tmp_path / "world.db")
        gid = w.create_goal("test", "")
        # No body -> Pydantic validation 422 (was query-string-only before).
        resp = client.post(f"/api/v1/goals/{gid}/answer")
        assert resp.status_code == 422

    @staticmethod
    def _parked_goal(tmp_path, monkeypatch, *questions, status="blocked"):
        """A goal the agent parked with ``ask_user``: 'blocked', no result, and
        the given open questions. Returns (world, goal id, question ids, runner
        calls) with the background runner stubbed out."""
        from maverick import world_model
        w = world_model.WorldModel(tmp_path / "world.db")
        gid = w.create_goal("plan the launch", "")
        w.set_goal_status(gid, status)
        qids = [w.ask(q, goal_id=gid) for q in questions]
        calls = []

        async def run(*args, **kwargs):
            calls.append((args, kwargs))

        monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)
        return w, gid, qids, calls

    def test_answering_the_last_open_question_resumes_the_goal(self, tmp_path, monkeypatch):
        w, gid, (qid,), calls = self._parked_goal(tmp_path, monkeypatch, "Which market first?")
        resp = client.post(
            f"/api/v1/goals/{gid}/answer",
            json={"question_id": qid, "answer": "Small businesses in the US"},
        )
        assert resp.status_code == 204, resp.text
        assert w.open_questions(goal_id=gid) == []
        # The turn closes on its own: back to pending and handed to the runner.
        assert w.get_goal(gid).status == "pending"
        assert [c[0] for c in calls] == [(gid,)]

    def test_answering_one_of_several_questions_keeps_waiting(self, tmp_path, monkeypatch):
        w, gid, (first, second), calls = self._parked_goal(
            tmp_path, monkeypatch, "Which market first?", "What is the budget?"
        )
        resp = client.post(
            f"/api/v1/goals/{gid}/answer", json={"question_id": first, "answer": "US"}
        )
        assert resp.status_code == 204, resp.text
        assert [q.id for q in w.open_questions(goal_id=gid)] == [second]
        assert w.get_goal(gid).status == "blocked"
        assert calls == []

    def test_answering_while_the_goal_still_runs_does_not_requeue(self, tmp_path, monkeypatch):
        w, gid, (qid,), calls = self._parked_goal(
            tmp_path, monkeypatch, "Which market first?", status="running"
        )
        resp = client.post(
            f"/api/v1/goals/{gid}/answer", json={"question_id": qid, "answer": "US"}
        )
        assert resp.status_code == 204, resp.text
        assert w.get_goal(gid).status == "running"
        assert calls == []


class TestAttachments:
    def test_upload_text_then_list(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_ATTACH_MAX_FILE_BYTES", "1000000")
        # Attachment bytes land on disk; route to tmp_path so tests don't
        # litter ~/.maverick.
        import maverick.attachments as att_mod
        monkeypatch.setattr(att_mod, "DEFAULT_ROOT", tmp_path / "att")

        from maverick.world_model import DEFAULT_DB, WorldModel
        wm = WorldModel(DEFAULT_DB)
        gid = wm.create_goal("attach", "")

        resp = client.post(
            f"/api/v1/goals/{gid}/attachments",
            files={"file": ("hello.txt", b"hello world", "text/plain")},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["filename"] == "hello.txt"
        assert data["mime"] == "text/plain"
        assert data["size_bytes"] == len(b"hello world")

        # List endpoint returns the same record.
        resp = client.get(f"/api/v1/goals/{gid}/attachments")
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 1
        assert items[0]["filename"] == "hello.txt"

    def test_upload_rejects_disallowed_mime(self, tmp_path, monkeypatch):
        import maverick.attachments as att_mod
        monkeypatch.setattr(att_mod, "DEFAULT_ROOT", tmp_path / "att")
        from maverick.world_model import DEFAULT_DB, WorldModel
        wm = WorldModel(DEFAULT_DB)
        gid = wm.create_goal("attach", "")

        resp = client.post(
            f"/api/v1/goals/{gid}/attachments",
            files={"file": ("bad.exe", b"MZ\x00\x00",
                            "application/x-msdownload")},
        )
        assert resp.status_code == 400
        assert "mime type not allowed" in resp.json()["detail"]


    def test_upload_reads_with_size_cap(self, monkeypatch, tmp_path):
        import asyncio

        from maverick.world_model import WorldModel
        from maverick_dashboard import api as api_mod

        class _File:
            filename = "x.txt"
            content_type = "text/plain"

            def __init__(self):
                self.read_sizes = []

            async def read(self, size=-1):
                self.read_sizes.append(size)
                return b"x" if len(self.read_sizes) == 1 else b""

        monkeypatch.setattr("maverick.attachments.MAX_FILE_BYTES", 7)
        monkeypatch.setattr("maverick.attachments.DEFAULT_ROOT", tmp_path / "attachments")

        f = _File()
        # Use a real local request so current authority validation still runs.
        # BackgroundTasks (third) receives the companion-generation task; not
        # executing it here keeps the test focused on the size-cap read.
        from fastapi import BackgroundTasks
        from starlette.requests import Request
        request = Request({"type": "http", "method": "POST", "path": "/attachments", "headers": []})
        with WorldModel(tmp_path / "world.db") as world:
            monkeypatch.setattr(api_mod, "_world", lambda: world)
            goal_id = world.create_goal("Upload")
            out = asyncio.run(api_mod.upload_attachment(request, goal_id, BackgroundTasks(), f))
            assert world.list_attachments(goal_id)[0].size_bytes == 1

        assert f.read_sizes == [8, 7]
        assert out.size_bytes == 1

    def test_upload_to_unknown_goal_404(self):
        resp = client.post(
            "/api/v1/goals/99999/attachments",
            files={"file": ("x.txt", b"x", "text/plain")},
        )
        assert resp.status_code == 404


class TestFacts:
    def test_get_empty_initially(self):
        resp = client.get("/api/v1/facts")
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_set_then_get(self):
        resp = client.post("/api/v1/facts", json={"key": "city", "value": "Lisbon"})
        assert resp.status_code == 204
        resp = client.get("/api/v1/facts")
        assert resp.json() == {"city": "Lisbon"}

    def test_upsert_overwrites(self):
        client.post("/api/v1/facts", json={"key": "city", "value": "Lisbon"})
        current = client.get("/api/v1/facts/record", params={"key": "city"}).json()
        client.post("/api/v1/facts", json={"key": "city", "value": "Tokyo",
                    "expected_revision": current["item"]["revision"], "context": current["context"]})
        assert client.get("/api/v1/facts").json() == {"city": "Tokyo"}


class TestSkills:
    def test_list_returns_array(self):
        resp = client.get("/api/v1/skills")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_install_bare_path_rejected(self, monkeypatch):
        """REST callers can't POST {"source": "/etc/passwd"} (security fix)."""
        monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
        resp = client.post("/api/v1/skills", json={"source": "/etc/passwd"})
        assert resp.status_code == 400
        assert "not allowed" in resp.json()["detail"]

    def test_install_file_scheme_rejected(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
        resp = client.post("/api/v1/skills", json={"source": "file:///etc/passwd"})
        assert resp.status_code == 400

    def test_install_bad_gh_format_rejected(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
        resp = client.post("/api/v1/skills", json={"source": "gh:not-valid"})
        assert resp.status_code == 400

    def test_install_blocked_without_opt_in(self):
        """Without MAVERICK_ALLOW_SKILL_INSTALL=1, endpoint refuses."""
        resp = client.post("/api/v1/skills", json={"source": "gh:any/repo"})
        assert resp.status_code == 403
        assert "MAVERICK_ALLOW_SKILL_INSTALL" in resp.json()["detail"]

    def test_remove_unknown_404(self):
        # Removal is reviewed first; an unknown skill has nothing to review.
        context = client.get("/api/v1/manual-skill-removals").json()["context"]
        resp = client.post("/api/v1/manual-skill-removals/review",
                           json={"name": "does-not-exist", "context": context})
        assert resp.status_code == 409 and "no longer installed" in resp.json()["detail"]


class TestSpend:
    def test_returns_total_and_episodes(self):
        resp = client.get("/api/v1/spend")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "episodes" in data
        assert isinstance(data["episodes"], list)


class TestSecurityRegister:
    @pytest.fixture(autouse=True)
    def _clear_security_cache(self):
        from maverick_dashboard import api
        api._security_register_cache.clear()

    def test_returns_posture_hunt_and_remediation(self):
        resp = client.get("/api/v1/security")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["controls"], list)            # compliance posture
        assert data["threat_hunt"]["risk"] in {"clear", "low", "medium", "high"}
        assert isinstance(data["threat_hunt"]["findings"], list)
        assert "auto_fix_enabled" in data["remediation"]
        assert isinstance(data["remediation"]["gaps"], list)

    def test_security_register_bounds_hunt_and_avoids_second_scan(self, monkeypatch):
        from maverick.threat_hunt import ThreatReport

        hunt_calls = []
        plan_calls = []

        def fake_hunt(**kwargs):
            hunt_calls.append(kwargs)
            return ThreatReport([], 0, "clear")

        def fake_plan(**kwargs):
            plan_calls.append(kwargs)

            class P:
                auto_fix_enabled = False
                gaps = []
            return P()

        monkeypatch.setattr("maverick.threat_hunt.hunt", fake_hunt)
        monkeypatch.setattr("maverick.remediation.plan", fake_plan)

        resp = client.get("/api/v1/security")
        assert resp.status_code == 200
        assert len(hunt_calls) == 1
        assert hunt_calls[0]["all_days"] is False
        assert hunt_calls[0]["since"] <= hunt_calls[0]["until"]
        assert plan_calls == [{"include_breaches": False}]

    def test_security_register_cache_is_isolated_by_tenant(
        self, monkeypatch, tmp_path
    ):
        from maverick.paths import current_tenant_id_strict
        from maverick_dashboard import api

        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        calls: list[str] = []

        def snapshot() -> dict:
            tenant = current_tenant_id_strict() or "shared"
            calls.append(tenant)
            return {"tenant": tenant}

        monkeypatch.setattr(api, "_security_register_snapshot_uncached", snapshot)

        monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
        assert client.get("/api/v1/security").json() == {"tenant": "tenant-a"}
        assert client.get("/api/v1/security").json() == {"tenant": "tenant-a"}

        monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
        assert client.get("/api/v1/security").json() == {"tenant": "tenant-b"}
        assert calls == ["tenant-a", "tenant-b"]


class TestOpenAPI:
    def test_openapi_schema_served(self):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        spec = resp.json()
        paths = spec.get("paths", {})
        for required in (
            "/api/v1/goals", "/api/v1/goals/{goal_id}", "/api/v1/facts",
            "/api/v1/skills", "/api/v1/spend", "/api/v1/security",
        ):
            assert required in paths, f"missing {required}"

    def test_docs_served(self):
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_openapi_requires_bearer_auth(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        resp = client.get("/openapi.json")
        assert resp.status_code == 401

    def test_docs_require_bearer_auth(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        resp = client.get("/docs")
        assert resp.status_code == 401

    @pytest.mark.parametrize("path", [
        "/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect",
        "/static/swagger-ui-5.33.1-bundle.js", "/static/swagger-ui-5.33.1.css",
    ])
    def test_documentation_requires_valid_bearer(self, monkeypatch, path):
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"Authorization": "Bearer invalid"}).status_code == 401
        assert client.get(path, headers={"Authorization": "Bearer s3cr3t"}).status_code == 200

    def test_api_endpoint_requires_bearer_when_token_set(self, monkeypatch):
        """/api/v1 was never tested with auth.

        Silent auth bypass on the API would be catastrophic; this test
        catches that regression class.
        """
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        resp = client.get("/api/v1/goals")
        assert resp.status_code == 401

    def test_api_endpoint_with_bearer_succeeds(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        resp = client.get(
            "/api/v1/goals",
            headers={"Authorization": "Bearer s3cr3t"},
        )
        assert resp.status_code == 200

    def test_api_endpoint_with_query_token_rejected(self, monkeypatch):
        """`?token=...` leaks via Referer/history.

        Removed; callers must send Authorization: Bearer.
        """
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        resp = client.get("/api/v1/goals?token=s3cr3t")
        assert resp.status_code == 401

    def test_api_endpoint_with_wrong_bearer_rejected(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        resp = client.get(
            "/api/v1/goals",
            headers={"Authorization": "Bearer wrong"},
        )
        assert resp.status_code == 401

    def test_livez_exempt_from_bearer_auth(self, monkeypatch):
        """Cheap liveness check must work without auth."""
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        resp = client.get("/livez")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_healthz_deep_probe_returns_status_only(self, monkeypatch):
        """Deep healthz checks remain private on the public endpoint."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
        resp = client.get("/healthz")
        body = resp.json()
        assert set(body) == {"status"}

    def test_healthz_503_when_no_llm_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        resp = client.get("/healthz")
        assert resp.status_code == 503
        assert resp.json()["status"] == "degraded"
        assert set(resp.json()) == {"status"}


class TestMetrics:
    def test_healthz_redacts_exception_text_when_token_set(self, tmp_path, monkeypatch):
        """On a VPS with
        MAVERICK_DASHBOARD_TOKEN set, /healthz must NOT leak the
        absolute DB path in error messages (it exposes the OS username).

        Under a token the auth-exempt payload also drops the whole ``checks`` block under a token (which also leaked
        ``llm_key`` and a live in-flight gauge), collapsing to just the
        status. So no DB path can appear at all.
        """
        monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cr3t")
        # Point DEFAULT_DB at an unwritable path so the DB check fails.
        from maverick import world_model
        bad_path = tmp_path / "subdir-that-does-not-exist" / "world.db"
        monkeypatch.setattr(world_model, "DEFAULT_DB", bad_path)

        resp = client.get("/healthz")
        body = resp.json()
        # Minimal payload under a token: only the status, no checks block.
        assert "checks" not in body
        assert "subdir-that-does-not-exist" not in resp.text
        assert str(bad_path) not in resp.text

    def test_metrics_prometheus_format(self):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        text = resp.text
        # Prometheus text format requires HELP + TYPE lines.
        assert "# HELP maverick_goals_total" in text
        assert "# TYPE maverick_goals_total gauge" in text
        assert "# HELP maverick_cost_dollars_total" in text
        assert "# TYPE maverick_concurrent_goals gauge" in text
        assert "maverick_concurrent_goals" in text
        assert "maverick_max_concurrent_goals" in text
        # Job-queue backlog + dead-letter visibility.
        assert "# HELP maverick_queue_jobs" in text
        assert "# TYPE maverick_queue_jobs gauge" in text

    def test_metrics_bounds_principal_cardinality(self, monkeypatch):
        from maverick import quotas
        from maverick_dashboard import app as dash_app

        class _Usage:
            @staticmethod
            def spend_by_principal():
                return {f"user:{i}": float(i) for i in range(150)}

        monkeypatch.setattr(quotas, "UsageLedger", _Usage)
        monkeypatch.setattr(dash_app, "goal_owner_filter", lambda _request: None)

        text = client.get("/metrics").text
        series = [
            line for line in text.splitlines()
            if line.startswith("maverick_user_spend_dollars_today{")
        ]
        assert len(series) == dash_app._MAX_USER_SPEND_METRIC_SERIES
        assert any(
            f'principal="{dash_app._USER_SPEND_OVERFLOW_LABEL}"' in line
            for line in series
        )


def test_request_identity_refuses_a_non_ascii_bearer_like_any_wrong_token(monkeypatch):
    """A static-token deployment answers a crafted bearer with 401, not a 500."""
    from fastapi import HTTPException
    from maverick_dashboard import api
    from starlette.requests import Request

    token = "static-token-for-tests"  # pragma: allowlist secret
    monkeypatch.setattr(api, "caller_principal", lambda _request: None)
    monkeypatch.setattr(api, "_dashboard_token", lambda: token)

    def identity(authorization: bytes):
        return api._request_identity(Request({
            "type": "http", "method": "GET", "path": "/api/v1/connections",
            "headers": [(b"authorization", authorization)],
        }))

    # Header text arrives decoded as latin-1, so e-acute is a non-ASCII str.
    for wrong in (b"Bearer wrong", b"Bearer caf\xe9"):
        with pytest.raises(HTTPException) as refused:
            identity(wrong)
        assert refused.value.status_code == 401
    assert identity(b"Bearer " + token.encode()) == "auth:dashboard-token"
