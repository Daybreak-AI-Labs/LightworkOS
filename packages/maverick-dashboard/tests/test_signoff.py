"""Governed hand-off: record a sign-off on a gated deliverable, surface it on
the goal page, and export the deliverable as CSV for downstream loading."""
from __future__ import annotations

import csv
import io

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

_TABLE = "| Week | Net |\n| --- | ---: |\n| W1 | 300 |\n| W2 | 100 |\n"


def _world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    return world_model.WorldModel(tmp_path / "world.db")


def _forecast_goal(w):
    gid = w.create_goal("Refresh the cash forecast", "", domain="finance_cash13w")
    w.set_goal_status(gid, "done", result=_TABLE)
    return gid


def _decision(w, gid, decision, *, note=None, expected_updated_at=None):
    """API decision bound to the exact deliverable version the client saw."""
    if expected_updated_at is None:
        expected_updated_at = w.get_goal(gid).updated_at
    return {
        "decision": decision,
        "expected_updated_at": expected_updated_at,
        "note": note,
    }


class TestSignoffApi:
    def test_record_then_read_signoff(self, tmp_path, monkeypatch):
        w = _world(tmp_path, monkeypatch)
        gid = _forecast_goal(w)
        r = client.post(f"/api/v1/goals/{gid}/signoff",
                        json=_decision(w, gid, "approved", note="ties out"))
        assert r.status_code == 200
        body = r.json()
        assert body["signoff"]["decision"] == "approved"
        assert body["gate"] == "review"
        # persisted + readable
        got = client.get(f"/api/v1/goals/{gid}/signoff").json()
        assert got["deliverable_updated_at"] == w.get_goal(gid).updated_at
        assert got["signoff"]["decision"] == "approved"
        assert got["signoff"]["note"] == "ties out"

    def test_signoff_on_ungated_goal_is_rejected(self, tmp_path, monkeypatch):
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("generic", "")  # no domain -> no gate
        w.set_goal_status(gid, "done", result="just prose")
        r = client.post(
            f"/api/v1/goals/{gid}/signoff",
            json=_decision(w, gid, "approved"),
        )
        assert r.status_code == 400

    def test_signoff_before_deliverable_is_finished_is_rejected(self, tmp_path, monkeypatch):
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("forecast", "", domain="finance_cash13w")
        r = client.post(
            f"/api/v1/goals/{gid}/signoff",
            json=_decision(w, gid, "approved"),
        )
        assert r.status_code == 409
        assert w.signoff_for(gid) is None

    def test_terminal_workflow_gate_is_enforced_without_output_gate(
        self, tmp_path, monkeypatch,
    ):
        domains = tmp_path / "domains"
        domains.mkdir()
        (domains / "generated_gate.toml").write_text(
            'name = "generated_gate"\n'
            'description = "Generated approval-gated specialist"\n'
            f'persona = "{"x" * 240}"\n'
            'allow_tools = ["read_file"]\n'
            'deny_tools = ["shell", "write_file"]\n'
            'max_risk = "low"\n'
            '[output]\n'
            'shape = "table"\n'
            'deliverable = "generated forecast"\n'
            'consumers = ["reviewer"]\n'
            '[[workflow]]\n'
            'name = "Draft"\n'
            '[[workflow]]\n'
            'name = "Approve"\n'
            'gate = "approval"\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(domains))
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("generated", "", domain="generated_gate")
        w.set_goal_status(gid, "done", result=_TABLE)

        state = client.get(f"/api/v1/goals/{gid}/signoff")
        assert state.status_code == 200
        assert state.json()["gate"] == "approval"
        assert client.get(f"/api/v1/goals/{gid}/deliverable.csv").status_code == 403

        signed = client.post(
            f"/api/v1/goals/{gid}/signoff",
            json=_decision(w, gid, "approved"),
        )
        assert signed.status_code == 200
        assert signed.json()["signoff"]["decision"] == "approved"
        assert client.get(f"/api/v1/goals/{gid}/deliverable.csv").status_code == 200

    def test_bad_decision_is_422(self, tmp_path, monkeypatch):
        w = _world(tmp_path, monkeypatch)
        gid = _forecast_goal(w)
        r = client.post(
            f"/api/v1/goals/{gid}/signoff",
            json=_decision(w, gid, "maybe"),
        )
        assert r.status_code == 422

    def test_missing_client_seen_version_is_422(self, tmp_path, monkeypatch):
        w = _world(tmp_path, monkeypatch)
        gid = _forecast_goal(w)
        r = client.post(
            f"/api/v1/goals/{gid}/signoff",
            json={"decision": "approved"},
        )
        assert r.status_code == 422

    def test_stale_page_cannot_approve_replacement_deliverable(
        self, tmp_path, monkeypatch,
    ):
        w = _world(tmp_path, monkeypatch)
        gid = _forecast_goal(w)
        reviewed_version = client.get(
            f"/api/v1/goals/{gid}/signoff"
        ).json()["deliverable_updated_at"]
        w.set_goal_status(gid, "done", result="replacement the reviewer never saw")

        r = client.post(
            f"/api/v1/goals/{gid}/signoff",
            json=_decision(
                w,
                gid,
                "approved",
                expected_updated_at=reviewed_version,
            ),
        )

        assert r.status_code == 409
        assert w.signoff_for(gid) is None

    def test_approval_fires_handoff_rejection_does_not(self, tmp_path, monkeypatch):
        import maverick.webhooks as webhooks
        import maverick_dashboard.api as dashboard_api
        w = _world(tmp_path, monkeypatch)
        calls = []
        outcomes = []
        monkeypatch.setattr(webhooks, "fire_deliverable_handoff",
                            lambda payload: calls.append(payload) or 1)
        monkeypatch.setattr(
            dashboard_api,
            "_record_signoff_outcome",
            lambda _world, goal_id, decision: outcomes.append((goal_id, decision)),
        )

        gid = _forecast_goal(w)
        payload = _decision(w, gid, "approved")
        first = client.post(f"/api/v1/goals/{gid}/signoff", json=payload)
        retry = client.post(f"/api/v1/goals/{gid}/signoff", json=payload)
        assert first.json()["changed"] is True
        assert retry.json()["changed"] is False
        assert len(calls) == 1
        assert outcomes == [(gid, "approved")]
        assert calls[0]["goal_id"] == gid
        assert calls[0]["domain"] == "finance_cash13w"
        assert calls[0]["table"]["headers"] == ["Week", "Net"]  # parsed deliverable rides along
        assert calls[0]["result"] == ""  # no raw table text outside the reviewed artifact

        gid2 = _forecast_goal(w)
        client.post(
            f"/api/v1/goals/{gid2}/signoff",
            json=_decision(w, gid2, "rejected"),
        )
        assert len(calls) == 1  # rejection does not hand off downstream
        assert outcomes == [(gid, "approved"), (gid2, "rejected")]

    def test_handoff_omits_unreviewed_raw_text_for_table(self, tmp_path, monkeypatch):
        import maverick.webhooks as webhooks
        w = _world(tmp_path, monkeypatch)
        calls = []
        monkeypatch.setattr(webhooks, "fire_deliverable_handoff",
                            lambda payload: calls.append(payload) or 1)

        raw = "HIDDEN_PREFACE\n" + _TABLE + "\nHIDDEN_TRAILER"
        gid = w.create_goal("Refresh the cash forecast", "", domain="finance_cash13w")
        w.set_goal_status(gid, "done", result=raw)

        r = client.post(
            f"/api/v1/goals/{gid}/signoff",
            json=_decision(w, gid, "approved"),
        )

        assert r.status_code == 200
        assert len(calls) == 1
        assert calls[0]["table"] == {
            "headers": ["Week", "Net"],
            "rows": [["W1", "300"], ["W2", "100"]],
        }
        assert calls[0]["result"] == ""
        assert "HIDDEN" not in str(calls[0])


class TestSignoffGroundsLearning:
    """A human sign-off is the cleanest ground-truth label in the system; when
    [consequence] is on it must feed the learning loop as a grounded outcome."""

    def _isolate(self, tmp_path, monkeypatch):
        # consequence.shared() resolves its store under MAVERICK_HOME at call time.
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        from maverick import consequence
        consequence.reset_shared()
        return consequence

    def test_approval_records_grounded_outcome_1(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
        consequence = self._isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = _forecast_goal(w)
        eid = w.start_episode(gid)
        r = client.post(
            f"/api/v1/goals/{gid}/signoff",
            json=_decision(w, gid, "approved"),
        )
        assert r.status_code == 200
        assert consequence.resolve(gid, eid) == 1.0   # approval -> reward 1.0

    def test_rejection_records_grounded_outcome_0(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
        consequence = self._isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = _forecast_goal(w)
        eid = w.start_episode(gid)
        r = client.post(
            f"/api/v1/goals/{gid}/signoff",
            json=_decision(w, gid, "rejected"),
        )
        assert r.status_code == 200
        assert consequence.resolve(gid, eid) == 0.0   # rejection is signal too

    def test_no_outcome_when_consequence_disabled(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "0")
        consequence = self._isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = _forecast_goal(w)
        eid = w.start_episode(gid)
        r = client.post(
            f"/api/v1/goals/{gid}/signoff",
            json=_decision(w, gid, "approved"),
        )
        assert r.status_code == 200
        # An explicit opt-out keeps the kernel stateless.
        assert consequence.resolve(gid, eid) is None


class TestCancelDoesNotJudgeQuality:
    """Stopping work is not a quality judgment; explicit feedback remains separate."""

    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
        from maverick import consequence
        consequence.reset_shared()
        return consequence

    def test_cancel_does_not_record_a_negative_learning_outcome(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
        consequence = self._isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Long-running thing", "")
        eid = w.start_episode(gid)
        r = client.post(f"/api/v1/goals/{gid}/cancel")
        assert r.status_code == 204
        assert consequence.resolve(gid, eid) is None

    def test_no_outcome_when_consequence_disabled(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "0")
        consequence = self._isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Long-running thing", "")
        eid = w.start_episode(gid)
        assert client.post(f"/api/v1/goals/{gid}/cancel").status_code == 204
        assert consequence.resolve(gid, eid) is None


class TestDeliverableExport:
    def test_forecast_exports_as_csv_after_approval(self, tmp_path, monkeypatch):
        w = _world(tmp_path, monkeypatch)
        gid = _forecast_goal(w)
        w.record_signoff(gid, "approved", decided_by="user:alice", note="ok")
        r = client.get(f"/api/v1/goals/{gid}/deliverable.csv")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/csv")
        body = r.text
        assert "Week,Net" in body
        assert "W1,300" in body

    def test_gated_table_export_requires_approved_signoff(self, tmp_path, monkeypatch):
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Prepare payment batch", "", domain="finance_ap")
        w.set_goal_status(gid, "done", result=_TABLE)

        r = client.get(f"/api/v1/goals/{gid}/deliverable.csv")
        assert r.status_code == 403

        w.record_signoff(gid, "rejected", decided_by="user:alice", note="hold")
        r = client.get(f"/api/v1/goals/{gid}/deliverable.csv")
        assert r.status_code == 403

        w.record_signoff(gid, "approved", decided_by="user:alice", note="ok")
        r = client.get(f"/api/v1/goals/{gid}/deliverable.csv")
        assert r.status_code == 200

    def test_export_neutralizes_spreadsheet_formulas(self, tmp_path, monkeypatch):
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Review AML alerts", "", domain="bank_aml_alerts")
        w.set_goal_status(
            gid,
            "done",
            result=(
                "| Alert | Formula | Safe |\n"
                "| --- | --- | --- |\n"
                "| =HYPERLINK(\"http://attacker.test\") | +SUM(1,2) | ordinary |\n"
                "| @SUM(1,2) | -2+3 | unchanged |\n"
            ),
        )
        # bank_aml_alerts is gated (review), so an approved sign-off is required
        # before the gated table can be exported.
        w.record_signoff(gid, "approved", decided_by="user:alice", note="ok")

        r = client.get(f"/api/v1/goals/{gid}/deliverable.csv")

        assert r.status_code == 200
        rows = list(csv.reader(io.StringIO(r.text)))
        assert rows[0] == ["Alert", "Formula", "Safe"]
        assert rows[1] == [
            "'=HYPERLINK(\"http://attacker.test\")",
            "'+SUM(1,2)",
            "ordinary",
        ]
        assert rows[2] == ["'@SUM(1,2)", "'-2+3", "unchanged"]

    def test_no_table_is_404(self, tmp_path, monkeypatch):
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Refresh forecast", "", domain="finance_cash13w")
        w.set_goal_status(gid, "done", result="No grid here, just narrative.")
        assert client.get(f"/api/v1/goals/{gid}/deliverable.csv").status_code == 404


class TestSignoffUi:
    def test_gated_done_goal_shows_signoff_controls(self, tmp_path, monkeypatch):
        w = _world(tmp_path, monkeypatch)
        gid = _forecast_goal(w)
        t = client.get(f"/chat/goal/{gid}").text
        assert 'id="signoff-approve"' in t
        assert 'id="signoff-reject"' in t
        assert "/static/lightwork-answer-panel.js" in t
        asset = client.get("/static/lightwork-answer-panel.js")
        assert asset.status_code == 200 and "expected_updated_at" in asset.text

    def test_terminal_gated_prose_playbook_has_review_controls(
        self, tmp_path, monkeypatch,
    ):
        domains = tmp_path / "domains"
        domains.mkdir()
        (domains / "generated_prose.toml").write_text(
            'name = "generated_prose"\n'
            'description = "Generated prose specialist"\n'
            f'persona = "{"x" * 240}"\n'
            'allow_tools = ["read_file"]\n'
            'deny_tools = ["shell", "write_file"]\n'
            'max_risk = "low"\n'
            '[[workflow]]\n'
            'name = "Draft"\n'
            '[[workflow]]\n'
            'name = "Approve"\n'
            'gate = "approval"\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(domains))
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("generated", "", domain="generated_prose")
        w.set_goal_status(gid, "done", result="first-pass prose")

        page = client.get(f"/chat/goal/{gid}")

        assert page.status_code == 200
        assert "first-pass prose" in page.text
        assert 'id="signoff-approve"' in page.text
        assert 'id="signoff-reject"' in page.text

    def test_signed_off_goal_shows_decision_and_handoff(self, tmp_path, monkeypatch):
        w = _world(tmp_path, monkeypatch)
        gid = _forecast_goal(w)
        w.record_signoff(gid, "approved", decided_by="user:alice", note="ok")
        t = client.get(f"/chat/goal/{gid}").text
        assert 'id="signoff-approve"' not in t          # form replaced by the decision
        assert "approved" in t
        assert f"/api/v1/goals/{gid}/deliverable.csv" in t   # hand-off download offered

    def test_generic_goal_has_no_signoff_panel(self, tmp_path, monkeypatch):
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Summarize", "")
        w.set_goal_status(gid, "done", result="a summary")
        t = client.get(f"/chat/goal/{gid}").text
        assert 'class="signoff"' not in t
