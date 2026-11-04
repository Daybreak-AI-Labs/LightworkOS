"""The persona inbox: build_inbox shaping + the /deliverables page (runs grouped
by deliverable, scoped to a consumer role, gated-and-finished flagged for
sign-off)."""
from __future__ import annotations

from dataclasses import dataclass

from fastapi.testclient import TestClient
from maverick_dashboard.app import app
from maverick_dashboard.deliverables import build_inbox, persona_roles_for

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@dataclass
class _Run:
    id: int
    title: str
    status: str
    updated_at: float


_FORECAST = {"domain": "finance_cash13w", "deliverable": "13-week cash forecast",
             "shape": "forecast", "consumers": ["fpa_analyst", "treasurer"],
             "cadence": "weekly", "gate": "review", "suite": "finance"}
_RISK = {"domain": "risk_x", "deliverable": "Risk assessment", "shape": "report",
         "consumers": ["risk_officer"], "cadence": "", "gate": "approval", "suite": None}


class TestBuildInbox:
    def test_collects_every_consumer_role(self):
        m = build_inbox([_FORECAST, _RISK], {})
        assert m["roles"] == ["fpa_analyst", "risk_officer", "treasurer"]

    def test_role_filter_scopes_to_consumers(self):
        m = build_inbox([_FORECAST, _RISK], {}, role="risk_officer")
        assert [it["domain"] for it in m["items"]] == ["risk_x"]
        assert m["role"] == "risk_officer"

    def test_role_filter_accepts_partial_and_mixed_case_roles(self):
        # "billing" must reach billing_analyst the way the other searches do;
        # an exact role still wins over a substring hit.
        m = build_inbox([_FORECAST, _RISK], {}, role="fpa")
        assert [it["domain"] for it in m["items"]] == ["finance_cash13w"]
        m = build_inbox([_FORECAST, _RISK], {}, role="Risk_Officer")
        assert [it["domain"] for it in m["items"]] == ["risk_x"]
        # exact match preferred: "treasurer" is a consumer AND a substring of nothing else
        m = build_inbox([_FORECAST, _RISK], {}, role="treasurer")
        assert [it["domain"] for it in m["items"]] == ["finance_cash13w"]
        # a substring nobody has stays empty rather than 500ing
        assert build_inbox([_FORECAST, _RISK], {}, role="zzz")["items"] == []

    def test_finished_gated_run_is_awaiting_signoff(self):
        runs = {"finance_cash13w": [_Run(7, "Refresh forecast", "done", 100.0)]}
        m = build_inbox([_FORECAST], runs)
        assert len(m["awaiting"]) == 1
        assert m["awaiting"][0]["id"] == 7
        assert m["awaiting"][0]["deliverable"] == "13-week cash forecast"
        assert m["items"][0]["awaiting_count"] == 1

    def test_running_or_ungated_run_is_not_awaiting(self):
        # in-flight run: not finished -> not awaiting
        running = {"finance_cash13w": [_Run(8, "x", "running", 1.0)]}
        assert build_inbox([_FORECAST], running)["awaiting"] == []
        # finished but the pack declares no gate -> nothing to sign off
        ungated = dict(_FORECAST, gate=None)
        done = {"finance_cash13w": [_Run(9, "x", "done", 1.0)]}
        assert build_inbox([ungated], done)["awaiting"] == []

    def test_items_with_signoffs_float_to_top(self):
        runs = {"finance_cash13w": [_Run(1, "f", "done", 5.0)],  # awaiting
                "risk_x": [_Run(2, "r", "running", 6.0)]}        # not
        m = build_inbox([_RISK, _FORECAST], runs)  # risk first by input order
        assert m["items"][0]["domain"] == "finance_cash13w"     # floated up

    def test_signed_off_run_drops_out_of_awaiting(self):
        runs = {"finance_cash13w": [_Run(7, "Refresh forecast", "done", 100.0)]}
        # finished + gated, but reviewed -> no longer awaiting
        m = build_inbox([_FORECAST], runs, signoffs={7: "approved"})
        assert m["awaiting"] == []
        assert m["items"][0]["awaiting_count"] == 0
        assert m["items"][0]["runs"][0]["signoff"] == "approved"

    def test_mine_defaults_to_my_roles(self):
        # No explicit role + my roles -> only deliverables I consume, flagged.
        m = build_inbox([_FORECAST, _RISK], {}, mine={"risk_officer"})
        assert [it["domain"] for it in m["items"]] == ["risk_x"]
        assert m["showing_mine"] is True
        assert m["mine"] == ["risk_officer"]

    def test_explicit_role_overrides_mine(self):
        m = build_inbox([_FORECAST, _RISK], {}, role="fpa_analyst", mine={"risk_officer"})
        assert [it["domain"] for it in m["items"]] == ["finance_cash13w"]
        assert m["showing_mine"] is False     # an explicit chip wins over the default
        assert m["roles"] == ["fpa_analyst", "risk_officer", "treasurer"]  # all roles, for the filter


class TestPersonaRoles:
    def _cfg(self, monkeypatch, cfg):
        monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: cfg)

    def test_principal_mapping_wins(self, monkeypatch):
        self._cfg(monkeypatch, {"personas": {"user:alice": ["fpa_analyst", "treasurer"],
                                             "default": ["viewer_role"]}})
        assert persona_roles_for("user:alice") == ["fpa_analyst", "treasurer"]

    def test_falls_back_to_default(self, monkeypatch):
        self._cfg(monkeypatch, {"personas": {"default": ["risk_officer"]}})
        assert persona_roles_for("user:nobody") == ["risk_officer"]
        assert persona_roles_for(None) == ["risk_officer"]  # no-auth single user

    def test_string_is_coerced_to_list(self, monkeypatch):
        self._cfg(monkeypatch, {"personas": {"default": "controller"}})
        assert persona_roles_for(None) == ["controller"]

    def test_no_binding_is_empty(self, monkeypatch):
        self._cfg(monkeypatch, {})
        assert persona_roles_for("user:alice") == []


class TestDeliverablesPage:
    def _world(self, tmp_path, monkeypatch):
        from maverick import world_model
        monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
        return world_model.WorldModel(tmp_path / "world.db")

    def test_page_renders_with_filter_chips(self, tmp_path, monkeypatch):
        self._world(tmp_path, monkeypatch)
        r = client.get("/deliverables")
        assert r.status_code == 200
        assert "Results · Lightwork" in r.text   # the page is labelled Results
        # Nothing has run yet: a real empty state, not the catalogue.
        assert "No results yet" in r.text
        # The catalogue is still one click away (?role=all): finance_cash13w
        # ships a contract, so its consumers show as filter chips there.
        r = client.get("/deliverables?role=all")
        assert "fpa_analyst" in r.text
        assert "13-week cash forecast" in r.text

    def test_finished_forecast_shows_in_signoff_queue(self, tmp_path, monkeypatch):
        w = self._world(tmp_path, monkeypatch)
        gid = w.create_goal("Refresh the cash forecast", "", domain="finance_cash13w")
        w.set_goal_status(gid, "done", result="| Week | Net |\n| --- | --- |\n| W1 | 10 |\n")
        t = client.get("/deliverables").text
        assert "Awaiting approval" in t
        assert f'href="/chat/goal/{gid}"' in t   # Review links to the deliverable view

    def test_default_results_show_only_the_local_owner_finished_root_work(self, tmp_path, monkeypatch):
        w = self._world(tmp_path, monkeypatch)
        own = w.create_goal("My finished report", "")
        w.set_goal_status(own, "done", result="Report")
        other = w.create_goal("Another person's report", "", owner="user:other")
        w.set_goal_status(other, "done", result="Private")
        w.create_goal("My unfinished work", "")
        child = w.create_goal("Internal subtask", "", parent_id=own)
        w.set_goal_status(child, "done", result="Internal result")

        page = client.get("/deliverables").text
        assert "My finished report" in page
        assert "Another person's report" not in page
        assert "My unfinished work" not in page
        assert "Internal subtask" not in page
        assert f'href="/chat/goal/{own}"' in page

    def test_role_filter_narrows_and_can_empty(self, tmp_path, monkeypatch):
        self._world(tmp_path, monkeypatch)
        # a role nobody consumes -> empty state, not a 500
        r = client.get("/deliverables?role=nobody_consumes_this")
        assert r.status_code == 200
        assert "No results for Nobody consumes this" in r.text
        # the real consumer keeps the forecast visible
        assert "13-week cash forecast" in client.get("/deliverables?role=fpa_analyst").text

    def test_persona_identity_defaults_inbox_to_my_roles(self, tmp_path, monkeypatch):
        w = self._world(tmp_path, monkeypatch)
        # The default Results page shows completed work even when the caller
        # has a persona role; the explicit catalog keeps its role filters.
        monkeypatch.setattr("maverick.config.load_config",
                            lambda *a, **k: {"personas": {"default": ["tax_analyst"]}})
        gid = w.create_goal("Draft a welcome email", "")
        w.set_goal_status(gid, "done", result="Welcome!")
        t = client.get("/deliverables").text
        assert "Draft a welcome email" in t
        assert f'href="/chat/goal/{gid}"' in t
        assert "Browse what agents and specialists can produce" in t
        assert "13-week cash forecast" not in t
        # A role link still narrows the specialist catalog.
        assert "Tax provision" in client.get("/deliverables?role=tax_analyst").text
        t_all = client.get("/deliverables?role=all").text
        assert "13-week cash forecast" in t_all


def test_deliverables_page_shows_plain_role_names(tmp_path, monkeypatch):
    """Role keys stay in the link and picker values; people read names."""
    TestDeliverablesPage()._world(tmp_path, monkeypatch)
    r = client.get("/deliverables?role=all")
    assert r.status_code == 200
    assert 'id="dlv-role-pick"' in r.text
    assert "<datalist" not in r.text
    from test_support.element_text import element_texts
    from test_support.plain_language import visible_text

    page_text = visible_text(r.text)
    assert "{{" not in page_text
    badges = element_texts(r.text, "span", {"class": "badge"})
    assert badges and all(not label.endswith(" gate") for label in badges)
    assert element_texts(r.text, "option", {"value": "fpa_analyst"}) == ["Fpa analyst"]
    assert "fpa_analyst" not in page_text
