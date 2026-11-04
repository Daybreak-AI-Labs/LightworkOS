"""The /automations control page: one place to see/manage schedules + triggers.

The page is client-rendered (it fetches the existing /api/v1/schedules and
/api/v1/triggers); these tests cover the route, the feature gating of each
section, and the nav entry. The endpoints themselves are covered by
test_schedules.py / test_triggers.py.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


def test_page_renders_both_sections(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/automations")
    assert r.status_code == 200
    assert "Automations" in r.text
    assert 'id="auto-sched-list"' in r.text and "/api/v1/schedules" in r.text
    assert 'id="auto-trig-list"' in r.text and "/api/v1/triggers" in r.text


def test_sections_hidden_when_features_off(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import config
    real = config.get_features
    monkeypatch.setattr(
        config, "get_features",
        lambda: {**real(), "scheduling": False, "triggers": False})
    r = _client().get("/automations")
    assert r.status_code == 200
    assert 'id="auto-sched-list"' not in r.text
    assert 'id="auto-trig-list"' not in r.text
    assert "Automations are turned off" in r.text


def test_one_section_when_only_scheduling_on(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import config
    real = config.get_features
    monkeypatch.setattr(
        config, "get_features", lambda: {**real(), "triggers": False})
    r = _client().get("/automations")
    assert 'id="auto-sched-list"' in r.text          # scheduling stays
    assert 'id="auto-trig-list"' not in r.text         # triggers hidden
    assert "Automations are disabled" not in r.text


def test_automation_runs_validates_input(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    # an unknown kind is a 400
    assert c.get("/api/v1/automation-runs",
                 params={"kind": "bogus", "ref": "x"}).status_code == 400
    # an empty ref is an empty result, not an error (and touches no DB)
    r = c.get("/api/v1/automation-runs", params={"kind": "schedule", "ref": ""})
    assert r.status_code == 200
    assert r.json() == {"runs": [], "summary": {}}


def test_page_includes_run_history_loader(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    # the page wires the provenance endpoint for per-automation run history
    assert "/api/v1/automation-runs" in _client().get("/automations").text


def test_empty_states_use_shared_component(monkeypatch, tmp_path):
    # The schedule/trigger empties now use the shared .mv-empty component.
    _isolate(monkeypatch, tmp_path)
    t = _client().get("/automations").text
    assert 'class="mv-empty" id="auto-sched-empty"' in t
    assert 'class="mv-empty" id="auto-trig-empty"' in t


def test_run_history_links_drill_into_trajectory(monkeypatch, tmp_path):
    # Run-history entries link to each goal's trajectory ("what it did").
    _isolate(monkeypatch, tmp_path)
    assert "/trajectory" in _client().get("/automations").text


def test_templates_page_shows_automate_cta(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick_dashboard.app as appmod
    monkeypatch.setattr(appmod, "template_market_entries",
                        lambda owner=None: [{"name": "weekly-report", "title": "T", "body": "b", "params": []}])
    r = _client().get("/templates")
    assert r.status_code == 200
    assert "/workflow-builder?template=weekly-report" in r.text


def test_templates_rebuilt_on_shared_components(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick_dashboard.app as appmod
    monkeypatch.setattr(appmod, "template_market_entries",
                        lambda owner=None: [{"name": "x", "title": "T", "body": "b", "params": []}])
    t = _client().get("/templates").text
    assert 'class="card-grid"' in t and 'class="card"' in t      # shared card components
    assert 'class="btn btn--primary"' in t                        # Use = a real primary button


def test_templates_empty_uses_mv_empty(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick_dashboard.app as appmod
    monkeypatch.setattr(appmod, "template_market_entries", lambda owner=None: [])
    t = _client().get("/templates").text
    assert 'class="mv-empty"' in t and "No templates yet" in t


def test_shared_card_motion_gated_by_reduced_motion(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    css = _client().get("/static/lightwork.css").text
    assert "@keyframes mv-rise" in css and "animation: mv-rise" in css
    assert "prefers-reduced-motion: reduce) { .mv-toast, .mv-row, .card" in css


def test_templates_page_shows_edit_cta(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick_dashboard.app as appmod
    monkeypatch.setattr(appmod, "template_market_entries",
                        lambda owner=None: [{"name": "weekly-report", "title": "T", "body": "b", "params": []}])
    assert "/workflow-builder?edit=weekly-report" in _client().get("/templates").text


def test_templates_automate_cta_hidden_when_automation_off(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick_dashboard.app as appmod
    monkeypatch.setattr(appmod, "template_market_entries",
                        lambda owner=None: [{"name": "x", "title": "T", "body": "b", "params": []}])
    from maverick import config
    real = config.get_features
    monkeypatch.setattr(config, "get_features",
                        lambda: {**real(), "scheduling": False, "triggers": False})
    assert "/workflow-builder?template=" not in _client().get("/templates").text


def test_automations_page_uses_danger_token_run_history_error_and_shared_title(monkeypatch, tmp_path):
    # Design-system details visible on this page and via base.html.
    _isolate(monkeypatch, tmp_path)
    t = _client().get("/automations").text
    assert "#d92d20" not in t                          # failed runs use --danger, not raw hex
    assert "Run history unavailable" in t              # loadRuns surfaces fetch failure
    assert 'class="page-title hero-title"' in t        # shared title scale via the page hero
    assert 'id="auto-sched-h" tabindex="-1"' in t      # focus landing after a row is deleted
    # base.html primitives: assertive error region + mvConfirm focus-return
    # (the behavior itself ships from the extracted shell script)
    assert 'id="mv-toasts-alert"' in t and 'aria-live="assertive"' in t
    ui = _client().get("/static/lightwork-ui.js").text
    assert "opener" in ui and "isConnected" in ui
    assert 'id="i-clock"' in t and "#i-clock" in t     # Automations has its own nav icon


def test_scrim_token_copy_helper_and_stop_confirm_are_shared(monkeypatch, tmp_path):
    # One --scrim token (defined + used), mvCopy shipped, and the killswitch
    # uses mvConfirm rather than native confirm().
    _isolate(monkeypatch, tmp_path)
    css = _client().get("/static/lightwork.css").text
    assert "--scrim:" in css and "var(--scrim)" in css
    ui = _client().get("/static/lightwork-ui.js").text
    assert "window.mvCopy" in ui
    # The verified stop scope selects the consequence before localization.
    assert "mvConfirm(consequence, { productCopy: true, okText: 'Stop work' })" in ui


def test_templates_use_shared_dialogs_not_native_confirm_or_alert():
    # Guard against native confirm()/alert() creeping back into these pages.
    import pathlib
    base = pathlib.Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"
    for f in ["base.html", "chat_goal.html", "fleets.html", "learned.html"]:
        src = (base / f).read_text(encoding="utf-8")
        assert "confirm('" not in src and 'confirm("' not in src, f
        assert "alert('" not in src and 'alert("' not in src, f


def test_base_provides_shared_confirm_and_toast(monkeypatch, tmp_path):
    # The reusable feedback primitives ship from base.html on every page.
    _isolate(monkeypatch, tmp_path)
    t = _client().get("/automations").text
    assert 'id="mv-confirm"' in t and 'id="mv-toasts"' in t
    assert '/static/lightwork-ui.js' in t
    ui = _client().get("/static/lightwork-ui.js").text
    assert "window.mvConfirm" in ui and "window.mvToast" in ui


def test_nav_has_automations_link(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    # The primary nav renders on every page, so the page links to itself.
    assert 'href="/automations"' in _client().get("/automations").text


def test_automations_page_reads_plainly(monkeypatch, tmp_path):
    from test_support.plain_language import developer_terms

    _isolate(monkeypatch, tmp_path)
    t = _client().get("/automations").text
    assert developer_terms(t) == []
    for phrase in ("Source settings (JSON)", "Exported definitions (JSON)",
                   "Authorization code", "Approve exact operation", "credential_inventory_sha256"):
        assert phrase not in t
    # Schedules are described in words, not timetable codes.
    assert "function cronText" in t and "Weekdays" in t and "On a custom timetable" in t
