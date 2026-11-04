"""The Finance workspace: the department chassis (worklist, stats, memory,
catalog, shared review pop-out) over the finance assessment types — and the
department isolation between /finance and /privacy."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    api._world_cache.clear()


def _seed(type="sox_control", subject="Q3 revenue controls"):
    from maverick.assessment import TEMPLATES, AssessmentSession, save_session
    s = AssessmentSession(type=type, subject=subject)
    s.record(TEMPLATES[type].questions[0].id, "yes")
    save_session(s)
    return s


def test_page_renders_finance_worklist_and_catalog():
    _seed("sox_control", "Q3 revenue controls")
    resp = client.get("/finance")
    assert resp.status_code == 200
    html = resp.text
    assert "Q3 revenue controls" in html
    assert 'class="btn pw-review-btn"' in html
    # The shared pop-out rides the chassis.
    assert 'id="arv-dialog"' in html
    # The catalog lists the FINANCE frameworks — and only those.
    for label in ("SOX Control Assessment", "Fraud Risk Assessment",
                  "IT General Controls Assessment"):
        assert label in html, label
    assert "Privacy Impact Assessment" not in html
    # No privacy-records UI on the finance chassis.
    assert "Privacy records" not in html and "open DSARs" not in html
    assert "Automated finance checks" in html
    assert 'data-module-gate="finance_operations"' in html
    assert "[finance_operations] enable = true" not in html


def test_department_isolation():
    _seed("sox_control", "Q3 revenue controls")
    from maverick.assessment import AssessmentSession, save_session
    p = AssessmentSession(type="pia", subject="Acme CRM")
    p.record("pia_transfers", "yes")
    save_session(p)
    finance_html = client.get("/finance").text
    privacy_html = client.get("/privacy").text
    # Each worklist carries its own department's records only.
    assert "Q3 revenue controls" in finance_html
    assert "Acme CRM" not in finance_html
    assert "Acme CRM" in privacy_html
    assert "Q3 revenue controls" not in privacy_html


def test_page_empty_state():
    resp = client.get("/finance")
    assert resp.status_code == 200
    assert "No assessments yet" in resp.text


def test_enabled_operations_render_honest_licensing_and_review_boundaries(tmp_path):
    from maverick import config

    (tmp_path / "config.toml").write_text(
        """[finance_operations]
enable = true
regulatory_poll_seconds = 0
control_test_interval_seconds = 0
""",
        encoding="utf-8",
    )
    config.reset_config_cache()
    response = client.get("/finance")
    assert response.status_code == 200
    html = response.text
    assert "Regulation changes to review" in html
    assert "State licensing guides" in html
    # The legal caveat stays, in plain words.
    assert "Always confirm" in html and "with the regulator or your lawyer" in html
    assert "Unusual payments" in html
    assert "Anti-money-laundering, customer checks and sanctions" in html
    assert "two different reviewers agree" in html
    assert "never mark themselves as passed or failed" in html
    assert "sha256:" not in html and "source_check_required" not in html
