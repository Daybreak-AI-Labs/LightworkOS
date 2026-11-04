"""Govern → Assessments: the register page + the draft / review / export API."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


def _an_agent(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.domain_edit import list_agents
    agents = list_agents()
    return agents[0]["name"] if agents else None


def test_page_renders(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/assessments")
    assert r.status_code == 200
    import re
    assert re.search(r'<h1 class="page-title[^"]*"[^>]*>Assessments', r.text)
    assert "Assess a subject" in r.text


def test_empty_register(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    j = _client().get("/api/v1/assessments").json()
    assert j["assessments"] == []
    assert "baseline" in j["templates"]


def test_draft_review_and_export(monkeypatch, tmp_path):
    name = _an_agent(monkeypatch, tmp_path)
    if not name:
        import pytest
        pytest.skip("no packs discovered")
    c = _client()
    # Draft
    r = c.post(
        f"/api/v1/assessments/agent/{name}/refresh",
        json={"expected_revision": 0},
    )
    assert r.status_code == 200
    a = r.json()
    assert a["kind"] == "agent" and a["subject"] == name
    assert set(a["lenses"]) == {"privacy", "security", "ai_risk"}
    # It shows up in the register
    lst = c.get("/api/v1/assessments").json()["assessments"]
    assert any(x["subject"] == name for x in lst)
    # Review each lens -> reviewed
    revision = a["revision"]
    for lens in ("privacy", "security", "ai_risk"):
        rr = c.post(f"/api/v1/assessments/agent/{name}/review",
                    json={"expected_revision": revision, "lens": lens,
                          "decision": "accepted", "cadence_days": 90})
        assert rr.status_code == 200
        revision = rr.json()["revision"]
    assert c.get(f"/api/v1/assessments/agent/{name}").json()["status"] == "reviewed"
    # CSV export contains the subject
    csv = c.get("/api/v1/assessments/export?format=csv")
    assert csv.status_code == 200 and "text/csv" in csv.headers["content-type"]
    assert name in csv.text


def test_review_rejects_bad_lens(monkeypatch, tmp_path):
    name = _an_agent(monkeypatch, tmp_path)
    if not name:
        import pytest
        pytest.skip("no packs discovered")
    c = _client()
    current = c.post(
        f"/api/v1/assessments/agent/{name}/refresh",
        json={"expected_revision": 0},
    ).json()
    r = c.post(f"/api/v1/assessments/agent/{name}/review",
               json={"expected_revision": current["revision"],
                     "lens": "nonsense", "decision": "accepted"})
    assert r.status_code == 422  # schema pattern rejects it


def test_stale_assessment_mutations_conflict_without_overwriting(monkeypatch, tmp_path):
    name = _an_agent(monkeypatch, tmp_path)
    if not name:
        import pytest

        pytest.skip("no packs discovered")
    c = _client()
    created = c.post(
        f"/api/v1/assessments/agent/{name}/refresh",
        json={"expected_revision": 0},
    ).json()
    stale_revision = created["revision"]
    advanced = c.post(
        f"/api/v1/assessments/agent/{name}/review",
        json={
            "expected_revision": stale_revision,
            "lens": "privacy",
            "decision": "needs_work",
        },
    )
    assert advanced.status_code == 200

    stale_requests = (
        c.post(
            f"/api/v1/assessments/agent/{name}/refresh",
            json={"expected_revision": stale_revision},
        ),
        c.post(
            f"/api/v1/assessments/agent/{name}/review",
            json={
                "expected_revision": stale_revision,
                "lens": "security",
                "decision": "accepted",
            },
        ),
        c.post(
            f"/api/v1/assessments/agent/{name}/evidence",
            json={
                "expected_revision": stale_revision,
                "lens": "privacy",
                "control": created["lenses"]["privacy"]["findings"][0]["control"],
                "evidence": "stale reviewer note",
            },
        ),
        c.delete(
            f"/api/v1/assessments/agent/{name}",
            params={"expected_revision": stale_revision},
        ),
    )
    assert [response.status_code for response in stale_requests] == [409, 409, 409, 409]
    latest = c.get(f"/api/v1/assessments/agent/{name}").json()
    assert latest["revision"] == advanced.json()["revision"]
    assert latest["lenses"]["security"]["status"] != "accepted"


def test_sweep_endpoint(monkeypatch, tmp_path):
    name = _an_agent(monkeypatch, tmp_path)
    if not name:
        import pytest
        pytest.skip("no packs discovered")
    c = _client()
    c.post(
        f"/api/v1/assessments/agent/{name}/refresh",
        json={"expected_revision": 0},
    )
    r = c.post("/api/v1/assessments/sweep", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["refreshed"] >= 1 and "due" in body


def test_refresh_unknown_agent_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().post(
        "/api/v1/assessments/agent/____nope____/refresh",
        json={"expected_revision": 0},
    )
    assert r.status_code == 404


def test_bad_kind_400(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().post(
        "/api/v1/assessments/widget/x/refresh",
        json={"expected_revision": 0},
    )
    assert r.status_code == 400


def test_page_uses_selectors_and_plain_language(monkeypatch, tmp_path):
    import re

    _isolate(monkeypatch, tmp_path)
    body = _client().get("/assessments").text
    main = body.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    # Agent job titles ("Sequencing & Cadence Specialist") are business words;
    # the agent list is checked separately for readable, grouped names.
    agents = main.split('<select id="as-agent"', 1)[1].split("</select>", 1)[0]
    assert "<optgroup label=" in agents
    assert all("_" not in label for label in re.findall(r'<option value="[^"]+">([^<]+)</option>', agents))
    text = re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style)\b.*?</\1>", " ", main.replace(agents, ""), flags=re.DOTALL))
    assert re.search(r"\b(JSON|lens|cadence|HTTP \d{3})\b", text, re.IGNORECASE) is None
    assert '<select id="as-agent"' in body and "<datalist" not in body
    assert "format=json" not in body and "Download spreadsheet" in text
    script = main[main.index('<script nonce="'):]
    for label in ("Approve ' + esc", "Add evidence", "Review again", "Every 6 months"):
        assert label in script
    assert "replace('_', ' ')" not in script and "(HTTP " not in script
