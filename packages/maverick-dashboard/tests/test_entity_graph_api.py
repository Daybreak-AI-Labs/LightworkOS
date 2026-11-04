"""The entity graph in the product: the three regulator queries over HTTP,
and the Lineage tab on the privacy workspace."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _fresh(tmp_path, monkeypatch):
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


def _seed_vendor_story():
    """One vendor with a paper review and an approved assessment."""
    from maverick.assessment import (
        AssessmentSession,
        decide_assessment,
        save_session,
    )
    from maverick.paper_review import review_paper
    from maverick.privacy_ops import save_paper_review
    review = review_paper(
        "DATA PROCESSING AGREEMENT under Article 28 GDPR.\n"
        "Processor may engage sub-processors at its sole discretion.\n",
        vendor="Acme Corp", document_name="acme-dpa.docx", use_model=False)
    save_paper_review(review, redline=b"PK-fake", reviewed_by="A. Novak",
                      redline_filename="acme-dpa-redline.docx")
    s = AssessmentSession()
    s.restart("vendor_risk", "Acme Corp")
    for q in s.template().questions:
        s.record(q.id, "yes")
    save_session(s)
    decide_assessment(s.id, "approved", decided_by="dpo", cadence_days=365)
    return s.id


def test_dossier_endpoint_returns_the_governed_picture():
    _seed_vendor_story()
    client.post("/api/v1/graph/rebuild")
    r = client.get("/api/v1/graph/dossier", params={"vendor": "acme corp."})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["found"]                      # spelling variant resolves
    s = body["summary"]
    assert any(x["record_type"] == "paper_review" for x in s["reviews"])
    assert any(d["decision"] == "approved" for d in s["decisions"])
    assert "subprocessors" in s["open_clause_gaps"]


def test_why_endpoint_cites_a_record_on_every_hop():
    aid = _seed_vendor_story()
    client.post("/api/v1/graph/rebuild")
    body = client.get("/api/v1/graph/why",
                      params={"vendor": "Acme Corp"}).json()
    assert body["decision"] and "approved by dpo" in body["decision"]["what"]
    assert all(step["record_id"] for step in body["chain"])
    assert any(step["record_id"] == aid for step in body["chain"])


def test_blast_radius_endpoint_and_kind_validation():
    _seed_vendor_story()
    client.post("/api/v1/graph/rebuild")
    body = client.get("/api/v1/graph/blast-radius",
                      params={"kind": "clause",
                              "name": "subprocessors"}).json()
    assert "Acme Corp" in body["vendors"]
    assert any(d["decision"] == "approved" for d in body["decisions"])
    assert client.get("/api/v1/graph/blast-radius",
                      params={"kind": "sock", "name": "x"}).status_code == 400


def test_as_of_accepts_a_date_and_rejects_garbage():
    _seed_vendor_story()
    client.post("/api/v1/graph/rebuild")
    ok = client.get("/api/v1/graph/dossier",
                    params={"vendor": "Acme Corp", "as_of": "2020-01-01"})
    assert ok.status_code == 200
    # Before any record existed, the graph knew nothing about the vendor.
    assert ok.json()["found"] is False or not ok.json()["summary"]["reviews"]
    bad = client.get("/api/v1/graph/dossier",
                     params={"vendor": "Acme Corp", "as_of": "yesterday"})
    assert bad.status_code == 400


def test_disabled_graph_is_403(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[entity_graph]\nenable = false\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    from maverick import config
    config.reset_config_cache()
    assert client.get("/api/v1/graph/dossier",
                      params={"vendor": "x"}).status_code == 403
    assert client.post("/api/v1/graph/rebuild").status_code == 403


def test_privacy_page_renders_the_lineage_tab():
    page = client.get("/privacy")
    assert page.status_code == 200
    assert "Lineage" in page.text
    assert "Why was it approved?" in page.text
    assert "Show what depends on it" in page.text
