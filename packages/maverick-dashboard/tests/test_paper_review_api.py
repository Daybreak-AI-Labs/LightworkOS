"""Vendor-paper review in the product (not just the demo): upload, redline
download, the clause playbook, and assessment assignment."""
from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

DOCX_MIME = ("application/vnd.openxmlformats-officedocument"
             ".wordprocessingml.document")

VENDOR_DPA = [
    "DATA PROCESSING AGREEMENT",
    "Entered into pursuant to Article 28 GDPR.",
    "1. Processor shall process personal data only on documented instructions "
    "from the Controller.",
    "2. Processor may engage sub-processors at its sole discretion without "
    "notice to the Controller.",
]


@pytest.fixture(autouse=True)
def _fresh(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text(
        "[paper_review]\nuse_model = false\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    api._world_cache.clear()


def _docx(paragraphs: list[str]) -> bytes:
    from maverick import docx_redline as dr
    body = "".join(
        f'<w:p><w:r><w:t xml:space="preserve">{p}</w:t></w:r></w:p>'
        for p in paragraphs)
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           f'<w:document xmlns:w="{dr._W_NS}"><w:body>{body}{dr._SECT_PR}'
           "</w:body></w:document>")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", dr._CONTENT_TYPES)
        z.writestr("_rels/.rels", dr._ROOT_RELS)
        z.writestr("word/_rels/document.xml.rels", dr._DOCUMENT_RELS)
        z.writestr("word/settings.xml", dr._SETTINGS)
        z.writestr("word/document.xml", doc)
    return buf.getvalue()


def _upload(vendor="Acme Corp", paragraphs=None, name="Acme-DPA.docx",
            mime=DOCX_MIME, data=None):
    payload = data if data is not None else _docx(paragraphs or VENDOR_DPA)
    return client.post(
        "/api/v1/privacy/paper-reviews",
        files={"file": (name, payload, mime)},
        data={"vendor": vendor})


# --- the review round -----------------------------------------------------

def test_upload_produces_a_review_a_memo_and_a_redline():
    r = _upload()
    assert r.status_code == 201, r.text
    rec = r.json()
    assert rec["instrument"] == "dpa"
    assert rec["version"] == 1
    assert rec["gaps"] >= 1 and rec["high_severity_gaps"] >= 1
    assert rec["recommendation"] == "do_not_sign_without_changes"
    assert rec["redline_bytes"] > 500
    assert len(rec["redline"]["source_sha256"]) == 64
    assert rec["redline"]["edit_results"]
    assert all(outcome["scope"] == "paragraph" for outcome in rec["redline"]["edit_results"])

    # The memo quotes their actual wording and states the governance line.
    memo = client.get(f"/api/v1/privacy/paper-reviews/{rec['id']}/memo")
    assert memo.status_code == 200
    assert "sole discretion" in memo.text
    assert "a model cannot create or clear a finding" in memo.text
    assert f"(v{rec['version']})" in memo.text

    # The redline downloads as a real tracked-changes Word package.
    dl = client.get(f"/api/v1/privacy/paper-reviews/{rec['id']}/redline")
    assert dl.status_code == 200
    assert dl.headers["content-type"].startswith(DOCX_MIME)
    assert "attachment; filename=" in dl.headers["content-disposition"]
    from maverick import docx_redline as dr
    ins, dels = dr.revision_count(dl.content)
    assert ins >= 1 and dels >= 1


def test_versions_increment_per_vendor_and_instrument():
    a = _upload().json()
    b = _upload().json()
    assert (a["version"], b["version"]) == (1, 2)
    # A different vendor starts its own history.
    c = _upload(vendor="Globex").json()
    assert c["version"] == 1


def test_listing_and_fetch_round_trip():
    rec = _upload().json()
    rows = client.get("/api/v1/privacy/paper-reviews").json()["reviews"]
    assert any(r["id"] == rec["id"] for r in rows)
    got = client.get(f"/api/v1/privacy/paper-reviews/{rec['id']}")
    assert got.status_code == 200 and got.json()["vendor"] == "Acme Corp"
    assert client.get("/api/v1/privacy/paper-reviews/nope").status_code == 404
    assert client.get(
        "/api/v1/privacy/paper-reviews/nope/redline").status_code == 404


def test_unsupported_and_unreadable_uploads_are_refused():
    bad = _upload(name="notes.txt", mime="text/plain", data=b"hello")
    assert bad.status_code == 400 and "Word" in bad.json()["detail"]
    # A .docx that parses but yields no text must not be "reviewed" — that
    # would report every clause missing about a document we never read.
    empty = _upload(name="scanned.docx", data=_docx([]))
    assert empty.status_code == 422 and "no text" in empty.json()["detail"]


# --- the clause playbook (the setup path) ---------------------------------

def test_playbook_starts_shipped_and_can_be_customised():
    got = client.get("/api/v1/privacy/clause-playbook").json()
    assert got["customised"] == []
    assert "subprocessors" in got["positions"]

    mine = ("Supplier shall not appoint any Sub-Processor without Customer's "
            "prior written consent and shall impose equivalent obligations.")
    r = client.post("/api/v1/privacy/clause-playbook",
                    json={"positions": {"subprocessors": mine}})
    assert r.status_code == 200, r.text
    assert r.json()["customised"] == ["subprocessors"]

    after = client.get("/api/v1/privacy/clause-playbook").json()
    assert after["positions"]["subprocessors"] == mine
    # Clauses left alone keep the shipped position.
    assert after["positions"]["audit"] == after["shipped"]["audit"]


def test_playbook_drives_the_redline_language():
    mine = ("Supplier shall not appoint any Sub-Processor without Customer's "
            "prior written consent and shall impose equivalent obligations.")
    client.post("/api/v1/privacy/clause-playbook",
                json={"positions": {"subprocessors": mine}})
    rec = _upload().json()
    memo = client.get(f"/api/v1/privacy/paper-reviews/{rec['id']}/memo").text
    assert "Supplier shall not appoint any Sub-Processor" in memo


def test_playbook_rejects_unknown_clause_ids():
    r = client.post("/api/v1/privacy/clause-playbook",
                    json={"positions": {"not_a_clause": "..."}})
    assert r.status_code == 400 and "unknown clause" in r.json()["detail"]


# --- assignment -----------------------------------------------------------

def _saved_assessment() -> dict:
    from maverick.assessment import AssessmentSession, save_session
    s = AssessmentSession()
    s.restart("pia", "Acme CRM")
    for q in s.template().questions:
        s.record(q.id, "yes")
    save_session(s)
    from maverick.assessment import list_saved
    return list_saved()[0]


def test_assign_and_unassign_an_assessment():
    row = _saved_assessment()
    r = client.post(f"/api/v1/assess/sessions/{row['id']}/assign",
                    json={"assignee": "A. Novak",
                          "expected_revision": row["revision"]})
    assert r.status_code == 200, r.text
    assert r.json()["assignee"] == "A. Novak"

    from maverick.assessment import list_saved
    after = list_saved()[0]
    assert after["assignee"] == "A. Novak"

    # Blank returns it to the pool.
    r = client.post(f"/api/v1/assess/sessions/{row['id']}/assign",
                    json={"assignee": "", "expected_revision": after["revision"]})
    assert r.status_code == 200
    assert not r.json().get("assignee")
    assert list_saved()[0]["assignee"] == ""


def test_assign_is_revision_guarded():
    row = _saved_assessment()
    client.post(f"/api/v1/assess/sessions/{row['id']}/assign",
                json={"assignee": "A. Novak",
                      "expected_revision": row["revision"]})
    # A stale page must lose rather than clobber the newer state.
    stale = client.post(f"/api/v1/assess/sessions/{row['id']}/assign",
                        json={"assignee": "Someone Else",
                              "expected_revision": row["revision"]})
    assert stale.status_code == 409


def test_assign_unknown_assessment_is_404():
    assert client.post("/api/v1/assess/sessions/nope/assign",
                       json={"assignee": "X", "expected_revision": 1}
                       ).status_code == 404


def test_privacy_page_renders_the_vendor_paper_tab():
    page = client.get("/privacy")
    assert page.status_code == 200
    assert "Vendor paper" in page.text
    assert "pw-paper-form" in page.text
    # The worklist gained an owner column and the two ownership filters.
    assert "Mine (" in page.text and "Unassigned (" in page.text


# --- our-paper drafter + the negotiation round-trip ------------------------

def test_our_paper_draft_downloads_with_red_fills():
    r = client.get("/api/v1/privacy/our-paper",
                   params={"vendor": "Acme Corp", "instrument": "dpa"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith(DOCX_MIME)
    assert 'filename="Acme Corp-dpa-our-paper.docx"' \
        in r.headers["content-disposition"]
    doc = zipfile.ZipFile(io.BytesIO(r.content)).read(
        "word/document.xml").decode()
    from maverick.docx_redline import FILL_COLOR, revision_count
    assert doc.count(f'w:val="{FILL_COLOR}"') >= 5
    # The vendor value is filled; the unset org stays a red placeholder.
    assert "Acme Corp" in doc and "[CONTROLLER LEGAL ENTITY]" in doc
    # A draft is a clean document, not fabricated tracked changes.
    assert revision_count(r.content) == (0, 0)
    assert client.get("/api/v1/privacy/our-paper",
                      params={"vendor": "x", "instrument": "nda"}
                      ).status_code == 400


def test_our_paper_unicode_vendor_uses_rfc5987_filename():
    response = client.get(
        "/api/v1/privacy/our-paper",
        params={"vendor": "資料", "instrument": "dpa"},
    )

    assert response.status_code == 200
    disposition = response.headers["content-disposition"]
    assert "filename*=UTF-8''%E8%B3%87%E6%96%99-dpa-our-paper.docx" in disposition


def test_renegotiated_draft_reports_which_demands_were_accepted():
    first = _upload().json()
    assert first["gaps"] >= 2
    assert first["previous_version"] == 0
    # v2: they accepted our sub-processor clause verbatim, kept the rest.
    from maverick.paper_review import OUR_POSITIONS
    v2 = _upload(paragraphs=VENDOR_DPA[:2] + [
        VENDOR_DPA[2], OUR_POSITIONS["subprocessors"]]).json()
    assert v2["version"] == 2 and v2["previous_version"] == 1
    assert ("Sub-processor authorization and flow-down"
            in v2["closed_from_previous"])
    assert v2["gaps"] < first["gaps"]
    memo = client.get(
        f"/api/v1/privacy/paper-reviews/{v2['id']}/memo").text
    assert "NEGOTIATION PROGRESS" in memo
    assert "+ Sub-processor authorization and flow-down" in memo
