"""The tax preparation suite on the Finance page: first draft, firm
readiness, accuracy on past returns and the signed tax tables. Permissions,
behaviour and plain wording."""
from __future__ import annotations

import html as _html
import io
import json
import re
import zipfile

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
_BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
    r"idempoten\w*|lease|toml|yaml|stdout|traceback)\b|/api/v1|HTTP \d{3}|maverick |MAVERICK_|config\.toml",
    re.IGNORECASE,
)
_W2 = ("Form W-2 Wage and Tax Statement\nEmployer: Acme\n"
       "Box 1 Wages, tips, other compensation $55,000.00\n"
       "Box 2 Federal income tax withheld $6,000.00\nBox 15 State TX\n")


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    main = re.sub(r"<[^>]+>", " ", main)
    return _html.unescape(re.sub(r"\s+", " ", main))


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_CLIENT_ID"):
        monkeypatch.delenv(name, raising=False)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    config.reset_config_cache()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


def _as(monkeypatch, role: str, who: str = "user:someone"):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _bundle(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    return buffer.getvalue()


# ---- Tax preparation --------------------------------------------------------------

def test_tax_draft_readiness_and_permissions(client, monkeypatch):
    status = client.get("/api/v1/tax").json()
    assert status["tables"] == "Built-in tables" and "TX" in status["states"]
    draft = client.post("/api/v1/tax/prepare", json={"documents": [{"name": "w2.txt", "text": _W2}]}).json()
    assert draft["total_income"] == 55000.0 and draft["refund"] is True
    assert draft["documents"] == [{"name": "w2.txt", "type": "W-2", "check": False}]
    assert draft["state"]["code"] == "TX"
    ready = client.post("/api/v1/tax/readiness", json={
        "firm": "Smith & Co", "states": ["TX", "ZZ"], "clients": 5, "forms": ["W-2"],
        "names": [{"label": "Wage slip", "type": "W-2"}]}).json()
    assert ready["ready"] is False and ready["drafted_states"] == ["TX"]
    assert any("ZZ" in c["text"] for c in ready["checks"])
    for check in ready["checks"]:
        assert not _BANNED.search(check["text"]) and "--" not in check["text"]
    _as(monkeypatch, "viewer")
    assert client.get("/api/v1/tax").status_code == 200
    assert client.post("/api/v1/tax/prepare", json={"documents": [{"name": "a", "text": _W2}]}).status_code == 403
    assert client.post("/api/v1/tax/backtest", content=b"x").status_code == 403
    assert client.post("/api/v1/tax/tables/apply", content=b"{}").status_code == 403
    assert client.post("/api/v1/tax/tables/roll-back").status_code == 403
    assert client.post("/api/v1/tax/tables/check").status_code == 403


def test_tax_test_on_past_returns(client):
    filed = {"client": "Jane", "filing_status": "single",
             "filed": {"total_income": 55000, "taxable_income": 39250, "tax_after_credits": 4471.5,
                       "federal_withholding": 6000, "balance": -1528.5}}
    raw = _bundle({"cases/jane/w2.txt": _W2, "cases/jane/filed.json": json.dumps(filed),
                   "cases/jane/../../evil.txt": "x"})
    report = client.post("/api/v1/tax/backtest", content=raw).json()
    assert report["cases"] == 1 and report["matched"] == 1 and report["accuracy"] == 1.0
    assert client.post("/api/v1/tax/backtest", content=_bundle({"x.txt": "y"})).status_code == 422


def test_tax_tables_refuse_untrusted_updates_plainly(client):
    r = client.post("/api/v1/tax/tables/apply", content=json.dumps({"payload": {}, "sig": "", "publisher_key": ""}).encode())
    assert r.status_code == 409 and not _BANNED.search(r.json()["detail"])
    r = client.post("/api/v1/tax/tables/roll-back")
    assert r.status_code == 409 and "no earlier version" in r.json()["detail"]
    checked = client.post("/api/v1/tax/tables/check").json()
    assert checked["status"] == "disabled" and not _BANNED.search(checked["summary"])


def test_finance_page_offers_the_tax_suite_in_plain_words(client):
    page = client.get("/finance")
    assert page.status_code == 200
    text = visible_text(page.text)
    for label in ("Tax preparation", "Prepare draft", "Check readiness", "Test it on returns you already filed"):
        assert label in text, label
    section = text[text.index("Tax preparation"):text.index("Automated finance checks")]
    assert not _BANNED.search(section)
    assert "/static/lightwork-tax.js" in page.text


def test_tax_routes_follow_the_finance_department(client, monkeypatch):
    from maverick_dashboard import auth
    _as(monkeypatch, "operator")
    monkeypatch.setattr(auth, "caller_suites", lambda request: frozenset({"legal"}))
    assert client.get("/api/v1/tax").status_code == 403
    assert client.post("/api/v1/tax/prepare", json={"documents": [{"name": "a", "text": _W2}]}).status_code == 403
