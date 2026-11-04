"""The public rights-request form over HTTP: gate, pages, submission,
verification, status, CSRF/origin contract, admin round-trip, tracker
actions and the settings/module registrations."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick import config
from maverick import public_rights_form as prf
from maverick_dashboard.app import app

client = TestClient(app, base_url="https://127.0.0.1", headers={"Origin": "https://127.0.0.1"})
PUBLIC = "/api/v1/public/rights"
ADMIN = "/api/v1/privacy/rights-form"
_CONFIG = (
    "[privacy_ops]\nenable = true\n\n[privacy_automation]\nenable = true\n\n"
    "[privacy_automation.public_rights_form]\nenable = true\n"
)


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from maverick import audit, world_model
    from maverick.audit import writer as audit_writer

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_PUBLIC_BASE_URL", "https://127.0.0.1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    for name in (
        "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT",
        "MAVERICK_ENCRYPTION_KEY", "MAVERICK_CONFIG_OVERLAY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(audit, "record", lambda *_a, **_k: True)
    monkeypatch.setattr(audit, "record_global", lambda *_a, **_k: True)
    (tmp_path / "config.toml").write_text(_CONFIG, encoding="utf-8")
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    import maverick_dashboard.api as api

    api._world_cache.clear()
    prf.reset_limits()
    sent: list[dict] = []
    prf.set_mail_sender(lambda to, subject, body: (sent.append(
        {"to": to, "subject": subject, "body": body}) or True, ""))
    yield sent
    prf.set_mail_sender(None)
    prf.reset_limits()
    config.reset_config_cache()


def _property(**over):
    body = {
        "name": "Acme Shop", "organisation": "Acme Ltd",
        "contact_email": "privacy@acme.example",
        "jurisdictions": ["eu_gdpr", "us_ca_ccpa"], "default_jurisdiction": "us_ca_ccpa",
        "request_types": ["access", "deletion", "opt_out"],
        "allowed_origins": ["https://www.acme.example"],
    }
    body.update(over)
    r = client.put(f"{ADMIN}/properties/shop", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _answer(question: str) -> int:
    return sum(int(w) for w in question.replace("?", "").split() if w.isdigit())


def _submission(**over):
    form = client.get(f"{PUBLIC}/shop/form").json()
    body = {
        "email": "casey@example.com", "name": "Casey", "relationship": "customer",
        "request_type": "access", "jurisdiction": "us_ca_ccpa", "message": "Hello",
        "authorised_agent": False, "website": "",
        "challenge_token": form["challenge"]["token"],
        "challenge_answer": _answer(form["challenge"]["question"]),
    }
    body.update(over)
    return body


def _link(sent, marker):
    return next(line for line in sent[-1]["body"].splitlines() if marker in line).strip()


# --------------------------------------------------------------------------- #
# Gate and registrations
# --------------------------------------------------------------------------- #

def test_module_off_means_404_everywhere(tmp_path):
    (tmp_path / "config.toml").write_text("[privacy_ops]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    assert client.get("/rights/shop").status_code == 404
    assert "not available" in client.get("/rights/shop").text
    assert client.get(f"{PUBLIC}/shop/form").status_code == 404
    assert client.post(f"{PUBLIC}/shop/requests", json={}).status_code == 404
    assert client.get("/rights/status/abc").status_code == 404
    assert client.post("/rights/verify/abc").status_code == 404
    # Administration reads still work; writes say the module is off.
    assert client.get(f"{ADMIN}/properties").json()["enabled"] is False
    r = client.put(f"{ADMIN}/properties/shop", json={
        "name": "n", "organisation": "o", "contact_email": "a@b.co",
        "jurisdictions": ["eu_gdpr"]})
    assert r.status_code == 403
    page = client.get("/privacy/rights-form")
    assert page.status_code == 200
    assert 'data-module-gate="privacy_automation.public_rights_form"' in page.text


def test_module_switch_and_settings_are_registered():
    import maverick_dashboard.api as api
    from maverick_dashboard import settings_catalog, settings_store

    assert api._MODULE_SWITCHES["privacy_automation.public_rights_form"]["requires"] == (
        "privacy_automation",)
    assert "privacy_automation.public_rights_form" in settings_store.MODULE_ENABLE_PATHS
    keys = {s.key for s in settings_catalog.SETTINGS
            if s.section == "privacy_automation.public_rights_form"}
    assert keys == {"verification_ttl_hours", "status_ttl_days", "requests_per_ip_per_hour",
                    "requests_per_email_per_day", "internal_target_days", "max_message_chars"}
    rows = client.get("/api/v1/features/modules").json()["modules"]
    assert "privacy_automation.public_rights_form" in {row["section"] for row in rows}


def test_unknown_property_is_404_and_admin_round_trip():
    assert client.get("/rights/nope").status_code == 404
    created = _property()
    assert created["public_url"].endswith("/rights/shop")
    assert "<iframe" in created["embed_snippet"]
    listed = client.get(f"{ADMIN}/properties").json()
    assert listed["enabled"] is True and listed["properties"][0]["slug"] == "shop"
    bad = client.put(f"{ADMIN}/properties/shop", json={
        "name": "Acme Shop", "organisation": "Acme Ltd", "contact_email": "privacy@acme.example",
        "jurisdictions": ["ca_quebec"]})
    assert bad.status_code == 422 and "verified jurisdiction" in bad.json()["detail"]
    regimes = client.get(f"{ADMIN}/regimes").json()
    assert {r["id"] for r in regimes["unverified"]} == {"ca_quebec", "sg_pdpa"}
    assert all(r["source"].startswith("http") for r in regimes["regimes"])
    off = _property(enabled=False)
    assert off["enabled"] is False
    assert client.get("/rights/shop").status_code == 404
    assert client.delete(f"{ADMIN}/properties/shop").status_code == 200
    assert client.delete(f"{ADMIN}/properties/shop").status_code == 404


# --------------------------------------------------------------------------- #
# Public flow
# --------------------------------------------------------------------------- #

def test_public_page_and_form_definition():
    _property()
    page = client.get("/rights/shop")
    assert page.status_code == 200
    assert "Make a privacy request to Acme Ltd" in page.text
    assert 'name="website"' in page.text  # honeypot
    assert page.headers["x-robots-tag"] == "noindex"
    form = client.get(f"{PUBLIC}/shop/form").json()
    by_id = {j["id"]: j for j in form["jurisdictions"]}
    assert by_id["eu_gdpr"]["rights"] == ["access", "deletion"]
    assert "opt_out" in by_id["us_ca_ccpa"]["rights"]
    assert form["strings"]["submit"] == "Send my request"


def test_submit_verify_status_happy_path(_isolate):
    sent = _isolate
    _property()
    r = client.post(f"{PUBLIC}/shop/requests", json=_submission())
    assert r.status_code == 202, r.text
    assert "If that email" in r.json()["message"]
    assert r.headers["cache-control"] == "no-store, private"
    rows = client.get("/api/v1/privacy/dsar").json()["requests"]
    assert len(rows) == 1
    row = rows[0]
    assert row["status"] == "unverified" and row["source"] == "public_form"
    assert row["jurisdiction"] == "us_ca_ccpa" and row["acknowledge_by"] is not None
    assert row["days_left"] in (44, 45)
    # The list page shows the source, the law and the clock.
    listing = client.get("/privacy")
    assert "From your website" in listing.text and "California" in listing.text
    assert "Awaiting email confirmation" in listing.text
    # Verification: GET shows a button (no side effect), POST consumes.
    verify_url = _link(sent, "/rights/verify/")
    path = verify_url.split("://", 1)[1].split("/", 1)[1]
    assert client.get("/" + path).status_code == 200
    assert client.get("/api/v1/privacy/dsar").json()["requests"][0]["status"] == "unverified"
    done = client.post("/" + path)
    assert done.status_code == 200 and "Received and being worked on" in done.text
    row = client.get("/api/v1/privacy/dsar").json()["requests"][0]
    assert row["status"] == "open"
    assert row["verification"]["method"] == "email_challenge"
    assert [e["kind"] for e in row["public_form"]["emails"]] == ["verification", "acknowledgement"]
    # Reuse fails the same way an unknown token does.
    assert client.post("/" + path).status_code == 404
    assert client.post("/rights/verify/unknown").status_code == 404


    # Status page by its own token.
    status_url = next(
        line for line in sent[0]["body"].splitlines() if "/rights/status/" in line).strip()
    spath = status_url.split("://", 1)[1].split("/", 1)[1]
    page = client.get("/" + spath)
    assert page.status_code == 200 and row["id"] in page.text
    assert "opened_by" not in page.text
    token = spath.rsplit("/", 1)[1]
    api_view = client.get(f"{PUBLIC}/status/{token}").json()
    assert api_view["status"] == "open" and api_view["verified"] is True
    assert client.get(f"{PUBLIC}/status/nope").status_code == 404
    # Detail page shows the clock, identity and Send actions.
    detail = client.get(f"/privacy/dsar/{row['id']}")
    assert detail.status_code == 200
    assert "California (CCPA/CPRA)" in detail.text and "Confirmed by email" in detail.text
    assert 'data-kind="refusal"' in detail.text


def test_host_header_cannot_control_verification_email_or_inject_name(_isolate):
    sent = _isolate
    _property()
    response = client.post(f"{PUBLIC}/shop/requests", json=_submission(),
                           headers={"Host": "attacker.example", "Origin": "http://attacker.example"})
    assert response.status_code == 403 and sent == []
    response = client.post(f"{PUBLIC}/shop/requests", json=_submission(name="Casey\n\nVisit attacker.example"),
                           headers={"Host": "attacker.example", "Origin": "https://www.acme.example"})
    assert response.status_code == 202
    assert _link(sent, "/rights/verify/").startswith("https://127.0.0.1/rights/verify/")
    assert "attacker.example" not in sent[-1]["body"]


def test_public_rights_requires_configured_origin(monkeypatch):
    _property()
    body = _submission()
    monkeypatch.delenv("MAVERICK_PUBLIC_BASE_URL")
    monkeypatch.delenv("MAVERICK_PUBLIC_URL", raising=False)
    assert client.post(f"{PUBLIC}/shop/requests", json=body).status_code == 503


def test_public_rights_origin_normalization_and_invalid_config(monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard.public_rights_api import _origin_of, _public_base_url

    assert _origin_of("https://Example.COM:443/path") == "https://example.com"
    assert _origin_of("http://[") == ""
    for url in ("http://public.example", "https://public.example/prefix", "https://@public.example"):
        monkeypatch.setenv("MAVERICK_PUBLIC_BASE_URL", url)
        with pytest.raises(HTTPException):
            _public_base_url()


def test_challenge_honeypot_and_rate_limit_over_http(_isolate):
    _property()
    bad = client.post(f"{PUBLIC}/shop/requests", json=_submission(challenge_answer=99))
    assert bad.status_code == 422
    assert bad.json()["code"] == "challenge" and "question" in bad.json()["challenge"]
    trap = client.post(f"{PUBLIC}/shop/requests", json=_submission(website="x"))
    assert trap.status_code == 202
    assert client.get("/api/v1/privacy/dsar").json()["requests"] == []
    assert _isolate == []
    for _ in range(3):
        client.post(f"{PUBLIC}/shop/requests", json=_submission())
    limited = client.post(f"{PUBLIC}/shop/requests", json=_submission())
    assert limited.status_code == 429 and limited.headers["retry-after"]


def test_submission_never_reveals_whether_an_email_is_known(_isolate):
    _property()
    first = client.post(f"{PUBLIC}/shop/requests", json=_submission(email="a@example.com"))
    prf.reset_limits()
    second = client.post(f"{PUBLIC}/shop/requests", json=_submission(email="a@example.com"))
    assert first.status_code == second.status_code == 202
    # Identical apart from each request's own reference.
    one, two = first.json(), second.json()
    assert one["reference"] != two["reference"]
    for body in (one, two):
        body["message"] = body["message"].replace(body.pop("reference"), "")
    assert one == two
    prf.reset_limits()
    invalid = client.post(f"{PUBLIC}/shop/requests", json=_submission(email="nope"))
    assert invalid.status_code == 422 and "valid email" in invalid.json()["detail"]


def test_origin_and_content_type_contract():
    _property()
    body = _submission()
    cross = client.post(f"{PUBLIC}/shop/requests", json=body,
                        headers={"Origin": "https://evil.example"})
    assert cross.status_code == 403
    no_origin = client.post(f"{PUBLIC}/shop/requests", json=body, headers={"Origin": ""})
    assert no_origin.status_code == 403
    form_post = client.post(f"{PUBLIC}/shop/requests", data=body)
    assert form_post.status_code == 415
    embed = client.post(f"{PUBLIC}/shop/requests", json=_submission(),
                        headers={"Origin": "https://www.acme.example"})
    assert embed.status_code == 202
    assert embed.headers["access-control-allow-origin"] == "https://www.acme.example"
    preflight = client.options(f"{PUBLIC}/shop/requests",
                               headers={"Origin": "https://www.acme.example"})
    assert preflight.status_code == 204
    assert client.options(f"{PUBLIC}/shop/requests",
                          headers={"Origin": "https://evil.example"}).status_code == 403
    big = client.post(f"{PUBLIC}/shop/requests", json={**body, "message": "x" * 40_000})
    assert big.status_code == 413


# --------------------------------------------------------------------------- #
# Tracker actions and templates
# --------------------------------------------------------------------------- #

def test_tracker_actions_send_extend_acknowledge_verify(_isolate):
    sent = _isolate
    _property()
    client.post(f"{PUBLIC}/shop/requests", json=_submission())
    rid = client.get("/api/v1/privacy/dsar").json()["requests"][0]["id"]
    base = f"/api/v1/privacy/dsar/{rid}"
    assert client.post(f"{base}/send", json={"kind": "refusal"}).status_code == 422
    assert client.post(f"{base}/send", json={"kind": "extension"}).status_code == 422
    assert client.post(f"{base}/extend", json={"reason": "complex", "days": 60}).status_code == 422
    ext = client.post(f"{base}/extend", json={"reason": "complex", "days": 45})
    assert ext.status_code == 200 and ext.json()["extension_reason"] == "complex"
    out = client.post(f"{base}/send", json={"kind": "extension"}).json()
    assert out["sent"] is True and "complex" in sent[-1]["body"]
    ack = client.post(f"{base}/acknowledge")
    assert ack.status_code == 200 and ack.json()["acknowledged_at"] > 0
    ack_mail = client.post(f"{base}/send", json={"kind": "acknowledgement"}).json()
    assert ack_mail["sent"] is True
    email_challenge = client.post(f"{base}/verify", json={"method": "email_challenge", "reference": "x"})
    assert email_challenge.status_code == 422
    manual = client.post(f"{base}/verify", json={"method": "document_check", "reference": "ticket 1"})
    assert manual.status_code == 200 and manual.json()["status"] == "open"
    refusal = client.post(f"{base}/send", json={"kind": "refusal", "lawful_basis": "Manifestly unfounded"})
    assert refusal.status_code == 200 and "Manifestly unfounded" in sent[-1]["body"]
    assert client.post("/api/v1/privacy/dsar/DSAR-nope/acknowledge").status_code == 404


def test_templates_round_trip():
    _property()
    listing = client.get(f"{ADMIN}/templates").json()
    assert len(listing["templates"]) == 36 and "reference" in listing["placeholders"]
    bad = client.put(f"{ADMIN}/templates/gdpr/refusal", json={"subject": "x {oops}", "body": "y"})
    assert bad.status_code == 422 and "unknown placeholder" in bad.json()["detail"]
    saved = client.put(f"{ADMIN}/templates/gdpr/refusal",
                       json={"subject": "Decision {reference}", "body": "Because {lawful_basis}"})
    assert saved.status_code == 200 and saved.json()["version"] == 1
    hist = client.get(f"{ADMIN}/templates/gdpr/refusal/history").json()
    assert [v["version"] for v in hist["versions"]] == [1]
    reset = client.post(f"{ADMIN}/templates/gdpr/refusal/reset").json()
    assert reset["version"] == 2 and "data protection authority" in reset["body"]
    assert client.get(f"{ADMIN}/templates/nope/refusal/history").status_code == 404


def test_dashboard_open_accepts_jurisdiction_and_new_kinds():
    r = client.post("/api/v1/privacy/dsar", json={
        "subject_id": "jo@example.com", "kind": "correction", "jurisdiction": "ca_pipeda"})
    assert r.status_code == 201, r.text
    assert r.json()["due_basis"] == "statutory"
    bad = client.post("/api/v1/privacy/dsar", json={
        "subject_id": "jo@example.com", "kind": "opt_out", "jurisdiction": "eu_gdpr"})
    assert bad.status_code == 422


def test_client_address_is_proxy_aware_only_behind_a_pinned_proxy(tmp_path, _isolate):
    """Rate limiting keys on the real visitor: a forwarded header is honoured
    only when the peer is a trusted proxy (shared with the IP allowlist)."""
    from types import SimpleNamespace

    from maverick_dashboard import public_rights_api
    from starlette.datastructures import Headers

    def req(host, forwarded=None):
        headers = {"X-Forwarded-For": forwarded} if forwarded else {}
        return SimpleNamespace(client=SimpleNamespace(host=host), headers=Headers(headers))

    assert public_rights_api._client_ip(req("203.0.113.7", "10.9.9.9")) == "203.0.113.7"
    assert public_rights_api._client_ip(SimpleNamespace(client=None, headers=Headers({}))) == "unknown"
    (tmp_path / "config.toml").write_text(
        _CONFIG + "\n[auth.proxy]\ntrusted_proxies = [\"10.0.0.0/24\"]\n", encoding="utf-8",
    )
    config.reset_config_cache()
    assert public_rights_api._client_ip(req("10.0.0.5", "198.51.100.4, 10.0.0.6")) == "198.51.100.4"
    assert public_rights_api._client_ip(req("10.0.0.5")) == "10.0.0.5"


def test_submission_answers_with_a_reference_and_an_honest_email_promise():
    _property()
    r = client.post(f"{PUBLIC}/shop/requests", json=_submission())
    assert r.status_code == 202
    reference = r.json()["reference"]
    assert reference.startswith("DSAR-") and reference in r.json()["message"]
    assert r.json()["email_sent"] is True
    prf.set_mail_sender(lambda *_: (False, "no sending account configured ([email] / EMAIL_USER)"))
    r = client.post(f"{PUBLIC}/shop/requests", json=_submission(email="drew@example.com"),
                    headers={"X-Forwarded-For": "198.51.100.40"})
    assert r.status_code == 202
    body = r.json()
    assert body["email_sent"] is False and body["reference"] in body["message"]
    assert "we have sent" not in body["message"].lower()
    assert "EMAIL_USER" not in body["message"]
