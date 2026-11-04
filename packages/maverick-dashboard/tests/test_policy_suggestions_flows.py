"""Suggested edits to data use rules and privacy notices go through their own flows (NOT-4).

Accepting a suggestion only ever creates the document's next draft, through
the same route and checks as editing it by hand. A data use rule still needs
a different administrator to activate it; a privacy notice still needs
submitting, its approval rule's quorum and scheduling. Until then the version
in effect does not change.
"""
from __future__ import annotations

import hashlib
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
ANA = "user:ana@corp.com"
DANA = "user:dana@corp.com"
LEE = "user:lee@corp.com"
VIC = "user:vic@corp.com"
ROLES = {ANA: "admin", DANA: "admin", LEE: "admin", VIC: "viewer"}
DATA_USE = "/api/v1/data-use"
NOTICES = "/api/v1/privacy/notices"
SUGGEST = "/api/v1/policy-suggestions"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config
    from maverick.audit import writer as audit_writer

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    (tmp_path / "config.toml").write_text("[data_use_governance]\nenable = true\n", encoding="utf-8")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_OIDC_ENABLED",
                 "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT_BY_USER", "MAVERICK_DASHBOARD_ADMINS"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    from maverick_dashboard.app import app

    yield TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN), app, tmp_path
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()


_SIGNED_IN: dict[str, str | None] = {"principal": None}


class _SignedIn:
    """Carry the signed-in person on the request, as the auth middleware does.

    Privacy notice approvals re-check a fresh authenticated principal on the
    request itself, so an anonymous local request cannot decide them.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            state = dict(scope.get("state") or {})
            state["principal"] = SimpleNamespace(principal=_SIGNED_IN["principal"], sub=None, claims={})
            scope = {**scope, "state": state}
        await self.app(scope, receive, send)


def _as(monkeypatch, principal):
    from maverick_dashboard import auth, data_use_governance_api, rbac

    role = ROLES[principal]
    monkeypatch.setitem(_SIGNED_IN, "principal", principal)
    allowed = lambda request, perm, **kw: perm in rbac.permissions_for(role)  # noqa: E731
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: principal)
    monkeypatch.setattr(auth, "role_for_principal", lambda p: ROLES.get(p))
    monkeypatch.setattr(auth, "global_role_for_principal", lambda p: ROLES.get(p))
    monkeypatch.setattr(auth, "has_permission", allowed)
    monkeypatch.setattr(auth, "has_global_permission", allowed)
    # Who saved or activated a data use rule is bound to the signed-in person.
    monkeypatch.setattr(data_use_governance_api, "_actor_binding",
                        lambda request: ("actor-" + _digest(principal)[:32], _digest("authority:" + principal)))


# ---------------------------------------------------------------- data use rules

def _rule(effect: str) -> dict:
    control = {"control_id": "email", "effect": effect, "field_ids": ["email"]}
    if effect == "mask":
        control["mask_method"] = "hash_sha256"
    return {"scope": {"asset_ids": ["customers"], "field_ids": ["email"], "project_ids": [], "actions": ["read"]},
            "conditions": {}, "controls": [control]}


def _active_rule(client, monkeypatch) -> None:
    _as(monkeypatch, DANA)
    draft = client.post(f"{DATA_USE}/policies/email-rule/versions", json={
        "expected_revision": 0, "idempotency_key": "rule-v1", "version": 1, "document": _rule("mask"),
        "expected_current_version": 0})
    assert draft.status_code == 201, draft.text
    _as(monkeypatch, LEE)
    active = client.post(f"{DATA_USE}/policies/email-rule/activate", json={
        "expected_revision": draft.json()["revision"], "idempotency_key": "rule-v1-on", "version": 1,
        "reviewed_at": time.time() - 1})
    assert active.status_code == 200, active.text


def _pointer(client) -> dict:
    return client.get(f"{DATA_USE}/records/policy/email-rule").json()


def test_a_data_use_rule_suggestion_becomes_a_draft_that_still_needs_another_admin(client, monkeypatch):
    client, _app, _tmp = client
    _active_rule(client, monkeypatch)
    _as(monkeypatch, ANA)
    made = client.post(SUGGEST, json={"kind": "data-use-rule", "id": "email-rule", "field": "document",
                                      "document": _rule("deny"), "reason": "Analysts should not read email at all."})
    assert made.status_code == 201, made.text
    view = made.json()
    # The change reads as words, not as a rule file.
    assert [(d["op"], d["text"]) for d in view["diff"] if d["op"] != "same"] == [
        ("del", "hide part of each value"), ("ins", "block it"), ("del", "email by hash sha256."), ("ins", "email.")]
    assert _pointer(client)["current_version"] == 1  # nothing saved yet

    _as(monkeypatch, DANA)
    listed = client.get(SUGGEST, params={"kind": "data-use-rule"}).json()
    assert [s["id"] for s in listed["suggestions"]] == [view["id"]] and listed["ai_on"] is False
    accepted = client.post(f"{SUGGEST}/{view['id']}/accept", json={"reason": "Agreed."})
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["suggestion"]["applied_version"] == 2
    assert "another administrator" in accepted.json()["next_step"]
    pointer = _pointer(client)
    assert pointer["current_version"] == 2 and pointer["state"] == "draft"
    assert pointer["active_version"] == 1  # the rule in effect has not changed

    # The flow's own approval still applies: the person who accepted it cannot activate it.
    own = client.post(f"{DATA_USE}/policies/email-rule/activate", json={
        "expected_revision": pointer["revision"], "idempotency_key": "rule-v2-self", "version": 2,
        "reviewed_at": time.time() - 1})
    assert own.status_code == 422 and "author and reviewer must differ" in own.json()["detail"]
    _as(monkeypatch, LEE)
    other = client.post(f"{DATA_USE}/policies/email-rule/activate", json={
        "expected_revision": pointer["revision"], "idempotency_key": "rule-v2-on", "version": 2,
        "reviewed_at": time.time() - 1})
    assert other.status_code == 200, other.text
    assert _pointer(client)["active_version"] == 2


def test_data_use_suggestions_use_the_rules_own_checks(client, monkeypatch):
    client, _app, _tmp = client
    _active_rule(client, monkeypatch)
    _as(monkeypatch, VIC)
    assert client.post(SUGGEST, json={"kind": "data-use-rule", "id": "email-rule", "field": "document",
                                      "document": _rule("deny")}).status_code == 403
    _as(monkeypatch, ANA)
    broken = client.post(SUGGEST, json={"kind": "data-use-rule", "id": "email-rule", "field": "document",
                                        "document": {"controls": [{"control_id": "x", "effect": "explode"}]}})
    assert broken.status_code == 422 and "cannot be used" in broken.json()["detail"]
    sid = client.post(SUGGEST, json={"kind": "data-use-rule", "id": "email-rule", "field": "document",
                                     "document": _rule("deny")}).json()["id"]
    # Someone saves another draft first: the suggestion can no longer be accepted.
    _as(monkeypatch, DANA)
    pointer = _pointer(client)
    client.post(f"{DATA_USE}/policies/email-rule/versions", json={
        "expected_revision": pointer["revision"], "idempotency_key": "rule-v2-hand", "version": 2,
        "document": _rule("review"), "expected_current_version": 1})
    refused = client.post(f"{SUGGEST}/{sid}/accept", json={})
    assert refused.status_code == 409 and "changed since this was suggested" in refused.json()["detail"]


# ---------------------------------------------------------------- privacy notices

NOW = time.time() + 86_400


@pytest.fixture
def notices(client, monkeypatch):
    from maverick import privacy_notice_governance as notice
    from maverick_dashboard import auth
    from maverick_dashboard import privacy_notice_governance_api as native

    _http, app, tmp_path = client
    http = TestClient(_SignedIn(app), base_url="http://127.0.0.1", headers=ORIGIN)
    database = tmp_path / "notices.sqlite3"
    monkeypatch.setattr(notice, "require_enabled", lambda: None)
    monkeypatch.setattr(notice, "enabled", lambda: True)
    monkeypatch.setattr(native, "_principal",
                        lambda request, tenant: "png-principal-" + _digest(auth.caller_principal(request))[:32])

    def factory(**kwargs):
        return notice.PrivacyNoticeGovernanceStore(
            database, config_gate=lambda: None, principal_resolver=kwargs["principal_resolver"],
            signing_key_resolver=lambda _t, _r: b"notice-signing-secret-never-persisted-123456789",
            regulatory_reference_resolver=lambda *_a: False)

    monkeypatch.setattr(app.state, "privacy_notice_governance_store_factory", factory, raising=False)
    _as(monkeypatch, DANA)
    policy = http.put(f"{NOTICES}/approval-policies/notice-policy", json={
        "required_roles": ["privacy", "legal"], "quorum": 2, "approval_ttl_seconds": 3600,
        "expected_revision": 0, "idempotency_key": "policy-create"})
    assert policy.status_code == 200, policy.text
    release = http.put(f"{NOTICES}/releases/privacy-main/versions", json={
        "property_id": "property-main", "jurisdictions": ["eu", "us-ca"], "locales": ["en-US"],
        "policy_sha256": _digest("policy"), "content_sha256": _digest("content"),
        "configuration_sha256": _digest("configuration"), "consent_publication_ref": "consent-publication:1",
        "approval_policy_id": "notice-policy", "effective_from": NOW, "effective_until": NOW + 86_400,
        "retained_until": NOW + 2 * 86_400, "update_proposal_ref": None, "expected_latest_version": 0,
        "idempotency_key": "release-create"})
    assert release.status_code == 200, release.text
    return http


def test_a_privacy_notice_suggestion_becomes_a_draft_version_that_still_needs_its_approvals(notices, monkeypatch):
    http = notices
    _as(monkeypatch, ANA)
    made = http.post(SUGGEST, json={"kind": "privacy-notice", "id": "privacy-main", "field": "jurisdictions",
                                    "text": "eu, us-ca, gb", "reason": "We now serve the UK."})
    assert made.status_code == 201, made.text
    view = made.json()
    assert view["field_label"] == "Places it covers"
    assert [(d["op"], d["text"]) for d in view["diff"] if d["op"] != "same"] == [("del", "us-ca"), ("ins", "us-ca, gb")]

    _as(monkeypatch, DANA)
    accepted = http.post(f"{SUGGEST}/{view['id']}/accept", json={})
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["suggestion"]["applied_version"] == 2
    assert "approvals its approval rule asks for" in accepted.json()["next_step"]
    version = http.get(f"{NOTICES}/releases/privacy-main/versions/2").json()
    assert sorted(version["jurisdictions"]) == ["eu", "gb", "us-ca"]
    assert version["state"] == "draft"
    first = http.get(f"{NOTICES}/releases/privacy-main/versions/1").json()
    assert sorted(first["jurisdictions"]) == ["eu", "us-ca"]  # the earlier version is untouched
    records = http.get(f"{NOTICES}/records").json()
    assert [a for a in records["approvals"] if a["version"] == 2] == []

    # It cannot be scheduled for publication until the approval rule's quorum approves it.
    submitted = http.post(f"{NOTICES}/releases/privacy-main/versions/2/submit", json={
        "expected_revision": version["state_revision"], "idempotency_key": "submit-v2"})
    assert submitted.status_code == 200, submitted.text
    scheduled = http.post(f"{NOTICES}/releases/privacy-main/versions/2/schedule", json={
        "expected_revision": submitted.json()["state_revision"], "idempotency_key": "schedule-v2",
        "activate_at": NOW + 60, "expected_release_sha256": submitted.json()["definition_sha256"], "max_attempts": 3})
    assert scheduled.status_code == 409

    def approve(principal, role, revision):
        _as(monkeypatch, principal)
        return http.post(f"{NOTICES}/releases/privacy-main/versions/2/approvals", json={
            "role": role, "expected_release_sha256": submitted.json()["definition_sha256"],
            "expected_revision": revision, "idempotency_key": f"approve-{role}-{_digest(principal)[:12]}"})

    # The person who accepted the suggestion is its author and cannot approve it.
    assert approve(DANA, "privacy", submitted.json()["state_revision"]).status_code == 403
    first = approve(LEE, "privacy", submitted.json()["state_revision"])
    assert first.status_code == 200, first.text
    second = approve(ANA, "legal", first.json()["state_revision"])
    assert second.status_code == 200 and second.json()["state"] == "approved", second.text
    _as(monkeypatch, DANA)
    scheduled = http.post(f"{NOTICES}/releases/privacy-main/versions/2/schedule", json={
        "expected_revision": second.json()["state_revision"], "idempotency_key": "schedule-v2-approved",
        "activate_at": NOW + 60, "expected_release_sha256": submitted.json()["definition_sha256"], "max_attempts": 3})
    assert scheduled.status_code == 200, scheduled.text


def test_privacy_notice_suggestions_check_values_and_permission(notices, monkeypatch):
    http = notices
    _as(monkeypatch, ANA)
    bad = http.post(SUGGEST, json={"kind": "privacy-notice", "id": "privacy-main", "field": "locales",
                                   "text": "English please"})
    assert bad.status_code == 422 and "separated by commas" in bad.json()["detail"]
    sid = http.post(SUGGEST, json={"kind": "privacy-notice", "id": "privacy-main", "field": "locales",
                                   "text": "en-US, fr-FR"}).json()["id"]
    _as(monkeypatch, VIC)
    assert http.post(f"{SUGGEST}/{sid}/accept", json={}).status_code == 403
    _as(monkeypatch, DANA)
    rejected = http.post(f"{SUGGEST}/{sid}/reject", json={"reason": "French copy is not ready."})
    assert rejected.status_code == 200 and rejected.json()["suggestion"]["state"] == "rejected"
    assert len([r for r in http.get(f"{NOTICES}/records").json()["releases"]]) == 1


def test_suggestions_on_other_documents_are_refused(client, monkeypatch):
    http, _app, _tmp = client
    _as(monkeypatch, DANA)
    refused = http.get(SUGGEST, params={"kind": "contracts"})
    assert refused.status_code == 404


def test_both_pages_show_suggestions_inline(notices, monkeypatch):
    http = notices
    _as(monkeypatch, DANA)
    data_use = http.get("/data-use").text
    rules = data_use[data_use.index('id="dug-policies-heading"'):data_use.index('id="dug-exceptions-heading"')]
    assert 'data-kind="data-use-rule"' in rules and "another administrator" in rules
    assert "data-suggestion-ask" not in rules  # the AI assistant drafts wording for AI use rules only
    notice_page = http.get("/privacy/notice-governance").text
    assert 'data-kind="privacy-notice"' in notice_page and "/static/lightwork-policy-suggestions.js" in notice_page
