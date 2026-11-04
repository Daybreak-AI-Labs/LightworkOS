"""Private download links recheck account, tenant, scope, expiry and audit."""
import json
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import HTTPException
from maverick import model_test_retention
from maverick_dashboard import personal_data_exports as service


@pytest.fixture
def fixture(monkeypatch):
    identity = {"actor": "user:a", "context": "a" * 64}
    monkeypatch.setattr(service.native, "_actor", lambda request: identity["actor"])
    monkeypatch.setattr(service, "context_for", lambda request: identity["context"])
    monkeypatch.setattr(service.crypto_at_rest, "seal_to_str", lambda value: "sealed:" + value)
    monkeypatch.setattr(service.crypto_at_rest, "unseal_from_str", lambda value: value.removeprefix("sealed:"))
    monkeypatch.setattr(service.crypto_at_rest, "is_sealed_str", lambda value: value.startswith("sealed:"))
    monkeypatch.setattr(service, "audit_event", lambda *a, **kw: True)
    monkeypatch.setattr(model_test_retention, "export_owned", lambda owner: {"owner": owner, "checks": []})
    return identity


def token():
    return parse_qs(urlsplit(service.link(None, store="model_test_history")["href"]).query)["token"][0]


@pytest.mark.parametrize("field,value", [("actor", "user:b"), ("context", "b" * 64)])
def test_other_account_or_workspace_cannot_download(fixture, field, value):
    signed = token()
    fixture[field] = value
    with pytest.raises(HTTPException) as error:
        service.download(None, signed)
    assert error.value.status_code == 409


def test_expired_download_is_not_published(fixture, monkeypatch):
    signed = token()
    clock = service.time.time()
    monkeypatch.setattr(service.time, "time", lambda: clock + 601)
    with pytest.raises(HTTPException):
        service.download(None, signed)


def test_audit_failure_blocks_publication(fixture, monkeypatch):
    signed = token()
    monkeypatch.setattr(service, "audit_event", lambda *a, **kw: False)
    with pytest.raises(RuntimeError, match="audit"):
        service.download(None, signed)


def test_download_is_private_and_read_again_at_click(fixture, monkeypatch):
    signed = token()
    monkeypatch.setattr(model_test_retention, "export_owned", lambda owner: {"checks": ["current"]})
    response = service.download(None, signed)
    assert json.loads(response.body) == {"checks": ["current"]}
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_mid_read_account_change_blocks_publication(fixture, monkeypatch):
    signed = token()
    def changed(owner):
        fixture["actor"] = "user:b"
        return {"checks": ["private"]}
    monkeypatch.setattr(model_test_retention, "export_owned", changed)
    with pytest.raises(HTTPException):
        service.download(None, signed)


def test_unlinked_scope_is_rechecked_at_download(fixture, monkeypatch):
    monkeypatch.setattr(service.personal_memory, "require_scope", lambda *a: None)
    signed = parse_qs(urlsplit(service.link(None, channel="slack", user_id="verified")["href"]).query)["token"][0]
    def deny(*args):
        raise ValueError("unlinked")
    monkeypatch.setattr(service.personal_memory, "require_scope", deny)
    with pytest.raises(ValueError, match="unlinked"):
        service.download(None, signed)
