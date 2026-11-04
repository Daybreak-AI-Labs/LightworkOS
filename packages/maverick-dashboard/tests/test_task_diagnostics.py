import hashlib
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick import audit, cost_provenance
from maverick_dashboard import task_diagnostics as diagnostic


def test_document_excludes_raw_task_and_event_contents(monkeypatch):
    secret = 'PRIVATE-CLIENT-CONTENT-AND-KEY'
    goal = SimpleNamespace(id=7, status='failed', title=secret, description=secret, result=secret)
    world = SimpleNamespace(query=lambda *args: [(1, secret, 1000)])
    monkeypatch.setattr(cost_provenance, 'for_goal', lambda _: {'state':'unavailable', 'receipts':[]})
    document = diagnostic._document(world, goal, 'OTD-reference')
    assert secret not in repr(document)
    assert document['recent_event_metadata'][0]['kind'] == 'other'
    assert document['external_effects'] == 'Unknown outcomes remain possible.'


def _download(monkeypatch, *, expired=False, audit_ok=True):
    content = '{"correlation_id":"OTD-a","status":"failed"}\n'
    digest = hashlib.sha256(content.encode()).hexdigest()
    row = {'owner':'user:a', 'goal_id':7, 'context':'context-a', 'expires_at': time.time()+(-10 if expired else 60),
           'sealed':content, 'sha256':digest}
    monkeypatch.setattr(diagnostic, 'REPORTS', SimpleNamespace(get=lambda _:row))
    monkeypatch.setattr(diagnostic.auth, 'require_permission', lambda *args:None)
    monkeypatch.setattr(diagnostic, '_goal', lambda *args:('user:a',None))
    monkeypatch.setattr(diagnostic, 'context_for', lambda _: 'context-a')
    monkeypatch.setattr(diagnostic.crypto_at_rest, 'unseal_from_str', lambda value:value)
    monkeypatch.setattr(audit, 'record', lambda *args,**kwargs:audit_ok)
    return content,digest


def test_download_bytes_exactly_match_reviewed_preview(monkeypatch):
    content,digest = _download(monkeypatch)
    response = diagnostic.download(object(), 'OTD-a', digest)
    assert response.body == content.encode()
    assert response.headers['X-Content-SHA256'] == digest


@pytest.mark.parametrize('expired,audit_ok,status',[(True,True,410),(False,False,503)])
def test_expiry_and_missing_audit_refuse_download(monkeypatch,expired,audit_ok,status):
    _,digest = _download(monkeypatch,expired=expired,audit_ok=audit_ok)
    with pytest.raises(HTTPException) as error:
        diagnostic.download(object(),'OTD-a',digest)
    assert error.value.status_code == status


def test_non_ascii_download_digest_is_refused_as_a_mismatch(monkeypatch):
    _download(monkeypatch)
    with pytest.raises(HTTPException) as error:
        diagnostic.download(object(), 'OTD-a', 'é' * 64)
    assert error.value.status_code == 409


def test_non_ascii_prepare_context_is_refused_before_reading_the_task(monkeypatch):
    monkeypatch.setattr(diagnostic, '_app', lambda: SimpleNamespace(_require_same_origin=lambda request: None))
    monkeypatch.setattr(diagnostic, 'context_for', lambda _: 'context-a')
    monkeypatch.setattr(diagnostic, '_goal', lambda *args: pytest.fail('non-ASCII context reached the task'))
    with pytest.raises(HTTPException) as error:
        diagnostic.prepare_report(object(), 7, diagnostic.PrepareIn(context='context-ä'))
    assert error.value.status_code == 409
