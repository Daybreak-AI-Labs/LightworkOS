from uuid import UUID

import pytest
from fastapi import HTTPException
from maverick_dashboard import product_operations_notifications as operations


def test_changed_config_blocks_test_before_native_dispatch(monkeypatch):
    monkeypatch.setattr(operations.native, '_guard', lambda request: None)
    monkeypatch.setattr(operations, '_configuration', lambda: 'changed')
    calls = []
    monkeypatch.setattr(operations.native, '_test', lambda *args, **kwargs: calls.append(args))
    with pytest.raises(HTTPException) as caught:
        operations._execute_test(object(), {}, {}, {'configuration': 'reviewed', 'backend': 'ntfy'}, 'a' * 32)
    assert caught.value.status_code == 409
    assert not calls


def test_recovered_queued_test_does_not_dispatch_again(monkeypatch):
    monkeypatch.setattr(operations.native, '_guard', lambda request: None)
    monkeypatch.setattr(operations, '_configuration', lambda: 'current')
    record = {'id': 'b' * 64, 'state': 'queued', 'message': 'Waiting to send.'}
    monkeypatch.setattr(operations, '_test_record', lambda *_: record)
    outcome = operations._recover_test(object(), {}, {}, {'configuration': 'current'}, 'a' * 32)
    assert outcome.status == 'queued'
    assert outcome.details['receipt']['state'] == 'queued'
    assert outcome.details['seen'] == 'unknown'


def test_retry_recovery_recognizes_native_attempt_increment(monkeypatch):
    old = {'id': 'b' * 64, 'attempts': 1}
    current = {**old, 'attempts': 2, 'state': 'unknown', 'message': 'Delivery could not be confirmed.'}
    monkeypatch.setattr(operations, '_check', lambda *_: None)
    monkeypatch.setattr(operations, '_state', lambda *_: {'receipts': [current]})
    outcome = operations._recover_retry(object(), {}, {'receipt_id': old['id']}, {'record': old}, UUID(int=1).hex)
    assert outcome.status == 'unconfirmed'
    assert outcome.details['receipt']['state'] == 'unknown'
