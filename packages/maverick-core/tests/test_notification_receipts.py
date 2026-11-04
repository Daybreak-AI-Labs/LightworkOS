import json
from uuid import uuid4

import pytest
from maverick.notification_receipts import DeliveryReceipts


def test_accepted_delivery_cannot_be_replayed(tmp_path):
    receipts = DeliveryReceipts(tmp_path / 'receipts.json')
    event = str(uuid4())
    ident, acquired = receipts.claim(event, 'ntfy', kind='test')
    assert acquired
    receipts.update(ident, 'delivered', 'Accepted', safe_to_retry=False)
    assert receipts.claim(event, 'ntfy', kind='test') == (ident, False)
    assert receipts.claim(event, 'ntfy', kind='test', retry=True) == (ident, False)


def test_refused_test_has_three_attempt_ceiling_and_unknown_never_retries(tmp_path):
    receipts = DeliveryReceipts(tmp_path / 'receipts.json')
    event = str(uuid4())
    ident, _ = receipts.claim(event, 'slack', kind='test')
    for _ in range(2):
        receipts.update(ident, 'failed', 'Refused', safe_to_retry=True)
        assert receipts.claim(event, 'slack', kind='test', retry=True)[1]
    receipts.update(ident, 'failed', 'Refused', safe_to_retry=True)
    assert not receipts.claim(event, 'slack', kind='test', retry=True)[1]
    receipts.update(ident, 'unknown', 'Unconfirmed')
    assert not receipts.claim(event, 'slack', kind='test', retry=True)[1]


def test_receipt_has_no_event_content_or_destination(tmp_path):
    receipts = DeliveryReceipts(tmp_path / 'receipts.json')
    receipts.claim('private task title and destination secret', 'discord')
    saved = json.loads(receipts.path.read_text())
    assert 'private task title' not in json.dumps(saved)
    assert saved[0]['request_id'] is None


def test_capacity_does_not_evict_accepted_delivery_and_allow_a_duplicate(tmp_path):
    receipts = DeliveryReceipts(tmp_path / 'receipts.json')
    ident, _ = receipts.claim('first', 'ntfy')
    receipts.update(ident, 'delivered', 'Accepted')
    first = receipts._load()[0]
    receipts._save([first, *[{**first, 'id': str(index)} for index in range(999)]])
    with pytest.raises(ValueError, match='full'):
        receipts.claim('another event', 'ntfy')
    assert receipts.claim('first', 'ntfy') == (ident, False)


def test_revoked_authority_never_dispatches_and_is_not_reported_uncertain(tmp_path, monkeypatch):
    from maverick import notifications
    path = tmp_path / 'receipts.json'
    monkeypatch.setattr('maverick.paths.data_dir', lambda *parts: path)
    monkeypatch.setattr(notifications, '_load_config', lambda: {'backend': 'ntfy'})
    monkeypatch.setattr(notifications, '_dispatch', lambda *args, **kwargs: pytest.fail('must not dispatch after revocation'))
    def refuse():
        raise PermissionError('revoked')
    assert notifications.notify('synthetic', batch=False, async_dispatch=False, authorize=refuse,
                                delivery_key='revoked') == 0
    record = DeliveryReceipts(path).recent()[0]
    assert record['state'] == 'failed'
    assert record['message'].startswith('Not sent.')
    assert record['safe_to_retry'] is False


def test_async_queue_is_not_delivery_and_failed_backend_visible(tmp_path, monkeypatch):
    from maverick import notifications
    path = tmp_path / 'receipts.json'
    monkeypatch.setattr('maverick.paths.data_dir', lambda *parts: path)
    monkeypatch.setattr(notifications, '_load_config', lambda: {'backend':'ntfy', 'ntfy_topic':'synthetic'})
    jobs = []
    class Executor:
        def submit(self, fn, *args):
            jobs.append((fn, args))
    monkeypatch.setattr(notifications, '_get_executor', lambda: Executor())
    monkeypatch.setattr(notifications, '_send_ntfy', lambda *args: False)
    assert notifications.notify('PRIVATE', batch=False, delivery_key='event-once') == 1
    assert DeliveryReceipts(path).recent()[0]['state'] == 'queued'
    fn, args = jobs.pop()
    fn(*args)
    assert DeliveryReceipts(path).recent()[0]['state'] == 'failed'
    assert notifications.notify('PRIVATE', batch=False, delivery_key='event-once') == 0
    assert 'PRIVATE' not in path.read_text()


def test_sync_outcomes_report_each_backends_final_state(tmp_path, monkeypatch):
    from maverick import notifications
    path = tmp_path / 'receipts.json'
    monkeypatch.setattr('maverick.paths.data_dir', lambda *parts: path)
    monkeypatch.setattr(notifications, '_load_config', lambda: {'backend': 'ntfy'})

    def dispatch(backend, **kwargs):
        if backend == 'slack':
            raise TimeoutError('the service may have accepted it')
        return backend == 'ntfy'
    monkeypatch.setattr(notifications, '_dispatch', dispatch)
    outcomes = []
    assert notifications.notify('synthetic', backends=['ntfy', 'discord', 'slack'], batch=False,
                                async_dispatch=False, outcomes=outcomes) == 1
    assert outcomes == ['delivered', 'failed', 'unknown']

    def refuse():
        raise PermissionError('revoked')
    refused = []
    assert notifications.notify('synthetic', batch=False, async_dispatch=False, authorize=refuse,
                                outcomes=refused) == 0
    assert refused == ['failed']


def _failed_row(index, *, safe_to_retry=True, kind='event', state='failed', updated_at=None):
    import time
    now = time.time() if updated_at is None else updated_at
    return {'id': f'row-{index}', 'backend': 'ntfy', 'kind': kind, 'state': state, 'request_id': None,
            'updated_at': now, 'created_at': now, 'attempts': 1, 'safe_to_retry': safe_to_retry,
            'message': 'Not sent.'}


def test_a_flood_of_definite_failures_never_pauses_other_notifications(tmp_path):
    import time
    receipts = DeliveryReceipts(tmp_path / 'receipts.json')
    now = time.time()
    receipts._save([_failed_row(i, updated_at=now - 1000 + i) for i in range(1000)])
    ident, acquired = receipts.claim('a different event', 'ntfy')
    assert acquired
    rows = receipts._load()
    assert len(rows) == 1000 and {r['id'] for r in rows} >= {ident, 'row-999'}
    assert 'row-0' not in {r['id'] for r in rows}  # the oldest definite failure made room
    # An accepted send is still protected from replay while the history is otherwise full of failures.
    receipts.update(ident, 'delivered', 'Accepted')
    receipts.claim('another event', 'ntfy')
    assert receipts.claim('a different event', 'ntfy') == (ident, False)


@pytest.mark.parametrize('row', [
    {'state': 'delivered'}, {'state': 'queued'}, {'state': 'sending'}, {'state': 'unknown'},
    {'state': 'failed', 'safe_to_retry': False}, {'kind': 'test'},
])
def test_only_definite_failures_that_are_safe_to_retry_are_ever_dropped(tmp_path, row):
    receipts = DeliveryReceipts(tmp_path / 'receipts.json')
    receipts._save([_failed_row(i, **row) for i in range(1000)])
    with pytest.raises(ValueError, match='full'):
        receipts.claim('another event', 'ntfy')
    assert len(receipts._load()) == 1000


def test_notify_goes_out_when_the_history_is_full_of_definite_failures(tmp_path, monkeypatch):
    from maverick import notifications
    path = tmp_path / 'receipts.json'
    monkeypatch.setattr('maverick.paths.data_dir', lambda *parts: path)
    monkeypatch.setattr(notifications, '_load_config', lambda: {'backend': 'ntfy', 'ntfy_topic': 'synthetic'})
    DeliveryReceipts(path)._save([_failed_row(i) for i in range(1000)])
    monkeypatch.setattr(notifications, '_send_ntfy', lambda *args: True)
    assert notifications.notify('synthetic', batch=False, async_dispatch=False) == 1
    assert len(DeliveryReceipts(path)._load()) == 1000

