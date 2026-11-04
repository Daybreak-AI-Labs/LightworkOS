import sys
from types import SimpleNamespace

import pytest
from maverick import personal_notification_delivery as delivery
from maverick.personal_notifications import validate_preferences


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    monkeypatch.setattr(delivery, 'seal', lambda value: value)
    monkeypatch.setattr(delivery, 'unseal', lambda value: value)
    return delivery.DeliveryStore('user:alice', {'id': 'a' * 32, 'verified_at': 1}, tmp_path / 'synthetic-ledger')


def test_interrupted_send_claim_never_replays_and_digest_releases_once_per_day(ledger):
    first = {'id': 'a' * 64}
    second = {'id': 'b' * 64}
    assert ledger.claim([first], day='2026-09-30') is not None
    assert ledger.claim([first], day='2026-09-30') is None
    assert ledger.claim([first, second], day='2026-09-30') is None
    next_day = ledger.claim([first, second], day='2026-10-01')
    assert next_day[1] == [second]
    assert ledger.pending([first, second]) == []


def test_private_recipient_rejects_public_channel_identifiers():
    with pytest.raises(ValueError, match='private recipient'):
        delivery._transport({'channel': 'slack', 'sender_id': 'C12345678'})
    with pytest.raises(ValueError, match='private recipient'):
        delivery._transport({'channel': 'telegram', 'sender_id': '-10012345678'})


def _current_link(monkeypatch, link):
    """Delivery is enabled and ``link`` is the principal's current link, so the
    refusal under test comes from the bot/account identity check itself."""
    link = {'id': 'a' * 32, 'verified_at': 1, 'principal': 'user:alice', **link}
    monkeypatch.setattr(delivery, '_settings', lambda: {
        'personal_alerts': True, 'personal_background': True, 'personal_external': True})
    monkeypatch.setitem(sys.modules, 'maverick.personal_identity', SimpleNamespace(
        linked_channels=lambda principal: [dict(link)] if principal == 'user:alice' else []))
    return link


def test_telegram_bot_change_refuses_before_any_request(monkeypatch):
    monkeypatch.setattr(delivery, '_transport', lambda _: ('telegram', '123:synthetic'))
    monkeypatch.setattr(delivery, '_post', lambda *args: pytest.fail('bot mismatch must not send'))
    link = _current_link(monkeypatch, {'channel': 'telegram', 'sender_id': '456',
                                       'account_sha256': delivery._digest('789')})
    with pytest.raises(delivery.Refused):
        delivery.send_private(link, 'synthetic')


def test_slack_will_not_post_to_a_mismatched_direct_conversation(monkeypatch):
    monkeypatch.setattr(delivery, '_transport', lambda _: ('slack', 'synthetic-token'))
    calls = []
    def post(url, token, payload):
        calls.append(url)
        if url.endswith('/auth.test'):
            return {'ok': True, 'team_id': 'T12345678', 'user_id': 'U87654321'}
        return {'ok': True, 'channel': {'id': 'D12345678', 'is_im': True, 'user': 'U99999999'}}
    monkeypatch.setattr(delivery, '_post', post)
    link = _current_link(monkeypatch, {'channel': 'slack', 'sender_id': 'U11111111',
                                       'account_sha256': delivery._digest('T12345678:U87654321')})
    with pytest.raises(delivery.Refused):
        delivery.send_private(link, 'synthetic')
    assert len(calls) == 2
    assert not any(url.endswith('/chat.postMessage') for url in calls)


def test_link_revocation_between_projection_and_effect_blocks_dispatch(tmp_path, monkeypatch):
    monkeypatch.setattr(delivery, 'seal', lambda value: value)
    monkeypatch.setattr(delivery, 'unseal', lambda value: value)
    monkeypatch.setattr(delivery, 'data_dir', lambda *parts: tmp_path.joinpath(*parts))
    config = {'personal_alerts': True, 'personal_background': True, 'personal_external': True,
              'personal_dashboard_url': 'https://dashboard.example.test'}
    monkeypatch.setattr(delivery, '_settings', lambda: config)
    link = {'id': 'a' * 32, 'verified_at': 1, 'channel': 'telegram', 'sender_id': '123'}
    calls = []
    def links(_):
        calls.append(True)
        return [link] if len(calls) == 1 else []
    monkeypatch.setitem(sys.modules, 'maverick.personal_identity', SimpleNamespace(
        linked_channels=links, principal_current=lambda _: True))
    monkeypatch.setattr(delivery, 'send_private', lambda *args: pytest.fail('revoked link must not send'))
    choice = validate_preferences({'external_links': [link['id']]})
    delivery.dispatch('user:alice', {'items': [{'id': 'b' * 64, 'category': 'blocked', 'href': '/chat/goal/1'}]}, choice)
    receipt = delivery.DeliveryStore('user:alice', link).recent()[0]
    assert receipt['state'] == 'failed'


def test_private_links_never_accept_credentials_or_insecure_origins():
    for address in ('http://dashboard.example.test', 'https://user:synthetic@example.test',
                    'https://dashboard.example.test/other', 'https://dashboard.example.test?token=synthetic'):
        with pytest.raises(ValueError):
            delivery._base_url({'personal_dashboard_url': address})


def test_private_delivery_explains_missing_identity_link_policy(monkeypatch):
    from maverick import personal_identity

    monkeypatch.setattr(delivery, '_settings', lambda: {'personal_dashboard_url': 'https://dashboard.example.test'})
    monkeypatch.setattr(personal_identity, 'enabled', lambda: False)
    monkeypatch.setattr(personal_identity, 'linked_channels', lambda _: [])
    result = delivery.status('user:alice')
    assert result['enabled'] is False
    assert 'enable personal data controls' in result['note']
    assert result['channels'] == []


def test_personal_history_erasure_keeps_other_accounts(tmp_path, monkeypatch):
    monkeypatch.setattr(delivery, 'seal', lambda value: value)
    monkeypatch.setattr(delivery, 'unseal', lambda value: value)
    monkeypatch.setattr(delivery, 'data_dir', lambda *parts: tmp_path.joinpath(*parts))
    link = {'id': 'a' * 32, 'verified_at': 1}
    alice = delivery.DeliveryStore('user:alice', link)
    bob = delivery.DeliveryStore('user:bob', link)
    alice.claim([{'id': 'b' * 64}])
    bob.claim([{'id': 'c' * 64}])
    assert delivery.personal_history_inventory('user:alice')['consumed_items'] == 1
    delivery.remove_personal_history('user:alice')
    assert delivery.personal_history_inventory('user:alice')['consumed_items'] == 0
    assert bob.pending([{'id': 'c' * 64}]) == []


def test_misbound_delivery_file_cannot_publish_another_persons_history(ledger):
    ledger.claim([{'id': 'b' * 64}])
    other = delivery.DeliveryStore('user:bob', {'id': 'a' * 32, 'verified_at': 1}, path=ledger.path)
    with pytest.raises(ValueError, match='unavailable'):
        other.recent()


def _dispatch_fixture(tmp_path, monkeypatch, sent):
    monkeypatch.setattr(delivery, 'seal', lambda value: value)
    monkeypatch.setattr(delivery, 'unseal', lambda value: value)
    monkeypatch.setattr(delivery, 'data_dir', lambda *parts: tmp_path.joinpath(*parts))
    config = {'personal_alerts': True, 'personal_background': True, 'personal_external': True,
              'personal_dashboard_url': 'https://dashboard.example.test'}
    monkeypatch.setattr(delivery, '_settings', lambda: config)
    link = {'id': 'a' * 32, 'verified_at': 1, 'channel': 'telegram', 'sender_id': '123'}
    monkeypatch.setitem(sys.modules, 'maverick.personal_identity', SimpleNamespace(
        linked_channels=lambda _: [link], principal_current=lambda _: True))
    monkeypatch.setattr(delivery, 'send_private', lambda target, text: sent.append(text))
    return link


def test_private_message_says_why_what_and_by_when_without_task_text(tmp_path, monkeypatch):
    """NOT-1 for Slack/Telegram: reason, action and due time, plus the exact link."""
    sent = []
    link = _dispatch_fixture(tmp_path, monkeypatch, sent)
    item = {'id': 'b' * 64, 'category': 'needs-decision', 'label': 'Needs your decision',
            'title': 'Acquire Initech secretly', 'result': 'Confidential board memo',
            'reason': 'You were assigned this approval', 'action': 'Approve or reject the request',
            'due_at': 1791148500.0, 'href': '/approvals#approval-7', 'seen_at': None}
    choice = validate_preferences({'external_links': [link['id']], 'timezone': 'UTC'})
    delivery.dispatch('user:alice', {'items': [item]}, choice)
    assert len(sent) == 1
    text = sent[0]
    assert 'Why: You were assigned this approval.' in text
    assert 'Approve or reject the request' in text and 'Decide by ' in text
    assert 'https://dashboard.example.test/approvals#approval-7' in text
    assert 'Initech' not in text and 'Confidential' not in text


def test_an_alert_already_seen_in_the_app_is_not_sent_again_privately(tmp_path, monkeypatch):
    """NOT-2: reading an item in the app suppresses its pending external copy."""
    sent = []
    link = _dispatch_fixture(tmp_path, monkeypatch, sent)
    seen = {'id': 'c' * 64, 'category': 'completed', 'label': 'Finished', 'href': '/chat/goal/1',
            'seen_at': 100.0, 'state': 'seen'}
    choice = validate_preferences({'external_links': [link['id']]})
    delivery.dispatch('user:alice', {'items': [seen]}, choice)
    assert sent == []
    fresh = {**seen, 'id': 'd' * 64, 'seen_at': None, 'state': 'available', 'href': '/chat/goal/2'}
    delivery.dispatch('user:alice', {'items': [seen, fresh]}, choice)
    assert len(sent) == 1 and '/chat/goal/2' in sent[0] and '/chat/goal/1' not in sent[0]


def _clock(monkeypatch, start=1_800_000_000.0):
    import time

    now = [start]
    monkeypatch.setattr(delivery, 'time', SimpleNamespace(time=lambda: now[0], monotonic=time.monotonic))
    return now


def test_a_definite_refusal_releases_the_claim_for_a_later_retry(ledger, monkeypatch):
    now = _clock(monkeypatch)
    item = {'id': 'a' * 64}
    ident, _ = ledger.claim([item])
    ledger.finish(ident, 'failed', 'Not accepted.')
    # Waiting out the first back-off (5 minutes) before it is offered again.
    assert ledger.pending([item]) == [] and ledger.claim([item]) is None
    now[0] += 5 * 60 + 1
    assert ledger.pending([item]) == [item]
    again, fresh = ledger.claim([item])
    assert fresh == [item] and again != ident
    ledger.finish(again, 'failed', 'Not accepted.')
    now[0] += 5 * 60 + 1  # the second wait is longer (10 minutes)
    assert ledger.claim([item]) is None
    now[0] += 5 * 60
    ident, fresh = ledger.claim([item])
    assert fresh == [item]
    ledger.finish(ident, 'accepted', 'The service accepted this message.')
    now[0] += 24 * 3600
    assert ledger.pending([item]) == [] and ledger.claim([item]) is None  # delivered: never again


def test_an_uncertain_or_interrupted_send_is_never_released(ledger, monkeypatch):
    now = _clock(monkeypatch)
    unknown, interrupted = {'id': 'a' * 64}, {'id': 'b' * 64}
    ident, _ = ledger.claim([unknown])
    ledger.finish(ident, 'unknown', 'Acceptance is unknown.')
    assert ledger.claim([interrupted]) is not None  # claimed, then the process died: no finish
    now[0] += 6 * 24 * 3600  # days later, still inside the 7-day history
    assert ledger.pending([unknown, interrupted]) == []
    assert ledger.claim([unknown, interrupted]) is None


def test_a_refused_digest_is_offered_again_the_same_day(ledger, monkeypatch):
    now = _clock(monkeypatch)
    item = {'id': 'a' * 64}
    ident, _ = ledger.claim([item], day='2026-10-01')
    ledger.finish(ident, 'failed', 'Not accepted.')
    now[0] += 5 * 60 + 1
    retry = ledger.claim([item], day='2026-10-01')
    assert retry is not None and retry[1] == [item]
    ledger.finish(retry[0], 'accepted', 'The service accepted this message.')
    assert ledger.claim([item], day='2026-10-01') is None  # once the digest went, the day is done


def test_a_rate_limited_alert_is_sent_once_the_wait_is_over(tmp_path, monkeypatch):
    now = _clock(monkeypatch)
    sent, answers = [], [delivery.Refused(), None]

    def flaky(target, text):
        outcome = answers.pop(0)
        if outcome is not None:
            raise outcome
        sent.append(text)
        return 'message-1'
    link = _dispatch_fixture(tmp_path, monkeypatch, [])
    monkeypatch.setattr(delivery, 'send_private', flaky)
    item = {'id': 'e' * 64, 'category': 'needs-decision', 'label': 'Needs your decision',
            'reason': 'You were assigned this approval', 'action': 'Approve or reject the request',
            'due_at': now[0] + 86400, 'href': '/approvals#approval-9', 'seen_at': None}
    choice = validate_preferences({'external_links': [link['id']], 'timezone': 'UTC'})
    inbox = {'items': [item]}
    delivery.dispatch('user:alice', inbox, choice)  # the service said 429
    assert sent == []
    delivery.dispatch('user:alice', inbox, choice)  # still inside the wait
    assert sent == [] and len(answers) == 1
    now[0] += 5 * 60 + 1
    delivery.dispatch('user:alice', inbox, choice)
    assert len(sent) == 1
    now[0] += 3600
    delivery.dispatch('user:alice', inbox, choice)  # accepted once: not sent again
    assert len(sent) == 1
