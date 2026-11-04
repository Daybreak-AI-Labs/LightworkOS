import time
from datetime import datetime, timezone

from maverick import personal_notifications as alerts


def _timestamp(value):
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp()


def _source(goal=1, version='blocked', category='blocked'):
    return {'ref':f'goal:{goal}:state', 'version':version, 'category':category,
            'goal_id':goal, 'project_id':None, 'title':'Synthetic task', 'href':f'/chat/goal/{goal}'}


def _plaintext_test_storage(monkeypatch):
    monkeypatch.setattr(alerts, 'seal', lambda value: value)
    monkeypatch.setattr(alerts, 'unseal', lambda value: value)


def test_digest_handles_dst_gap_and_repeated_hour_without_double_delivery():
    prefs = alerts.validate_preferences({'mode':'digest', 'timezone':'America/New_York', 'digest_time':'02:30'})
    assert not alerts.delivery_window(prefs, now=_timestamp('2026-03-08T06:59:00'))[0]
    assert alerts.delivery_window(prefs, now=_timestamp('2026-03-08T07:01:00'))[0]
    prefs['digest_time'] = '01:30'
    assert alerts.delivery_window(prefs, now=_timestamp('2026-11-01T05:30:00'))[0]
    assert not alerts.delivery_window(prefs, now=_timestamp('2026-11-01T06:30:00'), last_digest_day='2026-11-01')[0]


def test_critical_quiet_hour_exception_requires_both_policy_and_personal_choice():
    prefs = alerts.validate_preferences({'timezone':'America/New_York', 'quiet_enabled':True,
                                        'critical_exceptions':True})
    now = _timestamp('2026-03-08T06:59:00')
    assert not alerts.delivery_window(prefs, now=now, critical=True, allow_critical=False)[0]
    assert alerts.delivery_window(prefs, now=now, critical=True, allow_critical=True)[0]


def test_two_recipients_keep_independent_delivery_modes_and_semantic_dedupe(tmp_path, monkeypatch):
    _plaintext_test_storage(monkeypatch)
    alice = alerts.PersonalInbox('user:alice', tmp_path / 'alice.enc')
    bob = alerts.PersonalInbox('user:bob', tmp_path / 'bob.enc')
    morning = _timestamp('2026-09-30T08:00:00')
    digest = alerts.validate_preferences({'mode':'digest', 'digest_time':'09:00'})
    immediate = alerts.validate_preferences({})
    assert not alice.refresh([_source()], digest, now=morning)['items']
    first = bob.refresh([_source()], immediate, now=morning)['items']
    again = bob.refresh([_source()], immediate, now=morning+60)['items']
    assert len(first) == len(again) == 1
    assert first[0]['id'] == again[0]['id']
    assert len(alice.refresh([_source()], digest, now=morning+7200)['items']) == 1
    assert not bob.refresh([], immediate, now=morning+120)['items']


def test_task_mute_does_not_silence_unrelated_work_or_expose_revoked_source(tmp_path, monkeypatch):
    _plaintext_test_storage(monkeypatch)
    now = time.time()
    inbox = alerts.PersonalInbox('user:alice', tmp_path / 'alice.enc')
    prefs = alerts.validate_preferences({'muted_tasks':{'1':now+3600}})
    result = inbox.refresh([_source(1), _source(2)], prefs, now=now)
    assert [item['goal_id'] for item in result['items']] == [2]
    assert not inbox.refresh([], prefs, now=now+1)['items']


def test_changed_result_requires_an_observed_previous_result(tmp_path, monkeypatch):
    _plaintext_test_storage(monkeypatch)
    inbox = alerts.PersonalInbox('user:alice', tmp_path / 'alice.enc')
    prefs = alerts.validate_preferences({'events':['changed-result']})
    source = _source(version='digest-one', category='changed-result')
    assert not inbox.refresh([source], prefs)['items']
    source['version'] = 'digest-two'
    assert len(inbox.refresh([source], prefs)['items']) == 1


def test_first_observation_delivers_only_completions_after_enrollment(tmp_path, monkeypatch):
    _plaintext_test_storage(monkeypatch)
    now = time.time()
    inbox = alerts.PersonalInbox('user:alice', tmp_path / 'alice.enc')
    old = {**_source(1, 'done:1', 'completed'), 'occurred_at': now - 60}
    fresh = {**_source(2, 'done:1', 'completed'), 'occurred_at': now + 1}
    result = inbox.refresh([old, fresh], alerts.validate_preferences({}),
                           now=now + 2, enrolled_at=now)
    assert [item['goal_id'] for item in result['items']] == [2]
    again = inbox.refresh([old, fresh], alerts.validate_preferences({}),
                          now=now + 3, enrolled_at=now)
    assert [item['id'] for item in again['items']] == [item['id'] for item in result['items']]


def test_in_app_alerts_are_on_unless_an_administrator_turned_them_off():
    assert alerts.PERSONAL_ALERTS_DEFAULT is True
    assert alerts.personal_alerts_on(None) is True and alerts.personal_alerts_on({}) is True
    assert alerts.personal_alerts_on({"personal_alerts": True}) is True
    assert alerts.personal_alerts_on({"personal_alerts": False}) is False  # an explicit choice stays
    assert alerts.personal_alerts_on({"personal_alerts": "yes"}) is False  # only a real yes turns it on
    # Out of the box a person hears about finished work, questions and
    # approvals waiting on them; nothing goes to another channel.
    assert {"completed", "needs-decision"} <= set(alerts.DEFAULTS["events"])
    assert alerts.DEFAULTS["external_links"] == [] and alerts.DEFAULTS["mode"] == "immediate"


def test_agent_mute_silences_that_agents_tasks_only_and_stays_bounded(tmp_path, monkeypatch):
    import pytest

    _plaintext_test_storage(monkeypatch)
    now = time.time()
    inbox = alerts.PersonalInbox('user:alice', tmp_path / 'alice.enc')
    prefs = alerts.validate_preferences({'muted_agents': {'finance_ap': now + 3600}})
    finance = {**_source(1), 'agent': 'finance_ap'}
    privacy = {**_source(2), 'agent': 'privacy_dsar'}
    approval = {**_source(3), 'ref': 'approval:3', 'goal_id': None}
    result = inbox.refresh([finance, privacy, approval], prefs, now=now)
    assert sorted(str(item['ref']) for item in result['items']) == ['approval:3', 'goal:2:state']
    # The mute ends on its own and is undone by removing it from preferences.
    assert len(inbox.refresh([finance, privacy, approval], alerts.validate_preferences({}), now=now + 1)['items']) == 3
    for bad in ({'Finance AP': now + 60}, {'finance_ap': now + 8 * 86400}, {'finance_ap': True}):
        with pytest.raises(ValueError, match='agent mute'):
            alerts.validate_preferences({'muted_agents': bad})
    # Expired mutes drop out instead of accumulating.
    assert alerts.validate_preferences({'muted_agents': {'finance_ap': now - 1}})['muted_agents'] == {}
    assert alerts.DEFAULTS['muted_agents'] == {}


def test_every_category_explains_why_what_and_when_without_task_text():
    """NOT-1: each alert category carries a reason, an action and due wording."""
    for category in alerts.EVENTS:
        filled = alerts.explain({'category': category})
        assert filled['reason'] and filled['action'] and filled['due_label'] and filled['no_due']
    # A source's own, more exact words win over the category defaults.
    own = alerts.explain({'category': 'needs-decision', 'reason': 'You were assigned this approval'})
    assert own['reason'] == 'You were assigned this approval'


def test_alert_brief_names_reason_action_and_due_time_but_never_the_task():
    due = _timestamp('2026-10-04T21:05:00')
    item = {'category': 'needs-decision', 'label': 'Needs your decision', 'title': 'Acquire Initech secretly',
            'result': 'Confidential board memo', 'reason': 'You were assigned this approval',
            'action': 'Approve or reject the request', 'due_at': due}
    brief = alerts.alert_brief(item, time_zone='Europe/London')
    assert brief == ('Needs your decision: Approve or reject the request. '
                     'Decide by Sun 04 Oct 2026, 22:05 (Europe/London). Why: You were assigned this approval.')
    assert 'Initech' not in brief and 'Confidential' not in brief
    question = alerts.alert_brief({'category': 'needs-decision', 'label': 'Needs your answer',
                                   'action': "Answer the agent's question", 'no_due': 'The task waits until you answer',
                                   'reason': 'You started this task'})
    assert 'The task waits until you answer.' in question and 'Why: You started this task.' in question


def test_seen_goal_ids_report_only_this_persons_seen_task_alerts(tmp_path, monkeypatch):
    _plaintext_test_storage(monkeypatch)
    now = time.time()
    inbox = alerts.PersonalInbox('user:alice', tmp_path / 'alice.enc')
    prefs = alerts.validate_preferences({})
    first = inbox.refresh([_source(1), _source(2)], prefs, now=now)
    seen = next(item for item in first['items'] if item['goal_id'] == 1)
    inbox.refresh([_source(1), _source(2)], prefs, now=now + 1, seen_id=seen['id'])
    assert inbox.seen_goal_ids() == {1}
    assert alerts.PersonalInbox('user:bob', tmp_path / 'bob.enc').seen_goal_ids() == set()
