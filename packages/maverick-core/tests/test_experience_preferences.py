"""Principal isolation, inheritance and native receipt contracts."""
import pytest
from maverick import experience_preferences as prefs


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv('MAVERICK_HOME', str(tmp_path))
    monkeypatch.setattr(prefs.config, 'config_path', lambda: tmp_path / 'config.toml')
    monkeypatch.setattr(prefs.config, 'dashboard_overrides_path', lambda: tmp_path / 'overlay.toml')
    monkeypatch.setattr(prefs.config, 'load_config', dict)
    monkeypatch.setattr(prefs.config, 'load_global_config', dict)
    monkeypatch.setattr(prefs.config, 'config_source_errors', list)
    monkeypatch.setattr(prefs.config, 'get_features', lambda: {'personal_preferences': True})
    monkeypatch.setattr(prefs, 'current_tenant_id_strict', lambda: None)
    monkeypatch.setattr(prefs, 'data_dir', lambda *parts: tmp_path.joinpath(*parts))
    # The storage codec is tested separately; this fixture checks scope and CAS.
    from maverick import styles
    monkeypatch.setattr(styles, 'active_style_name', lambda: "")
    monkeypatch.setattr(prefs, 'seal', lambda value: value)
    monkeypatch.setattr(prefs, 'unseal', lambda value: value)


def write(principal, changes, scope='personal', thread=None):
    return prefs.save(principal, scope=scope, changes=changes, thread=thread,
                      expected_revision=prefs.state(principal, thread=thread)['revision'])


def test_two_people_and_conversation_override_do_not_leak(isolated):
    write('user:alice', {'preferred_name': 'Alice', 'tone': 'friendly'})
    write('user:alice', {'tone': 'formal'}, thread=12)
    assert prefs.state('user:bob')['values']['preferred_name'] == ''
    assert prefs.state('user:alice')['values']['tone'] == 'friendly'
    assert prefs.state('user:alice', thread=12)['values']['tone'] == 'formal'
    assert prefs.state('user:bob', thread=12)['values']['tone'] == ''
    assert prefs.prompt('service:scheduled') == ''


def test_inheritance_and_stale_save(isolated):
    write('user:admin', {'tone': 'formal'}, scope='organization')
    old = prefs.state('user:alice')['revision']
    write('user:alice', {'tone': 'friendly'})
    with pytest.raises(prefs.PreferenceConflict):
        prefs.save('user:alice', scope='personal', changes={'tone': 'concise'}, expected_revision=old)
    assert write('user:alice', {'tone': None})['values']['tone'] == 'formal'


def test_policy_lock_cannot_be_removed_by_inherit(isolated, monkeypatch):
    monkeypatch.setattr(prefs.config, 'load_global_config', lambda: {'personalization': {
        'locked_fields': ['tone', 'preferred_name'], 'defaults': {'tone': 'formal', 'preferred_name': 'Wrong person'}}})
    assert prefs.state('user:bob')['values']['preferred_name'] == ''
    with pytest.raises(ValueError, match='organization policy'):
        write('user:bob', {'tone': None})
    assert prefs.state('user:bob')['values']['tone'] == 'formal'


def test_personal_name_and_authority_cannot_be_shared_preferences(isolated):
    with pytest.raises(ValueError):
        write('user:alice', {'preferred_name': 'Alice'}, scope='organization')
    with pytest.raises(ValueError):
        write('user:alice', {'tools': ['browser']})
    write('user:alice', {'preferred_name': 'Alice'})
    write('user:bob', {'preferred_name': 'Bob'})
    assert prefs.erase_personal('user:alice') == 1
    assert prefs.state('user:bob')['values']['preferred_name'] == 'Bob'


def test_workspace_overlay_cannot_remove_organization_locks(isolated, monkeypatch):
    monkeypatch.setattr(prefs.config, 'load_global_config', lambda: {'personalization': {
        'locked_fields': ['tone'], 'defaults': {'tone': 'formal'}}})
    monkeypatch.setattr(prefs.config, 'load_config', lambda: {'personalization': {'locked_fields': []}})
    assert prefs.state('user:alice')['values']['tone'] == 'formal'
    with pytest.raises(ValueError, match='organization policy'):
        write('user:alice', {'tone': 'friendly'}, scope='workspace')


def test_workspace_cannot_enable_globally_disabled_preferences(isolated, monkeypatch):
    monkeypatch.setattr(prefs.config, 'load_global_config', lambda: {'features': {'personal_preferences': False}})
    assert not prefs.enabled()
    with pytest.raises(ValueError, match='turned off'):
        write('user:alice', {'tone': 'friendly'})


def test_exact_operation_receipt_replays_once_and_is_principal_bound(isolated):
    before = prefs.state('user:alice')['revision']
    arguments = dict(scope='personal', changes={'tone': 'formal'}, expected_revision=before, operation_id='a' * 32)
    saved = prefs.save('user:alice', **arguments)
    replay = prefs.save('user:alice', **arguments)
    assert replay['revision'] == saved['revision']
    assert prefs.operation_confirmed('user:alice', **arguments)
    assert not prefs.operation_confirmed('user:bob', **arguments)
    with pytest.raises(prefs.PreferenceConflict):
        prefs.save('user:alice', **{**arguments, 'changes': {'tone': 'friendly'}})


def test_inherited_preview_matches_next_lower_layer(isolated):
    write('user:admin', {'tone': 'formal'}, scope='organization')
    write('user:alice', {'tone': 'friendly'})
    value = prefs.state('user:alice')
    assert value['inherited_by_scope']['personal']['values']['tone'] == 'formal'
    assert value['effective_by_scope']['personal']['values']['tone'] == 'friendly'


def test_interface_language_never_changes_response_language_or_prompt(isolated):
    write('user:alice', {'language': 'ja'})
    original = prefs.prompt('user:alice')
    write('user:alice', {'interface_language': 'fr'})
    assert prefs.state('user:alice')['values']['language'] == 'ja'
    assert prefs.prompt('user:alice') == original
    with pytest.raises(ValueError, match='Only response style'):
        write('user:alice', {'interface_language': 'de'}, thread=12)
    with pytest.raises(ValueError, match='available preference'):
        write('user:alice', {'interface_language': 'not-a-language'})


def test_glass_effects_are_off_until_the_installation_or_a_person_turns_them_on(isolated, monkeypatch):
    assert prefs.state('user:alice')['values']['glass'] == 'off'
    monkeypatch.setattr(prefs.config, 'load_config', lambda: {'dashboard': {'glass': 'on'}})
    inherited = prefs.state('user:alice')
    assert (inherited['values']['glass'], inherited['sources']['glass']) == ('on', 'installation settings')
    assert write('user:alice', {'glass': 'off'})['values']['glass'] == 'off'
    with pytest.raises(ValueError):
        write('user:alice', {'glass': 'sparkle'})
# Recent pages: the sidebar's short "Recent pages" list for one person.

def test_recent_pages_are_personal_newest_first_distinct_and_bounded(isolated):
    for path in ('/goals', '/approvals', '/goals', '/deliverables'):
        prefs.record_visit('user:alice', path)
    assert prefs.recent_pages('user:alice') == ['/deliverables', '/goals', '/approvals']
    assert prefs.recent_pages('user:bob') == []
    for index in range(prefs.RECENT_KEEP + 5):
        prefs.record_visit('user:alice', f'/page-{index}')
    kept = prefs.recent_pages('user:alice')
    assert len(kept) == prefs.RECENT_KEEP
    assert kept[0] == f'/page-{prefs.RECENT_KEEP + 4}'


def test_recording_a_visit_never_changes_the_preference_revision(isolated):
    # A page view must not turn another tab's preference draft into a conflict.
    before = prefs.state('user:alice')['revision']
    prefs.record_visit('user:alice', '/goals')
    assert prefs.state('user:alice')['revision'] == before
    assert 'recent_pages' not in prefs.state('user:alice')['values']


@pytest.mark.parametrize('address', ['', 'goals', '//evil.example/x', '/goals?tab=1', '/goals#top',
                                     'https://evil.example/', '/' + 'a' * 300, None, 5, '/bad path'])
def test_only_plain_page_addresses_are_remembered(isolated, address):
    with pytest.raises(ValueError):
        prefs.record_visit('user:alice', address)
    assert prefs.recent_pages('user:alice') == []


def test_recent_pages_follow_the_personal_preferences_switch(isolated, monkeypatch):
    prefs.record_visit('user:alice', '/goals')
    monkeypatch.setattr(prefs.config, 'load_global_config', lambda: {'features': {'personal_preferences': False}})
    with pytest.raises(ValueError, match='turned off'):
        prefs.record_visit('user:alice', '/approvals')
    assert prefs.recent_pages('user:alice') == []


def test_a_damaged_recent_list_reads_as_empty(isolated, tmp_path):
    prefs.record_visit('user:alice', '/goals')
    path, = (tmp_path / 'experience-preferences').glob('*-recent.enc')
    path.write_bytes(b'{"values": {"pages": "not a list"}}')
    assert prefs.recent_pages('user:alice') == []
    prefs.record_visit('user:alice', '/approvals')
    assert prefs.recent_pages('user:alice') == ['/approvals']


def test_clearing_and_erasing_remove_recent_pages_for_that_person_only(isolated):
    for person in ('user:alice', 'user:bob'):
        prefs.record_visit(person, '/goals')
    prefs.clear_recent('user:alice')
    assert prefs.recent_pages('user:alice') == [] and prefs.recent_pages('user:bob') == ['/goals']
    prefs.record_visit('user:alice', '/approvals')
    write('user:alice', {'preferred_name': 'Alice'})
    assert prefs.erase_personal('user:alice') == 2
    assert prefs.recent_pages('user:alice') == [] and prefs.recent_pages('user:bob') == ['/goals']


def test_navigation_choice_and_area_order_belong_to_one_person(isolated):
    assert prefs.state('user:alice')['values']['navigation'] == ''
    assert prefs.state('user:alice')['values']['navigation_areas'] == []
    saved = write('user:alice', {'navigation': 'areas', 'navigation_areas': ['Privacy', 'Work', 'Privacy']})
    assert saved['values']['navigation'] == 'areas'
    assert saved['values']['navigation_areas'] == ['Privacy', 'Work']
    with pytest.raises(ValueError):
        write('user:alice', {'navigation': 'sideways'})
    assert {'navigation', 'navigation_areas'} <= prefs.PERSONAL_ONLY
