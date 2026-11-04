"""Settings review and file-install regression cases; do not use live providers."""
import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_all_page as page
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    for key in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(page, "_record", lambda *args, **kwargs: None)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def test_catalog_stale_version_does_not_overwrite_newer_save():
    before = client.get(API).json()["revision"]
    body = {"expected_revision": before, "changes": [{"id": "persona.name", "value": "Atlas"}]}
    saved = client.post(API, json=body)
    assert saved.status_code == 200
    refused = client.post(API, json={**body, "changes": [{"id": "persona.name", "value": "Stale"}]})
    assert refused.status_code == 409
    assert refused.json()["conflicts"][0]["current"] == "Atlas"
    assert page._sources()["here"]["persona"]["name"] == "Atlas"


def test_inherit_is_distinct_from_product_default(tmp_path):
    from maverick.config import config_path
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('[persona]\nname = "Installer"\n', encoding="utf-8")
    for change in ({"id": "persona.name", "value": "Override"},
                   {"id": "persona.name", "inherit": True}):
        revision = client.get(API).json()["revision"]
        assert client.post(API, json={"expected_revision": revision, "changes": [change]}).status_code == 200
    assert "name" not in page._sources()["here"].get("persona", {})
    revision = client.get(API).json()["revision"]
    assert client.post(API, json={"expected_revision": revision,
                      "changes": [{"id": "persona.name", "reset": True}]}).status_code == 200
    assert page._sources()["here"]["persona"]["name"] == ""


def test_file_review_rejects_different_bytes_and_changed_configuration(monkeypatch):
    from maverick_dashboard import system_checks_api
    monkeypatch.setattr(system_checks_api, "_record", lambda *args, **kwargs: None)
    checked = client.post('/api/v1/setup/settings-file/check', content=b'[persona]\nname="A"\n')
    assert checked.status_code == 200
    review = checked.json()["review"]
    changed = client.post('/api/v1/setup/settings-file/install?confirm=true&review=' + review,
                          content=b'[persona]\nname="B"\n')
    assert changed.status_code == 409
    revision = client.get(API).json()["revision"]
    client.post(API, json={"expected_revision": revision,
                          "changes": [{"id": "persona.name", "value": "Later"}]})
    stale = client.post('/api/v1/setup/settings-file/install?confirm=true&review=' + review,
                        content=b'[persona]\nname="A"\n')
    assert stale.status_code == 409


def test_review_does_not_write_and_export_excludes_credentials():
    revision = client.get(API).json()['revision']
    reviewed = client.post(API + '/review', json={
        'expected_revision': revision, 'changes': [{'id': 'persona.name', 'value': 'Atlas'}]})
    assert reviewed.status_code == 200
    assert reviewed.json()['items'][0]['after'] == 'Atlas'
    assert page._revision() == revision
    exported = client.post('/api/v1/settings/profiles/export', json={'ids': ['persona.name', 'dashboard.token']})
    assert exported.status_code == 200
    assert 'dashboard.token' not in exported.json()['settings']
    imported = client.post('/api/v1/settings/profiles/import', json={'profile': {
        'format': 'lightwork-preferences-profile', 'version': 1, 'scope': 'organization',
        'settings': {'dashboard.token': 'must-not-import'}}})
    assert imported.status_code == 422
    assert page._revision() == revision


def test_display_cookie_cannot_cross_account_or_override_locked_policy(monkeypatch):
    from types import SimpleNamespace

    from maverick_dashboard import preferences_api

    monkeypatch.setattr(preferences_api.auth, 'caller_principal', lambda request: 'user:bob')
    monkeypatch.setattr(preferences_api, 'context_for', lambda request: 'bob-context')
    monkeypatch.setattr(preferences_api.preferences, 'enabled', lambda: True)
    monkeypatch.setattr(preferences_api.preferences, 'state', lambda principal: {
        'locked': ['theme'], 'values': {'theme': 'dark', 'density': 'comfortable'}})
    request = SimpleNamespace(state=SimpleNamespace(), cookies={
        'mvk_pref_context': 'alice-context', 'mvk_density': 'compact'})
    assert preferences_api.resolved_display(request, 'density') == 'comfortable'
    request.cookies = {'mvk_pref_context': 'bob-context', 'mvk_theme': 'light'}
    assert preferences_api.resolved_display(request, 'theme') == 'dark'


def test_every_runtime_writing_style_round_trips_catalog():
    from maverick.persona import STYLES, load_persona
    from maverick_dashboard.settings_catalog import BY_ID

    assert {key for key, _label in BY_ID['persona.style'].choices if key} == set(STYLES)
    for style in STYLES:
        revision = client.get(API).json()['revision']
        result = client.post(API, json={'expected_revision': revision,
                             'changes': [{'id': 'persona.style', 'value': style}]})
        assert result.status_code == 200
        assert load_persona()['style'] == style


def test_supported_profile_round_trip_uses_ordinary_conflict_checked_writer():
    original = client.post('/api/v1/settings/profiles/export', json={'ids': ['persona.name']}).json()
    revision = client.get(API).json()['revision']
    assert client.post(API, json={'expected_revision': revision,
                       'changes': [{'id': 'persona.name', 'value': 'Temporary'}]}).status_code == 200
    imported = client.post('/api/v1/settings/profiles/import', json={'profile': original}).json()
    reviewed = client.post(API + '/review', json={'expected_revision': imported['revision'],
                            'changes': imported['changes']})
    assert reviewed.status_code == 200
    assert client.post(API, json={'expected_revision': imported['revision'],
                       'changes': imported['changes']}).status_code == 200
    after = client.post('/api/v1/settings/profiles/export', json={'ids': ['persona.name']}).json()
    assert after['settings'] == original['settings']


def test_file_review_covers_non_catalog_fields_without_leaking_values(monkeypatch):
    from maverick_dashboard.setup_guide import _other_file_impact
    monkeypatch.setenv('OPENAI_API_KEY', 'deployment-secret')
    # Every built-in feature switch is now a catalog row (shown typed above);
    # a switch the catalog does not know, such as one left by an older
    # release, is still accounted for here.
    layers = {'base': {'features': {'personal_preferences': True, 'retired_preview': True},
                       'private_table': {'secret': 'old'}},
              'here': {'features': {'retired_preview': True}}, 'operator': {}}
    proposed = {'features': {'personal_preferences': False, 'retired_preview': False},
                'providers': {'openai': {'api_key': 'new-secret'}}}
    rows = _other_file_impact(layers, proposed)
    assert {row['label'] for row in rows} >= {'features.retired_preview', 'private_table.secret'}
    assert 'features.personal_preferences' not in {row['label'] for row in rows}
    feature = next(row for row in rows if row['label'] == 'features.retired_preview')
    assert feature['after'] == 'Disabled' and feature['overridden']
    assert next(row for row in rows if row['label'] == 'private_table.secret')['change'] == 'Removed'
    assert 'new-secret' not in str(rows) and 'deployment-secret' not in str(rows)


def test_review_conflict_never_calls_the_catalog_writer(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('A review may not enter the mutation handler')
    monkeypatch.setattr(page, '_catalog_update_locked', forbidden)
    result = client.post(API + '/review', json={'expected_revision': '0' * 64,
                         'changes': [{'id': 'persona.name', 'value': 'Draft'}]})
    assert result.status_code == 409


def test_personal_profile_import_is_review_only_and_rejects_authority(monkeypatch):
    import json
    from types import SimpleNamespace

    from maverick_dashboard import preferences_api
    current = {'values': {'tone': 'formal'}, 'locked': [], 'revision': 'a' * 64, 'context': 'alice'}
    monkeypatch.setattr(preferences_api, '_profiles_allowed', lambda request: None)
    monkeypatch.setattr(preferences_api, '_state', lambda request: current)
    monkeypatch.setattr(preferences_api, '_app', lambda: SimpleNamespace(_require_same_origin=lambda request: None))
    profile = {'format': 'lightwork-personal-style-profile', 'version': 1, 'scope': 'personal',
               'settings': {'tone': 'friendly'}}
    response = preferences_api.import_personal_profile(None, preferences_api.PersonalProfileImport(profile=profile))
    assert json.loads(response.body)['changes'] == {'tone': 'friendly'}
    assert current['values']['tone'] == 'formal'
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as refused:
        preferences_api.import_personal_profile(None, preferences_api.PersonalProfileImport(profile={**profile, 'settings': {'tools': ['browser']}}))
    assert refused.value.status_code == 422
    current['locked'] = ['tone']
    with pytest.raises(HTTPException) as locked:
        preferences_api.import_personal_profile(None, preferences_api.PersonalProfileImport(profile=profile))
    assert locked.value.status_code == 409


def test_personal_profile_excludes_identity_and_credential_like_guidance(monkeypatch):
    import json

    from maverick.experience_preferences import DEFAULTS
    from maverick_dashboard import preferences_api
    monkeypatch.setattr(preferences_api, '_profiles_allowed', lambda request: None)
    monkeypatch.setattr(preferences_api, '_state', lambda request: {'values': {
        **DEFAULTS, 'preferred_name': 'Private Alice', 'output_style': 'custom',
        'custom_style': 'Authorization: Bearer ' + 'a' * 45}})
    exported = json.loads(preferences_api.export_personal_profile(None).body)
    assert 'preferred_name' not in exported['settings']
    assert 'custom_style' not in exported['settings']
    assert 'output_style' not in exported['settings']


def test_member_search_finds_exact_personal_fields_without_admin_settings(monkeypatch):
    import json
    from types import SimpleNamespace

    from maverick import experience_preferences
    from maverick_dashboard import settings_experience
    monkeypatch.setattr(settings_experience.auth, 'require_permission', lambda *args: None)
    monkeypatch.setattr(settings_experience.auth, 'has_global_permission', lambda *args: False)
    monkeypatch.setattr(settings_experience.auth, 'caller_principal', lambda request: 'user:alice')
    monkeypatch.setattr(settings_experience.page, '_app', lambda: SimpleNamespace(_nav_context=lambda request: {
        'finder_pages': [{'links': [{'href': '/preferences', 'label': 'Preferences'}]}]}))
    monkeypatch.setattr(experience_preferences, 'enabled', lambda: True)
    monkeypatch.setattr(experience_preferences, 'state', lambda principal: {
        'values': experience_preferences.DEFAULTS, 'sources': dict.fromkeys(experience_preferences.DEFAULTS, 'product default')})
    theme = json.loads(settings_experience.search(None, 'theme').body)['items']
    assert theme[0]['href'] == '/preferences#preference-theme'
    assert json.loads(settings_experience.search(None, 'provider key').body)['items'] == []


@pytest.mark.parametrize('value', [[0], [1.1], [True], ['nan'], ['inf'], [], list(range(11))])
def test_budget_warning_thresholds_reject_invalid_or_unbounded_values(value):
    from maverick_dashboard.settings_catalog import BY_ID, SettingError, coerce
    with pytest.raises(SettingError):
        coerce(BY_ID['budget.warning_thresholds'], value)


def test_budget_warning_thresholds_preserve_numeric_toml_shape():
    from maverick_dashboard.settings_catalog import BY_ID, coerce
    assert coerce(BY_ID['budget.warning_thresholds'], ['1', '0.8', '0.95', '0.8']) == [0.8, 0.95, 1.0]


def test_file_review_binds_new_environment_references(monkeypatch):
    from maverick_dashboard.setup_guide import _file_review_revision
    monkeypatch.setenv('TEAM_DISPLAY_NAME', 'Before')
    raw = b'[persona]\nname="${TEAM_DISPLAY_NAME}"\n'
    first = _file_review_revision(raw)
    monkeypatch.setenv('TEAM_DISPLAY_NAME', 'After')
    assert _file_review_revision(raw) != first


def test_table_reset_and_inherit_match_actual_runtime_merge(monkeypatch):
    from maverick.config import config_path, load_global_config
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('[rate_limits]\nshell="2/minute"\ncustom="3/minute"\n', encoding='utf-8')
    row = 'rate_limits.other'
    def save(change):
        revision = client.get(API).json()['revision']
        return client.post(API, json={'expected_revision': revision, 'confirm': True, 'changes': [{'id': row, **change}]})
    assert save({'reset': True}).status_code == 200
    assert 'custom' not in load_global_config()['rate_limits']
    assert load_global_config()['rate_limits']['shell'] == '2/minute'
    assert page._resolve(page.catalog.BY_ID[row], page._sources())['source'] == 'here'
    assert save({'inherit': True}).status_code == 200
    assert load_global_config()['rate_limits']['custom'] == '3/minute'


def test_internal_reset_metadata_cannot_target_an_arbitrary_path():
    from maverick.config_resets import METADATA
    from maverick_dashboard import settings_store
    with pytest.raises(ValueError):
        settings_store.set_catalog_values({(METADATA, 'rate_limits.other'): {
            'path': ['dashboard', 'admins'], 'keep': [], 'entries': False, 'preserve_tables': False, 'remove_value': False}})
