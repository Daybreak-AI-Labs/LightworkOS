from maverick import config
from maverick.mobile_offline_policy import effective_policy


def test_workspace_cannot_relax_organization_offline_ceiling(monkeypatch):
    monkeypatch.setattr(config, 'config_source_errors', lambda **kwargs: [])
    monkeypatch.setattr(config, 'load_global_config', lambda: {'mobile_offline':{'max_age_seconds':600, 'max_bytes':1024}})
    monkeypatch.setattr(config, 'load_config', lambda: {'mobile_offline':{'max_age_seconds':86400, 'max_bytes':2097152}})
    policy = effective_policy()
    assert policy['allowed'] is True
    assert policy['max_age_seconds'] == 600
    assert policy['max_bytes'] == 1024


def test_disabled_or_unreadable_policy_fails_closed(monkeypatch):
    monkeypatch.setattr(config, 'config_source_errors', lambda **kwargs: [])
    monkeypatch.setattr(config, 'load_global_config', lambda: {'mobile_offline':{'enabled':False}})
    monkeypatch.setattr(config, 'load_config', lambda: {'mobile_offline':{'enabled':True}})
    assert effective_policy()['allowed'] is False
    monkeypatch.setattr(config, 'config_source_errors', lambda **kwargs: ['unavailable'])
    assert effective_policy()['allowed'] is False
    assert effective_policy()['max_age_seconds'] == 0
