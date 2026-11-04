from maverick_installer.wizard import _cfg_role_models


def test_paid_model_test_is_default_off_and_serializes_only_explicit_opt_in():
    assert _cfg_role_models({}) == []
    lines = _cfg_role_models({}, capability_tests=True)
    assert "[models]" in lines and "capability_tests = true" in lines
    assert "capability_tests = true" not in _cfg_role_models({"writer": "openai:synthetic"})


def test_pairing_prompt_group_keeps_optional_action_permission_separate(monkeypatch):
    from maverick_installer import wizard
    answers = iter([True, False])
    monkeypatch.setattr(wizard, "_q_confirm", lambda *args, **kwargs: next(answers))
    assert wizard._pick_device_pairing() == {"enabled": True, "credential_hours": 24, "allow_actions": False}
    answers = iter([False])
    assert wizard._pick_device_pairing() == {"enabled": False, "credential_hours": 24, "allow_actions": False}
