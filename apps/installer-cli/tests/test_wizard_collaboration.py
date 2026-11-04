"""The wizard's comments-and-mentions question (rule-6 loop for
[collaboration] comments): on by default, so saying yes writes nothing and
the kernel reads it as on; saying no writes comments = false and the kernel
reads it as off."""
from __future__ import annotations


def _write(cfg_dir, monkeypatch, collaboration):
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", cfg_dir / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", cfg_dir / "config.toml")
    from maverick_installer.wizard import write_config
    write_config(
        providers=["anthropic"], role_models={},
        channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"},
        keys={}, capabilities={},
        collaboration=collaboration,
    )
    return (cfg_dir / "config.toml").read_text()


def test_comments_question_defaults_to_yes(monkeypatch):
    from maverick_installer import wizard
    captured = {}

    def fake_confirm(message, default=True):
        captured["default"] = default
        return default

    monkeypatch.setattr(wizard, "_q_confirm", fake_confirm)
    assert wizard.pick_collaboration() == {}
    assert captured["default"] is True


def test_declining_writes_the_knob_and_the_kernel_reads_it(tmp_path, monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: False)
    answer = wizard.pick_collaboration()
    assert answer == {"comments": False}
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, answer)
    assert "[collaboration]" in cfg and "comments = false" in cfg
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_dir / "config.toml"))
    from maverick import comments, config
    config.reset_config_cache()
    try:
        assert comments.enabled() is False
    finally:
        config.reset_config_cache()


def test_suggested_edits_questions_default_to_yes_and_write_nothing(monkeypatch):
    from maverick_installer import wizard
    asked = []

    def fake_confirm(message, default=True):
        asked.append((message, default))
        return default

    monkeypatch.setattr(wizard, "_q_confirm", fake_confirm)
    assert wizard.pick_suggestions() == {}
    assert [default for _message, default in asked] == [True, True]
    assert "suggest" in asked[0][0] and "AI assistant" in asked[1][0]


def test_declining_ai_drafting_keeps_suggestions_and_the_kernel_reads_it(tmp_path, monkeypatch):
    from maverick_installer import wizard
    answers = iter([True, False])
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: next(answers))
    answer = wizard.pick_suggestions()
    assert answer == {"ai_suggestions": False}
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, answer)
    assert "ai_suggestions = false" in cfg
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_dir / "config.toml"))
    from maverick import config, policy_suggestions
    config.reset_config_cache()
    try:
        assert policy_suggestions.enabled() is True and policy_suggestions.ai_enabled() is False
    finally:
        config.reset_config_cache()


def test_declining_suggestions_skips_the_ai_question(monkeypatch):
    from maverick_installer import wizard
    asked = []
    monkeypatch.setattr(wizard, "_q_confirm", lambda message, default=True: asked.append(message) or False)
    assert wizard.pick_suggestions() == {"suggestions": False}
    assert len(asked) == 1
