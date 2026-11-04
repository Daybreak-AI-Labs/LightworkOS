"""Knowledge revision survives the wizard and kernel config projection."""
from maverick import config
from maverick_installer import wizard


def test_optional_revision_is_prompted_serialized_and_read(monkeypatch):
    monkeypatch.setattr(wizard, "_q_confirm", lambda *args, **kwargs: True)
    answers = iter(["local - local model", "sqlite - local store"])
    monkeypatch.setattr(wizard, "_q_select", lambda *args, **kwargs: next(answers))
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "a" * 40)
    chosen = wizard.pick_knowledge()
    assert chosen["revision"] == "a" * 40
    assert f'revision = "{"a" * 40}"' in wizard._cfg_knowledge(chosen)
    monkeypatch.setattr(config, "load_config", lambda: {"knowledge": chosen})
    assert config.get_knowledge()["revision"] == "a" * 40


def test_blank_revision_keeps_automatic_identity(monkeypatch):
    monkeypatch.setattr(wizard, "_q_confirm", lambda *args, **kwargs: True)
    monkeypatch.setattr(wizard, "_q_select", lambda *args, **kwargs: kwargs["default"])
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")
    assert "revision" not in wizard.pick_knowledge()
