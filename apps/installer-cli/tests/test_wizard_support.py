"""The wizard asks for the Help menu's status page and support contact and
writes the ``[support]`` keys the kernel reads (``maverick.config.get_support``)."""
from __future__ import annotations


def _answers(monkeypatch, confirm, texts):
    from maverick_installer import wizard

    replies = iter(texts)
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(replies))
    return wizard


def test_skipping_writes_nothing(monkeypatch):
    wizard = _answers(monkeypatch, False, [])
    assert wizard.pick_support() == {}


def test_answers_become_the_keys_the_kernel_reads(monkeypatch, tmp_path):
    from maverick import config

    wizard = _answers(monkeypatch, True, ["https://status.example.com", "help@vendor.example"])
    support = wizard.pick_support()
    assert support == {"status_page_url": "https://status.example.com", "contact_email": "help@vendor.example"}
    path = tmp_path / "config.toml"
    path.write_text("\n".join(wizard._cfg_table("support", support)) + "\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    config.reset_config_cache()
    try:
        assert config.get_support() == support
    finally:
        config.reset_config_cache()


def test_unsafe_answers_are_skipped(monkeypatch):
    wizard = _answers(monkeypatch, True, ["http://status.example.com", "not an email"])
    assert wizard.pick_support() == {}


def test_answers_the_kernel_would_drop_are_skipped(monkeypatch):
    # The step's own checks accepted these, the kernel's get_support() then
    # dropped them unseen, so the Help menu silently showed nothing.
    wizard = _answers(monkeypatch, True, ["https://", "help@vendor.c"])
    assert wizard.pick_support() == {}
    wizard = _answers(monkeypatch, True, ["https://status.example.com/\tpage", "a,b@vendor.example"])
    assert wizard.pick_support() == {}
