"""Wizard re-runs must not rotate the consent subject_salt.

Consent subject digests are sha256(salt:subject); a regenerated salt
orphans every stored consent receipt. The wizard re-reads the config it
is about to rewrite and keeps the salt the records were digested under.
"""
from __future__ import annotations

from maverick_installer import wizard


def test_first_enable_mints_a_fresh_salt(tmp_path, monkeypatch):
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    salt = wizard._prior_consent_salt()
    assert 16 <= len(salt) <= 256
    # Fresh each call when there is nothing to preserve.
    assert wizard._prior_consent_salt() != salt


def test_re_run_preserves_the_existing_salt(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text(
        '[consent_registry]\nenable = true\n'
        'subject_salt = "keep-this-salt-0123456789abcdef"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(wizard, "CONFIG_FILE", config)
    assert wizard._prior_consent_salt() == "keep-this-salt-0123456789abcdef"


def test_an_unusable_prior_salt_is_replaced(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text(
        '[consent_registry]\nsubject_salt = "short"\n', encoding="utf-8",
    )
    monkeypatch.setattr(wizard, "CONFIG_FILE", config)
    salt = wizard._prior_consent_salt()
    assert salt != "short" and len(salt) >= 16

    config.write_text("not [valid toml", encoding="utf-8")
    assert len(wizard._prior_consent_salt()) >= 16
