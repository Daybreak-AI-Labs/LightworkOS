"""[auth.local_owner] totp: the owner's authenticator app setting reads as optional unless set otherwise."""
from __future__ import annotations

import pytest
from maverick import config


def _with_global(monkeypatch, cfg):
    monkeypatch.setattr("maverick.config.load_global_config", lambda *a, **k: cfg)


def test_the_default_is_optional(monkeypatch):
    _with_global(monkeypatch, {})
    assert config.get_auth_local_owner_totp() == "optional"


@pytest.mark.parametrize("value, expected", [
    ("required", "required"),
    ("off", "off"),
    (" OFF ", "off"),
    ("optional", "optional"),
    ("maybe", "optional"),
    ("", "optional"),
    (True, "optional"),
    (None, "optional"),
    (["required"], "optional"),
])
def test_only_the_three_modes_are_read_and_anything_else_is_optional(monkeypatch, value, expected):
    _with_global(monkeypatch, {"auth": {"local_owner": {"totp": value}}})
    assert config.get_auth_local_owner_totp() == expected


@pytest.mark.parametrize("cfg", [
    {"auth": "not a table"},
    {"auth": {"local_owner": "not a table"}},
    {"auth": {"local_owner": None}},
])
def test_a_malformed_table_reads_as_optional(monkeypatch, cfg):
    _with_global(monkeypatch, cfg)
    assert config.get_auth_local_owner_totp() == "optional"


def test_an_unreadable_config_reads_as_optional(monkeypatch):
    def broken(*a, **k):
        raise OSError("config unreadable")

    monkeypatch.setattr("maverick.config.load_global_config", broken)
    assert config.get_auth_local_owner_totp() == "optional"


def test_an_unrecognised_mode_is_reported_by_name_and_read_as_optional(monkeypatch, caplog):
    """R11: a misspelt mode is not silent; it names the word and says what is used instead."""
    import logging

    _with_global(monkeypatch, {"auth": {"local_owner": {"totp": "requried"}}})
    with caplog.at_level(logging.WARNING, logger="maverick.config"):
        assert config.get_auth_local_owner_totp() == "optional"
    assert any("requried" in record.getMessage() and "optional" in record.getMessage()
               for record in caplog.records)


def test_a_value_that_looks_like_a_secret_is_not_written_to_the_log(monkeypatch, caplog):
    import logging

    secret = "JBSWY3DPEHPK3PXP"  # pragma: allowlist secret - a fixture value, not a key
    _with_global(monkeypatch, {"auth": {"local_owner": {"totp": secret}}})
    with caplog.at_level(logging.WARNING, logger="maverick.config"):
        assert config.get_auth_local_owner_totp() == "optional"
    assert caplog.records and secret not in caplog.text


@pytest.mark.parametrize("value", ["required", " OFF ", "optional"])
def test_a_recognised_mode_logs_nothing(monkeypatch, caplog, value):
    import logging

    _with_global(monkeypatch, {"auth": {"local_owner": {"totp": value}}})
    with caplog.at_level(logging.WARNING, logger="maverick.config"):
        config.get_auth_local_owner_totp()
    assert not caplog.records


def test_config_lint_flags_an_unrecognised_mode_as_a_warning():
    from maverick.config_lint import lint_config

    findings = lint_config({"auth": {"local_owner": {"totp": "requried"}}})
    hits = [f for f in findings if f.section == "auth.local_owner" and f.key == "totp"]
    assert len(hits) == 1 and hits[0].severity == "warning"
    assert all(mode in hits[0].message for mode in ("optional", "required", "off"))


@pytest.mark.parametrize("value", ["optional", "required", "off", " OFF "])
def test_config_lint_accepts_the_three_modes_as_the_runtime_does(value):
    from maverick.config_lint import lint_config

    findings = lint_config({"auth": {"local_owner": {"totp": value}}})
    assert not [f for f in findings if f.section == "auth.local_owner"]
