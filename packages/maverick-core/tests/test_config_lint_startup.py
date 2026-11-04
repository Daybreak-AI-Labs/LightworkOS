"""warn_config_at_startup: surface typo'd config at server start.

The full linter already exists; this wires it into startup so a mis-typed
security/cost key (which silently falls back to a default) is caught when a
long-running server starts, not only via `maverick config-lint`.
"""
from __future__ import annotations

import logging

import pytest
from maverick import config_lint


class _ExistingPath:
    def exists(self):
        return True


class _MissingPath:
    def exists(self):
        return False


def _stub_config(monkeypatch, cfg, *, exists=True):
    monkeypatch.setattr(
        "maverick.config.config_path",
        lambda: _ExistingPath() if exists else _MissingPath(),
    )
    # Startup lint reads the RAW (uninterpolated) TOML so a "${VAR}" reference
    # isn't mistaken for an inline secret after env expansion.
    monkeypatch.setattr("maverick.config._read_toml_raw", lambda p: cfg)


# 'max_dollarss' is an unknown key in [budget] -> a (warning-level) finding.
_TYPO_CFG = {"budget": {"max_dollarss": 5.0}}


def test_warns_and_does_not_raise_by_default(monkeypatch, caplog):
    monkeypatch.delenv("MAVERICK_CONFIG_STRICT", raising=False)
    _stub_config(monkeypatch, _TYPO_CFG)
    with caplog.at_level(logging.WARNING, logger="maverick.config"):
        findings = config_lint.warn_config_at_startup()
    assert findings
    assert any("max_dollarss" in r.message for r in caplog.records)


def test_strict_raises_on_any_finding(monkeypatch):
    # A typo is a *warning*, not an error -- strict must still fail on it.
    monkeypatch.setenv("MAVERICK_CONFIG_STRICT", "1")
    _stub_config(monkeypatch, _TYPO_CFG)
    with pytest.raises(SystemExit):
        config_lint.warn_config_at_startup()


def test_strict_clean_config_starts(monkeypatch):
    monkeypatch.setenv("MAVERICK_CONFIG_STRICT", "1")
    _stub_config(monkeypatch, {"budget": {"max_dollars": 5.0}})
    assert config_lint.warn_config_at_startup() == []


def test_no_config_file_is_a_noop(monkeypatch):
    monkeypatch.setenv("MAVERICK_CONFIG_STRICT", "1")
    _stub_config(monkeypatch, {}, exists=False)
    assert config_lint.warn_config_at_startup() == []


def test_strict_does_not_flag_env_ref_api_key(monkeypatch, tmp_path):
    # Regression: the DOCUMENTED `api_key = "${ANTHROPIC_API_KEY}"` pattern must
    # not be flagged as an inline secret at startup even when the env var is set
    # (which expands it to the literal key) -- otherwise strict mode refuses to
    # start a correctly-configured deployment. Uses a real file so the raw-read
    # path is exercised end to end.
    from maverick.config import _toml_cache
    _toml_cache.clear()
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        '[providers.anthropic]\napi_key = "${ANTHROPIC_API_KEY}"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("maverick.config.config_path", lambda: cfg_file)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret-value")
    monkeypatch.setenv("MAVERICK_CONFIG_STRICT", "1")
    # Must NOT raise SystemExit and must report no inline-secret finding.
    findings = config_lint.warn_config_at_startup()
    assert not any("inline secret" in f.message for f in findings)
