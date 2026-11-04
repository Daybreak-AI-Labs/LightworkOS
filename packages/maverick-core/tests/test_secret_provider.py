"""Pluggable secret resolution: the default env backend reads the environment; the
file backend reads mounted vault/Docker/k8s secret files with env fallback."""
from __future__ import annotations

import pytest
from maverick import secret_provider as sp


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("MAVERICK_SECRETS_BACKEND", "MAVERICK_SECRETS_DIR"):
        monkeypatch.delenv(var, raising=False)
    # No config in the way; tests opt in explicitly.
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def test_default_backend_is_env(monkeypatch):
    monkeypatch.setenv("MY_SECRET", "from-env")
    assert sp.get_secret("MY_SECRET") == "from-env"
    assert sp.get_secret("ABSENT") is None
    assert sp.get_secret("ABSENT", "fallback") == "fallback"


def test_file_backend_reads_mounted_secret(monkeypatch, tmp_path):
    (tmp_path / "MAVERICK_OIDC_CLIENT_SECRET").write_text("vault-value\n")
    monkeypatch.setenv("MAVERICK_SECRETS_BACKEND", "file")
    monkeypatch.setenv("MAVERICK_SECRETS_DIR", str(tmp_path))
    # Trailing newline stripped; file wins over a (here absent) env var.
    assert sp.get_secret("MAVERICK_OIDC_CLIENT_SECRET") == "vault-value"


def test_file_backend_falls_back_to_env(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_SECRETS_BACKEND", "file")
    monkeypatch.setenv("MAVERICK_SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("ONLY_IN_ENV", "env-value")
    # No file present -> env fallback keeps partial migrations working.
    assert sp.get_secret("ONLY_IN_ENV") == "env-value"


def test_file_backend_lowercase_sibling(monkeypatch, tmp_path):
    (tmp_path / "my_token").write_text("lower")
    monkeypatch.setenv("MAVERICK_SECRETS_BACKEND", "file")
    monkeypatch.setenv("MAVERICK_SECRETS_DIR", str(tmp_path))
    assert sp.get_secret("MY_TOKEN") == "lower"


def test_file_backend_rejects_traversal_name(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_SECRETS_BACKEND", "file")
    monkeypatch.setenv("MAVERICK_SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("../etc/passwd", "should-not-read")
    # An unsafe name never forms a path; env fallback returns the env value.
    assert sp.get_secret("../etc/passwd") == "should-not-read"


def test_unknown_backend_warns_and_falls_back_to_env(monkeypatch, tmp_path, caplog):
    # An operator who *meant* the file backend but mistyped it must not
    # silently get env resolution with no trace: a typo'd backend name still
    # resolves from env (safe default) but emits a one-time warning so the
    # disabled file-isolation is visible.
    sp._warned_backends.clear()
    (tmp_path / "MY_SECRET").write_text("from-file")
    monkeypatch.setenv("MAVERICK_SECRETS_BACKEND", "files")  # typo of "file"
    monkeypatch.setenv("MAVERICK_SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("MY_SECRET", "from-env")
    with caplog.at_level("WARNING"):
        # The file is never consulted (backend != 'file'); env value is used.
        assert sp.get_secret("MY_SECRET") == "from-env"
    assert any("unknown secrets backend" in r.message for r in caplog.records)
    assert "files" in sp._warned_backends


def test_known_backends_do_not_warn(monkeypatch, caplog):
    sp._warned_backends.clear()
    monkeypatch.setenv("MAVERICK_SECRETS_BACKEND", "ENV")  # case-insensitive
    monkeypatch.setenv("MY_SECRET", "from-env")
    with caplog.at_level("WARNING"):
        assert sp.get_secret("MY_SECRET") == "from-env"
    assert not any("unknown secrets backend" in r.message for r in caplog.records)


def test_backend_from_config_when_env_absent(monkeypatch, tmp_path):
    (tmp_path / "CFG_SECRET").write_text("cfg")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"secrets": {"backend": "file", "dir": str(tmp_path)}},
    )
    assert sp.get_secret("CFG_SECRET") == "cfg"


def test_saved_key_is_a_fallback_and_the_server_value_wins(monkeypatch):
    # A key saved (sealed) on the dashboard is used only when the server holds
    # nothing under the reference.
    assert sp.get_secret_or_saved("ABSENT_REF", "saved-value") == "saved-value"
    monkeypatch.setenv("PRESENT_REF", "server-value")
    assert sp.get_secret_or_saved("PRESENT_REF", "saved-value") == "server-value"
    assert sp.get_secret_or_saved("ABSENT_REF", "") is None
    assert sp.get_secret_or_saved("ABSENT_REF", None) is None
    assert sp.get_secret_or_saved("", "saved-value") == "saved-value"
