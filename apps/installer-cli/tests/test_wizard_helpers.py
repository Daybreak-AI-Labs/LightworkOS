"""Docker auto-detect, validation cache, error UI helpers."""
from __future__ import annotations

import json

# ---------- _docker_available ----------

def test_docker_available_no_binary(monkeypatch):
    import shutil as _shutil

    from maverick_installer import wizard
    monkeypatch.setattr(_shutil, "which", lambda _x: None)
    assert wizard._docker_available() is False


def test_docker_available_binary_but_daemon_down(monkeypatch):
    import shutil as _shutil
    import subprocess as _sp

    from maverick_installer import wizard
    monkeypatch.setattr(_shutil, "which", lambda _x: "/usr/bin/docker")
    def _raise(*a, **kw):
        raise _sp.CalledProcessError(1, ["docker", "version"])
    monkeypatch.setattr(_sp, "run", _raise)
    assert wizard._docker_available() is False


def test_docker_available_happy_path(monkeypatch):
    import shutil as _shutil
    import subprocess as _sp

    from maverick_installer import wizard
    monkeypatch.setattr(_shutil, "which", lambda _x: "/usr/bin/docker")
    monkeypatch.setattr(
        _sp, "run",
        lambda *a, **kw: _sp.CompletedProcess(a[0], 0, b"", b""),
    )
    assert wizard._docker_available() is True


# ---------- pick_sandbox default stays on docker ----------

def test_pick_sandbox_defaults_docker_when_unavailable(monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_docker_available", lambda: False)
    defaults = []
    def fake_select(message, choices, default=None):
        defaults.append(default)
        return default
    monkeypatch.setattr(wizard, "_q_select", fake_select)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: "/tmp/ws")
    wizard.pick_sandbox()
    # The backend prompt is first; its default stays docker even when the
    # daemon is down (security-first). A container backend then asks a second
    # question (the coding language), so assert on the first prompt, not last.
    assert defaults[0].startswith("docker")


# ---------- validation cache ----------

def test_validation_cache_round_trip(tmp_path, monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "VALIDATION_CACHE_PATH", tmp_path / "validation-cache.json")
    wizard._remember_validation("ANTHROPIC_API_KEY", "sk-ant-test", True, "ok")
    cached = wizard._cached_validation("ANTHROPIC_API_KEY", "sk-ant-test")
    assert cached == (True, "ok")


def test_validation_cache_miss_for_different_key(tmp_path, monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "VALIDATION_CACHE_PATH", tmp_path / "validation-cache.json")
    wizard._remember_validation("ANTHROPIC_API_KEY", "sk-ant-a", True, "ok")
    assert wizard._cached_validation("ANTHROPIC_API_KEY", "sk-ant-b") is None


def test_validation_cache_expires_after_ttl(tmp_path, monkeypatch):
    import time as _time

    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "VALIDATION_CACHE_PATH", tmp_path / "validation-cache.json")
    wizard._remember_validation("OPENAI_API_KEY", "sk-x", True, "ok")
    # Tamper the on-disk ts to 8 days ago.
    body = json.loads((tmp_path / "validation-cache.json").read_text())
    for entry in body.values():
        entry["ts"] = _time.time() - 8 * 24 * 3600
    (tmp_path / "validation-cache.json").write_text(json.dumps(body))
    assert wizard._cached_validation("OPENAI_API_KEY", "sk-x") is None


def test_validation_cache_persists_at_chmod_600(tmp_path, monkeypatch):
    import stat as _stat

    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "VALIDATION_CACHE_PATH", tmp_path / "validation-cache.json")
    wizard._remember_validation("ANTHROPIC_API_KEY", "sk-perm", True, "ok")
    path = tmp_path / "validation-cache.json"
    assert path.exists()
    import os
    mode = _stat.S_IMODE(path.stat().st_mode)
    if os.name != "nt":  # NTFS reports 0o666 regardless of the chmod
        assert mode == 0o600


def test_empty_key_never_caches(tmp_path, monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "VALIDATION_CACHE_PATH", tmp_path / "validation-cache.json")
    wizard._remember_validation("ANTHROPIC_API_KEY", "", True, "ok")
    assert not (tmp_path / "validation-cache.json").exists()
    assert wizard._cached_validation("ANTHROPIC_API_KEY", "") is None


# ---------- error UI panels ----------

def test_error_helpers_dont_crash(capsys):
    from maverick_installer import wizard
    wizard.show_bad_key_error("ANTHROPIC_API_KEY", "API rejected the key")
    wizard.show_network_error("Anthropic", "ConnectError")
    wizard.show_install_failure(RuntimeError("disk full"))
    # Smoke: they all rendered. (Panel chrome shortens lines; just verify
    # each panel's distinctive phrase appears somewhere in the output.)
    out = capsys.readouterr().out
    assert "Anthropic" in out
    assert "Setup hit a problem" in out
