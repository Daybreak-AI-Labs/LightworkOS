"""voice_models — local Whisper GGML registry, verified download, lookup."""
from __future__ import annotations

import hashlib
import io
import os
import threading
from types import SimpleNamespace
from urllib.request import Request

import pytest
from maverick import voice_models


def _home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    for env in ("MAVERICK_WHISPER_MODEL", "MAVERICK_WHISPER_CPP_MODEL",
                "MAVERICK_VOICE_AUTO_FETCH"):
        monkeypatch.delenv(env, raising=False)


class _FakeResp:
    def __init__(self, data: bytes):
        self._buf = io.BytesIO(data)

    def read(self, n: int) -> bytes:
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _serve(monkeypatch, payload: bytes):
    seen: list[str] = []

    def _fake_urlopen(url, timeout=0.0):
        seen.append(url)
        return _FakeResp(payload)

    monkeypatch.setattr(voice_models, "_open_model_url", _fake_urlopen)
    return seen


def _pin(monkeypatch, name: str, payload: bytes):
    fn = voice_models.KNOWN_MODELS[name][0]
    monkeypatch.setitem(
        voice_models.KNOWN_MODELS, name,
        (fn, hashlib.sha256(payload).hexdigest(), len(payload)))


def test_models_dir_under_maverick_home(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    assert voice_models.models_dir() == tmp_path / "models" / "whisper"


def test_model_path_unknown_name_lists_choices(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="unknown Whisper model.*base"):
        voice_models.model_path("bogus")


def test_download_rejects_checksum_mismatch(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    _pin(monkeypatch, "tiny", b"original bytes")
    _serve(monkeypatch, b"tampered bytes")
    with pytest.raises(ValueError, match="checksum mismatch"):
        voice_models.download_model("tiny")
    # Nothing installed, no .part litter.
    assert voice_models.installed_models() == []
    assert list(voice_models.models_dir().glob("*")) == []


def test_download_installs_verified_model(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    payload = b"fake ggml weights"
    _pin(monkeypatch, "tiny", payload)
    urls = _serve(monkeypatch, payload)
    ticks: list[tuple[int, int]] = []
    path = voice_models.download_model(
        "tiny", progress=lambda done, total: ticks.append((done, total)))
    assert path.read_bytes() == payload
    assert path.name == "ggml-tiny.bin"
    assert urls == [voice_models._BASE_URL + "ggml-tiny.bin"]
    assert ticks and ticks[-1] == (len(payload), len(payload))
    assert voice_models.verify_model(path) is True


def test_download_skips_existing_unless_force(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    dest = voice_models.model_path("tiny")
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"already here")

    def _boom(url, timeout=0.0):
        raise AssertionError("network hit despite existing file")

    monkeypatch.setattr(voice_models, "_open_model_url", _boom)
    assert voice_models.download_model("tiny") == dest

    payload = b"fresh copy"
    _pin(monkeypatch, "tiny", payload)
    _serve(monkeypatch, payload)
    assert voice_models.download_model("tiny", force=True).read_bytes() == payload


def test_verify_model_flags_pinned_mismatch_and_allows_foreign(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    d = voice_models.models_dir()
    d.mkdir(parents=True)
    bad = d / "ggml-tiny.bin"
    bad.write_bytes(b"wrong")
    assert voice_models.verify_model(bad) is False
    foreign = d / "ggml-custom-finetune.bin"
    foreign.write_bytes(b"operator supplied")
    assert voice_models.verify_model(foreign) is None


def test_locate_model_env_path_wins(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    explicit = tmp_path / "my-model.bin"
    explicit.write_bytes(b"x")
    monkeypatch.setenv("MAVERICK_WHISPER_CPP_MODEL", str(explicit))
    assert voice_models.locate_model() == explicit


def test_locate_model_uses_any_installed_ggml(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    d = voice_models.models_dir()
    d.mkdir(parents=True)
    hand_copied = d / "ggml-small.en.bin"
    hand_copied.write_bytes(b"x")
    # Configured size (default 'base') absent -> the hand-copied file works.
    assert voice_models.locate_model() == hand_copied


def test_locate_model_none_when_auto_fetch_disabled(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_VOICE_AUTO_FETCH", "0")

    def _boom(url, timeout=0.0):
        raise AssertionError("auto-fetch disabled; must not touch the network")

    monkeypatch.setattr("urllib.request.urlopen", _boom)
    assert voice_models.locate_model() is None


def test_auto_fetch_defaults_off_for_standard_deployments(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    assert voice_models.auto_fetch_enabled() is False
    monkeypatch.setattr(voice_models, "download_model", lambda *_: pytest.fail("unreviewed download"))
    assert voice_models.locate_model() is None


@pytest.mark.parametrize("payload", [b"short", b"longer than pinned bytes"])
def test_download_enforces_pinned_byte_limit(monkeypatch, tmp_path, payload):
    _home(monkeypatch, tmp_path)
    _pin(monkeypatch, "tiny", b"eight!!!")
    _serve(monkeypatch, payload)
    with pytest.raises(ValueError, match="size"):
        voice_models.download_model("tiny")
    assert not voice_models.model_path("tiny").exists()
    assert not list(voice_models.models_dir().glob("*.part"))


def test_download_cancellation_preserves_existing_file(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    _pin(monkeypatch, "tiny", b"new file")
    _serve(monkeypatch, b"new file")
    dest = voice_models.model_path("tiny")
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"old file")
    cancelled = threading.Event()
    with pytest.raises(voice_models.DownloadCancelled):
        voice_models.download_model("tiny", force=True, cancel=cancelled,
                                    progress=lambda *_: cancelled.set())
    assert dest.read_bytes() == b"old file"
    assert not list(dest.parent.glob("*.part"))


def test_explicit_setup_checks_and_repairs_existing_model(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    payload = b"valid model"
    _pin(monkeypatch, "tiny", payload)
    urls = _serve(monkeypatch, payload)
    dest = voice_models.model_path("tiny")
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"corrupt")
    assert voice_models.download_model("tiny", verify_existing=True).read_bytes() == payload
    assert len(urls) == 1
    voice_models.download_model("tiny", verify_existing=True)
    assert len(urls) == 1


def test_download_policy_preserves_global_floor_and_checks_redirects(monkeypatch):
    from maverick import config, enterprise

    monkeypatch.setattr(config, "load_global_config", lambda: {"enterprise": {"allowed_hosts": ["huggingface.co"]}})
    monkeypatch.setattr(config, "config_source_errors", lambda **_: [])
    monkeypatch.setattr(enterprise, "deployment_enterprise_enabled", lambda: True)
    # A permissive tenant cannot waive the deployment-wide floor.
    monkeypatch.setattr(enterprise, "egress_permitted", lambda _: True)
    url = voice_models._BASE_URL + "ggml-base.bin"
    assert voice_models.download_egress_permitted(url)
    redirect = voice_models._ModelRedirect()
    with pytest.raises(PermissionError, match="network policy"):
        redirect.redirect_request(Request(url), None, 302, "Found", {}, "https://unapproved.example/weights")
    with pytest.raises(PermissionError):
        redirect.redirect_request(Request(url), None, 302, "Found", {}, "http://huggingface.co/weights")
    monkeypatch.setattr(enterprise, "egress_permitted", lambda _: False)
    assert not voice_models.download_egress_permitted(url)


@pytest.mark.skipif(os.name != "nt", reason="Windows creation-time tunneling")
def test_verified_file_accepts_different_windows_fd_creation_time(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    payload = b"actual checked file"
    _pin(monkeypatch, "tiny", payload)
    dest = voice_models.model_path("tiny")
    dest.parent.mkdir(parents=True)
    dest.write_bytes(payload)
    actual_fstat = os.fstat
    def tunneled(fd):
        stat = actual_fstat(fd)
        return SimpleNamespace(st_size=stat.st_size, st_mtime_ns=stat.st_mtime_ns,
            st_dev=stat.st_dev, st_ino=stat.st_ino, st_ctime_ns=stat.st_ctime_ns + 100_000_000)
    monkeypatch.setattr(voice_models.os, "fstat", tunneled)
    assert voice_models.verified_model_fingerprint(dest) == voice_models.model_fingerprint(dest.stat())
    dest.write_bytes(b"X" * len(payload))
    assert voice_models.verified_model_fingerprint(dest) is None


def test_auto_fetch_defaults_off_under_egress_lock(monkeypatch, tmp_path):
    """An egress-locked box must not phone Hugging Face because someone
    clicked a mic — the enterprise boundary flips the default."""
    _home(monkeypatch, tmp_path)
    import maverick.enterprise as enterprise
    monkeypatch.setattr(enterprise, "enterprise_enabled", lambda: True)
    assert voice_models.auto_fetch_enabled() is False


def test_auto_fetch_explicit_config_beats_posture(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    import maverick.enterprise as enterprise
    (tmp_path / "config.toml").write_text(
        "[voice]\nauto_fetch_model = true\n", encoding="utf-8")
    monkeypatch.setattr(enterprise, "enterprise_enabled", lambda: True)
    assert voice_models.auto_fetch_enabled() is True
    (tmp_path / "config.toml").write_text(
        "[voice]\nauto_fetch_model = false\n", encoding="utf-8")
    monkeypatch.setattr(enterprise, "enterprise_enabled", lambda: False)
    assert voice_models.auto_fetch_enabled() is False


def test_auto_fetch_env_beats_everything(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    (tmp_path / "config.toml").write_text(
        "[voice]\nauto_fetch_model = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_VOICE_AUTO_FETCH", "0")
    assert voice_models.auto_fetch_enabled() is False


def test_locate_model_auto_fetch_downloads_configured(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    payload = b"auto fetched weights"
    _pin(monkeypatch, "base", payload)
    _serve(monkeypatch, payload)
    monkeypatch.setenv("MAVERICK_VOICE_AUTO_FETCH", "1")
    got = voice_models.locate_model()
    assert got is not None and got.name == "ggml-base.bin"
    assert got.read_bytes() == payload


def test_configured_model_env_beats_default(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    assert voice_models.configured_model() == "base"
    monkeypatch.setenv("MAVERICK_WHISPER_MODEL", "small.en")
    assert voice_models.configured_model() == "small.en"


# ---- maverick voice CLI ------------------------------------------------------


def test_cli_voice_status_runs(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    for env in ("OPENAI_API_KEY", "GROQ_API_KEY", "MAVERICK_WHISPER_CPP",
                "MAVERICK_VOICE_STT_BACKEND"):
        monkeypatch.delenv(env, raising=False)
    from click.testing import CliRunner
    from maverick.cli import main
    res = CliRunner().invoke(main, ["voice", "status"])
    assert res.exit_code == 0, res.output
    assert "Speech-to-text backends" in res.output
    assert "default backend: auto" in res.output


def test_cli_voice_setup_downloads_and_reports(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    payload = b"cli fetched weights"
    _pin(monkeypatch, "tiny", payload)
    _serve(monkeypatch, payload)
    from click.testing import CliRunner
    from maverick.cli import main
    res = CliRunner().invoke(main, ["voice", "setup", "--model", "tiny"])
    assert res.exit_code == 0, res.output
    assert "installed" in res.output
    assert voice_models.model_path("tiny").read_bytes() == payload


def test_cli_voice_setup_unknown_model_fails_cleanly(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    from click.testing import CliRunner
    from maverick.cli import main
    res = CliRunner().invoke(main, ["voice", "setup", "--model", "bogus"])
    assert res.exit_code != 0
    assert "unknown Whisper model" in res.output
