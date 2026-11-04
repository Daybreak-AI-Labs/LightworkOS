"""Sandbox picks a language-appropriate toolchain image (polyglot coding-mode).

coding_mode already detects + runs cargo / go test / jest and parses their
output; the missing piece was the container backend, which defaulted to
python:3.12-slim and so had no toolchain to run those with. build_sandbox now
resolves the image from the MAVERICK_LANGUAGE hint (the same signal coding_mode
threads into the test runner). An explicit [sandbox] image always wins; an
unknown language falls back to Python so existing setups are unchanged.
"""
from maverick.sandbox import _DEFAULT_IMAGE, _resolve_image


def test_explicit_image_always_wins(monkeypatch):
    monkeypatch.setenv("MAVERICK_LANGUAGE", "rust")
    assert _resolve_image({"image": "myco/custom:1"}) == "myco/custom:1"


def test_rust_selects_a_cargo_toolchain(monkeypatch):
    monkeypatch.setenv("MAVERICK_LANGUAGE", "rust")
    assert "rust" in _resolve_image({})


def test_go_selects_a_go_toolchain(monkeypatch):
    monkeypatch.setenv("MAVERICK_LANGUAGE", "go")
    assert "golang" in _resolve_image({})


def test_node_languages_share_the_node_image(monkeypatch):
    for lang in ("javascript", "typescript", "ts", "node"):
        monkeypatch.setenv("MAVERICK_LANGUAGE", lang)
        assert "node" in _resolve_image({})


def test_config_language_overrides_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_LANGUAGE", "python")
    assert "golang" in _resolve_image({"language": "go"})


def test_unknown_or_unset_language_falls_back_to_python(monkeypatch):
    monkeypatch.delenv("MAVERICK_LANGUAGE", raising=False)
    assert _resolve_image({}) == _DEFAULT_IMAGE
    monkeypatch.setenv("MAVERICK_LANGUAGE", "cobol")
    assert _resolve_image({}) == _DEFAULT_IMAGE


def test_non_string_config_language_falls_back_to_python(monkeypatch):
    monkeypatch.setenv("MAVERICK_LANGUAGE", "rust")
    for lang in (1, True, ["rust"]):
        assert _resolve_image({"language": lang}) == _DEFAULT_IMAGE


def test_local_backend_unaffected_by_language(monkeypatch, tmp_path):
    """The default (local) backend uses the host toolchain, so the language
    hint must not change which backend you get."""
    from maverick.sandbox import LocalBackend, build_sandbox
    monkeypatch.setenv("MAVERICK_LANGUAGE", "rust")
    sb = build_sandbox(workdir=tmp_path, backend="local")
    assert isinstance(sb, LocalBackend)
