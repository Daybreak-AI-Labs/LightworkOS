"""`diagnose` reports coding-language toolchains (polyglot operator UX).

Lightwork can now build/test Rust/Go/TS, but only the `local` sandbox uses the
host toolchain -- container backends get it from their image. diagnose surfaces
which toolchains are reachable and which backend supplies them, so an operator
setting up polyglot can see what's missing.
"""
from maverick import config
from maverick.tools import diagnose as d


def test_toolchains_line_always_present():
    assert "coding toolchains on PATH" in "\n".join(d._check_toolchains())


def test_local_backend_warns_about_missing_toolchain(monkeypatch):
    monkeypatch.setattr(config, "get_sandbox", lambda: {"backend": "local"})
    # Probe a binary that cannot exist -> nothing present, warning emitted.
    monkeypatch.setattr(d, "_TOOLCHAINS", [("cobol", "maverick-no-such-binary-xyz")])
    joined = "\n".join(d._check_toolchains())
    assert "(none)" in joined
    assert "can't build/test" in joined


def test_container_backend_notes_image_provides_toolchain(monkeypatch):
    monkeypatch.setattr(config, "get_sandbox", lambda: {"backend": "docker"})
    joined = "\n".join(d._check_toolchains())
    assert "image" in joined
    # A container backend must NOT nag about host toolchains being missing.
    assert "install them" not in joined


def test_diagnose_run_includes_toolchains():
    assert "coding toolchains on PATH" in d.diagnose().fn({})
