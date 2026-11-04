"""Hand-edited config must apply (case/whitespace) and tolerate bad values.

profile/backend/provider etc. come from hand-edited TOML (or CLI flags) and
were compared against lowercase literals, so "Docker" / "Anthropic:" silently
misapplied; a non-numeric [sandbox] timeout crashed the kernel outright. These
tests pin normalization + defensive coercion at the highest-impact
chokepoints:

  - build_sandbox(): a mis-cased backend must NOT silently degrade to the
    unsandboxed local backend (a security downgrade), and an unrecognized
    backend must warn loudly instead of failing quiet.
  - llm._parse_spec(): a mis-cased / aliased provider must canonicalize so the
    case-sensitive API-key lookup resolves (not just client creation).
"""
from __future__ import annotations

import logging

import maverick.sandbox as sandbox_mod
from maverick.llm import _parse_spec
from maverick.sandbox import LocalBackend, build_sandbox


class TestSandboxBackendCasing:
    # Patch the container backends to sentinels: DockerBackend/PodmanBackend
    # verify their runtime in __init__ (raise when absent), so we test the
    # selection logic in isolation -- and a sentinel return sharply proves the
    # branch taken (vs a silent fall-through to the real LocalBackend).
    def test_mixed_case_docker_resolves_to_docker_not_local(self, monkeypatch):
        monkeypatch.setattr(sandbox_mod, "DockerBackend", lambda **kw: "DOCKER")
        assert build_sandbox(backend="Docker") == "DOCKER"

    def test_surrounding_whitespace_and_case_tolerated(self, monkeypatch):
        monkeypatch.setattr(sandbox_mod, "PodmanBackend", lambda **kw: "PODMAN")
        assert build_sandbox(backend="  PODMAN  ") == "PODMAN"

    def test_unknown_backend_falls_back_to_local_with_named_warning(self, monkeypatch, caplog):
        # Silence the generic local-unsandboxed advisory so the assertion only
        # sees the unrecognized-backend warning my fix adds.
        monkeypatch.setenv("MAVERICK_SUPPRESS_SANDBOX_WARNING", "1")
        with caplog.at_level(logging.WARNING, logger="maverick.sandbox"):
            sb = build_sandbox(backend="dokcer")  # typo
        assert isinstance(sb, LocalBackend)
        assert "unrecognized sandbox backend" in caplog.text
        assert "dokcer" in caplog.text

    def test_explicit_local_does_not_warn_unrecognized(self, monkeypatch, caplog):
        monkeypatch.setenv("MAVERICK_SUPPRESS_SANDBOX_WARNING", "1")
        with caplog.at_level(logging.WARNING, logger="maverick.sandbox"):
            sb = build_sandbox(backend="Local")
        assert isinstance(sb, LocalBackend)
        assert "unrecognized sandbox backend" not in caplog.text


class TestParseSpecProviderCasing:
    def test_mixed_case_provider_canonicalizes(self):
        assert _parse_spec("Anthropic:claude-opus-4-7") == ("anthropic", "claude-opus-4-7")

    def test_advertised_alias_resolves(self):
        # 'claude' and 'kimi' are documented aliases (providers._PROVIDER_ALIASES).
        assert _parse_spec("claude:some-model") == ("anthropic", "some-model")
        assert _parse_spec("kimi:k2") == ("moonshot", "k2")

    def test_bare_model_id_defaults_to_anthropic(self):
        assert _parse_spec("claude-opus-4-7") == ("anthropic", "claude-opus-4-7")

    def test_only_first_colon_splits_provider(self):
        # Model ids can contain colons; split(":", 1) must preserve them.
        assert _parse_spec("openai:org/model:v2") == ("openai", "org/model:v2")


class TestNotifyBackendCasing:
    def test_mixed_case_backend_routes_to_handler(self, monkeypatch):
        import maverick.notifications as notif
        fired: list[str] = []
        monkeypatch.setattr(notif, "_send_discord", lambda *a, **k: fired.append("discord") or True)
        n = notif.notify("agent done", backends=["Discord"], async_dispatch=False)
        assert fired == ["discord"]
        assert n == 1

    def test_backend_whitespace_and_case_tolerated(self, monkeypatch):
        import maverick.notifications as notif
        fired: list[str] = []
        monkeypatch.setattr(notif, "_send_discord", lambda *a, **k: fired.append("discord") or True)
        notif.notify("agent done", backends=["  DISCORD  "], async_dispatch=False)
        assert fired == ["discord"]

    def test_none_sentinel_is_case_insensitive(self, monkeypatch):
        import maverick.notifications as notif
        # "None" must disable just like "none" -- nothing dispatched, returns 0.
        monkeypatch.setattr(notif, "_send_discord", lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not fire")))
        assert notif.notify("x", backends=["None"], async_dispatch=False) == 0


class TestDiagnosticsSandboxCasing:
    # The `maverick health` / `diagnose` readouts read the same user-typed
    # sandbox backend; they must normalize like build_sandbox or a valid
    # "Docker" config misreports (skips the docker probe / unsupported row).
    def test_health_routes_mixed_case_docker_to_docker_probe(self, monkeypatch):
        from maverick import health
        rows: list[str] = []
        monkeypatch.setattr(health, "_row", lambda color, name, msg, **k: rows.append(msg))
        monkeypatch.setattr("shutil.which", lambda name: None)  # docker "absent"
        health._check_sandbox({"sandbox": {"backend": "Docker"}})
        text = " ".join(rows)
        assert "docker not on PATH" in text          # took the docker branch
        assert "supported in v0.1" not in text        # not the unsupported catch-all

    def test_diagnose_sandbox_routes_mixed_case_docker(self, monkeypatch):
        from maverick import config
        from maverick.tools import diagnose as d
        monkeypatch.setattr(config, "get_sandbox", lambda: {"backend": "Docker"})
        monkeypatch.setattr("shutil.which", lambda name: None)  # docker "absent"
        joined = "\n".join(d._check_sandbox())
        assert "docker binary not on PATH" in joined

    def test_diagnose_toolchains_treats_mixed_case_local_as_local(self, monkeypatch):
        from maverick import config
        from maverick.tools import diagnose as d
        monkeypatch.setattr(config, "get_sandbox", lambda: {"backend": "LOCAL"})
        monkeypatch.setattr(d, "_TOOLCHAINS", [("cobol", "maverick-no-such-binary-xyz")])
        joined = "\n".join(d._check_toolchains())
        assert "can't build/test" in joined           # treated as local despite casing


class TestSandboxTimeoutCoercion:
    # [sandbox] timeout is hand-editable; a bad value must fall back to the
    # default, not crash build_sandbox() (and with it the whole agent startup).
    def test_non_numeric_timeout_falls_back_to_default(self, monkeypatch):
        from maverick import config
        monkeypatch.setattr(config, "get_sandbox", lambda: {"backend": "local", "timeout": "fast"})
        sb = build_sandbox()  # must not raise
        assert isinstance(sb, LocalBackend)
        assert sb.timeout == 60.0

    def test_non_positive_timeout_falls_back_to_default(self, monkeypatch):
        from maverick import config
        for bad in (-5, 0):
            monkeypatch.setattr(config, "get_sandbox", lambda bad=bad: {"backend": "local", "timeout": bad})
            assert build_sandbox().timeout == 60.0

    def test_valid_timeout_is_honored(self, monkeypatch):
        from maverick import config
        monkeypatch.setattr(config, "get_sandbox", lambda: {"backend": "local", "timeout": 30})
        assert build_sandbox().timeout == 30.0
