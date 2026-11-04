"""Allowlist-bounded plugin install: the dashboard may pip-install only packages
the operator pre-approved in [plugins] installable. pip runs as argv (no shell)."""
from __future__ import annotations

import subprocess
import types

import pytest
from maverick import plugins


def _cfg(monkeypatch, plugins_section):
    monkeypatch.setattr("maverick.config.load_config",
                        lambda *a, **k: {"plugins": plugins_section})


class TestInstallableAllowlist:
    def test_reads_list(self, monkeypatch):
        _cfg(monkeypatch, {"installable": ["pkg-a", "pkg-b"]})
        assert plugins.installable_plugins() == ["pkg-a", "pkg-b"]

    def test_string_coerced(self, monkeypatch):
        _cfg(monkeypatch, {"installable": "solo-pkg"})
        assert plugins.installable_plugins() == ["solo-pkg"]

    def test_absent_is_empty(self, monkeypatch):
        _cfg(monkeypatch, {})
        assert plugins.installable_plugins() == []


class TestInstallPlugin:
    def test_disabled_without_allowlist(self, monkeypatch):
        _cfg(monkeypatch, {})
        with pytest.raises(ValueError, match="disabled"):
            plugins.install_plugin("anything")

    def test_rejects_package_not_on_allowlist(self, monkeypatch):
        _cfg(monkeypatch, {"installable": ["approved-pkg"]})
        with pytest.raises(ValueError, match="not on the .* allowlist"):
            plugins.install_plugin("evil-pkg")

    def test_rejects_unsafe_name_even_if_allowlisted(self, monkeypatch):
        # A metacharacter-laden entry can't slip through the name guard.
        _cfg(monkeypatch, {"installable": ["bad name; rm -rf /"]})
        with pytest.raises(ValueError, match="unsafe package name"):
            plugins.install_plugin("bad name; rm -rf /")

    def test_success_runs_argv_pip_and_returns_slots(self, monkeypatch):
        _cfg(monkeypatch, {"installable": ["approved-pkg"]})
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            seen["shell"] = kw.get("shell", False)
            return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        out = plugins.install_plugin("approved-pkg")
        assert seen["cmd"][1:4] == ["-m", "pip", "install"]   # argv, python -m pip
        assert "approved-pkg" in seen["cmd"]
        assert seen["shell"] is False                          # never a shell
        assert set(out) == {"tools", "channels", "skills", "personas"}

    def test_pip_failure_raises_with_tail(self, monkeypatch):
        _cfg(monkeypatch, {"installable": ["approved-pkg"]})

        def fake_run(cmd, **kw):
            return types.SimpleNamespace(returncode=1, stdout="", stderr="No matching distribution")

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(ValueError, match="No matching distribution"):
            plugins.install_plugin("approved-pkg")
