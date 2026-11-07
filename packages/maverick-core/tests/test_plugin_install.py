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
        with pytest.raises(ValueError, match="unsafe package name|allowlist"):
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


_H = "a" * 64


class TestPinnedInstall:
    def test_pinned_entry_parses_and_names_only_the_package(self, monkeypatch):
        _cfg(monkeypatch, {"installable": [f"pkg-a==1.2.3 sha256:{_H}", "pkg-b"]})
        assert plugins.installable_plugins() == ["pkg-a", "pkg-b"]
        pins = plugins.installable_pins()
        assert pins["pkg-a"] == ("1.2.3", (f"sha256:{_H}",))
        assert pins["pkg-b"] == (None, ())

    @pytest.mark.parametrize("entry", [
        f"pkg-a sha256:{_H}",            # a hash needs an exact version
        "pkg-a==1.2.3 sha256:abc",       # malformed digest
        "pkg-a>=1.2.3",                  # ranges are not pins
        "pkg-a==1.2.3 md5:" + "b" * 32,  # only sha256
        "http://evil/pkg.whl",
    ])
    def test_malformed_entries_are_dropped_from_the_allowlist(self, monkeypatch, entry):
        _cfg(monkeypatch, {"installable": [entry]})
        assert plugins.installable_plugins() == []
        with pytest.raises(ValueError, match="disabled|allowlist"):
            plugins.install_plugin("pkg-a")

    def test_pinned_install_requires_hashes_and_runs_isolated(self, monkeypatch, tmp_path):
        _cfg(monkeypatch, {"installable": [f"pkg-a==1.2.3 sha256:{_H}"]})
        monkeypatch.delenv("PIP_INDEX_URL", raising=False)
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = list(cmd)
            req = cmd[cmd.index("-r") + 1]
            seen["requirements"] = open(req, encoding="utf-8").read()
            return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        plugins.install_plugin("pkg-a")
        cmd = seen["cmd"]
        assert cmd[1:4] == ["-m", "pip", "install"]
        for flag in ("--isolated", "--no-deps", "--require-hashes", "--only-binary", ":all:"):
            assert flag in cmd, flag
        assert "--index-url" not in cmd
        assert seen["requirements"].strip() == f"pkg-a==1.2.3 --hash=sha256:{_H}"

    def test_unpinned_install_is_isolated_wheel_only_and_warns(self, monkeypatch, caplog):
        _cfg(monkeypatch, {"installable": ["pkg-b"]})
        monkeypatch.setenv("PIP_INDEX_URL", "https://pypi.example/simple")
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = list(cmd)
            return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        with caplog.at_level("WARNING"):
            plugins.install_plugin("pkg-b")
        cmd = seen["cmd"]
        for flag in ("--isolated", "--no-deps", "--only-binary", ":all:"):
            assert flag in cmd, flag
        assert "--require-hashes" not in cmd
        assert cmd[-1] == "pkg-b"
        assert cmd[cmd.index("--index-url") + 1] == "https://pypi.example/simple"
        assert any("not pinned" in r.message for r in caplog.records)
