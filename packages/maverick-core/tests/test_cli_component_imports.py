"""A broken dependency is different from an uninstalled Lightwork component."""
from __future__ import annotations

import builtins

from click.testing import CliRunner
from maverick.cli import main


def _break_import(monkeypatch, component: str, exc: ImportError) -> None:
    original_import = builtins.__import__

    def broken_import(name, *args, **kwargs):
        if name == component:
            raise exc
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", broken_import)


def test_dashboard_reports_broken_dependency_not_missing_dashboard(monkeypatch):
    _break_import(monkeypatch, "maverick_dashboard.app", ImportError(
        "jinja2 must be installed to use Jinja2Templates"
    ))
    result = CliRunner().invoke(main, ["dashboard"])
    assert result.exit_code == 2
    assert "jinja2 must be installed" in result.output
    assert "maverick doctor" in result.output
    assert "Install the dashboard" not in result.output


def test_dashboard_refuses_token_in_command_line(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    result = CliRunner().invoke(main, ["dashboard", "--token", "sensitive-value"])
    assert result.exit_code != 0
    assert "sensitive-value" not in result.output
    import os
    assert "MAVERICK_DASHBOARD_TOKEN" not in os.environ


def test_installer_reports_broken_dependency_not_missing_installer(monkeypatch):
    _break_import(monkeypatch, "maverick_installer.wizard", ModuleNotFoundError(
        "No module named 'rich'", name="rich"
    ))
    result = CliRunner().invoke(main, ["init", "--fast"])
    assert result.exit_code == 2
    assert "rich" in result.output
    assert "maverick doctor" in result.output
    assert "Install the installer component" not in result.output


def test_missing_dashboard_keeps_reviewed_source_install_guidance(monkeypatch):
    _break_import(monkeypatch, "maverick_dashboard.app", ModuleNotFoundError(
        "No module named 'maverick_dashboard'", name="maverick_dashboard"
    ))
    result = CliRunner().invoke(main, ["dashboard"])
    assert result.exit_code == 2
    assert "Install the dashboard from the same reviewed Lightwork checkout" in result.output


def test_missing_installer_keeps_reviewed_source_install_guidance(monkeypatch):
    _break_import(monkeypatch, "maverick_installer.wizard", ModuleNotFoundError(
        "No module named 'maverick_installer'", name="maverick_installer"
    ))
    result = CliRunner().invoke(main, ["init", "--fast"])
    assert result.exit_code == 2
    assert "Install the installer component from the same reviewed Lightwork checkout" in result.output
