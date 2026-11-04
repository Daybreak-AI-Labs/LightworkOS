"""Contract tests for the Emacs + Neovim integrations. Same style as the VS Code extension contract: the artifacts exist,
are structurally sound, and only call CLI verbs that actually exist."""
from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_EMACS = _REPO / "apps" / "emacs" / "maverick.el"
_NVIM_INIT = _REPO / "apps" / "nvim" / "lua" / "maverick" / "init.lua"
_NVIM_PLUGIN = _REPO / "apps" / "nvim" / "plugin" / "maverick.lua"


def _strip_elisp(text: str) -> str:
    """Remove comments and strings so paren counting sees only structure."""
    out = []
    in_str = False
    i = 0
    while i < len(text):
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            i += 1
            continue
        if c == ";":
            nl = text.find("\n", i)
            i = len(text) if nl == -1 else nl
            continue
        if c == "?" and i + 1 < len(text) and text[i + 1] in "()":
            i += 2  # elisp char literal ?( or ?)
            continue
        out.append(c)
        i += 1
    return "".join(out)


def test_emacs_package_structure():
    text = _EMACS.read_text(encoding="utf-8")
    assert text.startswith(";;; maverick.el ---")
    assert "lexical-binding: t" in text
    assert "(provide 'maverick)" in text
    assert text.rstrip().endswith(";;; maverick.el ends here")
    stripped = _strip_elisp(text)
    assert stripped.count("(") == stripped.count(")"), "unbalanced parens"


def test_emacs_commands_present_and_autoloaded():
    text = _EMACS.read_text(encoding="utf-8")
    for fn in ("maverick-start", "maverick-status", "maverick-monitor",
               "maverick-logs", "maverick-halt", "maverick-unhalt"):
        assert f"(defun {fn}" in text, f"missing {fn}"
        assert "(interactive" in text.split(f"(defun {fn}", 1)[1][:400], \
            f"{fn} is not interactive"
    assert text.count(";;;###autoload") >= 6


def test_nvim_plugin_structure():
    init = _NVIM_INIT.read_text(encoding="utf-8")
    assert "local M = {}" in init and "return M" in init
    for fn in ("start", "status", "monitor", "logs", "halt", "unhalt", "setup"):
        assert f"function M.{fn}" in init, f"missing M.{fn}"
    plugin = _NVIM_PLUGIN.read_text()
    for cmd in ("MaverickStart", "MaverickStatus", "MaverickMonitor",
                "MaverickLogs", "MaverickHalt", "MaverickUnhalt"):
        assert f'nvim_create_user_command("{cmd}"' in plugin, f"missing :{cmd}"
    assert "loaded_maverick_nvim" in plugin  # double-load guard


def test_editor_integrations_only_call_real_cli_verbs():
    """Every CLI verb the integrations shell out to must exist in cli.py."""
    from maverick.cli import main
    real = set(main.commands)
    used = set()
    for text in (_EMACS.read_text(encoding="utf-8"), _NVIM_INIT.read_text(encoding="utf-8")):
        used |= set(re.findall(
            r'"(start|status|monitor|logs|halt|unhalt|resume|ps|export)"', text))
    missing = used - real
    assert not missing, f"integrations call nonexistent CLI verbs: {missing}"
    # The core six are all actually used.
    assert {"start", "status", "monitor", "logs", "halt", "unhalt"} <= used


def test_editor_status_cost_option_is_supported(tmp_path):
    """The editor status wrappers pass --cost, so the CLI must accept it."""
    from click.testing import CliRunner
    from maverick.cli import main

    result = CliRunner().invoke(main, ["--db", str(tmp_path / "world.db"), "status", "--cost"])

    assert result.exit_code == 0, result.output
    assert "Spend" in result.output
    assert "no goals yet" in result.output


def test_readmes_document_the_commands():
    emacs_readme = (_REPO / "apps" / "emacs" / "README.md").read_text(encoding="utf-8")
    nvim_readme = (_REPO / "apps" / "nvim" / "README.md").read_text(encoding="utf-8")
    assert "maverick-start" in emacs_readme
    assert ":MaverickStart" in nvim_readme
