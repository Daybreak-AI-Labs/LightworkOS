"""`maverick config-lint` must FAIL on a corrupt config, not say "config OK".

Previously, config-lint called load_config(), which is
deliberately fail-soft -- a TOMLDecodeError is swallowed and {} returned with
only a warning log. So linting a syntactically broken config.toml linted an
empty dict, found nothing, and printed "config OK" with exit 0. The one tool
whose entire job is to validate the config silently blessed a file in which
every user setting is being dropped. (maverick doctor's _check_config already
guards this by parsing the raw file; config-lint now does the same.)
"""
from __future__ import annotations

import os
import subprocess
import sys

from click.testing import CliRunner


def _invoke(tmp_path, monkeypatch, text: str):
    cfg = tmp_path / "config.toml"
    cfg.write_text(text, encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.cli import main
    return CliRunner().invoke(main, ["config-lint"])


def test_corrupt_toml_fails(tmp_path, monkeypatch):
    res = _invoke(tmp_path, monkeypatch, "[budget\nmax_dollars = \n")
    assert res.exit_code == 1, res.output
    assert "config OK" not in res.output
    low = res.output.lower()
    assert "toml" in low or "parse" in low or "invalid" in low or "syntax" in low


def test_corrupt_toml_is_reported_from_fresh_cli_process(tmp_path):
    """CLI import and group setup must not admit storage before diagnostics."""
    cfg = tmp_path / "config.toml"
    cfg.write_text("[budget\nmax_dollars = \n", encoding="utf-8")
    env = os.environ.copy()
    env.update(
        MAVERICK_CONFIG=str(cfg),
        MAVERICK_HOME=str(tmp_path / "home"),
    )
    env.pop("MAVERICK_CLIENT_ID", None)

    result = subprocess.run(
        [sys.executable, "-m", "maverick.cli", "config-lint"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )

    rendered = (result.stdout + result.stderr).lower()
    assert result.returncode == 1, rendered
    assert "toml" in rendered or "parse" in rendered or "invalid" in rendered


def test_valid_config_still_ok(tmp_path, monkeypatch):
    res = _invoke(tmp_path, monkeypatch, "[budget]\nmax_dollars = 5.0\n")
    assert res.exit_code == 0, res.output
    assert "OK" in res.output


def test_absent_config_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "nope.toml"))
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.cli import main
    res = CliRunner().invoke(main, ["config-lint"])
    assert res.exit_code == 0, res.output
    # An absent config is a legitimate (built-in defaults) state -- but it must
    # SAY so, not bless a non-existent file with a misleading "config OK" as if
    # a real file had been validated.
    assert "config OK" not in res.output
    assert "built-in defaults" in res.output
