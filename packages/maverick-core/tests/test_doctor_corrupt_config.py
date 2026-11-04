"""`maverick doctor` must flag a corrupt config.toml.

load_config() fails soft (returns {} on a TOML syntax error), so doctor's old
check went through it and always reported config OK -- even though every user
setting was being silently dropped. _check_config now parses the TOML directly.
"""
from __future__ import annotations

from pathlib import Path

from maverick.health import _check_config


def test_doctor_flags_corrupt_config(tmp_path: Path, capsys):
    # conftest's autouse fixture points HOME at tmp_path.
    (tmp_path / ".maverick").mkdir()
    (tmp_path / ".maverick" / "config.toml").write_text("[budget\nmax_dollars = oops\n")

    cfg = _check_config()
    out = capsys.readouterr().out
    # Reported as a blocking (red) row in plain words, naming the file.
    assert "✗ config" in out
    assert "unreadable or invalid" in out and "config.toml" in out
    assert cfg == {}


def test_doctor_passes_valid_config(tmp_path: Path, capsys):
    (tmp_path / ".maverick").mkdir()
    (tmp_path / ".maverick" / "config.toml").write_text("[budget]\nmax_dollars = 5.0\n")

    cfg = _check_config()
    out = capsys.readouterr().out
    assert "invalid TOML" not in out
    assert cfg.get("budget", {}).get("max_dollars") == 5.0


def test_doctor_anthropic_yellow_when_other_provider_configured(tmp_path, monkeypatch, capsys):
    """A keyless self-hosted setup (Ollama/vLLM via config) is healthy without
    an Anthropic key: doctor must not hard-RED `anthropic` regardless of every
    other configured provider."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text('[providers.vllm]\nbase_url = "http://127.0.0.1:9911/v1"\n',
                   encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))

    from maverick.health import _check_anthropic
    _check_anthropic()
    out = capsys.readouterr().out
    assert "another provider is configured" in out
    assert "✗" not in out  # yellow advisory, not a red failure


def test_doctor_anthropic_red_when_nothing_configured(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    for v in ("OPENAI_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY",
              "MOONSHOT_API_KEY", "DEEPSEEK_API_KEY", "XAI_API_KEY",
              "VLLM_BASE_URL", "TGI_BASE_URL", "OPENAI_COMPATIBLE_BASE_URL"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "absent.toml"))

    from maverick.health import _check_anthropic
    _check_anthropic()
    out = capsys.readouterr().out
    assert "ANTHROPIC_API_KEY not set" in out
    assert "another provider" not in out
