"""Tests for the diagnose tool (maverick.tools.diagnose)."""
from __future__ import annotations

# ---------- diagnose tool ----------

def test_diagnose_runs(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k1")
    monkeypatch.setenv("OPENAI_API_KEY", "k2")
    for k in ("DEEPSEEK_API_KEY", "MOONSHOT_API_KEY",
              "XAI_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    from maverick.tools.diagnose import diagnose
    out = diagnose().fn({})
    assert "Lightwork self-diagnose" in out
    assert "python" in out
    assert "anthropic" in out
    assert "openai" in out
    assert "sandbox backend" in out


def test_diagnose_flags_missing_keys(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY",
              "MOONSHOT_API_KEY", "XAI_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    from maverick.tools.diagnose import diagnose
    out = diagnose().fn({})
    assert "no provider keys set" in out
