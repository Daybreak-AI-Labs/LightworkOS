"""Local-first model routing."""
from __future__ import annotations

from maverick import provider_local_first as lf


def test_is_local():
    assert lf.is_local("ollama:llama3")
    assert lf.is_local("vllm:qwen")
    assert not lf.is_local("anthropic:claude-opus-4-8")
    assert not lf.is_local("claude-opus-4-8")  # bare = anthropic


def test_reorder_puts_reachable_local_first():
    specs = ["anthropic:opus", "ollama:llama3", "openai:gpt", "vllm:qwen"]
    out = lf.reorder(specs, available_fn=lambda p: True)
    assert out[:2] == ["ollama:llama3", "vllm:qwen"]  # locals first, stable
    assert out[2:] == ["anthropic:opus", "openai:gpt"]


def test_reorder_skips_unreachable_local():
    specs = ["anthropic:opus", "ollama:llama3"]
    out = lf.reorder(specs, available_fn=lambda p: False)  # nothing reachable
    assert out == specs  # unchanged when no local is reachable


def test_disabled_pick_local_is_none(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_LOCAL_FIRST", raising=False)
    assert lf.pick_local("worker") is None


def test_enabled_pick_local_with_config(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("MAVERICK_LOCAL_FIRST", "1")
    cfgdir = tmp_path / ".maverick"
    cfgdir.mkdir(parents=True, exist_ok=True)
    (cfgdir / "config.toml").write_text(
        '[local_first]\nmodel = "ollama:llama3"\n', encoding="utf-8")
    # reachable -> returns the local spec
    assert lf.pick_local("worker", probe_fn=lambda p: True) == "ollama:llama3"
    # unreachable -> falls through (None)
    assert lf.pick_local("worker", probe_fn=lambda p: False) is None


def test_pick_local_ignores_non_local_config(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("MAVERICK_LOCAL_FIRST", "1")
    cfgdir = tmp_path / ".maverick"
    cfgdir.mkdir(parents=True, exist_ok=True)
    (cfgdir / "config.toml").write_text(
        '[local_first]\nmodel = "anthropic:opus"\n', encoding="utf-8")
    assert lf.pick_local("worker", probe_fn=lambda p: True) is None
