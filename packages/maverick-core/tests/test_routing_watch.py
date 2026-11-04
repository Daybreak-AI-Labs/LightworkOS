"""Cascaded routing + Watch Mode tests."""
from __future__ import annotations

import types
from pathlib import Path

from maverick.cli import _watch_goal_allowed
from maverick.llm import MODEL_HAIKU, MODEL_OPUS, MODEL_SONNET
from maverick.routing import RouteSignal, cascade_enabled, pick
from maverick.watch_mode import scan_dir, scan_file, scan_text


def _patch_no_user_config(monkeypatch):
    """The picker's first step calls `from .config import get_role_model`
    inside the function. Patch the config module so it returns None for
    every role -> cascade defaults take over."""
    from maverick import config as _cfg
    monkeypatch.setattr(_cfg, "get_role_model", lambda role: None)


def _patch_user_config(monkeypatch, mapping):
    from maverick import config as _cfg
    monkeypatch.setattr(_cfg, "get_role_model", lambda role: mapping.get(role))


class TestCascadedRouting:
    def test_orchestrator_defaults_to_opus(self, monkeypatch):
        _patch_no_user_config(monkeypatch)
        assert pick(RouteSignal(role="orchestrator")) == MODEL_OPUS

    def test_researcher_defaults_to_sonnet(self, monkeypatch):
        _patch_no_user_config(monkeypatch)
        assert pick(RouteSignal(role="researcher")) == MODEL_SONNET

    def test_summarizer_defaults_to_haiku(self, monkeypatch):
        _patch_no_user_config(monkeypatch)
        assert pick(RouteSignal(role="summarizer")) == MODEL_HAIKU

    def test_low_verifier_confidence_escalates(self, monkeypatch):
        _patch_no_user_config(monkeypatch)
        sig = RouteSignal(role="researcher", verifier_confidence=0.3)
        assert pick(sig) == MODEL_OPUS

    def test_retry_escalates(self, monkeypatch):
        _patch_no_user_config(monkeypatch)
        sig = RouteSignal(role="researcher", prior_attempt=1)
        assert pick(sig) == MODEL_OPUS

    def test_deep_tool_chain_escalates(self, monkeypatch):
        _patch_no_user_config(monkeypatch)
        sig = RouteSignal(role="researcher", tool_call_depth=5)
        assert pick(sig) == MODEL_OPUS

    def test_explicit_thinking_requirement_escalates(self, monkeypatch):
        _patch_no_user_config(monkeypatch)
        sig = RouteSignal(role="coder", requires_thinking=True)
        assert pick(sig) == MODEL_OPUS

    def test_user_config_wins(self, monkeypatch):
        _patch_user_config(monkeypatch, {"coder": "openrouter:deepseek-v4-pro"})
        sig = RouteSignal(role="coder")
        assert pick(sig) == "openrouter:deepseek-v4-pro"

    def test_explicit_env_false_overrides_enabled_config(self, monkeypatch):
        from maverick import config as config_mod

        monkeypatch.setenv("MAVERICK_CASCADE_ROUTING", "0")
        monkeypatch.setattr(
            config_mod,
            "load_config",
            lambda: {"models": {"cascade": True}},
        )
        assert cascade_enabled() is False

    def test_canonical_env_parser_accepts_on(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_CASCADE_ROUTING", "on")
        assert cascade_enabled() is True

    def test_invalid_config_type_disables_with_actionable_warning(
        self, monkeypatch, caplog,
    ):
        from maverick import config as config_mod

        monkeypatch.delenv("MAVERICK_CASCADE_ROUTING", raising=False)
        monkeypatch.setattr(
            config_mod,
            "load_config",
            lambda: {"models": {"cascade": "false"}},
        )
        assert cascade_enabled() is False
        assert "models.cascade must be true or false" in caplog.text

    def test_invalid_env_value_is_visible_and_fails_closed(
        self, monkeypatch, caplog,
    ):
        from maverick import config as config_mod

        monkeypatch.setenv("MAVERICK_CASCADE_ROUTING", "treu")
        monkeypatch.setattr(
            config_mod,
            "load_config",
            lambda: {"models": {"cascade": True}},
        )
        assert cascade_enabled() is False
        assert "MAVERICK_CASCADE_ROUTING must be one of" in caplog.text


class TestWatchMode:
    def test_marker_question_captures_text(self):
        text = "# AI? rename foo to bar"
        matches = list(scan_text(text))
        assert len(matches) == 1
        assert matches[0].marker == "?"
        assert "rename foo to bar" in matches[0].text

    def test_marker_bang_captures_follow_lines(self):
        text = (
            "x = 1  # AI!\n"
            "    add a docstring explaining\n"
            "    why this exists\n"
            "\n"
            "y = 2\n"
        )
        matches = list(scan_text(text))
        assert len(matches) == 1
        assert matches[0].marker == "!"
        assert len(matches[0].follow_lines) == 2
        assert "add a docstring explaining" in matches[0].follow_lines[0]

    def test_marker_colon_inline_task(self):
        text = "// AI: refactor this branch into an early-return"
        matches = list(scan_text(text))
        assert len(matches) == 1
        assert matches[0].marker == ":"
        assert "refactor" in matches[0].text

    def test_to_goal_renders_context(self):
        text = "def foo():\n    # AI? add input validation"
        match = next(iter(scan_text(text, path=Path("foo.py"))))
        brief = match.to_goal()
        assert "foo.py" in brief
        assert "AI?" in brief
        assert "input validation" in brief

    def test_scan_dir_ignores_node_modules(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.py").write_text("# AI? fix the bug")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "b.js").write_text("// AI? also fix this")

        matches = list(scan_dir(tmp_path))
        files = {m.path.name for m in matches}
        assert "a.py" in files
        assert "b.js" not in files  # ignored

    def test_scan_dir_honors_extensions(self, tmp_path):
        (tmp_path / "a.py").write_text("# AI? fix")
        (tmp_path / "a.md").write_text("# AI? doc note")  # markdown not in list
        matches = list(scan_dir(tmp_path))
        files = {m.path.name for m in matches}
        assert "a.py" in files
        assert "a.md" not in files

    def test_scan_file_missing_returns_empty(self, tmp_path):
        matches = list(scan_file(tmp_path / "missing.py"))
        assert matches == []


class TestWatchModeShieldScan:
    def test_watch_goal_allowed_when_shield_missing(self, monkeypatch):
        import builtins
        orig_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "maverick_shield":
                raise ImportError
            return orig_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        allowed, reason = _watch_goal_allowed("safe goal")
        assert allowed is True
        assert reason is None

    def test_watch_goal_blocked_when_shield_rejects(self, monkeypatch):
        class _Shield:
            @classmethod
            def from_config(cls):
                return cls()

            def scan_input(self, _):
                return types.SimpleNamespace(
                    allowed=False, severity="high", reasons=["prompt injection"]
                )

        monkeypatch.setattr("maverick.cli.Shield", _Shield, raising=False)
        import sys
        # monkeypatch.setitem restores the original (or removes) on
        # teardown. Direct mutation of `sys.modules` would leak the fake
        # always-rejects Shield to subsequent tests (test_skills among
        # them) and cause unrelated failures whenever this test ran
        # first in the session.
        monkeypatch.setitem(
            sys.modules,
            "maverick_shield",
            types.SimpleNamespace(Shield=_Shield),
        )
        allowed, reason = _watch_goal_allowed("malicious goal")
        assert allowed is False
        assert "blocked by Shield" in (reason or "")
