"""Deferred tool loading: ToolRegistry exposure + find_tools meta-tool."""
from __future__ import annotations

import asyncio

from maverick.tools import Tool, ToolRegistry
from maverick.tools.find_tools import find_tools


def _tool(name: str, desc: str = "d") -> Tool:
    return Tool(
        name=name,
        description=desc,
        input_schema={"type": "object", "properties": {}},
        fn=lambda a, _n=name: f"ran {_n}",
    )


def _names(reg: ToolRegistry) -> set[str]:
    return {t["name"] for t in reg.to_anthropic()}


class TestExposure:
    def test_default_off_exposes_everything(self):
        reg = ToolRegistry()
        reg.register(_tool("read_file"))
        reg.register(_tool("jira"))
        assert reg.deferred_enabled() is False
        assert _names(reg) == {"read_file", "jira"}

    def test_enable_deferred_hides_long_tail(self):
        reg = ToolRegistry()
        for n in ("read_file", "shell", "jira", "stripe"):
            reg.register(_tool(n))
        reg.register(find_tools(reg))
        reg.enable_deferred({"read_file", "shell"})
        # Core + the meta-tool only; jira/stripe are hidden from the model.
        assert _names(reg) == {"read_file", "shell", "find_tools"}

    def test_core_intersects_registry(self):
        reg = ToolRegistry()
        reg.register(_tool("read_file"))
        reg.enable_deferred({"read_file", "not_registered"})
        assert _names(reg) == {"read_file"}  # phantom core name ignored

    def test_core_registered_after_enable_is_exposed(self):
        reg = ToolRegistry()
        reg.register(_tool("read_file"))
        reg.enable_deferred({"read_file", "spawn_subagent", "not_registered"})
        assert _names(reg) == {"read_file"}

        reg.register(_tool("spawn_subagent"))

        assert _names(reg) == {"read_file", "spawn_subagent"}

    def test_run_executes_hidden_tool(self):
        # Visibility != availability: run() still executes a deferred tool.
        reg = ToolRegistry()
        reg.register(_tool("read_file"))
        reg.register(_tool("jira"))
        reg.enable_deferred({"read_file"})
        assert "jira" not in _names(reg)
        assert asyncio.run(reg.run("jira", {})) == "ran jira"

    def test_catalog_is_byte_stable_until_activation(self):
        # The tool-catalog prompt cache needs a byte-identical catalog across
        # turns; the exposed list must not change until something activates.
        reg = ToolRegistry()
        for n in ("read_file", "jira"):
            reg.register(_tool(n))
        reg.register(find_tools(reg))
        reg.enable_deferred({"read_file"})
        first = reg.to_anthropic()
        assert reg.to_anthropic() == first  # stable across calls
        reg.activate(["jira"])
        assert reg.to_anthropic() != first  # changes once, then stable again
        assert reg.to_anthropic() == reg.to_anthropic()


class TestFindTools:
    def _reg(self):
        reg = ToolRegistry()
        reg.register(_tool("read_file"))
        reg.register(_tool("jira", "Create and update Jira issues and sprints"))
        reg.register(_tool("stripe", "Charge a credit card and issue refunds"))
        reg.register(find_tools(reg))
        reg.enable_deferred({"read_file"})
        return reg

    def test_query_activates_matching_tool(self):
        reg = self._reg()
        assert "jira" not in _names(reg)
        out = asyncio.run(reg.run("find_tools", {"query": "create a jira issue"}))
        assert "jira" in out
        # Now visible to the model, and the unrelated tool stayed hidden.
        assert "jira" in _names(reg)
        assert "stripe" not in _names(reg)

    def test_empty_query_is_guided_not_crashed(self):
        reg = self._reg()
        out = asyncio.run(reg.run("find_tools", {"query": "  "}))
        assert "query" in out.lower()

    def test_no_match_reports_clearly(self):
        reg = self._reg()
        out = asyncio.run(reg.run("find_tools", {"query": "quantum teleportation"}))
        assert "no additional tools" in out.lower()
        assert _names(reg) == {"read_file", "find_tools"}  # nothing activated

    def test_max_results_caps_activation(self):
        reg = ToolRegistry()
        reg.register(_tool("read_file"))
        for i in range(5):
            reg.register(_tool(f"db_tool_{i}", "query a sql database table"))
        reg.register(find_tools(reg))
        reg.enable_deferred({"read_file"})
        asyncio.run(reg.run("find_tools", {"query": "sql database", "max_results": 2}))
        activated = _names(reg) - {"read_file", "find_tools"}
        assert len(activated) == 2

    def test_small_model_limit_activates_only_the_strongest_visible_match(self):
        reg = ToolRegistry()
        reg.register(_tool("read_file"))
        reg.register(_tool("jira_issue", "Create Jira issues"))
        reg.register(_tool("issue_tool", "Track issues"))
        reg.register(find_tools(reg))
        reg.enable_deferred({"read_file"})
        assert {t["name"] for t in reg.to_anthropic(max_tools=2)} == {
            "read_file", "find_tools"
        }
        out = asyncio.run(reg.run("find_tools", {"query": "jira issue", "max_results": 2}))
        assert "jira_issue" in out and "issue_tool" not in out
        assert {t["name"] for t in reg.to_anthropic(max_tools=2)} == {
            "find_tools", "jira_issue"
        }


class TestEnvKnob:
    def test_env_enables(self, monkeypatch):
        from maverick.tools import _deferred_loading_enabled
        monkeypatch.setenv("MAVERICK_DEFERRED_TOOLS", "1")
        assert _deferred_loading_enabled() is True

    def test_off_by_default(self, monkeypatch):
        import maverick.config as config
        from maverick.tools import _deferred_loading_enabled
        monkeypatch.delenv("MAVERICK_DEFERRED_TOOLS", raising=False)
        monkeypatch.setattr(config, "load_config", dict)
        assert _deferred_loading_enabled() is False


class TestBaseRegistryWiring:
    def test_env_shrinks_catalog_and_adds_find_tools(self, tmp_path, monkeypatch):
        from maverick.sandbox import LocalBackend
        from maverick.tools import base_registry
        from maverick.world_model import WorldModel

        world = WorldModel(path=tmp_path / "w.db")
        sandbox = LocalBackend(workdir=tmp_path)

        monkeypatch.delenv("MAVERICK_DEFERRED_TOOLS", raising=False)
        full = base_registry(world, sandbox)
        full_names = {t["name"] for t in full.to_anthropic()}

        monkeypatch.setenv("MAVERICK_DEFERRED_TOOLS", "1")
        lean = base_registry(world, sandbox)
        lean_names = {t["name"] for t in lean.to_anthropic()}

        assert "find_tools" in lean_names
        assert len(lean_names) < len(full_names)        # long tail hidden
        assert "read_file" in lean_names                # core stays
        assert "stripe" in full_names and "stripe" not in lean_names
