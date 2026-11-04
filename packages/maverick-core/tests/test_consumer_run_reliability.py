"""Reliability of the consumer run path.

- A config-only provider (local / OpenAI-compatible model, key in config not a
  well-known env var) must not be wrongly blocked by the key gate.
- A run that errors must mark its goal failed, not leave a ghost stuck
  'active' forever.
- The "shield SDK missing" and "skill distill disabled" advisories must not
  spam every run / chat turn.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

# ---------- A: provider gate validates the selected route --------------------

def test_require_llm_key_accepts_selected_route(monkeypatch):
    from maverick import cli
    monkeypatch.setattr(
        cli,
        "_model_route_configuration_missing",
        lambda model=None: ("ollama", ()),
    )
    assert cli._require_llm_key("ollama:qwen") == "config"


def test_require_llm_key_blocks_when_selected_route_is_incomplete(monkeypatch):
    from maverick import cli
    monkeypatch.setattr(
        cli,
        "_model_route_configuration_missing",
        lambda model=None: ("anthropic", ("api_key",)),
    )
    with pytest.raises(SystemExit):
        cli._require_llm_key("anthropic:test")


@pytest.mark.parametrize("provider", ["ollama", "tgi", "vllm"])
def test_keyless_local_route_is_not_rejected(provider, monkeypatch):
    from maverick import cli

    monkeypatch.setattr("maverick.config.load_config", dict)
    assert cli._require_llm_key(f"{provider}:test") == "config"


def test_codex_login_is_not_rejected(monkeypatch):
    from maverick import cli

    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setattr(
        "maverick.providers.codex_cli_provider._auth_file_present",
        lambda: True,
    )
    assert cli._require_llm_key("codex_cli:gpt-5") == "config"


def test_codex_config_table_token_is_not_rejected(monkeypatch):
    from maverick import cli

    monkeypatch.delenv("CODEX_ACCESS_TOKEN", raising=False)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {
            "providers": {"codex_cli": {"api_key": "configured-token"}}  # pragma: allowlist secret
        },
    )
    monkeypatch.setattr(
        "maverick.providers.codex_cli_provider._auth_file_present",
        lambda: False,
    )
    assert cli._require_llm_key("codex_cli:gpt-5") == "config"


def test_unrelated_provider_key_does_not_unblock_selected_route(monkeypatch):
    from maverick import cli

    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "unrelated-openai-key")
    with pytest.raises(SystemExit):
        cli._require_llm_key("anthropic:test")


@pytest.mark.parametrize(
    "provider",
    [
        "anthropic",
        "openai",
        "openrouter",
        "ollama",
        "gemini",
        "moonshot",
        "deepseek",
        "xai",
        "tgi",
        "vllm",
        "azure",
        "bedrock",
        "openai_compatible",
        "codex_cli",
    ],
)
def test_cli_selected_route_contract_matches_operator_preflight(
    provider, monkeypatch,
):
    from maverick import cli, config
    from maverick.operator_preflight import _route_configuration_missing

    for name in (
        config.PROVIDER_CREDENTIAL_ENV_VARS
        + config.PROVIDER_BASE_URL_ENV_VARS
        + (
            "AZURE_OPENAI_AUTH",
            "AZURE_OPENAI_ENDPOINT",
            "AZURE_OPENAI_DEPLOYMENT",
            "AWS_REGION",
        )
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(
        "maverick.providers.codex_cli_provider._auth_file_present",
        lambda: False,
    )

    selected, missing = cli._model_route_configuration_missing(
        f"{provider}:test"
    )
    assert selected == provider
    assert missing == _route_configuration_missing(provider, {})


# ---------- B: an erroring run marks its goal failed (no ghost) ----------

@pytest.mark.asyncio
async def test_run_goal_marks_goal_failed_on_unexpected_error(tmp_path: Path):
    from maverick.budget import Budget
    from maverick.orchestrator import run_goal
    from maverick.sandbox import LocalBackend
    from maverick.world_model import WorldModel

    class BoomLLM:
        model = "fake:boom"

        async def complete_async(self, **kwargs):
            raise RuntimeError("simulated provider failure")

        def complete(self, **kwargs):
            raise RuntimeError("simulated provider failure")

    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("do a thing", "")
    with pytest.raises(RuntimeError):
        await run_goal(
            BoomLLM(), world, Budget(max_dollars=1.0), gid,
            sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
        )
    # The goal must NOT be left 'active' -- an unexpected error is a terminal
    # failure ('blocked' is reserved for allowance stops and refusals).
    assert world.get_goal(gid).status == "failed"


# ---------- C: advisories warn at most once per process ----------

def test_shield_sdk_missing_warns_once(caplog):
    from maverick_shield import guard

    if guard._HAVE_SDK:
        pytest.skip("agent-shield SDK installed; advisory not emitted")
    guard._WARNED_SDK_MISSING = False
    with caplog.at_level(logging.WARNING, logger="maverick_shield.guard"):
        guard.Shield(warn_if_missing=True)
        guard.Shield(warn_if_missing=True)
        guard.Shield(warn_if_missing=True)
    hits = [r for r in caplog.records if "agent-shield SDK not installed" in r.getMessage()]
    assert len(hits) == 1


# ---------- chat threads conversation memory across turns ----------

def test_chat_threads_conversation_across_turns(tmp_path: Path, monkeypatch):
    import maverick.cli as cli
    import maverick.orchestrator as orch
    from click.testing import CliRunner
    from maverick.world_model import open_world

    monkeypatch.setattr(cli, "_require_llm_key", lambda *args: "test")

    seen: list = []

    def fake_run_goal_sync(llm, world, bud, goal_id, **kwargs):
        seen.append((goal_id, kwargs.get("conversation_id")))
        return "DONE."

    monkeypatch.setattr(orch, "run_goal_sync", fake_run_goal_sync)

    db = tmp_path / "world.db"
    result = CliRunner().invoke(
        cli.main, ["--db", str(db), "chat"],
        input="the code is BANANA42\nwhat is the code\nexit\n",
    )
    assert result.exit_code == 0, result.output

    # Both turns ran under the SAME, non-None conversation id.
    assert len(seen) == 2
    conv_ids = {c for _, c in seen}
    assert None not in conv_ids and len(conv_ids) == 1

    # Both user turns were recorded, so run_goal can thread them as history.
    conv_id = seen[0][1]
    world = open_world(db)
    turns = world.recent_turns(conv_id, limit=10)
    user_msgs = [t.content for t in turns if t.role == "user"]
    assert "the code is BANANA42" in user_msgs
    assert "what is the code" in user_msgs

    # The CLI conversation key is session-scoped, not the persistent global
    # ("cli", "local") row that would leak turns across future chat runs.
    conv = next(c for c in world.list_conversations("cli") if c.id == conv_id)
    assert conv.user_id.startswith("local:")
    assert conv.user_id != "local"


def test_chat_starts_new_conversation_for_each_repl_session(tmp_path: Path, monkeypatch):
    import maverick.cli as cli
    import maverick.orchestrator as orch
    from click.testing import CliRunner

    monkeypatch.setattr(cli, "_require_llm_key", lambda *args: "test")

    seen: list[int] = []

    def fake_run_goal_sync(llm, world, bud, goal_id, **kwargs):
        seen.append(kwargs.get("conversation_id"))
        return "DONE."

    monkeypatch.setattr(orch, "run_goal_sync", fake_run_goal_sync)

    db = tmp_path / "world.db"
    runner = CliRunner()

    first = runner.invoke(
        cli.main, ["--db", str(db), "chat"], input="SESSION1_SECRET\nexit\n",
    )
    assert first.exit_code == 0, first.output

    second = runner.invoke(
        cli.main, ["--db", str(db), "chat"], input="unrelated later task\nexit\n",
    )
    assert second.exit_code == 0, second.output

    assert len(seen) == 2
    assert seen[0] is not None
    assert seen[1] is not None
    assert seen[0] != seen[1]

    world = cli.open_world(db)
    second_turns = world.recent_turns(seen[1], limit=10)
    second_contents = [t.content for t in second_turns]
    assert "unrelated later task" in second_contents
    assert "SESSION1_SECRET" not in second_contents
