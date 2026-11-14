"""Codex CLI provider: registry wiring, auth gating, subprocess hygiene.

No real ``codex`` binary and no network: ``shutil.which`` and
the owned subprocess adapter are monkeypatched. Actual process ownership is tested separately. The security-critical assertions --
the access token never appears on argv or in error text, argv is a list
(never ``shell=True``), the prompt travels on STDIN -- live here.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from maverick.budget import Budget
from maverick.llm import _parse_spec
from maverick.providers import KNOWN_PROVIDERS, get_provider_client, missing_sdks
from maverick.providers.codex_cli_provider import CodexCLIClient

FAKE_TOKEN = "codex-test-access-token-not-real"  # pragma: allowlist secret


@pytest.fixture
def codex_env(monkeypatch, tmp_path):
    """A world where the codex binary exists and a token is configured."""
    monkeypatch.setenv("CODEX_ACCESS_TOKEN", FAKE_TOKEN)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.setattr(
        "maverick.providers.codex_cli_provider.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )
    return tmp_path


def _write_auth(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "auth.json").write_text("{}")


class _FakeRun:
    """Records every owned subprocess call; plays a scripted codex exec."""

    def __init__(self, *, text="hello from codex", usage=None, returncode=0,
                 stderr=""):
        self.calls: list[dict] = []
        self.text = text
        self.usage = usage or {"input_tokens": 120, "cached_input_tokens": 20,
                               "output_tokens": 45}
        self.returncode = returncode
        self.stderr = stderr

    async def __call__(self, cmd, **kwargs):
        self.calls.append({"cmd": list(cmd), **kwargs})
        if "login" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if "--output-last-message" in cmd:
            out_file = Path(cmd[cmd.index("--output-last-message") + 1])
            if self.returncode == 0:
                out_file.write_text(self.text)
        stdout = "\n".join([
            "codex banner line (not json)",
            json.dumps({"type": "item.completed",
                        "item": {"type": "agent_message", "text": self.text}}),
            json.dumps({"type": "turn.completed", "usage": self.usage}),
        ])
        return subprocess.CompletedProcess(
            cmd, self.returncode, stdout=stdout, stderr=self.stderr,
        )


class TestRegistry:
    def test_known_provider(self):
        assert "codex_cli" in KNOWN_PROVIDERS

    def test_spec_aliases_canonicalize(self):
        assert _parse_spec("codex_cli:gpt-5.5-codex") == ("codex_cli", "gpt-5.5-codex")
        assert _parse_spec("codex-cli:gpt-5.5-codex") == ("codex_cli", "gpt-5.5-codex")
        assert _parse_spec("codex:gpt-5.5-codex") == ("codex_cli", "gpt-5.5-codex")

    def test_registry_instantiates(self, codex_env):
        client = get_provider_client("codex_cli")
        assert isinstance(client, CodexCLIClient)

    def test_missing_sdks_wants_binary_not_pip(self, monkeypatch):
        # Binary present: nothing missing, and crucially no `openai` pip demand.
        import shutil as _shutil
        monkeypatch.setattr(_shutil, "which", lambda name: f"/usr/bin/{name}")
        assert missing_sdks(["codex_cli:gpt-5.5-codex"]) == []
        # Binary absent: an actionable install hint, still no pip demand.
        monkeypatch.setattr(_shutil, "which", lambda name: None)
        msgs = missing_sdks(["codex_cli:gpt-5.5-codex"])
        assert len(msgs) == 1 and "@openai/codex" in msgs[0]

    def test_catalog_lists_codex(self):
        from maverick.llm import MODEL_CATALOG, PROVIDER_LABELS, catalog_specs
        assert "codex_cli" in MODEL_CATALOG
        assert "codex_cli" in PROVIDER_LABELS
        specs = [s for s, _ in catalog_specs()]
        # Catalogued ids must be ones a ChatGPT account actually serves; the
        # Codex-tuned *-codex ids 400 for ChatGPT-account auth, so they're out.
        assert "codex_cli:gpt-5.5" in specs
        assert not any(s.endswith("-codex") for s in specs if s.startswith("codex_cli:"))


class TestPricing:
    """codex_cli is subscription-metered -> always $0, even for model ids that
    collide with priced OpenAI-API entries (gpt-5.5, gpt-5)."""

    def test_codex_cli_prices_zero_despite_colliding_id(self):
        from maverick.budget import _lookup_price
        from maverick.llm import MODEL_PRICES
        # gpt-5.5 has a real (nonzero) OpenAI-API price in the table...
        assert MODEL_PRICES.get("gpt-5.5", (0, 0)) != (0.0, 0.0)
        # ...but behind the codex_cli: prefix it must resolve to $0, not that
        # API rate (the bug that billed a subscription run at ~$0.40).
        assert _lookup_price("codex_cli:gpt-5.5") == (0.0, 0.0)
        assert _lookup_price("codex_cli:gpt-5") == (0.0, 0.0)
        # The bare OpenAI id (openai provider) still bills at its API rate.
        assert _lookup_price("gpt-5.5") == MODEL_PRICES["gpt-5.5"]

    def test_codex_cli_budget_records_zero_dollars(self):
        from maverick.budget import Budget
        b = Budget(max_dollars=0.01)  # would trip immediately if billed as API
        b.record_tokens(75601, 813, model="codex_cli:gpt-5.5", cache_read_tok=7424)
        assert b.dollars == 0.0
        assert b.input_tokens == 75601 and b.output_tokens == 813


class TestLaunchPrefix:
    """Binary resolution + Windows .cmd-shim routing (so Windows npm installs
    do not fail with 'Codex CLI binary codex disappeared from PATH')."""

    def _client(self, monkeypatch, tmp_path, which_result):
        monkeypatch.setenv("CODEX_ACCESS_TOKEN", FAKE_TOKEN)
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
        _write_auth(tmp_path)
        monkeypatch.setattr(
            "maverick.providers.codex_cli_provider.shutil.which",
            lambda name: which_result,
        )
        return CodexCLIClient()

    def test_posix_exe_launched_directly(self, monkeypatch, tmp_path):
        client = self._client(monkeypatch, tmp_path, "/usr/local/bin/codex")
        monkeypatch.setattr(
            "maverick.providers.codex_cli_provider.os.name", "posix")
        assert client._binary_path == "/usr/local/bin/codex"
        assert client._launch_prefix() == ["/usr/local/bin/codex"]

    def test_windows_cmd_shim_routed_through_comspec(self, monkeypatch, tmp_path):
        monkeypatch.setenv("COMSPEC", r"C:\Windows\System32\cmd.exe")
        shim = r"C:\Users\me\AppData\Roaming\npm\codex.cmd"
        client = self._client(monkeypatch, tmp_path, shim)
        monkeypatch.setattr(
            "maverick.providers.codex_cli_provider.os.name", "nt")
        assert client._launch_prefix() == [
            r"C:\Windows\System32\cmd.exe", "/d", "/s", "/c", f'"{shim}"',
        ]
        cmd = client._launch_cmd("exec", "--model", "gpt&calc", "-")
        assert cmd == [
            r"C:\Windows\System32\cmd.exe", "/d", "/s", "/c",
            f'"{shim}" "exec" "--model" "gpt&calc" "-"',
        ]

    def test_windows_real_exe_launched_directly(self, monkeypatch, tmp_path):
        # An operator pointing [providers.codex_cli] binary straight at the
        # bundled codex.exe skips the interpreter hop.
        exe = r"C:\...\codex-win32-x64\vendor\x86_64-pc-windows-msvc\codex.exe"
        client = self._client(monkeypatch, tmp_path, exe)
        monkeypatch.setattr(
            "maverick.providers.codex_cli_provider.os.name", "nt")
        assert client._launch_prefix() == [exe]

    def test_windows_bat_shim_routed(self, monkeypatch, tmp_path):
        monkeypatch.delenv("COMSPEC", raising=False)  # falls back to cmd.exe
        shim = r"C:\tools\codex.bat"
        client = self._client(monkeypatch, tmp_path, shim)
        monkeypatch.setattr(
            "maverick.providers.codex_cli_provider.os.name", "nt")
        assert client._launch_prefix() == ["cmd.exe", "/d", "/s", "/c", f'"{shim}"']


class TestAuthGating:
    @pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
    def test_timeout_must_be_finite_and_positive(self, codex_env, monkeypatch, timeout):
        monkeypatch.setattr(CodexCLIClient, "_provider_config", staticmethod(lambda: {"timeout_seconds": timeout}))
        with pytest.raises(ValueError, match="finite and positive"):
            CodexCLIClient()

    @pytest.mark.asyncio
    async def test_failed_login_is_not_cached_as_success(self, codex_env, monkeypatch):
        fake = _FakeRun()
        logins = 0

        async def fail_first(cmd, **kwargs):
            nonlocal logins
            if "login" in cmd:
                logins += 1
                if logins == 1:
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="failed")
            return await fake(cmd, **kwargs)

        monkeypatch.setattr("maverick.providers.codex_cli_provider.run_owned", fail_first)
        client = CodexCLIClient()
        with pytest.raises(RuntimeError, match="login.*failed"):
            await client.complete_async("s", [])
        assert not client._login_lock.locked()
        await client.complete_async("s", [])
        assert logins == 2

    @pytest.mark.asyncio
    async def test_login_lock_deadline_does_not_start_process(self, codex_env, monkeypatch):
        from maverick.providers import codex_cli_provider as provider

        fake = _FakeRun()
        monkeypatch.setattr(provider, "run_owned", fake)
        client = CodexCLIClient()
        client.timeout_seconds = .03
        client._login_lock.acquire()
        try:
            with pytest.raises(TimeoutError):
                await client.complete_async("s", [])
            assert not fake.calls
        finally:
            client._login_lock.release()

    def test_refuses_without_token_or_login(self, monkeypatch, tmp_path):
        monkeypatch.delenv("CODEX_ACCESS_TOKEN", raising=False)
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "empty"))
        monkeypatch.setattr(
            "maverick.providers.codex_cli_provider.shutil.which",
            lambda name: f"/usr/bin/{name}",
        )
        with pytest.raises(RuntimeError, match="not authenticated"):
            CodexCLIClient()

    def test_refuses_without_binary(self, monkeypatch, tmp_path):
        monkeypatch.setenv("CODEX_ACCESS_TOKEN", FAKE_TOKEN)
        monkeypatch.setenv("CODEX_HOME", str(tmp_path))
        monkeypatch.setattr(
            "maverick.providers.codex_cli_provider.shutil.which",
            lambda name: None,
        )
        with pytest.raises(RuntimeError, match="not found on PATH"):
            CodexCLIClient()

    def test_auth_json_alone_suffices(self, monkeypatch, tmp_path):
        monkeypatch.delenv("CODEX_ACCESS_TOKEN", raising=False)
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
        _write_auth(tmp_path)
        monkeypatch.setattr(
            "maverick.providers.codex_cli_provider.shutil.which",
            lambda name: f"/usr/bin/{name}",
        )
        assert CodexCLIClient() is not None

    def test_auto_login_feeds_token_on_stdin_only(self, codex_env, monkeypatch):
        fake = _FakeRun()
        monkeypatch.setattr(
            "maverick.providers.codex_cli_provider.run_owned", fake)
        client = CodexCLIClient()
        client.complete("sys", [{"role": "user", "content": "hi"}])
        login = next(c for c in fake.calls if "login" in c["cmd"])
        assert login["cmd"][0] == client._binary_path
        assert login["cmd"][:2] == [client._binary_path, "login"]
        assert login["input"] == FAKE_TOKEN          # STDIN carries the token
        assert FAKE_TOKEN not in " ".join(login["cmd"])  # argv never does

    def test_no_login_when_auth_json_present(self, codex_env, monkeypatch):
        _write_auth(codex_env)
        fake = _FakeRun()
        monkeypatch.setattr(
            "maverick.providers.codex_cli_provider.run_owned", fake)
        CodexCLIClient().complete("sys", [{"role": "user", "content": "hi"}])
        assert not any("login" in c["cmd"] for c in fake.calls)


class TestExec:
    def _client(self, codex_env, monkeypatch, fake):
        _write_auth(codex_env)  # skip the login round-trip
        monkeypatch.setattr(
            "maverick.providers.codex_cli_provider.run_owned", fake)
        return CodexCLIClient()

    def test_complete_basic(self, codex_env, monkeypatch):
        fake = _FakeRun(text="The answer is 4.")
        client = self._client(codex_env, monkeypatch, fake)
        resp = client.complete("You are terse.",
                               [{"role": "user", "content": "2+2?"}])
        assert resp.text == "The answer is 4."
        assert resp.stop_reason == "end_turn"
        assert resp.tool_calls == []
        call = fake.calls[-1]
        cmd = call["cmd"]
        # cmd[0] is the RESOLVED absolute path (shutil.which result), not the
        # bare name, so Windows shims do not fail mid-run.
        assert cmd[0] == client._binary_path
        assert cmd[0].endswith("codex") and cmd[1] == "exec"
        assert "--json" in cmd and "--skip-git-repo-check" in cmd
        assert cmd[cmd.index("--sandbox") + 1] == "read-only"
        assert cmd[cmd.index("--model") + 1] == client.DEFAULT_MODEL
        assert cmd[-1] == "-"                      # prompt via STDIN
        assert "You are terse." in call["input"]   # system reached the prompt
        assert "2+2?" in call["input"]
        assert call.get("shell") is None           # list argv, never shell=True
        # Actual UTF-8 byte behavior is covered by test_owned_process.py.
        assert FAKE_TOKEN not in " ".join(cmd)

    def test_exec_gets_sanitized_environment(self, codex_env, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-secret")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-test-secret")
        fake = _FakeRun()
        client = self._client(codex_env, monkeypatch, fake)
        client.complete("s", [{"role": "user", "content": "q"}])
        env = fake.calls[-1]["env"]
        assert env["CODEX_HOME"] == str(codex_env / "codex-home")
        assert "PATH" in env
        assert "CODEX_ACCESS_TOKEN" not in env
        assert "OPENAI_API_KEY" not in env
        assert "AWS_SECRET_ACCESS_KEY" not in env

    def test_login_gets_sanitized_environment(self, codex_env, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-secret")
        fake = _FakeRun()
        monkeypatch.setattr(
            "maverick.providers.codex_cli_provider.run_owned", fake)
        CodexCLIClient().complete("sys", [{"role": "user", "content": "hi"}])
        login = next(c for c in fake.calls if "login" in c["cmd"])
        assert "CODEX_ACCESS_TOKEN" not in login["env"]
        assert "OPENAI_API_KEY" not in login["env"]

    def test_budget_records_tokens_at_zero_dollars(self, codex_env, monkeypatch):
        fake = _FakeRun()
        client = self._client(codex_env, monkeypatch, fake)
        budget = Budget(max_dollars=0.01)  # subscription: must not consume $
        client.complete("s", [{"role": "user", "content": "q"}], budget=budget)
        assert budget.dollars == 0.0
        # input_tokens counts the billable (non-cached) remainder: 120 - 20.
        assert budget.input_tokens == 100
        assert budget.cache_read_tokens == 20
        assert budget.output_tokens == 45

    def test_wall_clock_cap_still_enforced(self, codex_env, monkeypatch):
        from maverick.budget import BudgetExceeded
        fake = _FakeRun()
        client = self._client(codex_env, monkeypatch, fake)
        budget = Budget(max_wall_seconds=0.0)
        with pytest.raises(BudgetExceeded):
            client.complete("s", [{"role": "user", "content": "q"}],
                            budget=budget)

    def test_tool_call_protocol_round_trip(self, codex_env, monkeypatch):
        reply = (
            "Let me look that up.\n\n"
            '```json\n{"tool_call": {"name": "web_search", '
            '"input": {"query": "lightwork"}}}\n```'
        )
        fake = _FakeRun(text=reply)
        client = self._client(codex_env, monkeypatch, fake)
        tools = [{"name": "web_search", "description": "Search the web.",
                  "input_schema": {"type": "object",
                                   "properties": {"query": {"type": "string"}}}}]
        resp = client.complete("s", [{"role": "user", "content": "q"}],
                               tools=tools)
        assert resp.stop_reason == "tool_use"
        assert len(resp.tool_calls) == 1
        tc = resp.tool_calls[0]
        assert tc.name == "web_search"
        assert tc.input == {"query": "lightwork"}
        assert tc.id.startswith("codex_")
        assert resp.text == "Let me look that up."
        # The protocol instructions and schema made it into the prompt.
        prompt = fake.calls[-1]["input"]
        assert "web_search" in prompt and "tool_call" in prompt

    def test_plain_text_with_tools_is_end_turn(self, codex_env, monkeypatch):
        fake = _FakeRun(text="No tool needed: 4.")
        client = self._client(codex_env, monkeypatch, fake)
        resp = client.complete(
            "s", [{"role": "user", "content": "q"}],
            tools=[{"name": "t", "description": "", "input_schema": {}}],
        )
        assert resp.stop_reason == "end_turn"
        assert resp.tool_calls == []

    def test_history_flattening(self, codex_env, monkeypatch):
        fake = _FakeRun()
        client = self._client(codex_env, monkeypatch, fake)
        messages = [
            {"role": "user", "content": "find the file"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "Searching."},
                {"type": "tool_use", "id": "tu_1", "name": "grep",
                 "input": {"pattern": "x"}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "tu_1",
                 "content": [{"type": "text", "text": "found in a.py"}]},
            ]},
        ]
        client.complete("s", messages)
        prompt = fake.calls[-1]["input"]
        assert "find the file" in prompt
        assert "grep" in prompt and "tu_1" in prompt
        assert "found in a.py" in prompt

    def test_nonzero_exit_raises_with_scrubbed_stderr(self, codex_env, monkeypatch):
        fake = _FakeRun(returncode=1,
                        stderr=f"boom CODEX_ACCESS_TOKEN={FAKE_TOKEN} end")
        client = self._client(codex_env, monkeypatch, fake)
        with pytest.raises(RuntimeError, match="codex exec failed") as exc:
            client.complete("s", [{"role": "user", "content": "q"}])
        assert FAKE_TOKEN not in str(exc.value)

    def test_empty_reply_raises(self, codex_env, monkeypatch):
        fake = _FakeRun(text="")
        client = self._client(codex_env, monkeypatch, fake)
        with pytest.raises(RuntimeError, match="no agent message"):
            client.complete("s", [{"role": "user", "content": "q"}])

    @pytest.mark.asyncio
    async def test_complete_async(self, codex_env, monkeypatch):
        fake = _FakeRun(text="async ok")
        client = self._client(codex_env, monkeypatch, fake)
        resp = await client.complete_async(
            "s", [{"role": "user", "content": "q"}])
        assert resp.text == "async ok"


class TestEventParsing:
    def test_legacy_msg_shape(self):
        stdout = "\n".join([
            json.dumps({"msg": {"type": "agent_message", "message": "hi"}}),
            json.dumps({"msg": {"type": "token_count",
                                "info": {"input_tokens": 10,
                                         "output_tokens": 3}}}),
        ])
        text, usage = CodexCLIClient._parse_events(stdout)
        assert text == "hi"
        assert usage["input_tokens"] == 10
        assert usage["output_tokens"] == 3

    def test_garbage_lines_skipped(self):
        text, usage = CodexCLIClient._parse_events(
            "not json\n{broken\n" + json.dumps({"type": "other"}))
        assert text is None
        assert usage["input_tokens"] == 0

    def test_tool_call_block_with_no_marker_ignored(self):
        text, tc = CodexCLIClient._extract_tool_call(
            'see:\n```json\n{"just": "data"}\n```')
        assert tc is None and "just" in text

    def test_tool_call_scan_is_linear_on_unclosed_openers(self):
        # Many ```json{ openers with no closing fence made the old
        # ``\{.*?\}`` pattern rescan the rest of the reply per opener
        # (128 KB took seconds; the reply cap is 4 MiB). The paired scan
        # handles a full-size reply and still finds the real call before them.
        call = '```json\n{"tool_call": {"name": "read_file", "input": {"path": "a"}}}\n```'
        text, tc = CodexCLIClient._extract_tool_call(call + "\n" + "```json{" * 500_000)
        assert tc is not None and tc.name == "read_file"
        assert tc.input == {"path": "a"}
        assert text.endswith("```json{")
