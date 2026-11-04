"""Pin the defenses that keep Lightwork clear of the MCP STDIO RCE class.

OX Security disclosed a by-design RCE class in MCP STDIO transports across
official SDKs. Lightwork acts as an
MCP *client* spawning servers from the operator's own ~/.maverick/config.toml.
The spawn path is already hardened; these tests fail loudly if a refactor
reintroduces a hole:

  1. MCPServerSpec validates command/args/env on construction and raises
     ValueError on shell metacharacters / embedded newlines / non-string
     args -- the CVE-2026-30615 "STDIO Trifecta" injection vector.
  2. subprocess is spawned via create_subprocess_exec (argv), never a shell.
  3. _verify_command_pin resolves argv[0] via shutil.which and supports an
     operator-set pin_sha256 to refuse a swapped binary.
  4. child env is an allowlist (DEFAULT_ENV_ALLOWLIST), not full os.environ,
     so a hostile server can't read ANTHROPIC_API_KEY etc.
  5. MCP server config is sourced only from $MAVERICK_CONFIG or
     ~/.maverick/config.toml, never an attacker-plantable CWD/project file.
"""
from __future__ import annotations

import inspect

import maverick.config as config
import maverick.mcp_client as mc
import pytest


def test_shell_metacharacter_in_command_rejected():
    # The validator rejects shell metacharacters in the command that would
    # let a hostile server listing re-enter a shell parse. (A space-separated
    # "sh -c evil" is NOT rejected here -- it's exec'd as a single argv[0]
    # that simply won't resolve, not a shell command -- so it's excluded.)
    for bad in ("node;rm -rf /", "a|b", "x`whoami`", "a$(id)", "a>b", "a<b", "a&b"):
        with pytest.raises(ValueError):
            mc.MCPServerSpec(name="x", command=bad)


def test_newline_or_nul_in_command_rejected():
    for bad in ("node\nrm -rf /", "node\rfoo", "node\0foo"):
        with pytest.raises(ValueError):
            mc.MCPServerSpec(name="x", command=bad)


def test_non_string_or_injected_args_rejected():
    with pytest.raises(ValueError):
        mc.MCPServerSpec(name="x", command="node", args=[{"$inject": "evil"}])
    with pytest.raises(ValueError):
        mc.MCPServerSpec(name="x", command="node", args=["ok", "bad\narg"])


def test_bad_env_key_or_value_rejected():
    with pytest.raises(ValueError):
        mc.MCPServerSpec(name="x", command="node", env={"BAD KEY": "v"})
    with pytest.raises(ValueError):
        mc.MCPServerSpec(name="x", command="node", env={"OK": "bad\nvalue"})


def test_a_clean_spec_constructs():
    spec = mc.MCPServerSpec(
        name="fs", command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        env={"NODE_ENV": "production"},
    )
    assert spec.command == "npx"
    # from_config applies the same validation and rejects injection.
    with pytest.raises(ValueError):
        mc.MCPServerSpec.from_config("evil", {"command": "node;rm -rf /"})


def test_env_is_allowlisted_not_full_environ(monkeypatch):
    # A secret in the parent env must NOT leak into the child's env by default.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-should-not-leak")
    monkeypatch.setenv("PATH", "/usr/bin")
    spec = mc.MCPServerSpec(name="x", command="node")
    env = mc._build_env(spec)
    assert "ANTHROPIC_API_KEY" not in env
    assert "PATH" in env  # allowlisted infra vars do pass


def test_source_uses_which_and_no_shell_true():
    src = inspect.getsource(mc)
    assert "shutil.which(" in src, "lost PATH-resolution for pin verification"
    assert "create_subprocess_exec" in src, "must exec argv, not a shell"
    assert "shell=True" not in src, "shell=True reintroduces arg-injection RCE"


def test_config_trust_boundary_is_home_or_env_not_cwd():
    # The config path is resolved in config_path() (home dir or the explicit
    # MAVERICK_CONFIG override) -- never a project-local / CWD file.
    src = inspect.getsource(config.config_path)
    assert "MAVERICK_CONFIG" in src
    assert "getcwd" not in src
    assert "Path.cwd" not in src
