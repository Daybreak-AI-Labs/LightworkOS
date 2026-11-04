"""Cross-cutting security invariants — a single regression tripwire.

Each of these encodes a security contract that a red-team pass established and
that must NOT silently regress. They are deliberately fast, pure-function
assertions co-located so a reviewer can see the guarantees in one screen:

  * inbound signature verifiers FAIL CLOSED with no secret;
  * the sandbox child env is stripped of credential-shaped vars;
  * the SSRF guard refuses non-public addresses;
  * external MCP tool names are charset-validated before registration.

If you change one of these behaviours, you are changing a security guarantee
— update the contract deliberately, don't just make the test pass.
"""
from __future__ import annotations

import hashlib
import hmac
import socket

import pytest

# --- inbound webhook signature verifiers must fail closed ------------------

def test_github_app_signature_fails_closed_without_secret():
    from maverick.github_app import verify_signature
    assert verify_signature(b"{}", "sha256=whatever", None) is False
    assert verify_signature(b"{}", None, "") is False
    # Sanity: a correct signature with a secret still verifies.
    body = b'{"x":1}'
    sig = "sha256=" + hmac.new(b"s", body, hashlib.sha256).hexdigest()
    assert verify_signature(body, sig, "s") is True


def test_issue_webhook_signature_fails_closed_without_secret():
    from maverick.issue_webhooks import verify_signature
    assert verify_signature(b"{}", "deadbeef", None) is False
    assert verify_signature(b"{}", None, "s") is False


def test_outbound_webhook_verifier_rejects_unprefixed():
    from maverick.webhooks import verify_signature
    assert verify_signature(b"{}", "deadbeef", "s") is False  # no sha256= prefix
    assert verify_signature(b"{}", "", "s") is False


# --- sandbox child env must not carry credentials --------------------------

def test_scrub_env_strips_secret_shaped_vars():
    from maverick.sandbox.local import scrub_env
    src = {
        "ANTHROPIC_API_KEY": "sk-ant-secret",
        "GITHUB_TOKEN": "ghp_secret",
        "STRIPE_SECRET": "x",
        "DATABASE_URL": "postgres://u:p@h/db",
        "MAVERICK_OTEL_HEADERS": "authorization=Bearer secret,dd-api-key=dd-secret",
        "OTEL_EXPORTER_OTLP_HEADERS": "x-honeycomb-team=hc-secret",
        "MAVERICK_KMS_KEK": "deadbeef" * 8,
        "PATH": "/usr/bin",
        "HOME": "/home/u",
        "PLAIN_SETTING": "keep",
    }
    out = scrub_env(src)
    assert "ANTHROPIC_API_KEY" not in out
    assert "GITHUB_TOKEN" not in out
    assert "STRIPE_SECRET" not in out
    assert "DATABASE_URL" not in out  # connection string w/ embedded creds
    assert "MAVERICK_OTEL_HEADERS" not in out  # auth-bearing OTLP headers
    assert "OTEL_EXPORTER_OTLP_HEADERS" not in out
    # The tenant KMS key-encryption-key
    # matched none of KEY/TOKEN/SECRET/CREDENTIAL/... ("KEK" != "KEY") and
    # reached model-driven shell commands unstripped.
    assert "MAVERICK_KMS_KEK" not in out
    # Non-secret operational vars survive.
    assert out["PATH"] == "/usr/bin"
    assert out["HOME"] == "/home/u"
    assert out["PLAIN_SETTING"] == "keep"


def test_scrub_env_drops_harness_only_nousersite():
    """PYTHONNOUSERSITE hardens the HARNESS import path (deploy image sets it
    so a `pip install --user` can't shadow modules the harness lazily imports).
    The agent's own shell must NOT inherit it, or agent-installed user-site
    packages silently stop importing in the agent's own scripts."""
    from maverick.sandbox.local import scrub_env
    out = scrub_env({"PYTHONNOUSERSITE": "1", "PATH": "/usr/bin"})
    assert "PYTHONNOUSERSITE" not in out
    assert out["PATH"] == "/usr/bin"


def test_scrub_env_strips_github_cross_step_command_files():
    """Model-driven shells must not mutate later trusted Actions steps."""
    from maverick.sandbox.local import scrub_env

    src = {
        "GITHUB_ENV": "/runner/_temp/set_env",
        "GITHUB_OUTPUT": "/runner/_temp/set_output",
        "GITHUB_PATH": "/runner/_temp/add_path",
        "GITHUB_STATE": "/runner/_temp/save_state",
        "GITHUB_STEP_SUMMARY": "/runner/_temp/summary",
        # Environment names are case-insensitive on Windows.
        "github_path": r"C:\runner\_temp\add_path",
        "GITHUB_WORKSPACE": "/work/repo",
    }
    out = scrub_env(src)
    assert set(out) == {"GITHUB_WORKSPACE"}


def test_scrub_env_keeps_git_config_injection_consistent():
    """A partially-scrubbed GIT_CONFIG_COUNT/KEY_*/VALUE_* family aborts every
    git command with exit 128 ("missing config key GIT_CONFIG_KEY_0").

    _SECRET_ENV_RE matches GIT_CONFIG_KEY_* (the "KEY" token) and strips it, but
    leaves GIT_CONFIG_COUNT and GIT_CONFIG_VALUE_*, corrupting git's atomic
    env-config protocol. Hosts that inject git config via env -- GitHub Actions,
    Codespaces, devcontainers (url.insteadOf credential rewriting) -- would break
    every host-subprocess git invocation. scrub_env must keep the family
    all-or-nothing: if any member is stripped, drop them all so git cleanly falls
    back to file config. Regression for the stress-test git-cluster finding.
    """
    from maverick.sandbox.local import scrub_env
    src = {
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "credential.interactive",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "url.https://github.com/.insteadOf",
        "GIT_CONFIG_VALUE_1": "git@github.com:",
        "PATH": "/usr/bin",
    }
    out = scrub_env(src)
    leftovers = {k for k in out if k.startswith("GIT_CONFIG_")}
    # Never leave a dangling COUNT without its full KEY/VALUE complement.
    if "GIT_CONFIG_COUNT" in out:
        count = int(out["GIT_CONFIG_COUNT"])
        for i in range(count):
            assert f"GIT_CONFIG_KEY_{i}" in out, leftovers
            assert f"GIT_CONFIG_VALUE_{i}" in out, leftovers
    else:
        # Family dropped wholesale (the secret filter strips KEY_*): nothing left.
        assert not leftovers, leftovers
    assert out["PATH"] == "/usr/bin"  # unrelated vars untouched


# --- SSRF guard must refuse non-public addresses ---------------------------

def _fake_getaddrinfo(*ips):
    def _inner(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]
    return _inner


def test_ssrf_guard_refuses_loopback_and_metadata(monkeypatch):
    from maverick.tools._ssrf import BlockedHost, resolve_pinned_ip
    for ip in ("127.0.0.1", "169.254.169.254", "10.0.0.5", "::1"):
        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(ip))
        with pytest.raises(BlockedHost):
            resolve_pinned_ip("attacker.test")
    # A public address resolves fine.
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    assert resolve_pinned_ip("example.com") == "93.184.216.34"


# --- external MCP tool names must be validated -----------------------------

def test_mcp_tool_names_are_validated():
    from types import SimpleNamespace

    from maverick.mcp_tools import tools_from_mcp
    client = SimpleNamespace(
        spec=SimpleNamespace(name="srv"),
        tools=[
            {"name": "ok_tool", "description": "d", "inputSchema": {}},
            {"name": "inject\nname", "description": "d", "inputSchema": {}},
            {"name": "evil__shadow", "description": "d", "inputSchema": {}},
        ],
        call_tool=None,
    )
    names = {t.name for t in tools_from_mcp(client)}
    assert names == {"mcp_srv__ok_tool"}
