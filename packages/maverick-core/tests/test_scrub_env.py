"""Tests for sandbox environment scrubbing (scrub_env in maverick.sandbox.local)."""
from __future__ import annotations

import sys


def test_scrub_env_strips_passphrase_netrc_cookie_auth():
    from maverick.sandbox.local import scrub_env
    src = {
        "ANSIBLE_VAULT_PASSPHRASE": "p",
        "NETRC": "/root/.netrc",
        "SESSION_COOKIE": "abc",
        "GITHUB_AUTH": "tok",
        "PATH": "/usr/bin",
        "HOME": "/home/u",
    }
    out = scrub_env(src)
    for leaked in ("ANSIBLE_VAULT_PASSPHRASE", "NETRC", "SESSION_COOKIE", "GITHUB_AUTH"):
        assert leaked not in out, leaked
    assert out["PATH"] == "/usr/bin" and out["HOME"] == "/home/u"


# --- the local shell backend must scrub secrets, not just 5 names ---

def test_scrub_env_strips_secrets_keeps_benign():
    from maverick.sandbox.local import scrub_env

    src = {
        "PATH": "/usr/bin",
        "HOME": "/home/x",
        "LANG": "en_US.UTF-8",
        "STRIPE_API_KEY": "sk_live_x",
        "PLAID_SECRET": "ps",
        "AWS_SESSION_TOKEN": "t",
        "AWS_SECRET_ACCESS_KEY": "s",
        "CLOUDFLARE_API_TOKEN": "cf",
        "GH_TOKEN": "g",
        "MY_PASSWORD": "p",
        "DB_CREDENTIAL": "c",
        "ANTHROPIC_API_KEY": "a",
    }
    out = scrub_env(src)
    assert out == {"PATH": "/usr/bin", "HOME": "/home/x", "LANG": "en_US.UTF-8"}


# --- scrub_env strips connection-string secrets too ---

def test_scrub_env_strips_dsn_and_url_secrets():
    from maverick.sandbox.local import scrub_env
    src = {
        "PATH": "/usr/bin",
        "DATABASE_URL": "postgres://u:p@h/db",
        "SENTRY_DSN": "https://x@sentry.io/1",
        "MONGO_URI": "mongodb://u:p@h",
        "STRIPE_API_KEY": "sk",
    }
    out = scrub_env(src)
    # DATABASE_URL/SENTRY_DSN/MONGO_URI carry embedded creds.
    assert set(out) <= {"PATH"}  # everything secret-ish removed
    assert out.get("PATH") == "/usr/bin"


def test_local_backend_strips_gitlab_token(monkeypatch, tmp_path):
    from maverick.sandbox.local import LocalBackend
    monkeypatch.setenv("GITLAB_TOKEN", "glpat_test_secret")
    sb = LocalBackend(workdir=tmp_path)
    out = sb.exec(
        f'"{sys.executable}" -c "import os; '
        "print(os.environ.get('GITLAB_TOKEN', 'missing'))\""
    )
    assert out.exit_code == 0
    assert out.stdout.strip() == "missing"


# --- gold patch stripped from the non-opaque sandbox shell ----------

def test_scrub_env_strips_gold_patch_outside_opaque_mode():
    from maverick.sandbox.local import scrub_env
    # No MAVERICK_BENCHMARK_OPAQUE here: the shell tool only pops the var for
    # opaque runs, so without scrub_env covering it a normal-mode `printenv`
    # in the agent's shell would echo the SWE-bench gold patch.
    src = {
        "MAVERICK_GOLD_PATCH": "diff --git a/x b/x\n+the answer\n",
        "PATH": "/usr/bin",
    }
    out = scrub_env(src)
    assert "MAVERICK_GOLD_PATCH" not in out
    assert out["PATH"] == "/usr/bin"


def test_gold_patch_in_always_strip_list():
    from maverick.sandbox import local
    # GOLD_PATCH matches no keyword in _SECRET_ENV_RE, so it must be named
    # explicitly -- guard the regression in case the tuple is refactored.
    assert "MAVERICK_GOLD_PATCH" in local._ALWAYS_STRIP_ENV
    assert not local._SECRET_ENV_RE.search("MAVERICK_GOLD_PATCH")


def test_local_backend_hides_harness_environ_from_children(tmp_path):
    """scrub_env() only shapes the child's env; the child could still read the
    harness's exec-time environment from /proc/<ppid>/environ (same uid). The
    local backend marks the harness non-dumpable so /proc/<pid>/* is root-owned."""
    import os

    import pytest

    if sys.platform != "linux":
        pytest.skip("prctl(PR_SET_DUMPABLE) is Linux-only")
    from maverick.sandbox import local

    backend = local.LocalBackend(workdir=tmp_path)
    res = backend.exec("tr '\\0' '\\n' < /proc/$PPID/environ | head -c 1; echo rc=$?")
    assert local._harness_environ_hidden() is True
    if os.geteuid() != 0:  # root reads everything; the check is the dumpable flag
        assert "Permission denied" in (res.stderr or "") or "rc=1" in res.stdout
