"""Tests for the shell tool in opaque benchmark mode: blocking git internals,
.git reads through any utility, and gold-patch leaks.
"""
from __future__ import annotations

import os

import pytest

# ---- shell refuses git log -p / git show in opaque mode ----

class TestShellOpaqueGuard:
    @pytest.fixture(autouse=True)
    def _shell_consented(self, fresh_human_decision):
        # These tests exercise the OPAQUE-mode guard through the shell
        # tool; the shell's exact-approval permit needs a fresh human
        # decision, supplied by the shared fixture so the guard itself is
        # what is under test.
        del fresh_human_decision

    def _make_sandbox(self, tmp_path):
        class _Sandbox:
            workdir = tmp_path
            timeout = 30.0

            def exec(self, cmd):
                from maverick.sandbox.local import ExecResult
                return ExecResult(stdout="ran: " + cmd, stderr="", exit_code=0)
        return _Sandbox()

    def test_git_log_patch_blocked(self, tmp_path, monkeypatch):
        from maverick.tools.shell import shell
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = shell(self._make_sandbox(tmp_path))
        out = tool.fn({"cmd": "git log -p HEAD~1"})
        assert "blocked" in out.lower()
        assert "ran:" not in out

    def test_git_show_blocked(self, tmp_path, monkeypatch):
        from maverick.tools.shell import shell
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = shell(self._make_sandbox(tmp_path))
        out = tool.fn({"cmd": "git show HEAD~1"})
        assert "blocked" in out.lower()

    def test_normal_git_diff_allowed(self, tmp_path, monkeypatch):
        from maverick.tools.shell import shell
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = shell(self._make_sandbox(tmp_path))
        # plain `git diff` (HEAD vs worktree) is the normal path -- allowed.
        out = tool.fn({"cmd": "git diff"})
        assert "ran:" in out
        assert "blocked" not in out.lower()

    def test_pytest_allowed(self, tmp_path, monkeypatch):
        from maverick.tools.shell import shell
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = shell(self._make_sandbox(tmp_path))
        out = tool.fn({"cmd": "pytest tests/test_foo.py"})
        assert "ran:" in out

    def test_opaque_off_allows_git_log_patch(self, tmp_path, monkeypatch):
        from maverick.tools.shell import shell
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "0")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = shell(self._make_sandbox(tmp_path))
        out = tool.fn({"cmd": "git log -p"})
        assert "ran:" in out

    def test_github_downloads_blocked(self, tmp_path, monkeypatch):
        """Fetching an upstream fix from GitHub is refused in opaque mode."""
        from maverick.tools.shell import shell
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = shell(self._make_sandbox(tmp_path))
        for cmd in (
            "curl -sL https://raw.githubusercontent.com/foo/bar/abc.patch",
            "wget https://github.com/foo/bar/pull/123.diff",
        ):
            out = tool.fn({"cmd": cmd})
            assert "blocked" in out.lower(), f"expected {cmd!r} to be blocked"
            assert "ran:" not in out

    def test_package_installs_blocked(self, tmp_path, monkeypatch):
        """Opaque mode refuses every package install, editable or not."""
        from maverick.tools.shell import shell
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = shell(self._make_sandbox(tmp_path))
        for cmd in ("pip install -e .", "pip install requests", "npm install"):
            out = tool.fn({"cmd": cmd})
            assert "blocked" in out.lower(), f"expected {cmd!r} to be blocked; got {out[:200]}"
        assert "editable" in tool.fn({"cmd": "pip install -e ."}).lower()
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "0")
        assert "ran:" in tool.fn({"cmd": "pip install ."})

    def test_blocklist_is_linear_on_repeated_subcommands(self):
        """`"git log " * 474` took seconds before the consent prompt: each rule
        retried from every `git` (and every `log`). Rules now commit to the
        first `git` in a segment; the decisions themselves are unchanged."""
        from maverick.tools.shell import _is_blocked_in_opaque
        for many in ("git log " * 474, "cat " * 950, "curl " * 760):
            assert _is_blocked_in_opaque(many) == (False, "")
        assert _is_blocked_in_opaque("echo x; " + "git log " * 400 + "-p")[0]
        assert _is_blocked_in_opaque("ls | git -c a=b show HEAD")[0]
        assert _is_blocked_in_opaque("curl " * 300 + "https://github.com/x")[0]


@pytest.fixture(autouse=True)
def _shell_consented(fresh_human_decision):
    """These tests exercise git-internals BLOCKING through the shell tool;
    the shell's exact-approval permit needs a fresh human decision, which
    the shared fixture supplies so the blocking rules are what is tested."""
    del fresh_human_decision


@pytest.fixture
def opaque_mode(monkeypatch):
    monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
    monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
    from maverick.coding_mode import reset_gold_patch_cache
    reset_gold_patch_cache()
    yield
    reset_gold_patch_cache()


class TestShellGitFlagsBypass:
    """git plumbing wasn't blocked
    when preceded by `-P`, `--git-dir=...`, `-c k=v`, etc."""

    def _shell(self, tmp_path):
        from maverick.tools.shell import shell

        class _Sandbox:
            workdir = tmp_path
            timeout = 5.0

            def exec(self, cmd, timeout=None):
                from maverick.sandbox.local import ExecResult
                return ExecResult(stdout="ok", stderr="", exit_code=0)

        return shell(_Sandbox())

    def test_git_dash_p_log_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "git -P log -p HEAD"})
        assert "blocked" in out.lower()

    def test_git_dash_c_log_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "git -c color.ui=never log -p HEAD"})
        assert "blocked" in out.lower()

    def test_git_dash_dash_git_dir_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "git --git-dir=/workdir/.git rev-list HEAD"})
        assert "blocked" in out.lower()

    def test_git_rev_list_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "git rev-list HEAD"})
        assert "blocked" in out.lower()

    def test_git_show_ref_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "git show-ref"})
        assert "blocked" in out.lower()

    def test_git_ls_files_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "git ls-files --stage"})
        assert "blocked" in out.lower()


class TestShellAnyUtilityReadsDotGit:
    """Block .git/<sensitive> reads
    regardless of consuming utility — python, awk, xxd, grep, sed,
    cp, mv, tar all bypass the prior cat-blocker."""

    def _shell(self, tmp_path):
        from maverick.tools.shell import shell

        class _Sandbox:
            workdir = tmp_path
            timeout = 5.0

            def exec(self, cmd, timeout=None):
                from maverick.sandbox.local import ExecResult
                return ExecResult(stdout="ok", stderr="", exit_code=0)

        return shell(_Sandbox())

    def test_python_read_dotgit_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({
            "cmd": "python -c \"print(open('.git/HEAD').read())\"",
        })
        assert "blocked" in out.lower()

    def test_awk_read_dotgit_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "awk 1 .git/HEAD"})
        assert "blocked" in out.lower()

    def test_grep_dotgit_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "grep -r HEAD .git/refs"})
        assert "blocked" in out.lower()

    def test_cp_dotgit_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "cp .git/HEAD /tmp/leak"})
        assert "blocked" in out.lower()

    def test_sed_dotgit_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "sed n .git/refs/heads/main"})
        assert "blocked" in out.lower()


class TestShellGitInternalsBlocked:
    """Shell-level git plumbing + raw .git filesystem access."""

    def _shell(self, tmp_path):
        from maverick.tools.shell import shell

        class _Sandbox:
            workdir = tmp_path
            timeout = 5.0

            def exec(self, cmd, timeout=None):
                from maverick.sandbox.local import ExecResult
                return ExecResult(stdout="ok", stderr="", exit_code=0)

        return shell(_Sandbox())

    def test_git_cat_file_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "git cat-file -p HEAD"})
        assert "blocked" in out.lower()

    def test_git_for_each_ref_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "git for-each-ref"})
        assert "blocked" in out.lower()

    def test_cat_dotgit_refs_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "cat .git/refs/heads/main"})
        assert "blocked" in out.lower()

    def test_find_dotgit_blocked(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "find .git -type f"})
        assert "blocked" in out.lower()

    def test_legitimate_git_status_allowed(self, tmp_path, opaque_mode):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "git status"})
        assert "blocked" not in out.lower()
        assert "ok" in out


class TestShellPopsGoldPatch:
    """Subprocess must not inherit MAVERICK_GOLD_PATCH. The shell
    tool defensively pops the env var before forwarding to sandbox."""

    def test_shell_pops_gold_patch_in_opaque(self, tmp_path, monkeypatch):
        from maverick.coding_mode import reset_gold_patch_cache
        from maverick.tools.shell import shell
        reset_gold_patch_cache()
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
        monkeypatch.setenv("MAVERICK_GOLD_PATCH", "the gold")

        captured_env = {}

        class _Sandbox:
            workdir = tmp_path
            timeout = 5.0

            def exec(self, cmd, timeout=None):
                from maverick.sandbox.local import ExecResult
                captured_env["MAVERICK_GOLD_PATCH"] = os.environ.get(
                    "MAVERICK_GOLD_PATCH"
                )
                return ExecResult(stdout="", stderr="", exit_code=0)

        tool = shell(_Sandbox())
        tool.fn({"cmd": "echo hello"})
        assert captured_env.get("MAVERICK_GOLD_PATCH") is None, (
            "subprocess saw MAVERICK_GOLD_PATCH — gold answer leaked "
            "via env to the agent's sandboxed shell"
        )
        reset_gold_patch_cache()


class TestOpaqueGoldLeakBlocklist:
    """Opaque-mode gold-leak blocklist coverage.

    Three leak paths: single-ref `git diff <ref>` (no `..`), patch-emitting
    porcelain (format-patch --stdout / whatchanged / archive / bundle
    create / log --format=%H), and `.git` laundering to a non-`.git`
    name (cp/ln/tar/rsync .git). All blocked ONLY in opaque mode;
    normal-mode `git diff`/`git log` must keep working.
    """

    def _shell(self, tmp_path):
        from maverick.tools.shell import shell

        class _Sandbox:
            workdir = tmp_path
            timeout = 5.0

            def exec(self, cmd, timeout=None):
                from maverick.sandbox.local import ExecResult
                return ExecResult(stdout="ok", stderr="", exit_code=0)

        return shell(_Sandbox())

    # --- Task 1: single-ref `git diff <ref>` ---

    @pytest.mark.parametrize("cmd", [
        "git diff main",
        "git diff origin/main",
        "git diff HEAD~1",
        "git diff abc1234",
        "git -P diff main",
    ])
    def test_git_diff_single_ref_blocked(self, tmp_path, opaque_mode, cmd):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": cmd})
        assert "blocked" in out.lower(), cmd

    @pytest.mark.parametrize("cmd", [
        "git diff",
        "git diff --staged",
        "git diff --cached -- file.py",
        "git diff HEAD",
        "git diff HEAD --",
        "git diff -- path/to/file",
    ])
    def test_legit_git_diff_allowed_in_opaque(self, tmp_path, opaque_mode, cmd):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": cmd})
        assert "blocked" not in out.lower(), cmd
        assert "ok" in out

    # --- Task 2: patch-emitting porcelain ---

    @pytest.mark.parametrize("cmd", [
        "git format-patch HEAD~1 --stdout",
        "git whatchanged -p",
        "git archive HEAD",
        "git bundle create out.bundle HEAD",
        "git log --format=%H",
        "git log --pretty=%H",
    ])
    def test_patch_porcelain_blocked(self, tmp_path, opaque_mode, cmd):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": cmd})
        assert "blocked" in out.lower(), cmd

    # --- Task 3: .git laundering to a non-.git name ---

    @pytest.mark.parametrize("cmd", [
        "cp -r .git /tmp/g && cat /tmp/g/HEAD",
        "ln -s .git gd",
        "tar cf - .git",
        "rsync -a .git /tmp/x",
    ])
    def test_dotgit_laundering_blocked(self, tmp_path, opaque_mode, cmd):
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": cmd})
        assert "blocked" in out.lower(), cmd

    def test_gitignore_not_overblocked(self, tmp_path, opaque_mode):
        # `.gitignore` must not trip the `.git` laundering rule.
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": "cat .gitignore"})
        assert "blocked" not in out.lower()
        assert "ok" in out

    # --- Normal mode: none of the new blocks apply ---

    @pytest.mark.parametrize("cmd", [
        "git diff main",
        "git diff HEAD~1",
        "git format-patch HEAD~1 --stdout",
        "git whatchanged -p",
        "git archive HEAD",
        "git bundle create out.bundle HEAD",
        "git log --format=%H",
        "cp -r .git /tmp/g",
        "ln -s .git gd",
        "tar cf - .git",
    ])
    def test_all_allowed_in_normal_mode(self, tmp_path, monkeypatch, cmd):
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "0")
        monkeypatch.delenv("MAVERICK_CODING_MODE", raising=False)
        tool = self._shell(tmp_path)
        out = tool.fn({"cmd": cmd})
        assert "blocked" not in out.lower(), cmd
        assert "ok" in out
