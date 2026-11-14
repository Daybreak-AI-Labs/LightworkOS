"""Host-git RCE hardening (see maverick/git_safety.py).

A workdir the agent can write to (write_file / SEARCH-REPLACE) or that came
from cloning an untrusted repo can carry a `.git/config` `core.fsmonitor`
hook or a `[filter "x"] smudge` command. Git executes that command during
`diff`/`add`/`reset`/`worktree` operations, independent of
`--no-ext-diff`/`--no-textconv`. These tests prove:

  - `git_metadata_may_execute_filters` / `git_env_without_user_config` are
    shared from one module (`git_safety.py`), not reimplemented per caller.
  - `edit_format.render_diff`, `reviewer.get_diff`, and
    `coding_mode.evaluate_candidate` all refuse to touch a workdir carrying
    such metadata, and never let a repo-local `core.fsmonitor` hook run.
  - `write_file` / `str_replace_editor` / `ast_edit` (via
    `tools.fs.write_text_contained`) and `apply_patch` refuse to write
    anywhere under `.git/`, in ORDINARY (non-benchmark) operation -- the
    prior guard only fired under `MAVERICK_BENCHMARK_OPAQUE` + coding mode.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def _make_git_repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "commit.gpgsign", "false"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    (tmp_path / "seed.py").write_text("print('seed')\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "seed.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "seed"], check=True)
    return tmp_path


def _plant_fsmonitor_hook(repo: Path) -> Path:
    """Configure `core.fsmonitor` to a script that writes a marker file, and
    return the marker path. If any test's fix regresses, the marker appears."""
    marker = repo / "fsmonitor-ran"
    hook = repo / ".git" / "fsmon-hook"
    hook.write_text(f"#!/bin/sh\necho pwned > {marker}\nexit 0\n")
    hook.chmod(0o755)
    subprocess.run(
        ["git", "-C", str(repo), "config", "core.fsmonitor", str(hook)], check=True
    )
    return marker


class _SB:
    def __init__(self, workdir):
        self.workdir = str(workdir)


class TestGitSafetyShared:
    def test_metadata_check_flags_fsmonitor(self, tmp_path):
        from maverick.git_safety import git_metadata_may_execute_filters
        repo = _make_git_repo(tmp_path)
        subprocess.run(
            ["git", "-C", str(repo), "config", "core.fsmonitor", ".git/whatever"],
            check=True,
        )
        assert git_metadata_may_execute_filters(repo) is True

    def test_metadata_check_clean_repo_is_safe(self, tmp_path):
        from maverick.git_safety import git_metadata_may_execute_filters
        repo = _make_git_repo(tmp_path)
        assert git_metadata_may_execute_filters(repo) is False

    def test_partial_clone_filter_is_not_a_false_positive(self, tmp_path):
        """`partialclonefilter = blob:none` (from --filter=blob:none) must not
        trip the guard -- it never runs a command."""
        from maverick.git_safety import git_metadata_may_execute_filters
        repo = _make_git_repo(tmp_path)
        config = repo / ".git" / "config"
        config.write_text(
            config.read_text() + "\n[remote \"origin\"]\n\tpartialclonefilter = blob:none\n"
        )
        assert git_metadata_may_execute_filters(repo) is False

    def test_scrubbed_env_disables_repo_local_fsmonitor(self, tmp_path):
        from maverick.git_safety import git_env_without_user_config
        env = git_env_without_user_config()
        assert env["GIT_CONFIG_KEY_0"] == "core.fsmonitor"
        assert env["GIT_CONFIG_VALUE_0"] == "false"
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"

    def test_scrubbed_env_stops_repo_local_hooks(self, tmp_path):
        """`git reset --hard` runs `.git/hooks/reference-transaction` (and
        `post-index-change`); a hook planted by whatever can write `.git` must
        not run under the scrubbed environment."""
        from maverick.git_safety import git_env_without_user_config
        repo = _make_git_repo(tmp_path)
        marker = tmp_path / "hook-ran"
        for name in ("reference-transaction", "post-index-change"):
            hook = repo / ".git" / "hooks" / name
            hook.write_text(f"#!/bin/sh\necho {name} >> {marker}\nexit 0\n")
            hook.chmod(0o755)
        (repo / "seed.py").write_text("print('edited')\n")
        env = git_env_without_user_config()
        # The shared env is a complete family: git aborts on a partial one.
        assert int(env["GIT_CONFIG_COUNT"]) == sum(k.startswith("GIT_CONFIG_KEY_") for k in env)

        subprocess.run(["git", "-C", str(repo), "reset", "--hard", "HEAD"],
                       check=True, capture_output=True, env=env)

        assert not marker.exists(), "a repo-local hook ran under the scrubbed env"
        assert (repo / "seed.py").read_text() == "print('seed')\n"


def _git_ok(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


_FILTER_PWN = 'sh -c "id > PWNED; cat"'


class TestGitDirDiscovery:
    """The guard must read the settings git will actually use, not just
    `<wd>/.git/config`: a `.git` pointer file, a symlinked
    `.git`, a linked worktree's common dir, `config.worktree` and a bare layout
    each put the filter somewhere a `.git/config`-only check never looks."""

    def _repo(self, tmp_path: Path) -> Path:
        repo = tmp_path / "repo"
        repo.mkdir()
        return _make_git_repo(repo)

    def test_gitdir_pointer_file_with_a_filter_is_flagged(self, tmp_path):
        import shutil

        from maverick.git_safety import git_metadata_may_execute_filters
        repo = self._repo(tmp_path)
        shutil.move(str(repo / ".git"), str(repo / "gd"))
        (repo / ".git").write_text("gitdir: gd\n")
        assert git_metadata_may_execute_filters(repo) is False  # clean so far
        (repo / "gd" / "info").mkdir(exist_ok=True)
        (repo / "gd" / "info" / "attributes").write_text("* filter=pwn\n")
        _git_ok(repo, "config", "filter.pwn.smudge", _FILTER_PWN)
        assert git_metadata_may_execute_filters(repo) is True

    def test_absolute_gitdir_pointer_with_a_filter_is_flagged(self, tmp_path):
        import shutil

        from maverick.git_safety import git_metadata_may_execute_filters
        repo = self._repo(tmp_path)
        elsewhere = tmp_path / "elsewhere-gitdir"
        shutil.move(str(repo / ".git"), str(elsewhere))
        (repo / ".git").write_text(f"gitdir: {elsewhere}\n")
        _git_ok(repo, "config", "filter.pwn.clean", _FILTER_PWN)
        assert git_metadata_may_execute_filters(repo) is True

    def test_symlinked_dotgit_with_a_filter_is_flagged(self, tmp_path):
        import shutil

        from maverick.git_safety import git_metadata_may_execute_filters
        repo = self._repo(tmp_path)
        shutil.move(str(repo / ".git"), str(tmp_path / "real-gitdir"))
        try:
            (repo / ".git").symlink_to(tmp_path / "real-gitdir")
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                pytest.skip("Windows account cannot create symlinks")
            raise
        assert git_metadata_may_execute_filters(repo) is False
        _git_ok(repo, "config", "filter.pwn.smudge", _FILTER_PWN)
        assert git_metadata_may_execute_filters(repo) is True

    def test_unreadable_pointer_file_fails_closed(self, tmp_path):
        from maverick.git_safety import git_metadata_may_execute_filters
        repo = self._repo(tmp_path)
        (repo / ".git").rename(tmp_path / "moved")
        (repo / ".git").write_text("not a pointer\n")
        assert git_metadata_may_execute_filters(repo) is True
        (repo / ".git").write_text("gitdir: does-not-exist\n")
        assert git_metadata_may_execute_filters(repo) is True

    def test_worktree_config_filter_is_flagged(self, tmp_path):
        """`extensions.worktreeConfig` makes git read `.git/config.worktree`
        too, and a filter / attributesFile defined there is just as live."""
        from maverick.git_safety import git_metadata_may_execute_filters
        repo = self._repo(tmp_path)
        config = repo / ".git" / "config"
        config.write_text(
            config.read_text().replace("repositoryformatversion = 0", "repositoryformatversion = 1")
            + "[extensions]\n\tworktreeConfig = true\n")
        attrs = repo / ".git" / "evil-attributes"
        attrs.write_text("* filter=pwn\n")
        assert git_metadata_may_execute_filters(repo) is False
        (repo / ".git" / "config.worktree").write_text(
            f'[core]\n\tattributesFile = {attrs}\n[filter "pwn"]\n\tsmudge = "{_FILTER_PWN}"\n')
        assert git_metadata_may_execute_filters(repo) is True

    def test_benign_worktree_config_is_not_flagged(self, tmp_path):
        """`git sparse-checkout` turns worktreeConfig on and keeps its own
        settings there; that must not trip the guard."""
        from maverick.git_safety import git_metadata_may_execute_filters
        repo = self._repo(tmp_path)
        config = repo / ".git" / "config"
        config.write_text(
            config.read_text().replace("repositoryformatversion = 0", "repositoryformatversion = 1")
            + "[extensions]\n\tworktreeConfig = true\n")
        (repo / ".git" / "config.worktree").write_text("[core]\n\tsparseCheckout = true\n")
        assert git_metadata_may_execute_filters(repo) is False

    def test_linked_worktree_reads_the_main_repositories_settings(self, tmp_path):
        from maverick.git_safety import git_metadata_may_execute_filters
        main = self._repo(tmp_path)
        linked = tmp_path / "linked"
        _git_ok(main, "worktree", "add", "--detach", "--quiet", str(linked), "HEAD")
        assert (linked / ".git").is_file()
        assert git_metadata_may_execute_filters(linked) is False  # clean linked worktree is fine
        (main / ".git" / "info").mkdir(exist_ok=True)
        (main / ".git" / "info" / "attributes").write_text("* filter=pwn\n")
        _git_ok(main, "config", "filter.pwn.smudge", _FILTER_PWN)
        assert git_metadata_may_execute_filters(linked) is True

    def test_per_worktree_config_of_a_linked_worktree_is_flagged(self, tmp_path):
        from maverick.git_safety import git_metadata_may_execute_filters
        main = self._repo(tmp_path)
        linked = tmp_path / "linked"
        _git_ok(main, "worktree", "add", "--detach", "--quiet", str(linked), "HEAD")
        (main / ".git" / "worktrees" / "linked" / "config.worktree").write_text(
            f'[filter "pwn"]\n\tsmudge = "{_FILTER_PWN}"\n')
        assert git_metadata_may_execute_filters(main) is True
        assert git_metadata_may_execute_filters(linked) is True

    def test_bare_layout_without_dotgit_is_scanned(self, tmp_path):
        """With no `.git` entry git takes a directory that looks like a
        repository as the repository itself, so its `config` is live."""
        from maverick.git_safety import git_metadata_may_execute_filters
        bare = tmp_path / "bare"
        subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
        assert git_metadata_may_execute_filters(bare) is False
        (bare / "info").mkdir(exist_ok=True)
        (bare / "info" / "attributes").write_text("* filter=pwn\n")
        _git_ok(bare, "config", "filter.pwn.smudge", _FILTER_PWN)
        assert git_metadata_may_execute_filters(bare) is True

    def test_section_header_spacing_does_not_hide_a_filter(self, tmp_path):
        """git accepts any run of blanks between a section name and its
        quoted subsection (`[filter   "pwn"]`), so a literal `[filter "` match
        is evaded by an extra space or a tab."""
        from maverick.git_safety import git_metadata_may_execute_filters
        repo = self._repo(tmp_path)
        config = repo / ".git" / "config"
        original = config.read_text()
        for header in ('[filter   "pwn"]', '[filter\t"pwn"]', '[FILTER "pwn"]', "[filter.pwn]"):
            config.write_text(original + f"{header}\n\tsmudge = true\n")
            assert git_metadata_may_execute_filters(repo) is True, header
        for header in ('[include]', '[include  ]', '[includeIf "gitdir:/x/"]'):
            config.write_text(original + f"{header}\n\tpath = /x\n")
            assert git_metadata_may_execute_filters(repo) is True, header

    def test_promisor_transport_and_nested_repository_settings_are_flagged(self, tmp_path):
        """A promisor remote makes `git diff` lazily fetch a missing object,
        which runs the transport the repository chose; and git checks a nested
        repository's dirtiness with a child `git status` that applies that
        repository's own config and attributes."""
        from maverick.git_safety import git_metadata_may_execute_filters
        repo = self._repo(tmp_path)
        config = repo / ".git" / "config"
        original = config.read_text()
        for setting in (
            '[remote "origin"]\n\turl = /x\n\tpromisor = true\n\tuploadpack = id; git-upload-pack\n',
            "[core]\n\tsshCommand = id\n",
            '[credential "https://x"]\n\thelper = !id\n',
            '[protocol "ext"]\n\tallow = always\n',
        ):
            config.write_text(original + setting)
            assert git_metadata_may_execute_filters(repo) is True, setting
        config.write_text(original)
        sub = repo / "sub"
        sub.mkdir()
        _make_git_repo(sub)
        assert git_metadata_may_execute_filters(repo) is False
        (sub / ".git" / "info").mkdir(exist_ok=True)
        (sub / ".git" / "info" / "attributes").write_text("* filter=x\n")
        assert git_metadata_may_execute_filters(repo) is True
        (sub / ".git" / "info" / "attributes").write_text("")
        sub_config = sub / ".git" / "config"
        sub_config.write_text(sub_config.read_text() + f'[filter "x"]\n\tclean = {_FILTER_PWN}\n')
        assert git_metadata_may_execute_filters(repo) is True

    def test_filter_attribute_such_as_git_lfs_is_refused(self, tmp_path):
        """A repository that really uses a filter (git-lfs) is refused too:
        the host cannot tell a legitimate clean/smudge command from a planted
        one, so it does not run either. Documented limitation."""
        from maverick.git_safety import git_metadata_may_execute_filters
        repo = self._repo(tmp_path)
        (repo / ".gitattributes").write_text("*.bin filter=lfs diff=lfs merge=lfs -text\n")
        assert git_metadata_may_execute_filters(repo) is True

    def test_ordinary_repositories_are_still_safe(self, tmp_path):
        import shutil

        from maverick.git_safety import git_metadata_may_execute_filters
        repo = self._repo(tmp_path)
        assert git_metadata_may_execute_filters(repo) is False
        # a `gitdir:` pointer to a clean git directory (submodule / worktree layout)
        shutil.move(str(repo / ".git"), str(repo / "gd"))
        (repo / ".git").write_text("gitdir: gd\n")
        assert git_metadata_may_execute_filters(repo) is False
        # a directory that is not a repository at all
        plain = tmp_path / "plain"
        plain.mkdir()
        assert git_metadata_may_execute_filters(plain) is False

    def test_orchestrator_reexports_same_functions(self):
        """orchestrator.py's private names must be the git_safety module's
        functions, not a second reimplementation."""
        from maverick import git_safety, orchestrator
        assert orchestrator._git_metadata_may_execute_filters is git_safety.git_metadata_may_execute_filters
        assert orchestrator._git_env_without_user_config is git_safety.git_env_without_user_config


class TestRenderDiffRefusesUnsafeMetadata:
    def test_render_diff_does_not_run_fsmonitor_hook(self, tmp_path):
        from maverick.edit_format import render_diff
        repo = _make_git_repo(tmp_path)
        marker = _plant_fsmonitor_hook(repo)
        (repo / "seed.py").write_text("print('changed')\n")

        diff = render_diff(repo, paths=["seed.py"])

        assert diff == ""
        assert not marker.exists()

    def test_render_diff_still_works_on_a_clean_repo(self, tmp_path):
        from maverick.edit_format import render_diff
        repo = _make_git_repo(tmp_path)
        (repo / "seed.py").write_text("print('changed')\n")

        diff = render_diff(repo, paths=["seed.py"])

        assert "seed.py" in diff
        assert "+print('changed')" in diff

    def test_apply_blocks_refuses_dotgit_target(self, tmp_path):
        from maverick.edit_format import SearchReplaceBlock, apply_blocks
        repo = _make_git_repo(tmp_path)
        blk = SearchReplaceBlock(path=".git/config", search="", replace="[core]\n\tfsmonitor = pwn\n")
        summary = apply_blocks([blk], repo)
        assert not summary.ok
        assert "never a valid edit target" in summary.results[0].reason
        config_text = (repo / ".git" / "config").read_text()
        assert "fsmonitor" not in config_text


class TestReviewerGetDiffRefusesUnsafeMetadata:
    def test_get_diff_does_not_run_fsmonitor_hook(self, tmp_path):
        from maverick.reviewer import get_diff
        repo = _make_git_repo(tmp_path)
        marker = _plant_fsmonitor_hook(repo)
        (repo / "seed.py").write_text("print('changed')\n")

        diff = get_diff(repo)

        assert diff == ""
        assert not marker.exists()

    def test_get_diff_still_works_on_a_clean_repo(self, tmp_path):
        from maverick.reviewer import get_diff
        repo = _make_git_repo(tmp_path)
        (repo / "seed.py").write_text("print('changed')\n")

        diff = get_diff(repo)

        assert "seed.py" in diff


class TestEvaluateCandidateRefusesUnsafeMetadata:
    def test_evaluate_candidate_refuses_when_fsmonitor_present(self, tmp_path):
        import asyncio

        from maverick.coding_mode import CodingModeConfig, evaluate_candidate

        repo = _make_git_repo(tmp_path)
        marker = _plant_fsmonitor_hook(repo)
        # Patch a non-test file so the (separate) anti-cheat boundary guard
        # doesn't preempt the check this test targets.
        patch = (
            "diff --git a/seed.py b/seed.py\n"
            "--- a/seed.py\n+++ b/seed.py\n"
            "@@ -1 +1 @@\n-print('seed')\n+print('patched')\n"
        )
        cfg = CodingModeConfig(enabled=True, fail_to_pass=["tests/test_seed.py::test_a"])

        cand = asyncio.run(evaluate_candidate(patch, repo, cfg, _SB(repo), 0))

        assert cand.apply_check_passed is False
        assert "unsafe git filter" in cand.error
        assert not marker.exists()


class TestWriteFileRefusesDotGitOutsideBenchmarkMode:
    def test_write_file_refuses_git_config_in_normal_mode(self, tmp_path, monkeypatch):
        from maverick.tools.fs import write_file
        monkeypatch.delenv("MAVERICK_BENCHMARK_OPAQUE", raising=False)
        monkeypatch.delenv("MAVERICK_CODING_MODE", raising=False)
        repo = _make_git_repo(tmp_path)

        out = write_file(_SB(repo)).fn({
            "path": ".git/config",
            "content": "[core]\n\tfsmonitor = /tmp/pwn.sh\n",
        })

        assert out.startswith("ERROR")
        assert "fsmonitor" not in (repo / ".git" / "config").read_text()

    @pytest.mark.parametrize("name", [".GIT", ".Git", ".git.", ".git "])
    def test_write_file_refuses_git_aliases(self, tmp_path, name):
        from maverick.tools.fs import write_file

        out = write_file(_SB(tmp_path)).fn({"path": f"{name}/config", "content": "bad"})
        assert out.startswith("ERROR")
        assert not (tmp_path / name / "config").exists()

    @pytest.mark.parametrize("name", [".GIT", ".Git", ".git.", ".git "])
    def test_patch_and_editor_refuse_git_aliases(self, tmp_path, name):
        from maverick.edit_format import _writes_git_metadata
        from maverick.tools.apply_patch import _is_safe_path

        assert _writes_git_metadata(tmp_path / name / "config")
        assert not _is_safe_path(f"{name}/config", tmp_path.resolve())
        assert _is_safe_path("notes.txt", tmp_path.resolve())

    def test_write_file_still_writes_ordinary_files(self, tmp_path, monkeypatch):
        from maverick.tools.fs import write_file
        monkeypatch.delenv("MAVERICK_BENCHMARK_OPAQUE", raising=False)
        monkeypatch.delenv("MAVERICK_CODING_MODE", raising=False)
        repo = _make_git_repo(tmp_path)

        out = write_file(_SB(repo)).fn({"path": "new.py", "content": "print(1)\n"})

        assert out.startswith("wrote")
        assert (repo / "new.py").read_text() == "print(1)\n"


class TestApplyPatchRefusesDotGitTarget:
    def test_apply_patch_refuses_git_config_target(self, tmp_path):
        from maverick.tools.apply_patch import apply_patch
        repo = _make_git_repo(tmp_path)
        patch = (
            "diff --git a/.git/config b/.git/config\n"
            "--- a/.git/config\n+++ b/.git/config\n"
            "@@ -1 +1,2 @@\n [core]\n+\tfsmonitor = /tmp/pwn.sh\n"
        )

        out = apply_patch(_SB(repo)).fn({"patch": patch})

        assert "ERROR" in out
        assert "fsmonitor" not in (repo / ".git" / "config").read_text()
