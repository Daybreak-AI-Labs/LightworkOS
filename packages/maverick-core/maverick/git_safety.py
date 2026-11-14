"""Host-side git hardening shared by every module that runs `git` against a
workdir the agent (or an untrusted clone) can write to.

Git honours repo-local config: a `core.fsmonitor` hook, a `[filter "x"]`
smudge/clean command, or a config `include`/`includeIf` can make git execute
an attacker-controlled program during `diff`, `add`, `reset --hard`, or
`worktree add` -- independent of `--no-ext-diff`/`--no-textconv`, which only
disable two of those surfaces (the external-diff driver and textconv), not
fsmonitor or filter commands. A workdir the agent can write to (via
`write_file`/SEARCH-REPLACE) or that came from cloning an untrusted repo
(`github_app.process_issue`) is exactly such a workdir.

Every host-side git call against a workdir in that position must:
  1. Refuse when `git_metadata_may_execute_filters` finds config/attributes
     that could define one of these hooks (fail open: skip the git call
     rather than let it run).
  2. Run under `git_env_without_user_config` so global/system config, the
     calling process's environment (including provider API keys and other
     secrets), repo-local fsmonitor and repo-local hooks are never in scope
     even when (1) is a false negative.

`orchestrator.py`'s best-of-N candidate path, `edit_format.render_diff`,
`reviewer.get_diff` and `coding_mode`'s candidate evaluation all run `git` on
the host, and all share these protections. Without them, host-side git allows
code execution through repository config and leaks secrets into the child
environment.

Known limits: this is a static scan of what git will read, not a sandbox, and
these git calls do not run through `sandbox.exec()`. So a workdir whose git
settings define a filter at all -- git-lfs included -- is refused, because the
host cannot tell a legitimate clean/smudge command from a planted one.
"""
from __future__ import annotations

import os
import re
from pathlib import Path


def git_env_without_user_config() -> dict[str, str]:
    """Return a scrubbed environment for host-side git calls against a
    workdir that isn't a fully-isolated ephemeral checkout.

    Never let global/system config, the calling process's environment, or
    repo-local fsmonitor settings add executable helpers to these host-side
    git invocations. Local repo config is still checked separately (see
    `git_metadata_may_execute_filters`) before any git command runs.
    """
    env = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        # git 2.45+ never lazily fetches a missing object from a promisor
        # remote with this set; older git ignores it, and the transport
        # check in `git_metadata_may_execute_filters` covers them.
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_PAGER": "",
        "HOME": os.devnull,
        "PATH": os.environ.get("PATH", ""),
        # Override repo-local config entries that can otherwise make a
        # read-only host-side git probe execute workspace-controlled programs.
        # Hooks too: `reset --hard` runs `.git/hooks/reference-transaction`
        # and `post-index-change`, and whatever can write `.git` can plant one.
        "GIT_CONFIG_COUNT": "3",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "core.untrackedCache",
        "GIT_CONFIG_VALUE_1": "false",
        "GIT_CONFIG_KEY_2": "core.hooksPath",
        "GIT_CONFIG_VALUE_2": os.devnull,
    }
    for key in ("LANG", "LC_ALL", "LC_CTYPE", "TMPDIR"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


# Config text (lower-cased) that can make git run a command: a `[filter ...]`
# section (modern `[filter "name"]` or deprecated-but-supported `[filter.name]`
# syntax), a config include that could pull one in, `core.fsmonitor`, or an
# attributes file chosen from config. git accepts any run of blanks between a
# section name and its quoted subsection (`[filter   "x"]`), so the section
# names are matched as a pattern, not as the literal `[filter "`.
_CONFIG_SECTION = re.compile(r"\[\s*(?:filter|include)")
_CONFIG_NEEDLES = ("include.path", "includeif", "fsmonitor", "attributesfile")

# A promisor (partial-clone) remote makes a plain `git diff` fetch a missing
# object, and that fetch runs the transport settings:
# `remote.<name>.uploadpack`/`receivepack`, `core.sshCommand`,
# `core.gitProxy`, an askpass or credential helper, or a protocol (such as
# `ext::`) the repository allows itself. Without a promisor nothing on the
# host-side path fetches, so in an ordinary repository these settings (an
# ssh key choice, `protocol.version`, a credential store) are harmless.
_PROMISOR_NEEDLES = ("promisor", "partialclone")
_TRANSPORT_SECTION = re.compile(r"\[\s*(?:credential|protocol)")
_TRANSPORT_NEEDLES = ("uploadpack", "receivepack", "sshcommand", "gitproxy",
                      "askpass", "credential.", "protocol.")


def _text(path: Path) -> str:
    """Lower-cased contents of ``path``; empty when it is not a file. A read
    error propagates, and the caller treats that as unsafe."""
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore").lower()


def _config_hazard(text: str) -> str | None:
    """What in this (lower-cased, combined) config text can make git run a
    command, or None."""
    # The bare word "filter" is NOT sufficient and caused a false positive
    # on every partial clone: `git clone --filter=blob:none` writes a benign
    # `partialclonefilter = blob:none` into .git/config that never runs a
    # command, so matching "filter" would skip every git call on the entire
    # staged corpus. Match the executable surfaces precisely.
    if _CONFIG_SECTION.search(text) or any(n in text for n in _CONFIG_NEEDLES):
        return "a filter, config include or fsmonitor setting"
    if any(n in text for n in _PROMISOR_NEEDLES) and (
            _TRANSPORT_SECTION.search(text) or any(n in text for n in _TRANSPORT_NEEDLES)):
        return "a partial-clone remote with a transport command setting"
    return None


def _attributes_name_a_filter(text: str) -> bool:
    # An attributes file assigning a `filter` attribute references a named
    # filter whose clean/smudge command lives in config -- treat that
    # reference as unsafe. Attributes files never contain a
    # `partialclonefilter` value, so there is no blobless-clone false
    # positive here.
    return "filter=" in text or "filter " in text


def _gitfile_target(dotgit: Path) -> Path:
    """The git directory a `.git` pointer file names, read exactly as git
    reads it: only trailing line endings are stripped, the exact prefix
    `gitdir: ` is required, and the rest is the path unchanged (spaces
    included), relative to the file's directory. ValueError when git would
    refuse the file's format."""
    content = dotgit.read_bytes().rstrip(b"\r\n")
    if not content.startswith(b"gitdir: "):
        raise ValueError(f"invalid gitfile format: {dotgit}")
    return dotgit.parent / os.fsdecode(content[len(b"gitdir: "):])


def _git_directories(wd: Path) -> list[Path] | None:
    """The git directories git reads its settings from for a command run in
    ``wd``: the `.git` directory, or the one a `gitdir:` pointer file or a
    symlinked `.git` leads to, plus a linked worktree's common directory. With
    no `.git` entry at all git takes ``wd`` itself for the repository when it
    looks like a bare one, so that is scanned too. ``[]`` when there is
    nothing to read; ``None`` when a `.git` entry exists but cannot be
    followed, which the caller treats as unsafe."""
    dotgit = wd / ".git"
    if dotgit.is_symlink() or dotgit.exists():
        gitdir = None
        if dotgit.is_dir():
            gitdir = dotgit.resolve()
        elif dotgit.is_file():
            try:
                target = _gitfile_target(dotgit).resolve()
            except ValueError:
                target = None
            gitdir = target if target is not None and target.is_dir() else None
        if gitdir is None:
            return None
    elif (wd / "HEAD").is_file() and (wd / "objects").is_dir() and (wd / "refs").is_dir():
        gitdir = wd.resolve()
    else:
        return []
    directories = [gitdir]
    commondir = gitdir / "commondir"
    if commondir.is_file():
        # A linked worktree keeps its config and info/ in the main repository.
        # git strips only trailing line endings from `commondir`, as below.
        relative = os.fsdecode(commondir.read_bytes().rstrip(b"\r\n"))
        shared = (gitdir / relative).resolve()
        if not shared.is_dir():
            return None
        directories.append(shared)
    return directories


def git_metadata_may_execute_filters(wd: Path) -> bool:
    """Conservatively detect local git metadata that can make git run commands.

    A coding attempt can write the mounted workdir, including
    `.gitattributes`, `.git/info/attributes`, and local config. If those
    mention filters, config includes, fsmonitor hooks, or transport commands
    of a partial-clone remote, host-side `git diff`/`add`/`reset`/`worktree`
    may execute attacker-controlled commands. Fail open by skipping the git
    call instead. :func:`git_metadata_hazard` names what was found.

    The settings git reads are not always `<wd>/.git/config`: a `.git`
    pointer file or symlink moves the git directory (possibly inside the
    workspace), a linked worktree reads its main repository's, and
    `extensions.worktreeConfig` adds `config.worktree`. All of those are
    scanned, as are the git directories of repositories nested in ``wd``,
    and anything that cannot be followed or read counts as unsafe (except a
    nested `.git` pointer git cannot follow either: that is not a repository).
    """
    return git_metadata_hazard(wd) is not None


def git_metadata_hazard(wd: Path) -> str | None:
    """A short description of the git metadata in ``wd`` that could make
    host-side git run a command, or None when there is none."""
    try:
        wd = Path(wd)
        reason = _settings_hazard(_git_directories(wd))
        if reason:
            return reason
        nested, attributes = _scan_tree(wd)
        # A nested repository (a gitlink or submodule checkout) counts too:
        # git checks its dirtiness with a child `git status` that reads that
        # repository's own config and info/attributes.
        for repo in nested:
            if _stale_pointer(repo / ".git"):
                continue  # git cannot open it either: not a repository
            reason = _settings_hazard(_git_directories(repo))
            if reason:
                return f"{reason} in the nested repository {repo.relative_to(wd)}"
        for path in attributes:
            if _attributes_name_a_filter(_text(path)):
                return f"a filter (such as git-lfs) assigned in {path.relative_to(wd)}"
        return None
    except Exception:
        return "git metadata that could not be read"


def _stale_pointer(dotgit: Path) -> bool:
    """A well-formed `.git` pointer file whose exact target does not exist
    (a vendored package's leftover). Anything git could follow, or that
    cannot be parsed, is not stale."""
    if dotgit.is_symlink() or not dotgit.is_file():
        return False
    try:
        target = _gitfile_target(dotgit)
    except ValueError:
        return False
    return not os.path.lexists(target)


def _scan_tree(wd: Path) -> tuple[list[Path], list[Path]]:
    """One walk of the working tree: nested repository roots and every
    `.gitattributes`. Git directories themselves are not descended into."""
    nested: list[Path] = []
    attributes: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(wd):
        here = Path(dirpath)
        if ".gitattributes" in filenames:
            attributes.append(here / ".gitattributes")
        if ".git" in dirnames or ".git" in filenames:
            if here != wd:
                nested.append(here)
            if ".git" in dirnames:
                dirnames.remove(".git")
    return nested, attributes


def _settings_hazard(directories: list[Path] | None) -> str | None:
    if directories is None:
        return "a .git entry that cannot be followed"
    texts = []
    for directory in directories:
        config_files = [directory / "config", directory / "config.worktree"]
        config_files.extend(directory.glob("worktrees/*/config.worktree"))
        texts.extend(_text(path) for path in config_files)
        if _attributes_name_a_filter(_text(directory / "info" / "attributes")):
            return "a filter assigned in .git/info/attributes"
    return _config_hazard("\n".join(texts))
