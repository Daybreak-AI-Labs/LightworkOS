"""Shell tool. Sandbox-mediated."""
from __future__ import annotations

import os
import re
from inspect import Signature, signature

from . import Tool

# In benchmark opaque mode, refuse git subcommands that
# can leak the gold patch (the SWE-bench evaluator pre-applies the
# bug commit to HEAD; the fix is reachable via `git log -p`, `git
# show <commit>`, `git diff HEAD..main`, etc.). The list is the
# minimum-surprise blocklist — generic `git` (status, diff, apply,
# add, commit, reset) stays available so the agent can still work.
# Every `git <subcommand>` rule matches `git`, then any non-separator text,
# then the subcommand. Written naively (`\bgit\s[^\n;&|]*?X`) the engine
# retried from every `git` in a long segment, and rules ending in `.*?` from
# every `log` too, so `"git log " * 474` took seconds before the consent
# prompt. Rules start at a segment boundary and commit (atomic group) to the
# FIRST `git` in it: text after a later `git` in the same segment is also
# after the first, so the set of matched commands is unchanged. Rules with a
# trailing `.*?` likewise commit to the first subcommand occurrence.
_GIT = r"(?:^|(?<=[\n;&|]))(?>[^\n;&|]*?\bgit\s)[^\n;&|]*?"
_GIT_ATOMIC = r"(?:^|(?<=[\n;&|]))(?>[^\n;&|]*?\bgit\s)(?>[^\n;&|]*?"

_GIT_GOLD_LEAK_PATTERNS = [
    # Porcelain commands — most leak vectors. We accept that any of
    # these tokens after `git` (possibly with global flags like -P,
    # -C dir, --git-dir=path, -c k=v) defeats the simple `\bgit\s+log\b`
    # anchor, so we accept ANY non-newline char between `git` and the
    # subcommand. The `git\b` start anchor still rules out `gitlab` etc.
    re.compile(_GIT_ATOMIC + r"\blog\b).*?(?:-p|--patch|--all|--reflog)\b"),
    re.compile(_GIT + r"\bshow\b"),
    re.compile(_GIT + r"\bblame\b"),
    # `git diff` HEAD-vs-worktree is fine; block ref-vs-ref diffs.
    re.compile(_GIT + r"\bdiff\s+\S+\.\."),
    # A SINGLE ref (no `..`) — `git diff main` / `origin/main` /
    # `HEAD~1` / `<sha>` — compares that ref against the working tree,
    # which IS the inverted gold patch. Block `git diff <ref>` for any
    # ref other than HEAD / the working tree. We allow the bare options
    # cases (`git diff`, `git diff --staged`, `git diff -- path`,
    # `git diff HEAD`, `git diff HEAD --`) and block when the first
    # non-option token is a ref that isn't exactly HEAD. The negative
    # lookahead skips leading dash-options and `--` path separators.
    re.compile(
        _GIT + r"\bdiff\s+"
        r"(?:-(?!-\s|-$)[^\s]+\s+)*"  # skip dash-options, but NOT a lone `--`
        r"(?!HEAD(?:\s|$))"           # HEAD alone (vs worktree) is fine
        r"(?!-)"                      # not an option/`--` (paths-only sep)
        r"[A-Za-z0-9_./~^@]+"         # a ref token (branch/sha/tag)
    ),
    re.compile(_GIT + r"\bstash\s+(?:list|show)\b"),
    re.compile(_GIT + r"\breflog\b"),
    # Patch-emitting porcelain. `format-patch --stdout`,
    # `whatchanged -p`, `archive`, `bundle create` all materialize the
    # tree/history (and thus the gold patch) outside the blocked verbs.
    # Bare `git log --format=%H` / `--pretty=%H` leaks the gold SHA,
    # which then unlocks `git diff <sha>` — so block those too.
    re.compile(_GIT_ATOMIC + r"\bformat-patch\b).*?--stdout\b"),
    re.compile(_GIT + r"\bwhatchanged\b"),
    re.compile(_GIT + r"\barchive\b"),
    re.compile(_GIT + r"\bbundle\s+create\b"),
    re.compile(
        _GIT_ATOMIC + r"\blog\b).*?"
        r"(?:--format|--pretty)[=\s]\S*%H",
    ),
    # Plumbing: full coverage including subcommands
    # that the original list missed (rev-list, show-ref, ls-files,
    # fsck, update-ref, symbolic-ref).
    re.compile(_GIT + r"\bcat-file\b"),
    re.compile(_GIT + r"\bfor-each-ref\b"),
    re.compile(_GIT + r"\brev-list\b"),
    re.compile(_GIT + r"\bshow-ref\b"),
    re.compile(_GIT + r"\bsymbolic-ref\b"),
    re.compile(_GIT + r"\bls-tree\b"),
    re.compile(_GIT + r"\bls-files\b"),
    re.compile(_GIT + r"\bfsck\b"),
    re.compile(_GIT + r"\bupdate-ref\b"),
    re.compile(
        _GIT_ATOMIC + r"\brev-parse\b).*\b"
        r"(?:HEAD\^|HEAD~|main|master|origin)"
    ),
    # `git --git-dir=PATH` redirects to a foreign .git — block any
    # use that names a path.
    re.compile(r"\bgit\s+--git-dir[=\s]+\S+"),
    # Any *consuming utility* against `.git/<sensitive>` paths.
    # The prior allowlist (cat/
    # head/tail/less/more/strings/hexdump/od) missed python/awk/xxd/
    # grep/sed/cp/mv/tar/rsync. Anchor on the .git/<file> token so
    # the rule fires regardless of who reads it.
    re.compile(
        r"\.git/(?:HEAD|ORIG_HEAD|FETCH_HEAD|MERGE_HEAD|packed-refs"
        r"|refs(?:/|\b)|objects(?:/|\b)|index\b)",
    ),
    re.compile(r"\bfind\s+\.git\b"),
    # `.git` laundering. The rule above anchors on the literal
    # `.git/<file>` token, so relocating/aliasing the dir to a non-`.git`
    # name evades it: `cp -r .git /tmp/g && cat /tmp/g/HEAD`,
    # `ln -s .git gd && cat gd/HEAD`, `tar cf - .git`, `rsync -a .git x`.
    # Block any archiver/copier/linker/reader that NAMES `.git` as a
    # source/argument. Match `.git` as a whole path component (start of
    # token or after `/`), with a word/path boundary after, so we catch
    # both bare `.git` and `.git/...` but not e.g. `foo.gitignore`.
    re.compile(
        r"(?:^|(?<=[\n;&|]))(?>[^\n;&|]*?\b(?:cp|mv|ln|tar|rsync|cat|scp|install|7z|zip)\b)"
        r"[^\n;&|]*?(?:^|\s|=)\.git(?:/|\b)",
    ),
    # NOTE: string-matching is inherently brittle (quoting, `$(...)`,
    # env-var indirection, base64, etc. all evade it). The robust
    # complement is to relocate `.git` out of the sandbox workdir (or
    # make it unreadable) for the duration of an opaque-mode run; that
    # belongs in the sandbox/backend setup, not in this shell-tool regex
    # blocklist, and is intentionally NOT implemented here.
]


# Block external network egress in opaque benchmark mode.
# The agent can `curl` / `wget` the upstream fix PR off github.com,
# read it, then transcribe — fully bypassing our shell-level git
# blocks. This is the most common cheating vector documented in the
# SWE-bench-Pro post-mortems (Princeton issue #465, Scale's cheating
# detection blog 2025-11-19). LocalBackend has no `--network=none`
# equivalent so we have to gate it here at the tool layer.
_NETWORK_LEAK_PATTERNS = [
    re.compile(
        # Commit to the first fetcher on the line (see _GIT): linear time.
        r"(?:^|(?<=\n))(?>[^\n]*?\b(?:curl|wget|http(?:ie)?|aria2c|fetch)\b).*?"
        r"\b(?:github\.com|githubusercontent\.com|gist\.github\.com|"
        r"raw\.githubusercontent|api\.github\.com|patch-diff)\b",
        re.IGNORECASE,
    ),
    # `pip install <pkg>@git+...` and `git clone https://github.com/...`
    # would also fetch upstream — block them too in opaque mode.
    re.compile(r"\bgit\s+clone\s+\S*github\.com\S*", re.IGNORECASE),
    re.compile(r"\bpip\s+install\s+\S*git\+\S*github\S*", re.IGNORECASE),
    # Python one-liner fetch
    re.compile(
        r"\A(?>.*?\b(?:python|python3)\s+-c\s+[\"'])(?>.*?(?:urllib|requests|httpx)).*?"
        r"github\.com",
        re.IGNORECASE | re.DOTALL,
    ),
]


# Block `pip install -e .` in opaque mode when running inside
# a worktree. Editable installs from inside a
# git-worktree create .pth/.egg-link entries that may point at the
# ORIGINAL tree or fail to point anywhere useful; tests then import
# unpatched code from the original. We surface the right pattern
# instead of letting the agent burn cycles on a silent failure.
_EDITABLE_INSTALL_PATTERN = re.compile(
    r"\bpip\s+install\s+(?:[^|;&]*\s+)?-e\b",
    re.IGNORECASE,
)


# The prompt's Rule 11 ("never run pip
# install") is aspirational. Enforce here. The grader uses a pristine
# Docker image with deps pre-installed; any `pip install` from the
# agent's shell pollutes the LOCAL sandbox (changing test outcomes
# for subsequent instances when the workdir is shared) but is a
# no-op for the grader. Block in opaque mode.
_PACKAGE_INSTALL_PATTERN = re.compile(
    r"\b(?:"
    r"pip\s+install"
    r"|pip3\s+install"
    r"|python\s+-m\s+pip\s+install"
    r"|python3\s+-m\s+pip\s+install"
    r"|conda\s+install"
    r"|npm\s+(?:install|i|ci|add)"
    r"|yarn\s+(?:add|install)"
    r"|apt(?:-get)?\s+install"
    r"|apk\s+add"
    r"|brew\s+install"
    r")\b",
    re.IGNORECASE,
)


# Detect pytest / npm test / go test / cargo test invocations
# so we can raise the per-call timeout from the LocalBackend default
# of 60 s (way too short for real SWE-bench test suites — Django can
# take 5-10 min).
_LONG_RUN_TEST_PATTERNS = [
    re.compile(r"\b(?:python\s+-m\s+)?pytest\b", re.IGNORECASE),
    re.compile(r"\bnpm\s+(?:test|run\s+test)\b", re.IGNORECASE),
    re.compile(r"\bnpx\s+(?:jest|vitest|mocha)\b", re.IGNORECASE),
    re.compile(r"\byarn\s+(?:test|jest|vitest)\b", re.IGNORECASE),
    re.compile(r"\bgo\s+test\b", re.IGNORECASE),
    re.compile(r"\bcargo\s+test\b", re.IGNORECASE),
    re.compile(r"\bbundle\s+exec\s+rspec\b", re.IGNORECASE),
    re.compile(r"\bmvn\s+(?:test|verify)\b", re.IGNORECASE),
    re.compile(r"\b\./gradlew\s+test\b", re.IGNORECASE),
    re.compile(r"\btox\b", re.IGNORECASE),
    # Heavy build/install commands also need longer timeouts.
    re.compile(r"\bpip\s+install\b", re.IGNORECASE),
    re.compile(r"\bnpm\s+(?:i|install|ci)\b", re.IGNORECASE),
]


def _is_blocked_in_opaque(cmd: str) -> tuple[bool, str]:
    for pat in _GIT_GOLD_LEAK_PATTERNS:
        m = pat.search(cmd)
        if m:
            return True, m.group(0)
    for pat in _NETWORK_LEAK_PATTERNS:
        m = pat.search(cmd)
        if m:
            return True, m.group(0)
    return False, ""


def _is_long_running(cmd: str) -> bool:
    return any(p.search(cmd) for p in _LONG_RUN_TEST_PATTERNS)


def _time_limit_words(timeout: float | None) -> str:
    if timeout is None:
        return "Time limit: the sandbox's usual limit."
    if timeout >= 60 and timeout % 60 == 0:
        minutes = int(timeout // 60)
        return f"Time limit: {minutes} minute{'s' if minutes != 1 else ''}."
    return f"Time limit: {timeout:g} seconds."


def _reviewable_command_error(cmd: str) -> str | None:
    """Refuse commands whose complete contents cannot be shown for review."""
    if len(cmd) > 3800:
        return "ERROR: shell command is too long to review; split it into shorter commands"
    if any(char not in "\n\t" and not char.isprintable() for char in cmd):
        return "ERROR: shell command contains characters that cannot be safely reviewed"
    try:
        from ..safety.secret_detector import redact

        shown, _ = redact(cmd)
    except Exception:
        return "ERROR: shell command could not be checked for safe review"
    if shown != cmd:
        return "ERROR: shell command contains material that would be hidden from the reviewer"
    return None


def shell(sandbox) -> Tool:
    def _sandbox_target() -> dict[str, str]:
        backend = type(sandbox)
        return {
            "backend": f"{backend.__module__}.{backend.__qualname__}",
            "workdir": str(getattr(sandbox, "workdir", ".")),
        }

    def _sandbox_credentials() -> dict[str, str]:
        from ..approval_cards import digest

        return {
            "kind": "sandbox-runtime",
            "generation_sha256": digest(_sandbox_target()),
        }

    def fn(args: dict) -> str:
        cmd = args["cmd"]
        # Every shell invocation needs a reviewable complete command. Do not
        # approve an invisible tail or control/format characters the card may
        # omit or render misleadingly.
        if review_error := _reviewable_command_error(cmd):
            return review_error
        opaque = os.environ.get("MAVERICK_BENCHMARK_OPAQUE", "1") != "0"
        coding = os.environ.get("MAVERICK_CODING_MODE", "").lower() in ("1", "true", "yes")
        # Defensively pop MAVERICK_GOLD_PATCH
        # (and cache) before ANY subprocess inherits the env. This
        # guards the window between agent.run() start and the first
        # defensive_validate() call. Idempotent: a no-op once popped.
        if opaque:
            try:
                from ..coding_mode import get_gold_patch as _gp
                _gp()
            except Exception:
                pass
        if opaque and coding:
            blocked, fragment = _is_blocked_in_opaque(cmd)
            if blocked:
                return (
                    f"ERROR: shell command blocked in benchmark opaque "
                    f"mode (matched {fragment!r}). "
                    "git log -p / git show / git blame / git diff with refs / "
                    "git reflog / git stash list / curl|wget to github.com "
                    "can leak the gold patch; derive your fix from the bug "
                    "description and the code, not from inspecting the answer "
                    "in git history or fetching the upstream PR. "
                    "(Override by setting MAVERICK_BENCHMARK_OPAQUE=0.)"
                )
            if _EDITABLE_INSTALL_PATTERN.search(cmd):
                # Checked before the general install block below (which
                # also matches `pip install -e`) so an editable install gets
                # the worktree-specific explanation.
                return (
                    "ERROR: `pip install -e` is blocked in benchmark opaque "
                    "mode. Editable installs from inside a git worktree "
                    "create .pth/.egg-link entries that may import unpatched "
                    "code from the original tree, silently failing tests "
                    "even when your patch is correct. If you need to install "
                    "the package, use `pip install .` (non-editable) or set "
                    "PYTHONPATH to include the worktree explicitly. "
                    "(Override by setting MAVERICK_BENCHMARK_OPAQUE=0.)"
                )
            # Block ALL package-install commands
            # in opaque mode. The grader's container has deps already;
            # any install here just pollutes the local sandbox for
            # downstream instances. Surface the right framing so the
            # agent treats ImportError as a code bug, not env issue.
            if _PACKAGE_INSTALL_PATTERN.search(cmd):
                return (
                    "ERROR: package install commands are blocked in "
                    "benchmark opaque mode. The grader's test container "
                    "has dependencies pre-installed at the pinned "
                    "versions for this instance. If you see ImportError "
                    "or ModuleNotFoundError, treat it as a CODE bug "
                    "(missing import in production code, wrong module "
                    "path) — not an environment problem. Do NOT try "
                    "`pip install` / `npm install` / `apt install`; "
                    "fix the code instead. "
                    "(Override: MAVERICK_BENCHMARK_OPAQUE=0.)"
                )
        # Every shell command requires a fresh human decision. Silent
        # auto-approval and standing grants are ineligible; interactive modes
        # park the exact command in the dashboard queue or prompt in a TTY.
        # A denial surfaces as a tool result so the agent can react like it can
        # to any other tool error.
        # Bind the exact command, sandbox target, implementation generation,
        # current operator authority, and timeout budget to a one-use permit.
        # The permit is spent under the authority fence at ``sandbox.exec``.
        from ..approval_cards import ApprovalCardError
        from ..safety import (
            ConsentDenied,
            consume_operation_consent,
            require_operation_consent,
        )

        timeout_override = None
        if _is_long_running(cmd):
            try:
                from ..env_setting import env_or_config

                timeout_override = float(
                    env_or_config("MAVERICK_LONG_CMD_TIMEOUT", "sandbox",
                                  "long_command_timeout", "600") or "600"
                )
            except ValueError:
                timeout_override = 600.0
        parameters = {"command": cmd, "timeout_seconds": timeout_override}
        try:
            permit = require_operation_consent(
                "shell",
                risk="high",
                scope=f"sandbox:{_sandbox_target()['workdir']}",
                detail="Run a command in the sandbox.",
                provenance="shell",
                target=_sandbox_target(),
                parameters=parameters,
                parameter_summary=[
                    "Runs this exact command once; nothing else is approved.",
                    _time_limit_words(timeout_override),
                ],
                known_effects=[
                    "The command runs in the sandbox folder and can change files there."
                ],
                unresolved_assumptions=[
                    "The command may modify files or contact services allowed by the sandbox."
                ],
                before="The command has not run.",
                after="The command has run once; its changes stay.",
                irreversible=True,
                display_command=cmd,
                target_provider=_sandbox_target,
                parameters_provider=lambda: {
                    "command": cmd,
                    "timeout_seconds": timeout_override,
                },
                credential_versions_provider=_sandbox_credentials,
                budget_provider=lambda: {
                    "timeout_seconds": timeout_override,
                },
                allow_auto_approve=False,
                consult_ledger=False,
            )
        except ConsentDenied:
            return "ERROR: shell command was not approved; no command was run"
        except ApprovalCardError:
            return (
                "ERROR: shell target, command, or approval authority changed; "
                "review it again"
            )

        # Always falling back to `sandbox.timeout` (60 s on LocalBackend)
        # would kill pytest runs on real SWE-bench repos. Detect long-running commands and pass
        # a higher per-call timeout. Falls back gracefully when sandbox
        # backends don't accept the kwarg.
        try:
            with consume_operation_consent(permit):
                if timeout_override is None:
                    result = sandbox.exec(cmd)
                else:
                    # Determine support before dispatch. Retrying after a
                    # TypeError could duplicate a command whose backend raised
                    # after beginning the external effect.
                    try:
                        exec_signature: Signature = signature(sandbox.exec)
                        exec_signature.bind(cmd, timeout=timeout_override)
                    except (TypeError, ValueError):
                        result = sandbox.exec(cmd)
                    else:
                        result = sandbox.exec(cmd, timeout=timeout_override)
        except ApprovalCardError:
            return (
                "ERROR: shell target, command, or approval authority changed; "
                "review it again"
            )
        out = result.stdout
        if result.stderr:
            out += f"\n[stderr]\n{result.stderr}"
        out += f"\n[exit {result.exit_code}]"
        return out

    return Tool(
        name="shell",
        description=(
            "Run a shell command in the sandbox. Use for running "
            "tests, builds, greps, finding files, inspecting "
            "environment, running reproduction scripts.\n\n"
            "Each invocation starts a fresh shell — there's no "
            "persistent cwd, env, or shell variables between calls. "
            "Use absolute or workspace-relative paths; do NOT `cd` "
            "then expect the next call to be in that directory.\n\n"
            "Always pass non-interactive flags: `-y` / `-f` for "
            "package managers, `-q` to silence prompts. Interactive "
            "commands (vi, nano, less, more, `git rebase -i`) hang "
            "the sandbox. Use `cat`, `head -N`, `tail -N` for reading.\n\n"
            "Common patterns:\n"
            "  • `python -m pytest path::test -xvs` — single test, "
            "verbose, exit-on-fail, no capture\n"
            "  • `grep -rn 'pattern' src/` — recursive search, line "
            "numbers, file paths\n"
            "  • `git diff` — see what you're about to submit\n"
            "  • `python -c 'import pkg; print(pkg.__file__)'` — "
            "check which install Python loads\n\n"
            "In benchmark opaque mode, git-internals access is "
            "blocked: no `git log -p`, `git show <ref>`, `git cat-file`, "
            "`git for-each-ref`, `git rev-list`, or `cat .git/*`. The "
            "gold answer is reachable via those; we block them. Use "
            "`git diff` (working tree vs HEAD) and `git status` "
            "freely — those are safe."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "cmd": {
                    "type": "string",
                    "description": (
                        "Shell command to execute in the sandbox. "
                        "Single line preferred; chain with `&&` or "
                        "`;` for sequences."
                    ),
                },
            },
            "required": ["cmd"],
        },
        fn=fn,
    )
